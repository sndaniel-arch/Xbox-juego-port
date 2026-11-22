/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2022 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#include <chrono>
#include <memory>

#include <rex/logging.h>
#include <rex/runtime.h>
#include <rex/string.h>
#include <rex/system/flags.h>
#include <rex/system/kernel_state.h>

#include <imgui.h>

REXCVAR_DEFINE_BOOL(headless, false, "Kernel",
                    "Don't display any UI, using defaults for prompts as needed");
#include <rex/kernel/xam/private.h>
#include <rex/hook.h>
#include <rex/types.h>
#include <rex/system/xtypes.h>
#include <rex/thread.h>
#include <rex/ui/imgui_dialog.h>
#include <rex/ui/imgui_drawer.h>
#include <rex/ui/window.h>
#include <rex/ui/windowed_app_context.h>

namespace rex {
namespace kernel {
namespace xam {
using namespace rex::system;

// (Hunt v1.4.6, verificación profunda, segundo barrido, V-FE-14.)
// TranslateVirtual never validates and never returns null, so a guest
// pointer + length that runs past the end of the mapping SIGSEGVs the
// host on the read. Same heap validation as A2-R3-01 (see xam_user.cpp
// for the full comment), copied here because XamShowMessageBoxUI reads
// a guest button-pointer array: reject a range that wraps past 4 GiB,
// starts or ends outside any heap, or spans heaps of different kinds
// (or two physical heaps); inside a single heap, require the pages to
// be accessible (readable for a source).
static bool GuestRangeAccessible(uint32_t guest_address, size_t length, bool writable) {
  if (!length) {
    return true;
  }
  if (length > UINT32_MAX - guest_address) {
    return false;
  }
  uint32_t high_address = guest_address + static_cast<uint32_t>(length) - 1;
  rex::memory::BaseHeap* start_heap = REX_KERNEL_MEMORY()->LookupHeap(guest_address);
  const rex::memory::BaseHeap* end_heap = REX_KERNEL_MEMORY()->LookupHeap(high_address);
  if (!start_heap || !end_heap) {
    return false;
  }
  bool start_physical =
      start_heap->heap_type() == rex::memory::HeapType::kGuestPhysical;
  bool end_physical = end_heap->heap_type() == rex::memory::HeapType::kGuestPhysical;
  if (start_physical != end_physical || (start_physical && start_heap != end_heap)) {
    return false;
  }
  if (start_heap == end_heap) {
    auto access = start_heap->QueryRangeAccess(guest_address, high_address);
    if (start_physical) {
      return access == rex::memory::PageAccess::kReadWrite;
    }
    return writable ? access == rex::memory::PageAccess::kReadWrite
                    : access != rex::memory::PageAccess::kNoAccess;
  }
  return true;
}

static bool GuestRangeReadable(uint32_t guest_address, size_t length) {
  return GuestRangeAccessible(guest_address, length, false);
}

// (Hunt v1.4.6, caza ronda 6, A3-R6-05.) load_and_swap<std::u16string>
// scans for NUL with no cap (include/rex/memory/utils.h:245-255), so a
// guest string pointer near the end of the mapping with no NUL inside
// it reads past the mapping (SIGSEGV in the host) while growing the
// host string without bound. Read through this bounded reader instead:
// same 4096 UTF-16 code-unit cap the keyboard dialog buffer uses below
// (A3-R4-06), validated one page at a time so a short string at the end
// of a heap is not rejected for the unmapped pages after it. A unit
// never straddles a page boundary here: the address stays 2-aligned
// (an odd address is corrupt input for a UTF-16 string) and each chunk
// ends on a page boundary. Returns false on an invalid range; on
// success *out holds the string, truncated at the cap if it has no NUL
// within 4096 code units.
constexpr size_t kMaxGuestUiStringCodeUnits = 4096;

static bool ReadGuestU16String(uint32_t guest_address, std::u16string* out) {
  out->clear();
  if ((guest_address & 1) != 0) {
    return false;
  }
  size_t remaining = kMaxGuestUiStringCodeUnits;
  uint32_t address = guest_address;
  while (remaining > 0) {
    size_t page_units = (0x1000 - (address & 0xFFF)) / sizeof(uint16_t);
    size_t chunk_units = remaining < page_units ? remaining : page_units;
    if (!GuestRangeReadable(address, chunk_units * sizeof(uint16_t))) {
      return false;
    }
    const uint16_t* host_ptr =
        REX_KERNEL_MEMORY()->TranslateVirtual<const uint16_t*>(address);
    for (size_t i = 0; i < chunk_units; ++i) {
      uint16_t c = rex::memory::load_and_swap<uint16_t>(host_ptr + i);
      if (!c) {
        return true;
      }
      out->push_back(static_cast<wchar_t>(c));
    }
    address += static_cast<uint32_t>(chunk_units * sizeof(uint16_t));
    remaining -= chunk_units;
  }
  return true;
}

// TODO(gibbed): This is all one giant WIP that seems to work better than the
// previous immediate synchronous completion of dialogs.
//
// The deferred execution of dialog handling is done in such a way that there is
// a pre-, peri- (completion), and post- callback steps.
//
// pre();
// result = completion();
// CompleteOverlapped(result);
// post();
//
// There are games that are batshit insane enough to wait for the X_OVERLAPPED
// to be completed (ie not X_ERROR_PENDING) before creating a listener to
// receive a notification, which is why we have distinct pre- and post- steps.
//
// We deliberately delay the XN_SYS_UI = false notification to give games time
// to create a listener (if they're insane enough do this).

extern std::atomic<int> xam_dialogs_shown_;

class XamDialog : public rex::ui::ImGuiDialog {
 public:
  void set_close_callback(std::function<void()> close_callback) {
    close_callback_ = close_callback;
  }

 protected:
  XamDialog(rex::ui::ImGuiDrawer* imgui_drawer) : rex::ui::ImGuiDialog(imgui_drawer) {}

  void OnClose() override {
    if (close_callback_) {
      close_callback_();
    }
  }

 private:
  std::function<void()> close_callback_ = nullptr;
};

template <typename T>
X_RESULT xeXamDispatchDialog(T* dialog, std::function<X_RESULT(T*)> close_callback,
                             uint32_t overlapped) {
  auto pre = []() {
    // Broadcast XN_SYS_UI = true
    REX_KERNEL_STATE()->BroadcastNotification(0x9, true);
  };
  auto run = [dialog, close_callback]() -> X_RESULT {
    // (Hunt v1.4.6, ronda 4, A3-R4-16.) The result lives in a shared_ptr
    // so the close callback stays valid if the fence wait below times
    // out and run() returns while the dialog is still open: the old
    // code captured a stack `result` by reference, which would dangle
    // the moment run() returned early.
    auto result_state = std::make_shared<X_RESULT>(X_ERROR_FUNCTION_FAILED);
    dialog->set_close_callback(
        [dialog, result_state, close_callback]() { *result_state = close_callback(dialog); });
    rex::thread::Fence fence;
    rex::ui::WindowedAppContext* app_context = REX_KERNEL_STATE()->emulator()->app_context();
    if (app_context &&
        app_context->CallInUIThreadSynchronous([&dialog, &fence]() { dialog->Then(&fence); })) {
      ++xam_dialogs_shown_;
      // (Hunt v1.4.6, ronda 4, A3-R4-16.) The old unbounded fence.Wait()
      // hung the guest thread forever if the UI thread stalled with the
      // dialog up. Wait at most 1000 ms (same timeout as the A4-R3-02
      // pause fences); on timeout the dialog is left open for the user
      // to dismiss later and the guest thread gets FUNCTION_FAILED
      // instead of hanging. The dialog deletes itself on Close, and the
      // close callback above owns result_state, so nothing dangles.
      if (!fence.WaitFor(std::chrono::milliseconds(1000))) {
        REXKRNL_WARN("xeXamDispatchDialog: dialog fence timed out after 1000 ms; returning "
                     "FUNCTION_FAILED, dialog left open");
      }
      --xam_dialogs_shown_;
    } else {
      delete dialog;
    }
    // dialog should be deleted at this point!
    return *result_state;
  };
  auto post = []() {
    rex::thread::Sleep(std::chrono::milliseconds(100));
    // Broadcast XN_SYS_UI = false
    REX_KERNEL_STATE()->BroadcastNotification(0x9, false);
  };
  if (!overlapped) {
    pre();
    auto result = run();
    post();
    return result;
  } else {
    REX_KERNEL_STATE()->CompleteOverlappedDeferred(run, overlapped, pre, post);
    return X_ERROR_IO_PENDING;
  }
}

template <typename T>
X_RESULT xeXamDispatchDialogEx(T* dialog,
                               std::function<X_RESULT(T*, uint32_t&, uint32_t&)> close_callback,
                               uint32_t overlapped) {
  auto pre = []() {
    // Broadcast XN_SYS_UI = true
    REX_KERNEL_STATE()->BroadcastNotification(0x9, true);
  };
  auto run = [dialog, close_callback](uint32_t& extended_error, uint32_t& length) -> X_RESULT {
    rex::ui::WindowedAppContext* app_context = REX_KERNEL_STATE()->emulator()->app_context();
    // (Hunt v1.4.6, ronda 3, A3-R3-18.) As in xeXamDispatchDialog:
    // result/extended_error/length are only assigned inside the close
    // callback, which never runs when there is no UI thread.
    // (Hunt v1.4.6, ronda 4, A3-R4-16.) The outcome lives in shared
    // state for the same reason as in xeXamDispatchDialog: the fence
    // wait below can time out and return early while the dialog is
    // still open.
    struct DialogExOutcome {
      X_RESULT result = X_ERROR_FUNCTION_FAILED;
      uint32_t extended_error = X_ERROR_FUNCTION_FAILED;
      uint32_t length = 0;
    };
    auto outcome = std::make_shared<DialogExOutcome>();
    dialog->set_close_callback([dialog, outcome, close_callback]() {
      outcome->result = close_callback(dialog, outcome->extended_error, outcome->length);
    });
    rex::thread::Fence fence;
    if (app_context &&
        app_context->CallInUIThreadSynchronous([&dialog, &fence]() { dialog->Then(&fence); })) {
      ++xam_dialogs_shown_;
      if (!fence.WaitFor(std::chrono::milliseconds(1000))) {
        REXKRNL_WARN("xeXamDispatchDialogEx: dialog fence timed out after 1000 ms; returning "
                     "FUNCTION_FAILED, dialog left open");
      }
      --xam_dialogs_shown_;
    } else {
      delete dialog;
    }
    // dialog should be deleted at this point!
    extended_error = outcome->extended_error;
    length = outcome->length;
    return outcome->result;
  };
  auto post = []() {
    rex::thread::Sleep(std::chrono::milliseconds(100));
    // Broadcast XN_SYS_UI = false
    REX_KERNEL_STATE()->BroadcastNotification(0x9, false);
  };
  if (!overlapped) {
    pre();
    // (Hunt v1.4.6, ronda 3, A3-R3-18.) See xeXamDispatchDialogEx
    // above: these are only assigned inside the close callback.
    uint32_t extended_error = X_ERROR_FUNCTION_FAILED;
    uint32_t length = 0;
    auto result = run(extended_error, length);
    post();
    // TODO(gibbed): do something with extended_error/length?
    return result;
  } else {
    REX_KERNEL_STATE()->CompleteOverlappedDeferredEx(run, overlapped, pre, post);
    return X_ERROR_IO_PENDING;
  }
}

X_RESULT xeXamDispatchHeadless(std::function<X_RESULT()> run_callback, uint32_t overlapped) {
  auto pre = []() {
    REXKRNL_DEBUG("xeXamDispatchHeadless: Broadcasting XN_SYS_UI = true");
    // Broadcast XN_SYS_UI = true
    REX_KERNEL_STATE()->BroadcastNotification(0x9, true);
  };
  auto post = []() {
    rex::thread::Sleep(std::chrono::milliseconds(100));
    REXKRNL_DEBUG("xeXamDispatchHeadless: Broadcasting XN_SYS_UI = false");
    // Broadcast XN_SYS_UI = false
    REX_KERNEL_STATE()->BroadcastNotification(0x9, false);
  };
  if (!overlapped) {
    pre();
    auto result = run_callback();
    post();
    return result;
  } else {
    REX_KERNEL_STATE()->CompleteOverlappedDeferred(run_callback, overlapped, pre, post);
    return X_ERROR_IO_PENDING;
  }
}

X_RESULT xeXamDispatchHeadlessEx(std::function<X_RESULT(uint32_t&, uint32_t&)> run_callback,
                                 uint32_t overlapped) {
  auto pre = []() {
    // Broadcast XN_SYS_UI = true
    REX_KERNEL_STATE()->BroadcastNotification(0x9, true);
  };
  auto post = []() {
    rex::thread::Sleep(std::chrono::milliseconds(100));
    // Broadcast XN_SYS_UI = false
    REX_KERNEL_STATE()->BroadcastNotification(0x9, false);
  };
  if (!overlapped) {
    pre();
    // (Hunt v1.4.6, ronda 4, A3-R4-17.) Same class as R3-18 in the
    // dispatchers with callers: these were passed to the callback
    // uninitialised. This dispatcher currently has no callers, but the
    // fix is the same one-liner as R3-18.
    uint32_t extended_error = X_ERROR_FUNCTION_FAILED;
    uint32_t length = 0;
    auto result = run_callback(extended_error, length);
    post();
    // TODO(gibbed): do something with extended_error/length?
    return result;
  } else {
    REX_KERNEL_STATE()->CompleteOverlappedDeferredEx(run_callback, overlapped, pre, post);
    return X_ERROR_IO_PENDING;
  }
}

u32 XamIsUIActive_entry() {
  return xeXamIsUIActive();
}

class MessageBoxDialog : public XamDialog {
 public:
  MessageBoxDialog(rex::ui::ImGuiDrawer* imgui_drawer, std::string title, std::string description,
                   std::vector<std::string> buttons, uint32_t default_button)
      : XamDialog(imgui_drawer),
        title_(title),
        description_(description),
        buttons_(std::move(buttons)),
        default_button_(default_button),
        chosen_button_(default_button) {
    if (!title_.size()) {
      title_ = "Message Box";
    }
  }

  uint32_t chosen_button() const { return chosen_button_; }

  void OnDraw(ImGuiIO& io) override {
    bool first_draw = false;
    if (!has_opened_) {
      ImGui::OpenPopup(title_.c_str());
      has_opened_ = true;
      first_draw = true;
    }
    if (ImGui::BeginPopupModal(title_.c_str(), nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
      if (description_.size()) {
        ImGui::Text("%s", description_.c_str());
      }
      if (first_draw) {
        ImGui::SetKeyboardFocusHere();
      }
      for (size_t i = 0; i < buttons_.size(); ++i) {
        if (ImGui::Button(buttons_[i].c_str())) {
          chosen_button_ = static_cast<uint32_t>(i);
          ImGui::CloseCurrentPopup();
          Close();
        }
        ImGui::SameLine();
      }
      ImGui::Spacing();
      ImGui::Spacing();
      ImGui::EndPopup();
    } else {
      Close();
    }
  }

 private:
  bool has_opened_ = false;
  std::string title_;
  std::string description_;
  std::vector<std::string> buttons_;
  uint32_t default_button_ = 0;
  uint32_t chosen_button_ = 0;
};

// https://www.se7ensins.com/forums/threads/working-xshowmessageboxui.844116/
u32 XamShowMessageBoxUI_entry(u32 user_index, mapped_wstring title_ptr, mapped_wstring text_ptr,
                              u32 button_count, mapped_u32 button_ptrs, u32 active_button,
                              u32 flags, mapped_u32 result_ptr, mapped_void overlapped) {
  // (Audit A3, ronda 6, R6-06.) result_ptr is written by the lambdas
  // below (headless run + dialog close); a NULL one used to write the
  // chosen button to guest address 0 when the dialog closed.
  if (!result_ptr) {
    return X_ERROR_INVALID_PARAMETER;
  }

  // (Hunt v1.4.6, ronda 4, A3-R4-16.) A message box with no buttons
  // can never be closed: the guest thread would wait on its fence
  // forever. And active_button must name one of the buttons — the
  // headless path and the close callback both return it as the result.
  if (!button_count || active_button >= button_count) {
    return X_ERROR_INVALID_PARAMETER;
  }

  // (Hunt v1.4.6, verificación profunda, segundo barrido, V-FE-14.)
  // Same shape as FE-08 (WriteProfileSettings): `button_count` is
  // guest-controlled (u32) with no upper bound, and the loop below
  // reads button_ptrs[i] for i < button_count. A real message box has
  // 1-3 buttons (the modern equivalent takes at most three); cap at 16
  // -- 5x that -- so the loop is bounded, and validate the whole
  // button_ptrs array (button_count * 4 bytes) before the first read:
  // an array crossing the end of the mapping SIGSEGVd the host, and a
  // huge count with a valid array would grow the host button vector
  // without bound. The cap is checked first so the validated length
  // can never overflow. (Each button *string* is still read
  // NUL-terminated like title_ptr/text_ptr above; that is the systemic
  // string-read class, not this array/count fix.)
  constexpr uint32_t kMaxMessageBoxButtons = 16;
  if (button_count > kMaxMessageBoxButtons) {
    return X_ERROR_INVALID_PARAMETER;
  }

  REXKRNL_DEBUG(
      "XamShowMessageBoxUI({:08X}, {:08X}, {:08X}, {:08X}, {:08X}, {:08X}, {:08X}, {:08X}, {:08X})",
      uint32_t(user_index), title_ptr.guest_address(), text_ptr.guest_address(),
      uint32_t(button_count), button_ptrs.guest_address(), uint32_t(active_button), uint32_t(flags),
      result_ptr.guest_address(), overlapped.guest_address());
  std::string title;
  if (title_ptr) {
    // (Hunt v1.4.6, caza ronda 6, A3-R6-05.) Bounded read: the old
    // load_and_swap<std::u16string> scanned for NUL with no cap.
    std::u16string title_u16;
    if (!ReadGuestU16String(title_ptr.guest_address(), &title_u16)) {
      return X_ERROR_INVALID_PARAMETER;
    }
    title = rex::string::to_utf8(title_u16);
  } else {
    title = "";  // TODO(gibbed): default title based on flags?
  }
  std::string text_str;
  if (text_ptr) {
    // (Hunt v1.4.6, caza ronda 6, A3-R6-05.) Bounded read, as title above.
    std::u16string text_u16;
    if (!ReadGuestU16String(text_ptr.guest_address(), &text_u16)) {
      return X_ERROR_INVALID_PARAMETER;
    }
    text_str = rex::string::to_utf8(text_u16);
  } else {
    text_str = "";
  }

  std::vector<std::string> buttons;
  // (Hunt v1.4.6, ronda 3, A3-R3-12.) button_ptrs was the one
  // pointer in this function without a guard (result_ptr, title_ptr
  // and text_ptr all have one): button_count > 0 with a NULL array
  // SIGSEGVd the host on the first iteration.
  if (button_count && !button_ptrs) {
    return X_ERROR_INVALID_PARAMETER;
  }
  // (Hunt v1.4.6, verificación profunda, segundo barrido, V-FE-14.)
  // NULL is covered above; validate the array range itself before the
  // loop reads button_ptrs[i]. button_count <= 16 here (cap above),
  // so the validated length is at most 64 bytes.
  if (button_count &&
      !GuestRangeReadable(button_ptrs.guest_address(),
                          static_cast<size_t>(button_count) * sizeof(uint32_t))) {
    return X_ERROR_INVALID_PARAMETER;
  }
  for (uint32_t i = 0; i < button_count; ++i) {
    uint32_t button_ptr = button_ptrs[i];
    // (Hunt v1.4.6, caza ronda 6, A3-R6-05.) Bounded read, as title
    // above: each button string was another unbounded NUL scan. A NULL
    // button pointer is corrupt input and is rejected here (the array
    // itself was validated above, not the strings it points to).
    std::u16string button_u16;
    if (!ReadGuestU16String(button_ptr, &button_u16)) {
      return X_ERROR_INVALID_PARAMETER;
    }
    buttons.push_back(rex::string::to_utf8(button_u16));
  }

  X_RESULT result;
  if (REXCVAR_GET(headless)) {
    // Auto-pick the focused button.
    auto run = [result_ptr, active_button]() -> X_RESULT {
      *result_ptr = static_cast<uint32_t>(active_button);
      return X_ERROR_SUCCESS;
    };
    result = xeXamDispatchHeadless(run, overlapped.guest_address());
  } else {
    // TODO(benvanik): setup icon states.
    switch (flags & 0xF) {
      case 0:
        // config.pszMainIcon = nullptr;
        break;
      case 1:
        // config.pszMainIcon = TD_ERROR_ICON;
        break;
      case 2:
        // config.pszMainIcon = TD_WARNING_ICON;
        break;
      case 3:
        // config.pszMainIcon = TD_INFORMATION_ICON;
        break;
    }
    auto close = [result_ptr](MessageBoxDialog* dialog) -> X_RESULT {
      *result_ptr = dialog->chosen_button();
      return X_ERROR_SUCCESS;
    };
    const Runtime* emulator = REX_KERNEL_STATE()->emulator();
    ui::ImGuiDrawer* imgui_drawer = emulator->imgui_drawer();
    if (imgui_drawer) {
      result = xeXamDispatchDialog<MessageBoxDialog>(
          new MessageBoxDialog(imgui_drawer, title, text_str, buttons, active_button), close,
          overlapped.guest_address());
    } else {
      // Fallback to headless if no drawer available
      auto run = [result_ptr, active_button]() -> X_RESULT {
        *result_ptr = static_cast<uint32_t>(active_button);
        return X_ERROR_SUCCESS;
      };
      result = xeXamDispatchHeadless(run, overlapped.guest_address());
    }
  }
  return result;
}

class KeyboardInputDialog : public XamDialog {
 public:
  KeyboardInputDialog(rex::ui::ImGuiDrawer* imgui_drawer, std::string title,
                      std::string description, std::string default_text, size_t max_length)
      : XamDialog(imgui_drawer),
        title_(title),
        description_(description),
        default_text_(default_text),
        max_length_(max_length),
        text_buffer_() {
    if (!title_.size()) {
      if (!description_.size()) {
        title_ = "Keyboard Input";
      } else {
        title_ = description_;
        description_ = "";
      }
    }
    text_ = default_text;
    text_buffer_.resize(max_length);
    rex::string::copy_truncating(text_buffer_.data(), default_text_, text_buffer_.size());
  }

  const std::string& text() const { return text_; }
  bool cancelled() const { return cancelled_; }

  void OnDraw(ImGuiIO& io) override {
    bool first_draw = false;
    if (!has_opened_) {
      ImGui::OpenPopup(title_.c_str());
      has_opened_ = true;
      first_draw = true;
    }
    if (ImGui::BeginPopupModal(title_.c_str(), nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
      if (description_.size()) {
        ImGui::TextWrapped("%s", description_.c_str());
      }
      if (first_draw) {
        ImGui::SetKeyboardFocusHere();
      }
      if (ImGui::InputText("##body", text_buffer_.data(), text_buffer_.size(),
                           ImGuiInputTextFlags_EnterReturnsTrue)) {
        text_ = std::string(text_buffer_.data(), text_buffer_.size());
        cancelled_ = false;
        ImGui::CloseCurrentPopup();
        Close();
      }
      if (ImGui::Button("OK")) {
        text_ = std::string(text_buffer_.data(), text_buffer_.size());
        cancelled_ = false;
        ImGui::CloseCurrentPopup();
        Close();
      }
      ImGui::SameLine();
      if (ImGui::Button("Cancel")) {
        text_ = "";
        cancelled_ = true;
        ImGui::CloseCurrentPopup();
        Close();
      }
      ImGui::Spacing();
      ImGui::EndPopup();
    } else {
      Close();
    }
  }

 private:
  bool has_opened_ = false;
  std::string title_;
  std::string description_;
  std::string default_text_;
  size_t max_length_ = 0;
  std::vector<char> text_buffer_;
  std::string text_ = "";
  bool cancelled_ = true;
};

// https://www.se7ensins.com/forums/threads/release-how-to-use-xshowkeyboardui-release.906568/
u32 XamShowKeyboardUI_entry(u32 user_index, u32 flags, mapped_wstring default_text,
                            mapped_wstring title, mapped_wstring description, mapped_wstring buffer,
                            u32 buffer_length, mapped_void overlapped) {
  REXKRNL_DEBUG("XamShowKeyboardUI({:08X}, {:08X}, {:08X}, {:08X}, {:08X}, {:08X}, {:08X}, {:08X})",
                uint32_t(user_index), uint32_t(flags), default_text.guest_address(),
                title.guest_address(), description.guest_address(), buffer.guest_address(),
                uint32_t(buffer_length), overlapped.guest_address());
  if (!buffer) {
    return X_ERROR_INVALID_PARAMETER;
  }

  // (Hunt v1.4.6, ronda 4, A3-R4-06.) buffer_length is guest controlled
  // (u32): the old code memset buffer_length * 2 bytes from it — up to
  // ~8 GiB past the end of the mapping — and built a dialog with a
  // buffer_length + 1 vector, which wrapped to 0 at 0xFFFFFFFF and
  // could resize to 4 GiB. Keyboard input is short text: reject
  // anything over 4096 UTF-16 code units, and validate the destination
  // range before the memset below runs. The +1 below is computed in
  // size_t, so it cannot wrap.
  if (buffer_length > 4096) {
    return X_ERROR_INVALID_PARAMETER;
  }
  {
    size_t buffer_size_check = static_cast<size_t>(buffer_length) * 2;
    uint32_t buffer_guest = buffer.guest_address();
    bool range_ok = true;
    if (buffer_size_check > UINT32_MAX - buffer_guest) {
      range_ok = false;
    } else if (buffer_size_check) {
      uint32_t high_address = buffer_guest + static_cast<uint32_t>(buffer_size_check) - 1;
      rex::memory::BaseHeap* start_heap = REX_KERNEL_MEMORY()->LookupHeap(buffer_guest);
      const rex::memory::BaseHeap* end_heap = REX_KERNEL_MEMORY()->LookupHeap(high_address);
      range_ok = start_heap && end_heap;
      if (range_ok) {
        bool start_physical =
            start_heap->heap_type() == rex::memory::HeapType::kGuestPhysical;
        bool end_physical = end_heap->heap_type() == rex::memory::HeapType::kGuestPhysical;
        range_ok = start_physical == end_physical &&
                   !(start_physical && start_heap != end_heap);
      }
      if (range_ok && start_heap == end_heap) {
        range_ok = start_heap->QueryRangeAccess(buffer_guest, high_address) ==
                   rex::memory::PageAccess::kReadWrite;
      }
    }
    if (!range_ok) {
      return X_ERROR_INVALID_PARAMETER;
    }
  }

  assert_true(overlapped.guest_address() != 0);

  auto buffer_size = static_cast<size_t>(buffer_length) * 2;

  X_RESULT result;
  if (REXCVAR_GET(headless)) {
    auto run = [default_text, buffer, buffer_length, buffer_size]() -> X_RESULT {
      // Redirect default_text back into the buffer.
      if (!default_text) {
        std::memset(buffer, 0, buffer_size);
      } else {
        rex::string::copy_and_swap_truncating(buffer, default_text.value(), buffer_length);
      }
      return X_ERROR_SUCCESS;
    };
    result = xeXamDispatchHeadless(run, overlapped.guest_address());
  } else {
    auto close = [buffer, buffer_length](KeyboardInputDialog* dialog, uint32_t& extended_error,
                                         uint32_t& length) -> X_RESULT {
      if (dialog->cancelled()) {
        extended_error = X_ERROR_CANCELLED;
        length = 0;
        return X_ERROR_SUCCESS;
      } else {
        // Zero the output buffer.
        auto text = rex::string::to_utf16(dialog->text());
        rex::string::copy_and_swap_truncating(buffer, text, buffer_length);
        extended_error = X_ERROR_SUCCESS;
        length = 0;
        return X_ERROR_SUCCESS;
      }
    };
    const Runtime* emulator = REX_KERNEL_STATE()->emulator();
    ui::ImGuiDrawer* imgui_drawer = emulator->imgui_drawer();

    // Read and convert title/description/default_text from guest memory as utf16 to utf8 strings
    // (Hunt v1.4.6, caza ronda 6, A3-R6-05.) Bounded reads: these were
    // the same unbounded NUL scans as the message-box strings above.
    std::string title_str;
    if (title) {
      std::u16string title_u16;
      if (!ReadGuestU16String(title.guest_address(), &title_u16)) {
        return X_ERROR_INVALID_PARAMETER;
      }
      title_str = rex::string::to_utf8(title_u16);
    }
    std::string desc_str;
    if (description) {
      std::u16string desc_u16;
      if (!ReadGuestU16String(description.guest_address(), &desc_u16)) {
        return X_ERROR_INVALID_PARAMETER;
      }
      desc_str = rex::string::to_utf8(desc_u16);
    }
    std::string def_text_str;
    if (default_text) {
      std::u16string def_text_u16;
      if (!ReadGuestU16String(default_text.guest_address(), &def_text_u16)) {
        return X_ERROR_INVALID_PARAMETER;
      }
      def_text_str = rex::string::to_utf8(def_text_u16);
    }

    if (imgui_drawer) {
      // (Hunt v1.4.6, ronda 4, A3-R4-06.) +1 in size_t: the old u32
      // arithmetic wrapped 0xFFFFFFFF + 1 to 0.
      size_t buffer_length_safe = static_cast<size_t>(buffer_length) + 1;  // +1 for null terminator, just in case
      result = xeXamDispatchDialogEx<KeyboardInputDialog>(
          new KeyboardInputDialog(imgui_drawer, title_str, desc_str, def_text_str,
                                  buffer_length_safe),
          close, overlapped.guest_address());
    } else {
      // Fallback to headless
      auto run = [default_text, buffer, buffer_length, buffer_size]() -> X_RESULT {
        if (!default_text) {
          std::memset(buffer, 0, buffer_size);
        } else {
          rex::string::copy_and_swap_truncating(buffer, default_text.value(), buffer_length);
        }
        return X_ERROR_SUCCESS;
      };
      result = xeXamDispatchHeadless(run, overlapped.guest_address());
    }
  }
  return result;
}

u32 XamShowDeviceSelectorUI_entry(u32 user_index, u32 content_type, u32 content_flags,
                                  u64 total_requested, mapped_u32 device_id_ptr,
                                  mapped_void overlapped) {
  // (Audit A3, ronda 6, R6-06.) device_id_ptr is written by the
  // headless lambda below; a NULL one used to write the device id to
  // guest address 0.
  if (!device_id_ptr) {
    return X_ERROR_INVALID_PARAMETER;
  }

  REXKRNL_INFO("XamShowDeviceSelectorUI({:08X}, {:08X}, {:08X}, {:016X}, {:08X}, {:08X})",
                uint32_t(user_index), uint32_t(content_type), uint32_t(content_flags),
                uint64_t(total_requested), device_id_ptr.guest_address(),
                overlapped.guest_address());
  return xeXamDispatchHeadless(
      [device_id_ptr]() -> X_RESULT {
        // NOTE: 0x00000001 is our dummy device ID from xam_content.cc
        *device_id_ptr = 0x00000001;
        return X_ERROR_SUCCESS;
      },
      overlapped.guest_address());
}

void XamShowDirtyDiscErrorUI_entry(u32 user_index) {
  REXKRNL_ERROR("XamShowDirtyDiscErrorUI called! user_index={}", uint32_t(user_index));
  REXKRNL_ERROR("This indicates a disc/file read error - check that all game files exist");

  const Runtime* emulator = REX_KERNEL_STATE()->emulator();
  ui::ImGuiDrawer* imgui_drawer = emulator->imgui_drawer();
  if (imgui_drawer) {
    xeXamDispatchDialog<MessageBoxDialog>(
        new MessageBoxDialog(imgui_drawer, "Disc Read Error",
                             "There's been an issue reading content from the game disc.\nThis is "
                             "likely caused by bad or unimplemented file IO calls.",
                             {"OK"}, 0),
        [](MessageBoxDialog*) -> X_RESULT { return X_ERROR_SUCCESS; }, 0);
  } else {
    // No UI available - log prominently and pause to let user see the error
    REXKRNL_ERROR("===========================================");
    REXKRNL_ERROR("FATAL: Disc Read Error (no UI to display)");
    REXKRNL_ERROR("Check that all game content files are present");
    REXKRNL_ERROR("Missing files or bad mounts cause this error");
    REXKRNL_ERROR("===========================================");
  }
  // This is death, and should never return.
  // TODO(benvanik): cleaner exit.
  exit(1);
}

u32 XamShowPartyUI_entry(u32 r3, u32 r4) {
  return X_ERROR_FUNCTION_FAILED;
}

u32 XamShowCommunitySessionsUI_entry(u32 r3, u32 r4) {
  return X_ERROR_FUNCTION_FAILED;
}

uint32_t XamShowMessageBoxUIEx_entry() {
  // TODO(tomc): implement properly
  // (Hunt v1.4.6, ronda 4, A3-R4-15.) The old code returned 0 (success)
  // without doing anything: the game believed the dialog had been shown
  // and answered. The honest answer until this is implemented is the
  // same FUNCTION_FAILED the other unimplemented UI stubs in this file
  // return (XamShowPartyUI, XamShowCommunitySessionsUI).
  static bool warned = false;
  if (!warned) {
    REXKRNL_WARN("[STUB] XamShowMessageBoxUIEx - not implemented");
    warned = true;
  }
  return X_ERROR_FUNCTION_FAILED;
}

}  // namespace xam
}  // namespace kernel
}  // namespace rex

REX_EXPORT(__imp__XamIsUIActive, rex::kernel::xam::XamIsUIActive_entry)
REX_EXPORT(__imp__XamShowMessageBoxUI, rex::kernel::xam::XamShowMessageBoxUI_entry)
REX_EXPORT(__imp__XamShowKeyboardUI, rex::kernel::xam::XamShowKeyboardUI_entry)
REX_EXPORT(__imp__XamShowDeviceSelectorUI, rex::kernel::xam::XamShowDeviceSelectorUI_entry)
REX_EXPORT(__imp__XamShowDirtyDiscErrorUI, rex::kernel::xam::XamShowDirtyDiscErrorUI_entry)
REX_EXPORT(__imp__XamShowPartyUI, rex::kernel::xam::XamShowPartyUI_entry)
REX_EXPORT(__imp__XamShowCommunitySessionsUI, rex::kernel::xam::XamShowCommunitySessionsUI_entry)
REX_EXPORT(__imp__XamShowMessageBoxUIEx, rex::kernel::xam::XamShowMessageBoxUIEx_entry)

REX_EXPORT_STUB_RETURN(__imp__XamIsGuideDisabled, 0);
REX_EXPORT_STUB_RETURN(__imp__XamIsMessageBoxActive, 0);
REX_EXPORT_STUB_RETURN(__imp__XamIsNuiUIActive, 0);
REX_EXPORT_STUB_RETURN(__imp__XamIsSysUiInvokedByTitle, 0);
REX_EXPORT_STUB_RETURN(__imp__XamIsSysUiInvokedByXenonButton, 0);
REX_EXPORT_STUB_RETURN(__imp__XamIsUIThread, 0);
REX_EXPORT_STUB_RETURN(__imp__XamNavigate, 0);
REX_EXPORT_STUB_RETURN(__imp__XamNavigateBack, 0);
REX_EXPORT_STUB_RETURN(__imp__XamOverrideHudOpenType, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowAchievementDetailsUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowAchievementsUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowAchievementsUIEx, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowAndWaitForMessageBoxEx, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowAvatarAwardGamesUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowAvatarAwardsUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowAvatarMiniCreatorUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowBadDiscErrorUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowBeaconsUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowBrandedKeyboardUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowChangeGamerTileUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowComplaintUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowCreateProfileUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowCreateProfileUIEx, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowCsvTransitionUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowCustomMessageComposeUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowCustomPlayerListUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowDirectAcquireUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowEditProfileUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowFirstRunWelcomeUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowFitnessBodyProfileUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowFitnessClearUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowFitnessWarnAboutPrivacyUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowFitnessWarnAboutTimeUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowFofUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowForcedNameChangeUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowFriendRequestUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowFriendsUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowFriendsUIp, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowGameInviteUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowGameVoiceChannelUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowGamerCardUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowGamerCardUIForXUID, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowGamerCardUIForXUIDp, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowGamesUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowGenericOnlineAppUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowGoldUpgradeUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowGraduateUserUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowGuideUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowJoinPartyUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowJoinSessionByIdInProgressUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowJoinSessionInProgressUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowKeyboardUIMessenger, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowLiveSignupUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowLiveUpsellUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowLiveUpsellUIEx, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowMarketplaceDownloadItemsUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowMarketplaceGetOrderReceipts, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowMarketplacePurchaseOrderUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowMarketplacePurchaseOrderUIEx, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowMarketplaceUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowMarketplaceUIEx, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowMessageBox, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowMessageComposeUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowMessagesUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowMessagesUIEx, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowMessengerUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowMultiplayerUpgradeUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowNetworkStorageSyncUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowNuiAchievementsUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowNuiCommunitySessionsUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowNuiControllerRequiredUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowNuiDeviceSelectorUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowNuiDirtyDiscErrorUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowNuiFriendRequestUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowNuiFriendsUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowNuiGameInviteUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowNuiGamerCardUIForXUID, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowNuiGamesUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowNuiGuideUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowNuiHardwareRequiredUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowNuiJoinSessionInProgressUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowNuiMarketplaceDownloadItemsUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowNuiMarketplaceUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowNuiMessageBoxUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowNuiMessagesUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowNuiPartyUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowNuiSigninUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowNuiVideoRichPresenceUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowOptionalMediaUpdateRequiredUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowOptionalMediaUpdateRequiredUIEx, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowOptionsUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowPamUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowPartyInviteUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowPartyJoinInProgressUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowPasscodeVerifyUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowPasscodeVerifyUIEx, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowPaymentOptionsUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowPersonalizationUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowPlayerReviewUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowPlayersUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowPrivateChatInviteUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowQuickChatUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowQuickChatUIp, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowQuickLaunchUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowRecentMessageUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowRecentMessageUIEx, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowReputationUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowSigninUIEx, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowSigninUIp, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowSignupCreditCardUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowSocialPostUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowStorePickerUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowTFAUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowTermsOfUseUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowUpdaterUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowVideoChatInviteUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowVideoRichPresenceUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowVoiceMailUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowVoiceSettingsUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowWhatsOnUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamShowWordRegisterUI, 0);
REX_EXPORT_STUB_RETURN(__imp__XamSysUiDisableAutoClose, 0);

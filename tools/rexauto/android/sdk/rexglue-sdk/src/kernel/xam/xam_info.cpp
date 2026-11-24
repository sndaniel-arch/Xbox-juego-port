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

#include <string>

#include <rex/kernel/xam/module.h>
#include <rex/kernel/xam/private.h>
#include <rex/logging.h>
#include <rex/hook.h>
#include <rex/types.h>
#include <rex/string.h>
#include <rex/system/kernel_state.h>
#include <rex/system/user_module.h>
#include <rex/system/xenumerator.h>
#include <rex/system/xthread.h>
#include <rex/system/xtypes.h>

#if REX_PLATFORM_WIN32
#include <windows.h>
#endif

#include <fmt/format.h>
#include <fmt/xchar.h>

namespace rex {
namespace kernel {
namespace xam {
using namespace rex::system;

// (Hunt v1.4.6, verificación profunda, segundo barrido, V-FE-15.)
// TranslateVirtual never validates and never returns null, so a guest
// pointer + length that runs past the end of the mapping SIGSEGVs the
// host on the memset/memcpy. Same heap validation as A2-R3-01 (see
// xam_user.cpp for the full comment), copied here because this file's
// format/loader entries write guest buffers sized by a guest count:
// reject a range that wraps past 4 GiB, starts or ends outside any
// heap, or spans heaps of different kinds (or two physical heaps);
// inside a single heap, require the pages to be accessible (readable
// for a source, read/write for a destination).
static bool GuestRangeAccessible(uint32_t guest_address, size_t length, bool writable) {
  if (!length) {
    return true;
  }
  if (length > UINT32_MAX - guest_address) {
    return false;
  }
  uint32_t high_address = guest_address + static_cast<uint32_t>(length) - 1;
  rex::memory::BaseHeap* start_heap = REX_KERNEL_MEMORY()->LookupHeap(guest_address);
  rex::memory::BaseHeap* end_heap = REX_KERNEL_MEMORY()->LookupHeap(high_address);
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
  // (Hunt v1.4.6, ronda 8, A3-R8-13.) The range straddles a heap
  // boundary -- legitimate allocations never do (each allocation
  // lives in a single heap) -- and the old code returned true here
  // without checking anything, so a buffer whose first page is
  // uncommitted or NoAccess sailed through every GuestRange* check.
  // Validate both ends instead: the tail of the start heap and the
  // head of the end heap, with the same read/write rule as above.
  // (Hunt v1.4.6, ronda 9, A3-R9-10.) A range spanning more than
  // two heaps is rejected outright below: the middle heap would
  // otherwise go unchecked, and no legitimate range spans even
  // one boundary (see the R8-13 comment above).
  auto range_ok = [&](rex::memory::PageAccess access) {
    if (start_physical) {
      return access == rex::memory::PageAccess::kReadWrite;
    }
    return writable ? access == rex::memory::PageAccess::kReadWrite
                    : access != rex::memory::PageAccess::kNoAccess;
  };
  uint32_t start_heap_end = start_heap->heap_base() + start_heap->heap_size() - 1;
  // (Hunt v1.4.6, ronda 9, A3-R9-10.) The heap right after the start
  // heap must be the end heap: anything else means the range spans
  // three or more heaps (or a gap in the heap map) and the middle heap
  // would go unchecked. Reject outright instead of validating only
  // the two ends.
  if (REX_KERNEL_MEMORY()->LookupHeap(start_heap_end + 1) != end_heap) {
    return false;
  }
  return range_ok(start_heap->QueryRangeAccess(guest_address, start_heap_end)) &&
         range_ok(end_heap->QueryRangeAccess(end_heap->heap_base(), high_address));
}

static bool GuestRangeReadable(uint32_t guest_address, size_t length) {
  return GuestRangeAccessible(guest_address, length, false);
}

static bool GuestRangeWritable(uint32_t guest_address, size_t length) {
  return GuestRangeAccessible(guest_address, length, true);
}

// (Hunt v1.4.6, ronda 10, A3-R10-03.) Bounded guest C-string read:
// MappedPtr<char>::value() builds a string_view straight off the
// host pointer -- a strlen to NUL with no cap -- so a guest launch
// path with no NUL in its page ran the host scan into unmapped
// memory. Read page by page (each chunk validated readable first,
// like the R6-05 ReadGuestU16String reader in xam_ui.cpp), stop at
// the first NUL, truncate at 4096 chars if there is none. Returns
// false on an invalid range.
constexpr size_t kMaxGuestPathChars = 4096;

static bool ReadGuestCString(uint32_t guest_address, std::string* out) {
  out->clear();
  size_t remaining = kMaxGuestPathChars;
  uint32_t address = guest_address;
  while (remaining > 0) {
    size_t page_bytes = 0x1000 - (address & 0xFFF);
    size_t chunk = remaining < page_bytes ? remaining : page_bytes;
    if (!GuestRangeReadable(address, chunk)) {
      return false;
    }
    const char* host_ptr = REX_KERNEL_MEMORY()->TranslateVirtual<const char*>(address);
    for (size_t i = 0; i < chunk; ++i) {
      char c = host_ptr[i];
      if (!c) {
        return true;
      }
      out->push_back(c);
    }
    address += static_cast<uint32_t>(chunk);
    remaining -= chunk;
  }
  return true;
}

// (Hunt v1.4.6, ronda 10, A3-R10-03.) Bounded guest UTF-16 read
// (same reader as R6-05 in xam_ui.cpp, copied here): the resource
// locator entries below scanned container/resource/filename for
// NUL with no cap. 4096 code-unit cap, validated one page at a
// time; returns false on an invalid range.
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

// (Hunt v1.4.6, ronda 10, A3-R10-04.) A guest address is only a
// freeable system-heap allocation if it is the start of a live
// (committed) region: BaseHeap::Release already rejects a
// non-region-start, but it happily frees ANY region start, including
// a live game allocation the guest merely guessed. QueryRegionInfo
// reports allocation_base == the region start and state == 0 for a
// free region, so both checks together reject interior pages, free
// regions and gap addresses. This cannot prove ownership -- no live
// allocation tracking exists -- so freeing another live region start
// remains possible; see NOTES.md.
static bool GuestSystemHeapRegionStart(uint32_t guest_address) {
  auto* heap = REX_KERNEL_MEMORY()->LookupHeap(guest_address);
  if (!heap) {
    return false;
  }
  rex::memory::HeapAllocationInfo info;
  if (!heap->QueryRegionInfo(guest_address, &info)) {
    return false;
  }
  return info.state != 0 && info.allocation_base == guest_address;
}

u32 XamFeatureEnabled_entry(u32 unk) {
  return 0;
}

// Empty stub schema binary.
uint8_t schema_bin[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x2C, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
    0x00, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18,
};

u32 XamGetOnlineSchema_entry() {
  static uint32_t schema_guest = 0;

  if (!schema_guest) {
    // (Hunt v1.4.6, ronda 4, segundo barrido, V-A3-01.) SystemHeapAlloc
    // returns 0 on failure: the old code translated 0 and memcpied the
    // schema onto guest address 0, then cached schema_guest = 0, so
    // every later call retried the same corrupting write. Only write
    // and cache on success; on failure return 0 (a null schema pointer
    // the caller already has to handle).
    uint32_t alloc = REX_KERNEL_MEMORY()->SystemHeapAlloc(8 + sizeof(schema_bin));
    if (alloc) {
      schema_guest = alloc;
      auto schema = REX_KERNEL_MEMORY()->TranslateVirtual(schema_guest);
      std::memcpy(schema + 8, schema_bin, sizeof(schema_bin));
      memory::store_and_swap<uint32_t>(schema + 0, schema_guest + 8);
      memory::store_and_swap<uint32_t>(schema + 4, sizeof(schema_bin));
    }
  }

  // return pointer to the schema ptr/schema size struct
  return schema_guest;
}

#if REX_PLATFORM_WIN32
static SYSTEMTIME xeGetLocalSystemTime(uint64_t filetime) {
  FILETIME t;
  t.dwHighDateTime = filetime >> 32;
  t.dwLowDateTime = (uint32_t)filetime;

  SYSTEMTIME st;
  SYSTEMTIME local_st;
  FileTimeToSystemTime(&t, &st);
  SystemTimeToTzSpecificLocalTime(NULL, &st, &local_st);
  return local_st;
}
#endif

void XamFormatDateString_entry(u32 unk, u64 filetime, mapped_void output_buffer, u32 output_count) {
  // (Hunt v1.4.6, verificación profunda, segundo barrido, V-FE-15.)
  // Same shape as A3-R4-08 (XamReadTileToTexture, xam_user.cpp):
  // output_count is guest-controlled (u32) and the memset below writes
  // output_count * 2 bytes from an unvalidated pointer -- up to ~8 GiB
  // past the end of the mapping, or to guest address 0 for a NULL
  // buffer. The memset runs on every platform (the formatting itself
  // is Win32-only), so validate the whole destination range first.
  // The count is in UTF-16 code units, so the range is output_count *
  // sizeof(char16_t) bytes; computed in size_t, it cannot wrap, and
  // the helper rejects any length that cannot lie inside a heap.
  if (!output_buffer ||
      !GuestRangeWritable(output_buffer.guest_address(),
                          static_cast<size_t>(output_count) * sizeof(char16_t))) {
    return;
  }
  std::memset(output_buffer, 0, output_count * sizeof(char16_t));

// TODO: implement this for other platforms
#if REX_PLATFORM_WIN32
  auto st = xeGetLocalSystemTime(filetime);
  // TODO: format this depending on users locale?
  auto str = fmt::format(u"{:02d}/{:02d}/{}", st.wMonth, st.wDay, st.wYear);
  rex::string::copy_and_swap_truncating(output_buffer.as<char16_t*>(), str, output_count);
#else
  assert_always();
#endif
}

void XamFormatTimeString_entry(u32 unk, u64 filetime, mapped_void output_buffer, u32 output_count) {
  // (Hunt v1.4.6, verificación profunda, segundo barrido, V-FE-15.)
  // Same as XamFormatDateString_entry above: guest-controlled count,
  // unvalidated destination, memset runs on every platform.
  if (!output_buffer ||
      !GuestRangeWritable(output_buffer.guest_address(),
                          static_cast<size_t>(output_count) * sizeof(char16_t))) {
    return;
  }
  std::memset(output_buffer, 0, output_count * sizeof(char16_t));

// TODO: implement this for other platforms
#if REX_PLATFORM_WIN32
  auto st = xeGetLocalSystemTime(filetime);
  // TODO: format this depending on users locale?
  auto str = fmt::format(u"{:02d}:{:02d}", st.wHour, st.wMinute);
  rex::string::copy_and_swap_truncating(output_buffer.as<char16_t*>(), str, output_count);
#else
  assert_always();
#endif
}

u32 keXamBuildResourceLocator(uint64_t module, std::u16string_view container,
                              std::u16string_view resource, mapped_void buffer_ptr,
                              uint32_t buffer_count) {
  // (Hunt v1.4.6, verificación profunda, segundo barrido, V-FE-15.)
  // copy_and_swap_truncating below writes up to buffer_count UTF-16
  // code units (count * 2 bytes) into buffer_ptr, which was never
  // validated -- a non-NULL pointer outside the mapping SIGSEGVs the
  // host. Validate the whole destination range first. buffer_count is
  // in code units, like output_count in the format entries above.
  if (!buffer_ptr ||
      !GuestRangeWritable(buffer_ptr.guest_address(),
                          static_cast<size_t>(buffer_count) * sizeof(char16_t))) {
    return X_ERROR_INVALID_PARAMETER;
  }
  std::u16string path;
  if (!module) {
    path = fmt::format(u"file://media:/{}.xzp#{}", container, resource);
    REXKRNL_DEBUG("XamBuildResourceLocator({0}) returning locator to local file {0}.xzp",
                  rex::string::to_utf8(container));
  } else {
    path = fmt::format(u"section://{:X},{}#{}", (uint32_t)module, container, resource);
  }
  rex::string::copy_and_swap_truncating(buffer_ptr.as<char16_t*>(), path, buffer_count);
  return 0;
}

u32 XamBuildResourceLocator_entry(u64 module, mapped_wstring container, mapped_wstring resource,
                                  mapped_void buffer_ptr, u32 buffer_count) {
  // (Hunt v1.4.6, ronda 10, A3-R10-03.) Bounded reads: the old
  // container.value() / resource.value() scanned for NUL with no
  // cap. A null string stays empty, as before.
  std::u16string container_str;
  if (container && !ReadGuestU16String(container.guest_address(), &container_str)) {
    return X_ERROR_INVALID_PARAMETER;
  }
  std::u16string resource_str;
  if (resource && !ReadGuestU16String(resource.guest_address(), &resource_str)) {
    return X_ERROR_INVALID_PARAMETER;
  }
  return keXamBuildResourceLocator(module, container_str, resource_str, buffer_ptr, buffer_count);
}

u32 XamBuildGamercardResourceLocator_entry(mapped_wstring filename, mapped_void buffer_ptr,
                                           u32 buffer_count) {
  // On an actual xbox these funcs would return a locator to xam.xex resources,
  // but for Xenia we can return a locator to the resources as local files. (big
  // thanks to MS for letting XamBuildResourceLocator return local file
  // locators!)

  // If you're running an app that'll need them, make sure to extract xam.xex
  // resources with xextool ("xextool -d . xam.xex") and add a .xzp extension.

  // (Hunt v1.4.6, ronda 10, A3-R10-03.) Bounded read, as
  // XamBuildResourceLocator above.
  std::u16string filename_str;
  if (filename && !ReadGuestU16String(filename.guest_address(), &filename_str)) {
    return X_ERROR_INVALID_PARAMETER;
  }
  return keXamBuildResourceLocator(0, u"gamercrd", filename_str, buffer_ptr, buffer_count);
}

u32 XamBuildSharedSystemResourceLocator_entry(mapped_wstring filename, mapped_void buffer_ptr,
                                              u32 buffer_count) {
  // see notes inside XamBuildGamercardResourceLocator above
  // (Hunt v1.4.6, ronda 10, A3-R10-03.) Bounded read, as
  // XamBuildResourceLocator above.
  std::u16string filename_str;
  if (filename && !ReadGuestU16String(filename.guest_address(), &filename_str)) {
    return X_ERROR_INVALID_PARAMETER;
  }
  return keXamBuildResourceLocator(0, u"shrdres", filename_str, buffer_ptr, buffer_count);
}

u32 XamBuildLegacySystemResourceLocator_entry(mapped_wstring filename, mapped_void buffer_ptr,
                                              u32 buffer_count) {
  return XamBuildSharedSystemResourceLocator_entry(filename, buffer_ptr, buffer_count);
}

u32 XamBuildXamResourceLocator_entry(mapped_wstring filename, mapped_void buffer_ptr,
                                     u32 buffer_count) {
  // (Hunt v1.4.6, ronda 10, A3-R10-03.) Bounded read, as
  // XamBuildResourceLocator above.
  std::u16string filename_str;
  if (filename && !ReadGuestU16String(filename.guest_address(), &filename_str)) {
    return X_ERROR_INVALID_PARAMETER;
  }
  return keXamBuildResourceLocator(0, u"xam", filename_str, buffer_ptr, buffer_count);
}

u32 XamGetSystemVersion_entry() {
  // eh, just picking one. If we go too low we may break new games, but
  // this value seems to be used for conditionally loading symbols and if
  // we pretend to be old we have less to worry with implementing.
  // 0x200A3200
  // 0x20096B00
  return 0;
}

void XCustomRegisterDynamicActions_entry() {
  // ???
}

u32 XGetAVPack_entry() {
  // DWORD
  // Not sure what the values are for this, but 6 is VGA.
  // Other likely values are 3/4/8 for HDMI or something.
  // Games seem to use this as a PAL check - if the result is not 3/4/6/8
  // they explode with errors if not in PAL mode.
  REXKRNL_IMPORT_RESULT("XGetAVPack", "6");
  return 6;
}

uint32_t xeXGetGameRegion() {
  return 0xFFFFu;
}

u32 XGetGameRegion_entry() {
  return xeXGetGameRegion();
}

u32 XGetLanguage_entry() {
  auto desired_language = XLanguage::kEnglish;

  // Switch the language based on game region.
  // TODO(benvanik): pull from xex header.
  uint32_t game_region = XEX_REGION_NTSCU;
  if (game_region & XEX_REGION_NTSCU) {
    desired_language = XLanguage::kEnglish;
  } else if (game_region & XEX_REGION_NTSCJ) {
    desired_language = XLanguage::kJapanese;
  }
  // Add more overrides?

  return uint32_t(desired_language);
}

u32 XamGetCurrentTitleId_entry() {
  // NOTE(tomc): Switched this up to get title ID from executable module instead of runtime
  // (emulator)
  auto module = REX_KERNEL_STATE()->GetExecutableModule();
  if (module) {
    return module->title_id();
  }
  return 0;
}

u32 XamGetExecutionId_entry(mapped_u32 info_ptr) {
  // (Audit A3, ronda 6, R6-06.) A NULL info_ptr used to write the
  // header pointer to guest address 0.
  if (!info_ptr) {
    return X_STATUS_INVALID_PARAMETER;
  }

  // (Hunt v1.4.6, ronda 10, A3-R10-12.) *info_ptr is written below
  // with only the NULL check above: validate the 4-byte range first.
  if (!GuestRangeWritable(info_ptr.guest_address(), sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }

  auto module = REX_KERNEL_STATE()->GetExecutableModule();
  // (Hunt v1.4.6, ronda 10, A3-R10-15.) GetExecutableModule() can
  // return nullptr; the old code only had assert_not_null (a no-op
  // in Release) before module->GetOptHeader below.
  if (!module) {
    return X_STATUS_INVALID_PARAMETER;
  }

  uint32_t guest_hdr_ptr;
  X_STATUS result = module->GetOptHeader(XEX_HEADER_EXECUTION_INFO, &guest_hdr_ptr);

  if (XFAILED(result)) {
    return result;
  }

  *info_ptr = guest_hdr_ptr;
  return X_STATUS_SUCCESS;
}

u32 XamLoaderSetLaunchData_entry(mapped_void data, u32 size) {
  // (Hunt v1.4.6, verificación profunda, segundo barrido, V-FE-15.)
  // Same shape as A3-R4-08: `size` is guest-controlled (u32) and `data`
  // was never validated, but resize(size) allocates that many host
  // bytes and the memcpy reads that many guest bytes. A wild pointer
  // SIGSEGVs the host, and a huge size (up to 4 GiB) exhausts the host
  // heap (bad_alloc -> terminate). Validate the whole source range
  // first: the range must lie inside readable guest memory, which
  // bounds the size by the mapping itself without inventing a cap.
  if (size && (!data || !GuestRangeReadable(data.guest_address(), size))) {
    return X_ERROR_INVALID_PARAMETER;
  }
  auto xam = REX_KERNEL_STATE()->GetKernelModule<XamModule>("xam.xex");
  auto& loader_data = xam->loader_data();
  loader_data.launch_data_present = size ? true : false;
  loader_data.launch_data.resize(size);
  std::memcpy(loader_data.launch_data.data(), data, size);
  return 0;
}

u32 XamLoaderGetLaunchDataSize_entry(mapped_u32 size_ptr) {
  if (!size_ptr) {
    return X_ERROR_INVALID_PARAMETER;
  }

  // (Hunt v1.4.6, ronda 10, A3-R10-12.) *size_ptr is written below
  // with only the NULL check above: validate the 4-byte range first.
  if (!GuestRangeWritable(size_ptr.guest_address(), sizeof(uint32_t))) {
    return X_ERROR_INVALID_PARAMETER;
  }

  auto xam = REX_KERNEL_STATE()->GetKernelModule<XamModule>("xam.xex");
  auto& loader_data = xam->loader_data();
  if (!loader_data.launch_data_present) {
    *size_ptr = 0;
    return X_ERROR_NOT_FOUND;
  }

  *size_ptr = uint32_t(xam->loader_data().launch_data.size());
  return X_ERROR_SUCCESS;
}

u32 XamLoaderGetLaunchData_entry(mapped_void buffer_ptr, u32 buffer_size) {
  auto xam = REX_KERNEL_STATE()->GetKernelModule<XamModule>("xam.xex");
  auto& loader_data = xam->loader_data();
  if (!loader_data.launch_data_present) {
    return X_ERROR_NOT_FOUND;
  }

  uint32_t copy_size = std::min(uint32_t(loader_data.launch_data.size()), uint32_t(buffer_size));
  // (Hunt v1.4.6, verificación profunda, segundo barrido, V-FE-15.)
  // Same as the setter above: buffer_ptr was never validated, and the
  // memcpy writes copy_size bytes into it. Validate the destination
  // range first (a zero copy_size needs no buffer).
  if (copy_size && (!buffer_ptr || !GuestRangeWritable(buffer_ptr.guest_address(), copy_size))) {
    return X_ERROR_INVALID_PARAMETER;
  }
  std::memcpy(buffer_ptr, loader_data.launch_data.data(), copy_size);
  return X_ERROR_SUCCESS;
}

void XamLoaderLaunchTitle_entry(mapped_string raw_name_ptr, u32 flags) {
  auto xam = REX_KERNEL_STATE()->GetKernelModule<XamModule>("xam.xex");

  auto& loader_data = xam->loader_data();
  loader_data.launch_flags = flags;

  // Translate the launch path to a full path.
  if (raw_name_ptr) {
    // (Hunt v1.4.6, ronda 10, A3-R10-03.) Bounded read: the old
    // raw_name_ptr.value() scanned for NUL with no cap.
    std::string path;
    if (!ReadGuestCString(raw_name_ptr.guest_address(), &path)) {
      return;
    }
    if (path.empty()) {
      loader_data.launch_path = "game:\\default.xex";
    } else {
      if (rex::string::utf8_find_name_from_guest_path(path) == path) {
        // (Hunt v1.4.6, ronda 10, A3-R10-15.)
        // GetExecutableModule() can return nullptr; the old code
        // derefed it here with only an assert (a no-op in Release).
        auto module = REX_KERNEL_STATE()->GetExecutableModule();
        if (!module) {
          return;
        }
        path = rex::string::utf8_join_guest_paths(
            rex::string::utf8_find_base_guest_path(module->path()), path);
      }
      loader_data.launch_path = path;
    }
  } else {
    assert_always("Game requested exit to dashboard via XamLoaderLaunchTitle");
  }

  // This function does not return.
  REX_KERNEL_STATE()->TerminateTitle();
}

void XamLoaderTerminateTitle_entry() {
  // This function does not return.
  REX_KERNEL_STATE()->TerminateTitle();
}

u32 XamAlloc_entry(u32 unk, u32 size, mapped_u32 out_ptr) {
  // (Audit A3, ronda 6, R6-06.) A NULL out_ptr used to write the
  // allocated address to guest address 0.
  if (!out_ptr) {
    return X_E_INVALIDARG;
  }

  // (Hunt v1.4.6, ronda 10, A3-R10-12.) *out_ptr is written below
  // with only the NULL check above: validate the 4-byte range first.
  if (!GuestRangeWritable(out_ptr.guest_address(), sizeof(uint32_t))) {
    return X_E_INVALIDARG;
  }

  assert_true(unk == 0);

  // Allocate from the heap. Not sure why XAM does this specially, perhaps
  // it keeps stuff in a separate heap?
  uint32_t ptr = REX_KERNEL_MEMORY()->SystemHeapAlloc(size);
  // (Hunt v1.4.6, ronda 4, segundo barrido, V-A3-01.) The old code
  // wrote the (possibly 0) result to *out_ptr and returned SUCCESS:
  // the game believed it owned a buffer at guest address 0. Fail
  // honestly instead — X_STATUS_NO_MEMORY is the NTSTATUS out-of-memory
  // value; note the NTSTATUS-vs-X_RESULT domain mix in this file
  // (XamQueryLiveHiveW already returns an X_STATUS value).
  if (!ptr) {
    return X_STATUS_NO_MEMORY;
  }
  *out_ptr = ptr;

  return X_ERROR_SUCCESS;
}

u32 XamFree_entry(mapped_u32 ptr) {
  // (Hunt v1.4.6, ronda 10, A3-R10-04.) The old code freed any
  // guest-supplied address in the system heap with no check at all.
  // Only a live region start may be freed (same
  // GuestSystemHeapRegionStart check as ExFreePool); a null pointer
  // stays a no-op, as SystemHeapFree already treats it.
  if (ptr && !GuestSystemHeapRegionStart(ptr.guest_address())) {
    return X_E_INVALIDARG;
  }
  REX_KERNEL_MEMORY()->SystemHeapFree(ptr.guest_address());

  return X_ERROR_SUCCESS;
}

u32 XamQueryLiveHiveW_entry(mapped_wstring name, mapped_void out_buf, u32 out_size,
                            u32 type /* guess */) {
  return X_STATUS_INVALID_PARAMETER_1;
}

u32 XamLoaderGetDvdTrayState_entry(mapped_u32 out_state) {
  // 0 = tray open, 1 = tray closed with disc
  // (Hunt v1.4.6, ronda 10, A3-R10-12.) *out_state was written with
  // only a NULL check: validate the 4-byte range first.
  if (out_state && !GuestRangeWritable(out_state.guest_address(), sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  if (out_state)
    *out_state = 1;
  return X_STATUS_SUCCESS;
}

u32 XamSwapDisc_entry(u32 disc_number) {
  // Stub for multi-disc games. Single-disc games (like Blue Dragon's reblue test)
  // don't need this, but the game may look it up dynamically via XexGetProcedureAddress.
  REXKRNL_DEBUG("XamSwapDisc({}) - stub, returning success", (uint32_t)disc_number);
  return X_STATUS_SUCCESS;
}

}  // namespace xam
}  // namespace kernel
}  // namespace rex

REX_EXPORT(__imp__XamFeatureEnabled, rex::kernel::xam::XamFeatureEnabled_entry)
REX_EXPORT(__imp__XamGetOnlineSchema, rex::kernel::xam::XamGetOnlineSchema_entry)
REX_EXPORT(__imp__XamFormatDateString, rex::kernel::xam::XamFormatDateString_entry)
REX_EXPORT(__imp__XamFormatTimeString, rex::kernel::xam::XamFormatTimeString_entry)
REX_EXPORT(__imp__XamBuildResourceLocator, rex::kernel::xam::XamBuildResourceLocator_entry)
REX_EXPORT(__imp__XamBuildGamercardResourceLocator,
           rex::kernel::xam::XamBuildGamercardResourceLocator_entry)
REX_EXPORT(__imp__XamBuildSharedSystemResourceLocator,
           rex::kernel::xam::XamBuildSharedSystemResourceLocator_entry)
REX_EXPORT(__imp__XamBuildLegacySystemResourceLocator,
           rex::kernel::xam::XamBuildLegacySystemResourceLocator_entry)
REX_EXPORT(__imp__XamBuildXamResourceLocator, rex::kernel::xam::XamBuildXamResourceLocator_entry)
REX_EXPORT(__imp__XamGetSystemVersion, rex::kernel::xam::XamGetSystemVersion_entry)
REX_EXPORT(__imp__XCustomRegisterDynamicActions,
           rex::kernel::xam::XCustomRegisterDynamicActions_entry)
REX_EXPORT(__imp__XGetAVPack, rex::kernel::xam::XGetAVPack_entry)
REX_EXPORT(__imp__XGetGameRegion, rex::kernel::xam::XGetGameRegion_entry)
REX_EXPORT(__imp__XGetLanguage, rex::kernel::xam::XGetLanguage_entry)
REX_EXPORT(__imp__XamGetCurrentTitleId, rex::kernel::xam::XamGetCurrentTitleId_entry)
REX_EXPORT(__imp__XamGetExecutionId, rex::kernel::xam::XamGetExecutionId_entry)
REX_EXPORT(__imp__XamLoaderSetLaunchData, rex::kernel::xam::XamLoaderSetLaunchData_entry)
REX_EXPORT(__imp__XamLoaderGetLaunchDataSize, rex::kernel::xam::XamLoaderGetLaunchDataSize_entry)
REX_EXPORT(__imp__XamLoaderGetLaunchData, rex::kernel::xam::XamLoaderGetLaunchData_entry)
REX_EXPORT(__imp__XamLoaderLaunchTitle, rex::kernel::xam::XamLoaderLaunchTitle_entry)
REX_EXPORT(__imp__XamLoaderTerminateTitle, rex::kernel::xam::XamLoaderTerminateTitle_entry)
REX_EXPORT(__imp__XamAlloc, rex::kernel::xam::XamAlloc_entry)
REX_EXPORT(__imp__XamFree, rex::kernel::xam::XamFree_entry)
REX_EXPORT(__imp__XamQueryLiveHiveW, rex::kernel::xam::XamQueryLiveHiveW_entry)
REX_EXPORT(__imp__XamLoaderGetDvdTrayState, rex::kernel::xam::XamLoaderGetDvdTrayState_entry)
REX_EXPORT(__imp__XamSwapDisc, rex::kernel::xam::XamSwapDisc_entry)

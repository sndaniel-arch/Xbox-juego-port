/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2020 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#include <rex/kernel/xam/apps/xmp_app.h>
#include <rex/logging.h>
#include <rex/system/xthread.h>
#include <rex/thread.h>

namespace rex {
namespace kernel {
namespace xam {
using namespace rex::system;
using namespace rex::system::xam;
namespace apps {
using namespace rex::system;

// (Hunt v1.4.6, ronda 7, A3-R7-02.) Same helper as XamApp (ronda 4,
// A3-R4-07): TranslateVirtual never validates and never returns null,
// so a guest message buffer that runs past the end of the mapping
// SIGSEGVs the host on the first struct read. Validate each message
// struct (and every nested out-pointer it carries) before touching
// it; an invalid buffer returns X_E_INVALIDARG, like XamApp does.
static bool GuestRangeAccessible(rex::memory::Memory* memory, uint32_t guest_address,
                                 size_t length, bool writable) {
  if (!length) {
    return true;
  }
  if (length > UINT32_MAX - guest_address) {
    return false;
  }
  uint32_t high_address = guest_address + static_cast<uint32_t>(length) - 1;
  rex::memory::BaseHeap* start_heap = memory->LookupHeap(guest_address);
  const rex::memory::BaseHeap* end_heap = memory->LookupHeap(high_address);
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

static bool GuestRangeReadable(rex::memory::Memory* memory, uint32_t guest_address,
                               size_t length) {
  return GuestRangeAccessible(memory, guest_address, length, false);
}

static bool GuestRangeWritable(rex::memory::Memory* memory, uint32_t guest_address,
                               size_t length) {
  return GuestRangeAccessible(memory, guest_address, length, true);
}

XmpApp::XmpApp(KernelState* kernel_state)
    : App(kernel_state, 0xFA),
      state_(State::kIdle),
      playback_client_(PlaybackClient::kTitle),
      playback_mode_(PlaybackMode::kUnknown),
      repeat_mode_(RepeatMode::kUnknown),
      unknown_flags_(0),
      volume_(1.0f),
      active_playlist_(nullptr),
      active_song_index_(0),
      next_playlist_handle_(1),
      next_song_handle_(1) {}

X_HRESULT XmpApp::XMPGetStatus(uint32_t state_ptr) {
  if (!XThread::GetCurrentThread()->main_thread()) {
    // Some stupid games will hammer this on a thread - induce a delay
    // here to keep from starving real threads.
    rex::thread::Sleep(std::chrono::milliseconds(1));
  }

  // (Hunt v1.4.6, ronda 7, A3-R7-02.) state_ptr is a 4-byte out-param
  // with no NULL-check at all: a zero state_ptr wrote to guest
  // address 0.
  if (!state_ptr ||
      !GuestRangeWritable(memory_, state_ptr, sizeof(uint32_t))) {
    return X_E_INVALIDARG;
  }
  REXKRNL_TRACE("XMPGetStatus({:08X})", state_ptr);
  memory::store_and_swap<uint32_t>(memory_->TranslateVirtual(state_ptr),
                                   static_cast<uint32_t>(state_));
  return X_E_SUCCESS;
}

X_HRESULT XmpApp::XMPCreateTitlePlaylist(uint32_t songs_ptr, uint32_t song_count,
                                         uint32_t playlist_name_ptr,
                                         const std::u16string& playlist_name, uint32_t flags,
                                         uint32_t out_song_handles, uint32_t out_playlist_handle) {
  REXKRNL_DEBUG(
      "XMPCreateTitlePlaylist({:08X}, {:08X}, {:08X}({}), {:08X}, {:08X}, "
      "{:08X})",
      songs_ptr, song_count, playlist_name_ptr, rex::string::to_utf8(playlist_name), flags,
      out_song_handles, out_playlist_handle);
  auto playlist = std::make_unique<Playlist>();
  playlist->handle = ++next_playlist_handle_;
  playlist->name = playlist_name;
  playlist->flags = flags;
  if (songs_ptr) {
    // (Hunt v1.4.6, ronda 7, A3-R7-02.) song_count is a guest u32 with
    // no cap: the loop below reads song_count 36-byte structs from
    // songs_ptr and writes song_count dwords to out_song_handles.
    // Cap the playlist at 1024 songs (36 KiB of structs, 4 KiB of
    // handles -- far above anything a title builds) and validate both
    // arrays up front with 64-bit math, so a wrapped count cannot slip
    // through. (The per-song u16string scans inside the loop are the
    // documented V-R6-02 residue and are intentionally left untouched.)
    constexpr uint32_t kMaxPlaylistSongs = 1024;
    if (song_count > kMaxPlaylistSongs) {
      return X_E_INVALIDARG;
    }
    if (!GuestRangeReadable(memory_, songs_ptr,
                            static_cast<size_t>(song_count) * 36)) {
      return X_E_INVALIDARG;
    }
    if (out_song_handles &&
        !GuestRangeWritable(memory_, out_song_handles,
                            static_cast<size_t>(song_count) * 4)) {
      return X_E_INVALIDARG;
    }
    for (uint32_t i = 0; i < song_count; ++i) {
      auto song = std::make_unique<Song>();
      song->handle = ++next_song_handle_;
      uint8_t* song_base = memory_->TranslateVirtual(songs_ptr + (i * 36));
      song->file_path = memory::load_and_swap<std::u16string>(
          memory_->TranslateVirtual(memory::load_and_swap<uint32_t>(song_base + 0)));
      song->name = memory::load_and_swap<std::u16string>(
          memory_->TranslateVirtual(memory::load_and_swap<uint32_t>(song_base + 4)));
      song->artist = memory::load_and_swap<std::u16string>(
          memory_->TranslateVirtual(memory::load_and_swap<uint32_t>(song_base + 8)));
      song->album = memory::load_and_swap<std::u16string>(
          memory_->TranslateVirtual(memory::load_and_swap<uint32_t>(song_base + 12)));
      song->album_artist = memory::load_and_swap<std::u16string>(
          memory_->TranslateVirtual(memory::load_and_swap<uint32_t>(song_base + 16)));
      song->genre = memory::load_and_swap<std::u16string>(
          memory_->TranslateVirtual(memory::load_and_swap<uint32_t>(song_base + 20)));
      song->track_number = memory::load_and_swap<uint32_t>(song_base + 24);
      song->duration_ms = memory::load_and_swap<uint32_t>(song_base + 28);
      song->format = static_cast<Song::Format>(memory::load_and_swap<uint32_t>(song_base + 32));
      if (out_song_handles) {
        memory::store_and_swap<uint32_t>(memory_->TranslateVirtual(out_song_handles + (i * 4)),
                                         song->handle);
      }
      playlist->songs.emplace_back(std::move(song));
    }
  }
  // (Hunt v1.4.6, ronda 7, A3-R7-02.) out_playlist_handle is a 4-byte
  // out-param with only a NULL-check.
  if (out_playlist_handle &&
      !GuestRangeWritable(memory_, out_playlist_handle, sizeof(uint32_t))) {
    return X_E_INVALIDARG;
  }
  if (out_playlist_handle) {
    memory::store_and_swap<uint32_t>(memory_->TranslateVirtual(out_playlist_handle),
                                     playlist->handle);
  }

  auto global_lock = global_critical_region_.Acquire();
  playlists_.insert({playlist->handle, playlist.get()});
  playlist.release();
  return X_E_SUCCESS;
}

X_HRESULT XmpApp::XMPDeleteTitlePlaylist(uint32_t playlist_handle) {
  REXKRNL_DEBUG("XMPDeleteTitlePlaylist({:08X})", playlist_handle);
  auto global_lock = global_critical_region_.Acquire();
  auto it = playlists_.find(playlist_handle);
  if (it == playlists_.end()) {
    REXKRNL_ERROR("Playlist {:08X} not found", playlist_handle);
    return X_E_NOTFOUND;
  }
  auto playlist = it->second;
  if (playlist == active_playlist_) {
    XMPStop(0);
  }
  playlists_.erase(it);
  delete playlist;
  return X_E_SUCCESS;
}

X_HRESULT XmpApp::XMPPlayTitlePlaylist(uint32_t playlist_handle, uint32_t song_handle) {
  REXKRNL_DEBUG("XMPPlayTitlePlaylist({:08X}, {:08X})", playlist_handle, song_handle);
  Playlist* playlist = nullptr;
  {
    auto global_lock = global_critical_region_.Acquire();
    auto it = playlists_.find(playlist_handle);
    if (it == playlists_.end()) {
      REXKRNL_ERROR("Playlist {:08X} not found", playlist_handle);
      return X_E_NOTFOUND;
    }
    playlist = it->second;
  }

  if (playback_client_ == PlaybackClient::kSystem) {
    REXKRNL_WARN("XMPPlayTitlePlaylist: System playback is enabled!");
    return X_E_SUCCESS;
  }

  // Start playlist?
  REXKRNL_WARN("Playlist playback not supported");
  active_playlist_ = playlist;
  active_song_index_ = 0;
  state_ = State::kPlaying;
  OnStateChanged();
  kernel_state_->BroadcastNotification(kMsgPlaybackBehaviorChanged, 1);
  return X_E_SUCCESS;
}

X_HRESULT XmpApp::XMPContinue() {
  REXKRNL_DEBUG("XMPContinue()");
  if (state_ == State::kPaused) {
    state_ = State::kPlaying;
  }
  OnStateChanged();
  return X_E_SUCCESS;
}

X_HRESULT XmpApp::XMPStop(uint32_t unk) {
  assert_zero(unk);
  REXKRNL_DEBUG("XMPStop({:08X})", unk);
  active_playlist_ = nullptr;  // ?
  active_song_index_ = 0;
  state_ = State::kIdle;
  OnStateChanged();
  return X_E_SUCCESS;
}

X_HRESULT XmpApp::XMPPause() {
  REXKRNL_DEBUG("XMPPause()");
  if (state_ == State::kPlaying) {
    state_ = State::kPaused;
  }
  OnStateChanged();
  return X_E_SUCCESS;
}

X_HRESULT XmpApp::XMPNext() {
  REXKRNL_DEBUG("XMPNext()");
  if (!active_playlist_) {
    return X_E_NOTFOUND;
  }
  state_ = State::kPlaying;
  active_song_index_ = (active_song_index_ + 1) % active_playlist_->songs.size();
  OnStateChanged();
  return X_E_SUCCESS;
}

X_HRESULT XmpApp::XMPPrevious() {
  REXKRNL_DEBUG("XMPPrevious()");
  if (!active_playlist_) {
    return X_E_NOTFOUND;
  }
  state_ = State::kPlaying;
  if (!active_song_index_) {
    active_song_index_ = static_cast<int>(active_playlist_->songs.size()) - 1;
  } else {
    --active_song_index_;
  }
  OnStateChanged();
  return X_E_SUCCESS;
}

void XmpApp::OnStateChanged() {
  kernel_state_->BroadcastNotification(kMsgStateChanged, static_cast<uint32_t>(state_));
}

X_HRESULT XmpApp::DispatchMessageSync(uint32_t message, uint32_t buffer_ptr,
                                      uint32_t buffer_length) {
  // NOTE: buffer_length may be zero or valid.
  auto buffer = memory_->TranslateVirtual(buffer_ptr);
  switch (message) {
    case 0x00070002: {
      // (Hunt v1.4.6, ronda 7, A3-R7-02.) Validate the 12-byte
      // message struct before reading it (XamApp pattern, A3-R4-07).
      if (!GuestRangeReadable(memory_, buffer_ptr, 12)) {
        return X_E_INVALIDARG;
      }
      assert_true(!buffer_length || buffer_length == 12);
      uint32_t xmp_client = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t storage_ptr = memory::load_and_swap<uint32_t>(buffer + 4);
      uint32_t song_handle = memory::load_and_swap<uint32_t>(buffer + 8);  // 0?
      // (Hunt v1.4.6, ronda 7, A3-R7-02.) storage_ptr is dereferenced
      // (4 bytes) with no NULL-check at all.
      if (!storage_ptr ||
          !GuestRangeReadable(memory_, storage_ptr, sizeof(uint32_t))) {
        return X_E_INVALIDARG;
      }
      uint32_t playlist_handle =
          memory::load_and_swap<uint32_t>(memory_->TranslateVirtual(storage_ptr));
      assert_true(xmp_client == 0x00000002);
      return XMPPlayTitlePlaylist(playlist_handle, song_handle);
    }
    case 0x00070003: {
      // (Hunt v1.4.6, ronda 7, A3-R7-02.) Validate the 4-byte
      // message struct before reading it (XamApp pattern, A3-R4-07).
      if (!GuestRangeReadable(memory_, buffer_ptr, 4)) {
        return X_E_INVALIDARG;
      }
      assert_true(!buffer_length || buffer_length == 4);
      uint32_t xmp_client = memory::load_and_swap<uint32_t>(buffer + 0);
      assert_true(xmp_client == 0x00000002);
      return XMPContinue();
    }
    case 0x00070004: {
      // (Hunt v1.4.6, ronda 7, A3-R7-02.) Validate the 8-byte
      // message struct before reading it (XamApp pattern, A3-R4-07).
      if (!GuestRangeReadable(memory_, buffer_ptr, 8)) {
        return X_E_INVALIDARG;
      }
      assert_true(!buffer_length || buffer_length == 8);
      uint32_t xmp_client = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t unk = memory::load_and_swap<uint32_t>(buffer + 4);
      assert_true(xmp_client == 0x00000002);
      return XMPStop(unk);
    }
    case 0x00070005: {
      // (Hunt v1.4.6, ronda 7, A3-R7-02.) Validate the 4-byte
      // message struct before reading it (XamApp pattern, A3-R4-07).
      if (!GuestRangeReadable(memory_, buffer_ptr, 4)) {
        return X_E_INVALIDARG;
      }
      assert_true(!buffer_length || buffer_length == 4);
      uint32_t xmp_client = memory::load_and_swap<uint32_t>(buffer + 0);
      assert_true(xmp_client == 0x00000002);
      return XMPPause();
    }
    case 0x00070006: {
      // (Hunt v1.4.6, ronda 7, A3-R7-02.) Validate the 4-byte
      // message struct before reading it (XamApp pattern, A3-R4-07).
      if (!GuestRangeReadable(memory_, buffer_ptr, 4)) {
        return X_E_INVALIDARG;
      }
      assert_true(!buffer_length || buffer_length == 4);
      uint32_t xmp_client = memory::load_and_swap<uint32_t>(buffer + 0);
      assert_true(xmp_client == 0x00000002);
      return XMPNext();
    }
    case 0x00070007: {
      // (Hunt v1.4.6, ronda 7, A3-R7-02.) Validate the 4-byte
      // message struct before reading it (XamApp pattern, A3-R4-07).
      if (!GuestRangeReadable(memory_, buffer_ptr, 4)) {
        return X_E_INVALIDARG;
      }
      assert_true(!buffer_length || buffer_length == 4);
      uint32_t xmp_client = memory::load_and_swap<uint32_t>(buffer + 0);
      assert_true(xmp_client == 0x00000002);
      return XMPPrevious();
    }
    case 0x00070008: {
      // (Hunt v1.4.6, ronda 7, A3-R7-02.) Validate the 16-byte
      // message struct before reading it (XamApp pattern, A3-R4-07).
      if (!GuestRangeReadable(memory_, buffer_ptr, 16)) {
        return X_E_INVALIDARG;
      }
      assert_true(!buffer_length || buffer_length == 16);
      struct {
        rex::be<uint32_t> xmp_client;
        rex::be<uint32_t> playback_mode;
        rex::be<uint32_t> repeat_mode;
        rex::be<uint32_t> flags;
      }* args = memory_->TranslateVirtual<decltype(args)>(buffer_ptr);
      static_assert_size(decltype(*args), 16);

      assert_true(args->xmp_client == 0x00000002 || args->xmp_client == 0x00000000);
      REXKRNL_DEBUG("XMPSetPlaybackBehavior({:08X}, {:08X}, {:08X})", uint32_t(args->playback_mode),
                    uint32_t(args->repeat_mode), uint32_t(args->flags));
      playback_mode_ = static_cast<PlaybackMode>(uint32_t(args->playback_mode));
      repeat_mode_ = static_cast<RepeatMode>(uint32_t(args->repeat_mode));
      unknown_flags_ = args->flags;
      kernel_state_->BroadcastNotification(kMsgPlaybackBehaviorChanged, 0);
      return X_E_SUCCESS;
    }
    case 0x00070009: {
      // (Hunt v1.4.6, ronda 7, A3-R7-02.) Validate the 8-byte
      // message struct before reading it (XamApp pattern, A3-R4-07).
      if (!GuestRangeReadable(memory_, buffer_ptr, 8)) {
        return X_E_INVALIDARG;
      }
      assert_true(!buffer_length || buffer_length == 8);
      uint32_t xmp_client = memory::load_and_swap<uint32_t>(buffer + 0);
      uint32_t state_ptr = memory::load_and_swap<uint32_t>(buffer + 4);  // out ptr to 4b - expect 0
      assert_true(xmp_client == 0x00000002);
      return XMPGetStatus(state_ptr);
    }
    case 0x0007000B: {
      // (Hunt v1.4.6, ronda 7, A3-R7-02.) Validate the 8-byte
      // message struct before reading it (XamApp pattern, A3-R4-07).
      if (!GuestRangeReadable(memory_, buffer_ptr, 8)) {
        return X_E_INVALIDARG;
      }
      assert_true(!buffer_length || buffer_length == 8);
      struct {
        rex::be<uint32_t> xmp_client;
        rex::be<uint32_t> volume_ptr;
      }* args = memory_->TranslateVirtual<decltype(args)>(buffer_ptr);
      static_assert_size(decltype(*args), 8);

      assert_true(args->xmp_client == 0x00000002);
      REXKRNL_DEBUG("XMPGetVolume({:08X})", uint32_t(args->volume_ptr));
      // (Hunt v1.4.6, ronda 7, A3-R7-02.) volume_ptr is a 4-byte
      // out-param with no NULL-check at all.
      if (!args->volume_ptr ||
          !GuestRangeWritable(memory_, uint32_t(args->volume_ptr), sizeof(float))) {
        return X_E_INVALIDARG;
      }
      memory::store_and_swap<float>(memory_->TranslateVirtual(args->volume_ptr), volume_);
      return X_E_SUCCESS;
    }
    case 0x0007000C: {
      // (Hunt v1.4.6, ronda 7, A3-R7-02.) Validate the 8-byte
      // message struct before reading it (XamApp pattern, A3-R4-07).
      if (!GuestRangeReadable(memory_, buffer_ptr, 8)) {
        return X_E_INVALIDARG;
      }
      assert_true(!buffer_length || buffer_length == 8);
      struct {
        rex::be<uint32_t> xmp_client;
        rex::be<float> value;
      }* args = memory_->TranslateVirtual<decltype(args)>(buffer_ptr);
      static_assert_size(decltype(*args), 8);

      assert_true(args->xmp_client == 0x00000002);
      REXKRNL_DEBUG("XMPSetVolume({:g})", float(args->value));
      volume_ = args->value;
      return X_E_SUCCESS;
    }
    case 0x0007000D: {
      // (Hunt v1.4.6, ronda 7, A3-R7-02.) Validate the 36-byte
      // message struct before reading it (XamApp pattern, A3-R4-07).
      if (!GuestRangeReadable(memory_, buffer_ptr, 36)) {
        return X_E_INVALIDARG;
      }
      assert_true(!buffer_length || buffer_length == 36);
      struct {
        rex::be<uint32_t> xmp_client;
        rex::be<uint32_t> storage_ptr;
        rex::be<uint32_t> storage_size;
        rex::be<uint32_t> songs_ptr;
        rex::be<uint32_t> song_count;
        rex::be<uint32_t> playlist_name_ptr;
        rex::be<uint32_t> flags;
        rex::be<uint32_t> song_handles_ptr;
        rex::be<uint32_t> playlist_handle_ptr;
      }* args = memory_->TranslateVirtual<decltype(args)>(buffer_ptr);
      static_assert_size(decltype(*args), 36);

      // (Hunt v1.4.6, ronda 7, A3-R7-02.) playlist_handle_ptr == 0 used
      // to write the storage pointer to guest address 0; a non-NULL
      // pointer is validated as a 4-byte out-param. (A zero pointer
      // simply skips the store, like the optional out-params below.)
      if (args->playlist_handle_ptr &&
          !GuestRangeWritable(memory_, uint32_t(args->playlist_handle_ptr),
                              sizeof(uint32_t))) {
        return X_E_INVALIDARG;
      }
      if (args->playlist_handle_ptr) {
        memory::store_and_swap<uint32_t>(memory_->TranslateVirtual(args->playlist_handle_ptr),
                                         args->storage_ptr);
      }
      assert_true(args->xmp_client == 0x00000002 || args->xmp_client == 0x00000000);
      std::u16string playlist_name;
      if (!args->playlist_name_ptr) {
        playlist_name = u"";
      } else {
        playlist_name = memory::load_and_swap<std::u16string>(
            memory_->TranslateVirtual(args->playlist_name_ptr));
      }
      // dummy_alloc_ptr is the result of a XamAlloc of storage_size.
      assert_true(uint32_t(args->storage_size) == 4 + uint32_t(args->song_count) * 128);
      return XMPCreateTitlePlaylist(args->songs_ptr, args->song_count, args->playlist_name_ptr,
                                    playlist_name, args->flags, args->song_handles_ptr,
                                    args->storage_ptr);
    }
    case 0x0007000E: {
      // (Hunt v1.4.6, ronda 7, A3-R7-02.) Validate the 12-byte
      // message struct before reading it (XamApp pattern, A3-R4-07).
      if (!GuestRangeReadable(memory_, buffer_ptr, 12)) {
        return X_E_INVALIDARG;
      }
      assert_true(!buffer_length || buffer_length == 12);
      struct {
        rex::be<uint32_t> xmp_client;
        rex::be<uint32_t> unk_ptr;  // 0
        rex::be<uint32_t> info_ptr;
      }* args = memory_->TranslateVirtual<decltype(args)>(buffer_ptr);
      static_assert_size(decltype(*args), 12);

      // (Hunt v1.4.6, ronda 7, A3-R7-02.) info_ptr is written at
      // offsets 0..784 (fixed fields end at 788 bytes) with no
      // NULL-check at all; validate that range. (Over-long song
      // strings can store past it -- their reads are the V-R6-02
      // residue, left untouched here.)
      if (!args->info_ptr ||
          !GuestRangeWritable(memory_, uint32_t(args->info_ptr), 788)) {
        return X_E_INVALIDARG;
      }
      auto info = memory_->TranslateVirtual(args->info_ptr);
      assert_true(args->xmp_client == 0x00000002);
      assert_zero(args->unk_ptr);
      REXKRNL_ERROR("XMPGetInfo?({:08X}, {:08X})", uint32_t(args->unk_ptr),
                    uint32_t(args->info_ptr));
      if (!active_playlist_) {
        return X_E_FAIL;
      }
      auto& song = active_playlist_->songs[active_song_index_];
      memory::store_and_swap<uint32_t>(info + 0, song->handle);
      memory::store_and_swap<std::u16string>(info + 4 + 572 + 0, song->name);
      memory::store_and_swap<std::u16string>(info + 4 + 572 + 40, song->artist);
      memory::store_and_swap<std::u16string>(info + 4 + 572 + 80, song->album);
      memory::store_and_swap<std::u16string>(info + 4 + 572 + 120, song->album_artist);
      memory::store_and_swap<std::u16string>(info + 4 + 572 + 160, song->genre);
      memory::store_and_swap<uint32_t>(info + 4 + 572 + 200, song->track_number);
      memory::store_and_swap<uint32_t>(info + 4 + 572 + 204, song->duration_ms);
      memory::store_and_swap<uint32_t>(info + 4 + 572 + 208, static_cast<uint32_t>(song->format));
      return X_E_SUCCESS;
    }
    case 0x00070013: {
      // (Hunt v1.4.6, ronda 7, A3-R7-02.) Validate the 8-byte
      // message struct before reading it (XamApp pattern, A3-R4-07).
      if (!GuestRangeReadable(memory_, buffer_ptr, 8)) {
        return X_E_INVALIDARG;
      }
      assert_true(!buffer_length || buffer_length == 8);
      struct {
        rex::be<uint32_t> xmp_client;
        rex::be<uint32_t> storage_ptr;
      }* args = memory_->TranslateVirtual<decltype(args)>(buffer_ptr);
      static_assert_size(decltype(*args), 8);

      // (Hunt v1.4.6, ronda 7, A3-R7-02.) storage_ptr is dereferenced
      // (4 bytes) with no NULL-check at all.
      if (!args->storage_ptr ||
          !GuestRangeReadable(memory_, uint32_t(args->storage_ptr), sizeof(uint32_t))) {
        return X_E_INVALIDARG;
      }
      uint32_t playlist_handle =
          memory::load_and_swap<uint32_t>(memory_->TranslateVirtual(args->storage_ptr));
      assert_true(args->xmp_client == 0x00000002 || args->xmp_client == 0x00000000);
      return XMPDeleteTitlePlaylist(playlist_handle);
    }
    case 0x0007001A: {
      // XMPSetPlaybackController
      assert_true(!buffer_length || buffer_length == 12);
      // (Hunt v1.4.6, ronda 7, A3-R7-02.) Validate the 12-byte
      // message struct before reading it (XamApp pattern, A3-R4-07).
      if (!GuestRangeReadable(memory_, buffer_ptr, 12)) {
        return X_E_INVALIDARG;
      }
      struct {
        rex::be<uint32_t> xmp_client;
        rex::be<uint32_t> controller;
        rex::be<uint32_t> playback_client;
      }* args = memory_->TranslateVirtual<decltype(args)>(buffer_ptr);
      static_assert_size(decltype(*args), 12);

      assert_true((args->xmp_client == 0x00000002 && args->controller == 0x00000000) ||
                  (args->xmp_client == 0x00000000 && args->controller == 0x00000001));
      REXKRNL_DEBUG("XMPSetPlaybackController({:08X}, {:08X})", uint32_t(args->controller),
                    uint32_t(args->playback_client));

      playback_client_ = PlaybackClient(uint32_t(args->playback_client));
      kernel_state_->BroadcastNotification(kMsgPlaybackControllerChanged, !args->playback_client);
      return X_E_SUCCESS;
    }
    case 0x0007001B: {
      // XMPGetPlaybackController
      assert_true(!buffer_length || buffer_length == 12);
      // (Hunt v1.4.6, ronda 7, A3-R7-02.) Validate the 12-byte
      // message struct before reading it (XamApp pattern, A3-R4-07).
      if (!GuestRangeReadable(memory_, buffer_ptr, 12)) {
        return X_E_INVALIDARG;
      }
      struct {
        rex::be<uint32_t> xmp_client;
        rex::be<uint32_t> controller_ptr;
        rex::be<uint32_t> locked_ptr;
      }* args = memory_->TranslateVirtual<decltype(args)>(buffer_ptr);
      static_assert_size(decltype(*args), 12);

      assert_true(args->xmp_client == 0x00000002);
      REXKRNL_DEBUG("XMPGetPlaybackController({:08X}, {:08X}, {:08X})", uint32_t(args->xmp_client),
                    uint32_t(args->controller_ptr), uint32_t(args->locked_ptr));
      // (Hunt v1.4.6, ronda 7, A3-R7-02.) Both out-params are written
      // (4 bytes each) with no NULL-check at all; a zero pointer
      // skips its write, like the optional out-params in 0x70029.
      if ((args->controller_ptr &&
           !GuestRangeWritable(memory_, uint32_t(args->controller_ptr),
                               sizeof(uint32_t))) ||
          (args->locked_ptr &&
           !GuestRangeWritable(memory_, uint32_t(args->locked_ptr), sizeof(uint32_t)))) {
        return X_E_INVALIDARG;
      }
      if (args->controller_ptr) {
        memory::store_and_swap<uint32_t>(memory_->TranslateVirtual(args->controller_ptr), 0);
      }
      if (args->locked_ptr) {
        memory::store_and_swap<uint32_t>(memory_->TranslateVirtual(args->locked_ptr), 0);
      }

      if (!XThread::GetCurrentThread()->main_thread()) {
        // Atrain spawns a thread 82437FD0 to call this in a tight loop forever.
        rex::thread::Sleep(std::chrono::milliseconds(10));
      }

      return X_E_SUCCESS;
    }
    case 0x00070029: {
      // XMPGetPlaybackBehavior
      assert_true(!buffer_length || buffer_length == 16);
      // (Hunt v1.4.6, ronda 7, A3-R7-02.) Validate the 16-byte
      // message struct before reading it (XamApp pattern, A3-R4-07).
      if (!GuestRangeReadable(memory_, buffer_ptr, 16)) {
        return X_E_INVALIDARG;
      }
      struct {
        rex::be<uint32_t> xmp_client;
        rex::be<uint32_t> playback_mode_ptr;
        rex::be<uint32_t> repeat_mode_ptr;
        rex::be<uint32_t> unk3_ptr;
      }* args = memory_->TranslateVirtual<decltype(args)>(buffer_ptr);
      static_assert_size(decltype(*args), 16);

      assert_true(args->xmp_client == 0x00000002 || args->xmp_client == 0x00000000);
      REXKRNL_DEBUG("XMPGetPlaybackBehavior({:08X}, {:08X}, {:08X})",
                    uint32_t(args->playback_mode_ptr), uint32_t(args->repeat_mode_ptr),
                    uint32_t(args->unk3_ptr));
      if (args->playback_mode_ptr) {
        // (Hunt v1.4.6, ronda 7, A3-R7-02.) The NULL-check was
        // there; the 4-byte range was not.
        if (!GuestRangeWritable(memory_, uint32_t(args->playback_mode_ptr), sizeof(uint32_t))) {
          return X_E_INVALIDARG;
        }
        memory::store_and_swap<uint32_t>(memory_->TranslateVirtual(args->playback_mode_ptr),
                                         static_cast<uint32_t>(playback_mode_));
      }
      if (args->repeat_mode_ptr) {
        // (Hunt v1.4.6, ronda 7, A3-R7-02.) The NULL-check was
        // there; the 4-byte range was not.
        if (!GuestRangeWritable(memory_, uint32_t(args->repeat_mode_ptr), sizeof(uint32_t))) {
          return X_E_INVALIDARG;
        }
        memory::store_and_swap<uint32_t>(memory_->TranslateVirtual(args->repeat_mode_ptr),
                                         static_cast<uint32_t>(repeat_mode_));
      }
      if (args->unk3_ptr) {
        // (Hunt v1.4.6, ronda 7, A3-R7-02.) The NULL-check was
        // there; the 4-byte range was not.
        if (!GuestRangeWritable(memory_, uint32_t(args->unk3_ptr), sizeof(uint32_t))) {
          return X_E_INVALIDARG;
        }
        memory::store_and_swap<uint32_t>(memory_->TranslateVirtual(args->unk3_ptr), unknown_flags_);
      }
      return X_E_SUCCESS;
    }
    case 0x0007002E: {
      assert_true(!buffer_length || buffer_length == 12);
      // (Hunt v1.4.6, ronda 7, A3-R7-02.) Validate the 12-byte
      // message struct before reading it (XamApp pattern, A3-R4-07).
      if (!GuestRangeReadable(memory_, buffer_ptr, 12)) {
        return X_E_INVALIDARG;
      }
      // Query of size for XamAlloc - the result of the alloc is passed to
      // 0x0007000D.
      struct {
        rex::be<uint32_t> xmp_client;
        rex::be<uint32_t> song_count;
        rex::be<uint32_t> size_ptr;
      }* args = memory_->TranslateVirtual<decltype(args)>(buffer_ptr);
      static_assert_size(decltype(*args), 12);

      assert_true(args->xmp_client == 0x00000002 || args->xmp_client == 0x00000000);
      // (Hunt v1.4.6, ronda 7, A3-R7-02.) size_ptr had no NULL-check,
      // and 4 + song_count * 128 wrapped in u32 (song_count =
      // 0x2000000 used to report 4): compute the size in 64 bits and
      // reject it if it does not fit the u32 out-param.
      if (!args->size_ptr ||
          !GuestRangeWritable(memory_, uint32_t(args->size_ptr), sizeof(uint32_t))) {
        return X_E_INVALIDARG;
      }
      const uint64_t size =
          4ull + static_cast<uint64_t>(uint32_t(args->song_count)) * 128ull;
      if (size > UINT32_MAX) {
        return X_E_INVALIDARG;
      }
      // We don't use the storage, so just fudge the number.
      memory::store_and_swap<uint32_t>(memory_->TranslateVirtual(args->size_ptr),
                                       static_cast<uint32_t>(size));
      return X_E_SUCCESS;
    }
    case 0x0007003D: {
      // XMPCaptureOutput - not sure how this works :/
      REXKRNL_DEBUG("XMPCaptureOutput(...)");
      assert_always("XMP output not unimplemented");
      return X_E_FAIL;
    }
  }
  REXKRNL_ERROR(
      "Unimplemented XMP message app={:08X}, msg={:08X}, arg1={:08X}, "
      "arg2={:08X}",
      app_id(), message, buffer_ptr, buffer_length);
  return X_E_FAIL;
}

}  // namespace apps
}  // namespace xam
}  // namespace kernel
}  // namespace rex

/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2021 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 * @modified    Aurora, 2026-11-14 - XbMovie video-playback device (audit C,
 *              ronda 2). PROBE ONLY, see xbmovie_device.h.
 */

#pragma once

#include <atomic>
#include <span>
#include <string>

#include <rex/filesystem.h>
#include <rex/filesystem/file.h>

namespace rex::filesystem {

class XbMovieEntry;

class XbMovieFile : public File {
 public:
  XbMovieFile(uint32_t file_access, XbMovieEntry* entry);
  ~XbMovieFile() override;

  void Destroy() override;

  X_STATUS ReadSync(std::span<uint8_t> buffer, size_t byte_offset, size_t* out_bytes_read) override;
  X_STATUS WriteSync(std::span<const uint8_t> buffer, size_t byte_offset,
                     size_t* out_bytes_written) override;
  X_STATUS SetLength(size_t length) override;

  // (Hunt v1.4.6, A2-R6-01.) Records one NOT_IMPLEMENTED answer to an
  // IOCTL on this handle. Returns true once the same IOCTL code has been
  // answered NOT_IMPLEMENTED kMaxConsecutiveIoctlRetries times in a row:
  // the caller should then answer with the probe's terminal "movie ended"
  // status (X_STATUS_END_OF_FILE) instead of NOT_IMPLEMENTED forever, so
  // a component that retries its start IOCTL until it succeeds can
  // terminate. A different code, or any write / SetLength, resets the
  // streak (see WriteSync/SetLength).
  bool RecordUnimplementedIoctl(uint32_t io_control_code);
  // Current NOT_IMPLEMENTED streak length (for the throttled log in
  // NtDeviceIoControlFile).
  uint32_t ConsecutiveIoctlCount() const { return consecutive_ioctl_count_; }
  // Backoff for the current NOT_IMPLEMENTED streak: 0 until the streak
  // passes kProbeLogFirstN, then 1/2/4/8 ms, capped at 8 ms. The caller
  // (NtDeviceIoControlFile, which holds no XFile lock) sleeps this long.
  uint32_t IoctlBackoffMs() const;
  // (Hunt v1.4.6, A2-R6-12.) Backoff for a caller looping on EOF reads,
  // in ms, from the xbmovie_probe_eof_sleep_ms cvar clamped to [0, 10]:
  // 0 until this handle has read EOF kProbeLogEveryN times in a row.
  // Read by NtReadFile/NtReadFileScatter AFTER XFile::Read returns, so
  // the sleep runs outside XFile::file_lock_. The default File
  // implementation returns 0 (no backoff).
  uint32_t EofBackoffMs() const override;

 private:
  // The probe logs only the first few reads/writes in full; after that it
  // counts, logging the running total every kProbeLogEveryN so a game
  // spinning on EOF reads stays visible in the log instead of going silent
  // after the first 8 (audit D, ronda 3, D-X-C-2).
  //
  // (Audit D, ronda 5, R5-D5.) The counters live in xbmovie_file.cpp as
  // process-wide statics, NOT as members: every open creates a new
  // XbMovieFile (XbMovieEntry::Open), so per-instance counters reset on
  // every re-open and the #1-#8 detail lines repeat while the 1024-totals
  // never grow. Shared counters keep one running total per process, which
  // is what the X-2a/X-2b phone discriminators read.
  static constexpr uint32_t kProbeLogFirstN = 8;
  static constexpr uint32_t kProbeLogEveryN = 1024;
  // (Hunt v1.4.6, A2-R6-01.) After this many consecutive NOT_IMPLEMENTED
  // answers to the SAME ioctl code on one handle, the probe stops saying
  // NOT_IMPLEMENTED and answers END_OF_FILE ("movie ended") instead.
  // 64 is generous: a component that falls back to another method after a
  // few NOT_IMPLEMENTEDs never reaches it, while one that retries its
  // start ioctl until SUCCESS terminates instead of spinning forever.
  static constexpr uint32_t kMaxConsecutiveIoctlRetries = 64;

  // (Hunt v1.4.6, A2-R6-01/A2-R6-12.) Per-handle streaks, NOT process
  // totals: a fresh open starts at 0, and a streak only grows while THIS
  // handle keeps hitting the same dead end. The old C-04 sleep keyed off
  // the process-wide read total, so after 1024 EOF reads anywhere in the
  // process every later EOF read on every handle slept; these counters
  // make the backoff apply only to the handle that is actually looping.
  //
  // (Second sweep, V-03.) Atomics, not plain uint32_t: the IOCTL path
  // (RecordUnimplementedIoctl / IoctlBackoffMs, called from
  // NtDeviceIoControlFile) and the EOF-backoff read (EofBackoffMs, called
  // from NtReadFile after XFile::Read returns) run with NO XFile lock
  // held, while WriteSync / SetLength reset the same counters under
  // file_lock_. Two guest threads on one handle -- one doing IOCTLs, one
  // writing -- would otherwise race on plain members. The check-then-act
  // in RecordUnimplementedIoctl stays approximate across threads (same as
  // before, just no longer UB); the consequence of a lost update is a
  // streak off by one, i.e. a backoff of a few ms. The process-wide
  // counters in xbmovie_file.cpp are already atomic; these match them.
  std::atomic<uint32_t> last_ioctl_code_ = 0;
  std::atomic<uint32_t> consecutive_ioctl_count_ = 0;
  std::atomic<uint32_t> consecutive_eof_reads_ = 0;
};

}  // namespace rex::filesystem

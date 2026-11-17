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
 *              ronda 2). PROBE ONLY, see xbmovie_device.h. Template:
 *              NullFile.
 *
 * TODO(PROTOCOL): the semantics below are GUESSES, not the real xbmovie
 * wire protocol:
 * - ReadSync returns EOF as X_STATUS_END_OF_FILE (audit D, ronda 6,
 *   R6-D1), the status every real file device in this tree returns at EOF
 *   (HostPathFile, StfsContainerFile, DiscImageFile) -- NOT SUCCESS +
 *   0 bytes, which the probe inherited from its NullFile template.
 *   SUCCESS + 0 is indistinguishable from "no bytes this time, retry"
 *   for a status-based reader, and on an async handle NtReadFile rewrites
 *   SUCCESS to PENDING while letting END_OF_FILE through untouched
 *   (xboxkrnl_io.cpp), so the old signal could spin the component in a
 *   read loop instead of ending the movie. On real hardware a read on
 *   this device most likely returns decoded frames / stream state, but
 *   which one, in which layout, is unknown without RE on default.pe or
 *   a traced session. EOF was chosen because it most closely mimics
 *   "the movie ended", which is the behaviour the game already handles
 *   (today it skips the movie when the open fails).
 * - WriteSync accepts and drops the bytes (like NullFile). If the game
 *   actually writes the movie URL / play command to the device, the
 *   first bytes of each write are logged so the phone log reveals it.
 * - (Audit D, ronda 8, R8-D4.) A denied access is logged, not silent:
 *   a read on a handle opened without kFileReadData (or a write on one
 *   opened without kFileWriteData/kFileAppendData) still returns
 *   ACCESS_DENIED -- the status is faithful -- but the attempt is counted
 *   and logged with the handle's access mask. Without this, a component
 *   that opens read-only and then writes its play command (or vice
 *   versa) would leave NO trace at all, and the phone log would wrongly
 *   read as "the component never writes/reads" (X-2c).
 * - (Audit D, ronda 9, R9-D1/R9-D2/R9-D3.) Three gaps left by R8-D4,
 *   same pattern: a denied SetLength (NtSetInformationFile
 *   FileEndOfFile/AllocationInformation on a handle without write
 *   access) was silent; a denied write logged the attempt but dropped
 *   the first bytes -- the play-command payload itself; and the close
 *   was never logged at all, so the log could not tell "still holding
 *   the handle" from "done with the movie". All three are now counted
 *   and logged the same way (first-8 / every-1024 for the denials, one
 *   line per close with the final totals). Behaviour is unchanged
 *   apart from the log: same statuses, same bytes.
 * - X-C-2 (audit D, ronda 3): reads return EOF forever, so a component
 *   looping on reads could spin. The probe does NOT sleep in ReadSync and
 *   does NOT fail reads after N: an error after N reads would invent
 *   protocol semantics the game may treat as fatal, and a sleep would
 *   stall direct reads. (Ronda 7, auditor A — R7-A3: la vieja cláusula
 *   del abanico ya no vale para esta sonda — ronda 6, R6-D1: un scatter
 *   en EOF se detiene tras su primer segmento, XFile::ReadScatter corta
 *   con cualquier status no-SUCCESS, así que ya no hay len/4096
 *   ReadSyncs por lectura.) The mitigation is observability only: the
 *   running read/write totals are logged every 1024 calls (see
 *   ReadSync/WriteSync below), so the phone log shows the spin and its
 *   rate.
 * Do NOT build a decoder on top of these semantics until the traced
 * protocol says what a read/write really carries.
 */

#include <rex/filesystem/devices/xbmovie_file.h>

#include <atomic>
#include <cstdio>

#include <rex/filesystem/devices/xbmovie_entry.h>
#include <rex/logging.h>

namespace rex::filesystem {

// (Audit D, ronda 5, R5-D5.) Process-wide probe counters: every open creates
// a new XbMovieFile, so member counters reset on every re-open of the device
// (the #1-#8 detail lines would repeat and the 1024-totals would never grow
// if the component opens once per movie). Shared counters keep one running
// total per process, which is what the X-2a/X-2b phone discriminators read.
// Only this file touches them; no header change beyond removing the members.
namespace {
std::atomic<uint32_t> g_xbmovie_read_count{0};
std::atomic<uint32_t> g_xbmovie_write_count{0};
// (Audit D, ronda 8, R8-D4.) Denied attempts are counted separately from
// successful ones: a denied read must not inflate the X-1j/X-2a read
// totals (which count EOF reads), and a denied write must not inflate
// the X-2c write totals. Same first-8 / every-1024 pattern as above.
std::atomic<uint32_t> g_xbmovie_read_denied_count{0};
std::atomic<uint32_t> g_xbmovie_write_denied_count{0};
// (Audit D, ronda 9, R9-D1.) Same for a denied SetLength: it reaches here
// from NtSetInformationFile (FileEndOfFile/AllocationInformation) and was
// the last silent denial on the probe path.
std::atomic<uint32_t> g_xbmovie_setlength_denied_count{0};
}  // namespace

XbMovieFile::XbMovieFile(uint32_t file_access, XbMovieEntry* entry) : File(file_access, entry) {}

XbMovieFile::~XbMovieFile() = default;

void XbMovieFile::Destroy() {
  // (Audit D, ronda 9, R9-D3.) The close is the last protocol fact: the
  // header promises the log reveals the "close order", but no line was
  // ever written when the handle died (NtClose only traces the handle
  // number, invisible at log_level=info, with no device name and no
  // totals). One WARN per close, with the final totals, so the phone log
  // can tell "the component closed after N reads" from "the component is
  // still holding the handle". Destroy() is the single choke point: it
  // is only called from XFile::~XFile (plus the vfs_dump tool, which
  // never opens this device).
  REXFS_WARN("XbMovieDevice: closed (access={:#x} reads={} writes={} denied_reads={} "
             "denied_writes={} denied_setlengths={})",
             file_access_, g_xbmovie_read_count.load(), g_xbmovie_write_count.load(),
             g_xbmovie_read_denied_count.load(), g_xbmovie_write_denied_count.load(),
             g_xbmovie_setlength_denied_count.load());
  delete this;
}

X_STATUS XbMovieFile::ReadSync(std::span<uint8_t> buffer, size_t byte_offset,
                               size_t* out_bytes_read) {
  if (!(file_access_ & FileAccess::kFileReadData)) {
    // (Audit D, ronda 8, R8-D4.) The denial itself is faithful (a read on
    // a handle without read access fails on real hardware too), but it was
    // silent: no line and no counter, so the phone log could not tell "the
    // component never reads" apart from "the component reads on a handle
    // that may not read". Log the attempt with the handle's access mask.
    const uint32_t denied_count = ++g_xbmovie_read_denied_count;
    if (denied_count <= kProbeLogFirstN) {
      REXFS_WARN("XbMovieDevice: ReadSync denied #{} (len={} offset={} access={:#x}) "
                 "-> ACCESS_DENIED",
                 denied_count, buffer.size(), byte_offset, file_access_);
    } else if (denied_count % kProbeLogEveryN == 0) {
      REXFS_WARN("XbMovieDevice: ReadSync total denied={} (len={} offset={} access={:#x}) "
                 "-> ACCESS_DENIED",
                 denied_count, buffer.size(), byte_offset, file_access_);
    }
    return X_STATUS_ACCESS_DENIED;
  }

  const uint32_t read_count = ++g_xbmovie_read_count;
  if (read_count <= kProbeLogFirstN) {
    REXFS_WARN("XbMovieDevice: ReadSync #{} (len={} offset={}) -> EOF", read_count,
               buffer.size(), byte_offset);
  } else if (read_count % kProbeLogEveryN == 0) {
    // (Audit D, ronda 3, D-X-C-2.) A game looping on EOF reads would
    // otherwise go silent after the first 8 lines while spinning; the
    // running total makes the spin visible in the phone log (and its rate
    // shows whether it is a tight loop or one read per frame). Behaviour
    // is unchanged apart from the status (R6-D1): still 0 bytes, now
    // X_STATUS_END_OF_FILE instead of SUCCESS + 0.
    REXFS_WARN("XbMovieDevice: ReadSync total reads={} (len={} offset={}) -> EOF", read_count,
               buffer.size(), byte_offset);
  }

  // EOF: end of movie. See the TODO(PROTOCOL) note at the top of this file.
  // (Audit D, ronda 6, R6-D1.) END_OF_FILE, not SUCCESS + 0: that is the
  // status every real file device returns at EOF in this tree, and the one
  // NtReadFile lets through unrewritten on async handles (it rewrites
  // SUCCESS to PENDING). A scatter read at EOF now also stops after its
  // first segment instead of fanning out to len/4096 ReadSync calls
  // (XFile::ReadScatter breaks on any non-SUCCESS status), which supersedes
  // the D-S-1 fan-out note for this device.
  if (out_bytes_read) {
    *out_bytes_read = 0;
  }
  return X_STATUS_END_OF_FILE;
}

X_STATUS XbMovieFile::WriteSync(std::span<const uint8_t> buffer, size_t byte_offset,
                                size_t* out_bytes_written) {
  if (!(file_access_ & (FileAccess::kFileWriteData | FileAccess::kFileAppendData))) {
    // (Audit D, ronda 8, R8-D4.) Same as ReadSync above: the denial is
    // faithful, the silence was not. A component that opens read-only and
    // then writes its play command would otherwise leave no trace, and
    // X-2c would wrongly read as "the game never writes".
    // (Audit D, ronda 9, R9-D2.) R8-D4 logged the attempt but dropped the
    // payload: the denied write's first bytes ARE the play command (or
    // URL) the probe exists to reveal, exactly as on the accepted path
    // below. Log the same first 16 bytes, built only when a line will
    // actually print (first-8 / every-1024), so a component spinning on
    // denied writes pays the hex formatting once per 1024 attempts.
    const uint32_t denied_count = ++g_xbmovie_write_denied_count;
    const bool will_log =
        denied_count <= kProbeLogFirstN || denied_count % kProbeLogEveryN == 0;
    char hex[16 * 3 + 1] = {};
    if (will_log) {
      size_t shown = buffer.size() < 16 ? buffer.size() : 16;
      for (size_t i = 0; i < shown; ++i) {
        std::snprintf(hex + i * 3, sizeof(hex) - i * 3, "%02X ", buffer[i]);
      }
    }
    if (denied_count <= kProbeLogFirstN) {
      REXFS_WARN("XbMovieDevice: WriteSync denied #{} (len={} offset={} access={:#x} "
                 "first_bytes=[{}]) -> ACCESS_DENIED",
                 denied_count, buffer.size(), byte_offset, file_access_, hex);
    } else if (denied_count % kProbeLogEveryN == 0) {
      REXFS_WARN("XbMovieDevice: WriteSync total denied={} (len={} offset={} access={:#x} "
                 "first_bytes=[{}]) -> ACCESS_DENIED",
                 denied_count, buffer.size(), byte_offset, file_access_, hex);
    }
    return X_STATUS_ACCESS_DENIED;
  }

  const uint32_t write_count = ++g_xbmovie_write_count;
  if (write_count <= kProbeLogFirstN) {
    // Log the first bytes: if the game writes a URL / command block to the
    // device, this is where the protocol shows up. Plain C hex, no new
    // dependencies (NullFile has none either).
    char hex[16 * 3 + 1] = {};
    size_t shown = buffer.size() < 16 ? buffer.size() : 16;
    for (size_t i = 0; i < shown; ++i) {
      std::snprintf(hex + i * 3, sizeof(hex) - i * 3, "%02X ", buffer[i]);
    }
    REXFS_WARN("XbMovieDevice: WriteSync #{} (len={} offset={} first_bytes=[{}]) -> accepted",
               write_count, buffer.size(), byte_offset, hex);
  } else if (write_count % kProbeLogEveryN == 0) {
    // (Audit D, ronda 3, D-X-C-2.) Same running-total visibility as reads.
    REXFS_WARN("XbMovieDevice: WriteSync total writes={} (len={} offset={}) -> accepted",
               write_count, buffer.size(), byte_offset);
  }

  if (out_bytes_written) {
    *out_bytes_written = buffer.size();
  }
  return X_STATUS_SUCCESS;
}

X_STATUS XbMovieFile::SetLength(size_t length) {
  if (!(file_access_ & FileAccess::kFileWriteData)) {
    // (Audit D, ronda 9, R9-D1.) The last silent denial on the probe
    // path: NtSetInformationFile (FileEndOfFileInformation and
    // FileAllocationInformation, xboxkrnl_io_info.cpp) routes straight
    // here, and a handle opened without write access got ACCESS_DENIED
    // with no line and no counter -- the same hole R8-D4 closed for
    // ReadSync/WriteSync. R8 set SetLength aside as "not part of the
    // observable protocol", but the NtSetInformationFile caller path was
    // never traced: truncating / setting EOF is a normal file operation
    // a component can try on the device, and the denial is a protocol
    // fact (it says the component expected write access). Same
    // first-8 / every-1024 pattern and separate counter as R8-D4; the
    // SUCCESS no-op below stays silent by design (R4-D5).
    const uint32_t denied_count = ++g_xbmovie_setlength_denied_count;
    if (denied_count <= kProbeLogFirstN) {
      REXFS_WARN("XbMovieDevice: SetLength denied #{} (len={} access={:#x}) -> ACCESS_DENIED",
                 denied_count, length, file_access_);
    } else if (denied_count % kProbeLogEveryN == 0) {
      REXFS_WARN("XbMovieDevice: SetLength total denied={} (len={} access={:#x}) "
                 "-> ACCESS_DENIED",
                 denied_count, length, file_access_);
    }
    return X_STATUS_ACCESS_DENIED;
  }

  (void)length;
  return X_STATUS_SUCCESS;
}

}  // namespace rex::filesystem

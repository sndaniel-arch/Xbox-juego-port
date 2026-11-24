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

// Disable warnings about unused parameters for kernel functions
#pragma GCC diagnostic ignored "-Wunused-parameter"

#include <cstring>
#include <string>

#if REX_PLATFORM_MAC
#include <sys/select.h>
#endif

#include <rex/chrono/clock.h>
#include <rex/kernel/xam/module.h>
#include <rex/kernel/xam/private.h>
#include <rex/kernel/xboxkrnl/error.h>
#include <rex/kernel/xboxkrnl/threading.h>
#include <rex/logging.h>
#include <rex/hook.h>
#include <rex/types.h>
#include <rex/string.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xevent.h>
#include <rex/system/xsocket.h>
#include <rex/system/xthread.h>
#include <rex/system/xtypes.h>

#if REX_PLATFORM_WIN32
// NOTE: must be included last as it expects windows.h to already be included.
#define _WINSOCK_DEPRECATED_NO_WARNINGS  // inet_addr
#include <winsock2.h>                    // NOLINT(build/include_order)
#elif REX_PLATFORM_LINUX || REX_PLATFORM_MAC
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#endif

namespace rex {
namespace kernel {
namespace xam {
using namespace rex::system;
using namespace rex::system::xam;

// (Hunt v1.4.6, ronda 4, A3-R4-09.) TranslateVirtual never validates
// and never returns null, so a guest pointer + length that runs past
// the end of the mapping SIGSEGVs the host on the memcpy/memset/host
// send/recv. Same heap validation as A2-R3-01 (see xam_user.cpp for
// the full comment).
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
// host pointer -- a strlen to NUL with no cap -- so a guest address
// string with no NUL in its page ran the host scan into unmapped
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

// https://github.com/G91/TitanOffLine/blob/1e692d9bb9dfac386d08045ccdadf4ae3227bb5e/xkelib/xam/xamNet.h
enum {
  XNCALLER_INVALID = 0x0,
  XNCALLER_TITLE = 0x1,
  XNCALLER_SYSAPP = 0x2,
  XNCALLER_XBDM = 0x3,
  XNCALLER_TEST = 0x4,
  NUM_XNCALLER_TYPES = 0x4,
};

// https://github.com/pmrowla/hl2sdk-csgo/blob/master/common/xbox/xboxstubs.h
typedef struct {
  // FYI: IN_ADDR should be in network-byte order.
  in_addr ina;                    // IP address (zero if not static/DHCP)
  in_addr inaOnline;              // Online IP address (zero if not online)
  rex::be<uint16_t> wPortOnline;  // Online port
  uint8_t abEnet[6];              // Ethernet MAC address
  uint8_t abOnline[20];           // Online identification
} XNADDR;

typedef struct {
  rex::be<int32_t> status;
  rex::be<uint32_t> cina;
  in_addr aina[8];
} XNDNS;

typedef struct {
  uint8_t flags;
  uint8_t reserved;
  rex::be<uint16_t> probes_xmit;
  rex::be<uint16_t> probes_recv;
  rex::be<uint16_t> data_len;
  rex::be<uint32_t> data_ptr;
  rex::be<uint16_t> rtt_min_in_msecs;
  rex::be<uint16_t> rtt_med_in_msecs;
  rex::be<uint32_t> up_bits_per_sec;
  rex::be<uint32_t> down_bits_per_sec;
} XNQOSINFO;

typedef struct {
  rex::be<uint32_t> count;
  rex::be<uint32_t> count_pending;
  XNQOSINFO info[1];
} XNQOS;

struct Xsockaddr_t {
  rex::be<uint16_t> sa_family;
  char sa_data[14];
};

struct X_WSADATA {
  rex::be<uint16_t> version;
  rex::be<uint16_t> version_high;
  char description[256 + 1];
  char system_status[128 + 1];
  rex::be<uint16_t> max_sockets;
  rex::be<uint16_t> max_udpdg;
  rex::be<uint32_t> vendor_info_ptr;
};

struct XWSABUF {
  rex::be<uint32_t> len;
  rex::be<uint32_t> buf_ptr;
};

struct XWSAOVERLAPPED {
  rex::be<uint32_t> internal;
  rex::be<uint32_t> internal_high;
  union {
    struct {
      rex::be<uint32_t> low;
      rex::be<uint32_t> high;
    } offset;  // must be named to avoid GCC error
    rex::be<uint32_t> pointer;
  };
  rex::be<uint32_t> event_handle;
};

void LoadSockaddr(const uint8_t* ptr, sockaddr* out_addr) {
  out_addr->sa_family = memory::load_and_swap<uint16_t>(ptr + 0);
  switch (out_addr->sa_family) {
    case AF_INET: {
      auto in_addr = reinterpret_cast<sockaddr_in*>(out_addr);
      in_addr->sin_port = memory::load_and_swap<uint16_t>(ptr + 2);
      // Maybe? Depends on type.
      in_addr->sin_addr.s_addr = *(uint32_t*)(ptr + 4);
      break;
    }
    default:
      assert_unhandled_case(out_addr->sa_family);
      break;
  }
}

void StoreSockaddr(const sockaddr& addr, uint8_t* ptr) {
  switch (addr.sa_family) {
    case AF_UNSPEC:
      std::memset(ptr, 0, sizeof(addr));
      break;
    case AF_INET: {
      auto& in_addr = reinterpret_cast<const sockaddr_in&>(addr);
      memory::store_and_swap<uint16_t>(ptr + 0, in_addr.sin_family);
      memory::store_and_swap<uint16_t>(ptr + 2, in_addr.sin_port);
      // Maybe? Depends on type.
      memory::store_and_swap<uint32_t>(ptr + 4, in_addr.sin_addr.s_addr);
      break;
    }
    default:
      assert_unhandled_case(addr.sa_family);
      break;
  }
}

// https://github.com/joolswills/mameox/blob/master/MAMEoX/Sources/xbox_Network.cpp#L136
struct XNetStartupParams {
  uint8_t cfgSizeOfStruct;
  uint8_t cfgFlags;
  uint8_t cfgSockMaxDgramSockets;
  uint8_t cfgSockMaxStreamSockets;
  uint8_t cfgSockDefaultRecvBufsizeInK;
  uint8_t cfgSockDefaultSendBufsizeInK;
  uint8_t cfgKeyRegMax;
  uint8_t cfgSecRegMax;
  uint8_t cfgQosDataLimitDiv4;
  uint8_t cfgQosProbeTimeoutInSeconds;
  uint8_t cfgQosProbeRetries;
  uint8_t cfgQosSrvMaxSimultaneousResponses;
  uint8_t cfgQosPairWaitTimeInSeconds;
};

XNetStartupParams xnet_startup_params = {};

u32 NetDll_XNetStartup_entry(u32 caller, ppc_ptr_t<XNetStartupParams> params) {
  if (params) {
    // (Hunt v1.4.6, ronda 7, A3-R7-08.) The 13-byte params struct is
    // read (assert + memcpy) with only a NULL-check; skip the copy
    // on a bad range, like the NULL case already does.
    if (!GuestRangeReadable(params.guest_address(), sizeof(XNetStartupParams))) {
      return 0;
    }
    assert_true(params->cfgSizeOfStruct == sizeof(XNetStartupParams));
    std::memcpy(&xnet_startup_params, params, sizeof(XNetStartupParams));
  }

  auto xam = REX_KERNEL_STATE()->GetKernelModule<XamModule>("xam.xex");

  /*
  if (!xam->xnet()) {
    auto xnet = new XNet(REX_KERNEL_STATE());
    xnet->Initialize();

    xam->set_xnet(xnet);
  }
  */

  return 0;
}

u32 NetDll_XNetCleanup_entry(u32 caller, mapped_void params) {
  auto xam = REX_KERNEL_STATE()->GetKernelModule<XamModule>("xam.xex");
  // auto xnet = xam->xnet();
  // xam->set_xnet(nullptr);

  // TODO: Shut down and delete.
  // delete xnet;

  return 0;
}

u32 NetDll_XNetGetOpt_entry(u32 one, u32 option_id, mapped_void buffer_ptr,
                            mapped_u32 buffer_size) {
  assert_true(one == 1);
  switch (option_id) {
    case 1:
      // (Hunt v1.4.6, ronda 2, A3-R2-03.) *buffer_size is read and
      // written and buffer_ptr is memcpied below with no null check
      // (same class as R6-06); a NULL out-param used to touch guest
      // address 0.
      if (!buffer_size || !buffer_ptr) {
        return 0x2726;  // WSAEINVAL
      }
      // (Hunt v1.4.6, ronda 10, A3-R10-12.) *buffer_size is read and
      // written and buffer_ptr is memcpied below, all with only the
      // NULL checks above: validate the 4-byte size range first, and
      // the 13-byte destination range before the memcpy runs (the
      // memcpy only runs when *buffer_size >= sizeof, so the buffer
      // check is gated on that -- a smaller size only writes
      // *buffer_size and returns WSAEMSGSIZE).
      if (!GuestRangeReadable(buffer_size.guest_address(), sizeof(uint32_t)) ||
          !GuestRangeWritable(buffer_size.guest_address(), sizeof(uint32_t))) {
        return 0x2726;  // WSAEINVAL
      }
      if (*buffer_size >= sizeof(XNetStartupParams) &&
          !GuestRangeWritable(buffer_ptr.guest_address(), sizeof(XNetStartupParams))) {
        return 0x2726;  // WSAEINVAL
      }
      if (*buffer_size < sizeof(XNetStartupParams)) {
        *buffer_size = sizeof(XNetStartupParams);
        return 0x2738;  // WSAEMSGSIZE
      }
      std::memcpy(buffer_ptr, &xnet_startup_params, sizeof(XNetStartupParams));
      return 0;
    default:
      REXKRNL_ERROR("NetDll_XNetGetOpt: option {} unimplemented", option_id);
      return 0x2726;  // WSAEINVAL
  }
}

u32 NetDll_XNetRandom_entry(u32 caller, mapped_void buffer_ptr, u32 length) {
  // (Hunt v1.4.6, ronda 2 second sweep, LOW-4.) Null guest pointer: same
  // R6-06 class as the GetOpt guard above — return WSAEFAULT instead of
  // faulting the host on the memset.
  if (!buffer_ptr) {
    return 0x271E;  // WSAEFAULT
  }
  // (Hunt v1.4.6, ronda 4, A3-R4-09, hermana.) Same class as WSASendTo
  // below: `length` is guest controlled (u32) and the old code memsets
  // that many bytes from an unvalidated pointer. Validate the whole
  // destination range first.
  if (!GuestRangeWritable(buffer_ptr.guest_address(), length)) {
    return 0x271E;  // WSAEFAULT
  }
  // For now, constant values.
  // This makes replicating things easier.
  std::memset(buffer_ptr, 0xBB, length);

  return 0;
}

u32 NetDll_WSAStartup_entry(u32 caller, u16 version, ppc_ptr_t<X_WSADATA> data_ptr) {
  // (Hunt v1.4.6, caza ronda 6, A3-R6-02.) data_ptr is written below
  // (~0x190 bytes: the struct itself is 0x18E, and the Win32 branch
  // round-trips the vendor pointer at offset 0x190) with only a NULL
  // check; a non-NULL pointer at the end of the mapping SIGSEGVs the
  // host. Validate the whole written range first (0x194 covers the
  // struct plus the 4-byte vendor round-trip). A NULL data_ptr is still
  // tolerated, as before. WSAEFAULT, like the other entries here.
  if (data_ptr && !GuestRangeWritable(data_ptr.guest_address(), 0x194)) {
    return 0x271E;  // WSAEFAULT
  }
// TODO(benvanik): abstraction layer needed.
#if REX_PLATFORM_WIN32
  WSADATA wsaData;
  ZeroMemory(&wsaData, sizeof(WSADATA));
  int ret = WSAStartup(version, &wsaData);

  auto data_out = REX_KERNEL_MEMORY()->TranslateVirtual(data_ptr.guest_address());

  if (data_ptr) {
    data_ptr->version = wsaData.wVersion;
    data_ptr->version_high = wsaData.wHighVersion;
    std::memcpy(&data_ptr->description, wsaData.szDescription, 0x100);
    std::memcpy(&data_ptr->system_status, wsaData.szSystemStatus, 0x80);
    data_ptr->max_sockets = wsaData.iMaxSockets;
    data_ptr->max_udpdg = wsaData.iMaxUdpDg;

    // Some games (5841099F) want this value round-tripped - they'll compare if
    // it changes and bugcheck if it does.
    uint32_t vendor_ptr = memory::load_and_swap<uint32_t>(data_out + 0x190);
    memory::store_and_swap<uint32_t>(data_out + 0x190, vendor_ptr);
  }
#else
  int ret = 0;
  if (data_ptr) {
    // Guess these values!
    data_ptr->version = version;
    data_ptr->description[0] = '\0';
    data_ptr->system_status[0] = '\0';
    data_ptr->max_sockets = 100;
    data_ptr->max_udpdg = 1024;
  }
#endif

  // DEBUG
  /*
  auto xam = REX_KERNEL_STATE()->GetKernelModule<XamModule>("xam.xex");
  if (!xam->xnet()) {
    auto xnet = new XNet(REX_KERNEL_STATE());
    xnet->Initialize();

    xam->set_xnet(xnet);
  }
  */

  return ret;
}

u32 NetDll_WSACleanup_entry(u32 caller) {
  // This does nothing. Xenia needs WSA running.
  return 0;
}

u32 NetDll_WSAGetLastError_entry() {
  return XThread::GetLastError();
}

u32 NetDll_WSARecvFrom_entry(u32 caller, u32 socket, ppc_ptr_t<XWSABUF> buffers_ptr,
                             u32 buffer_count, mapped_u32 num_bytes_recv, mapped_u32 flags_ptr,
                             ppc_ptr_t<XSOCKADDR_IN> from_addr,
                             ppc_ptr_t<XWSAOVERLAPPED> overlapped_ptr,
                             mapped_void completion_routine_ptr) {
  if (overlapped_ptr) {
    // auto evt = REX_KERNEL_OBJECTS()->LookupObject<XEvent>(
    //    overlapped_ptr->event_handle);

    // if (evt) {
    //  //evt->Set(0, false);
    //}
  }

  // we're not going to be receiving packets any time soon
  // return error so we don't wait on that - Cancerous
  return -1;
}

// If the socket is a VDP socket, buffer 0 is the game data length, and buffer 1
// is the unencrypted game data.
u32 NetDll_WSASendTo_entry(u32 caller, u32 socket_handle, ppc_ptr_t<XWSABUF> buffers,
                           u32 num_buffers, mapped_u32 num_bytes_sent, u32 flags,
                           ppc_ptr_t<XSOCKADDR_IN> to_ptr, u32 to_len,
                           ppc_ptr_t<XWSAOVERLAPPED> overlapped, mapped_void completion_routine) {
  assert(!overlapped);
  assert(!completion_routine);

  auto socket = REX_KERNEL_OBJECTS()->LookupObject<XSocket>(socket_handle);
  if (!socket) {
    // WSAENOTSOCK
    XThread::SetLastError(0x2736);
    return -1;
  }

  // (Hunt v1.4.6, ronda 3, A3-R3-02.) `buffers` is a guest pointer: NULL
  // with num_buffers > 0 used to dereference a null host pointer on the
  // first iteration. The combined length is guest-controlled, so
  // accumulate in 64 bits and reject anything over 16 MiB before sizing
  // the host vector -- two 0x80000000 buffers used to wrap the old
  // uint32_t sum to 0, resize(0), then memcpy ~4 GiB into an empty
  // vector (host heap overflow).
  if (num_buffers && !buffers) {
    // WSAEFAULT
    XThread::SetLastError(0x271E);
    return -1;
  }
  // (Hunt v1.4.6, verificación profunda, FE-04.) `num_buffers` is
  // guest-controlled (u32) and both loops below index `buffers[i]`
  // directly, but nothing validated the XWSABUF array itself: an array
  // crossing the end of the mapping SIGSEGVd the host on the first read,
  // before the 16 MiB cap below could abort (that cap bounds total
  // bytes, not the array position), and with len == 0 in every entry the
  // cap never trips, so the loops could spin up to 2^32 iterations.
  // Validate the whole array first, and cap the entry count: the host
  // combines the buffers into a single vector and the normal game
  // pattern is 1-2 entries (VDP: buffer 0 = length, buffer 1 = data),
  // so 1024 entries -- 512x that, 8 KiB of array -- bounds the loop
  // without touching legitimate use. The cap is checked first so the
  // validated length below can never overflow.
  constexpr uint32_t kMaxSendToBuffers = 1024;
  if (num_buffers > kMaxSendToBuffers) {
    // WSAEMSGSIZE, same as the 16 MiB total cap below.
    XThread::SetLastError(0x2738);
    return -1;
  }
  if (num_buffers &&
      !GuestRangeReadable(buffers.guest_address(),
                          static_cast<size_t>(num_buffers) * sizeof(XWSABUF))) {
    // WSAEFAULT
    XThread::SetLastError(0x271E);
    return -1;
  }
  uint64_t combined_buffer_size = 0;
  for (uint32_t i = 0; i < num_buffers; i++) {
    combined_buffer_size += buffers[i].len;
    if (combined_buffer_size > 16u * 1024u * 1024u) {
      // WSAEMSGSIZE
      XThread::SetLastError(0x2738);
      return -1;
    }
  }

  // Our sockets implementation doesn't support multiple buffers, so we need
  // to combine the buffers the game has given us!
  std::vector<uint8_t> combined_buffer_mem;
  combined_buffer_mem.resize(static_cast<size_t>(combined_buffer_size));
  uint32_t combined_buffer_offset = 0;
  for (uint32_t i = 0; i < num_buffers; i++) {
    uint8_t* combined_buffer = combined_buffer_mem.data();

    // (Hunt v1.4.6, ronda 4, A3-R4-09.) The 16 MiB cap above bounds
    // the TOTAL, not the position: a buffer near the end of the mapping
    // (or a wild pointer) still reads past it. Validate each source
    // range before the copy.
    if (!GuestRangeReadable(static_cast<uint32_t>(buffers[i].buf_ptr),
                            static_cast<uint32_t>(buffers[i].len))) {
      // WSAEFAULT
      XThread::SetLastError(0x271E);
      return -1;
    }
    std::memcpy(combined_buffer + combined_buffer_offset,
                REX_KERNEL_MEMORY()->TranslateVirtual(buffers[i].buf_ptr), buffers[i].len);
    combined_buffer_offset += buffers[i].len;
  }

  // (Hunt v1.4.6, verificación profunda, segundo barrido, V-FE-09.)
  // Same class as FE-05 (sendto/recvfrom): `to_ptr` is read below
  // (N_XSOCKADDR_IN copies sin_family/sin_port/sin_addr, 16 bytes) and
  // `num_bytes_sent` is written back after SendTo, but neither range was
  // validated -- only the NULL case was covered (A3-R3-01 for `to_ptr`,
  // A3-R3-16 for the out-param write). A non-NULL pointer outside the
  // mapping SIGSEGVs the host on the read or the write-back. Validate
  // both up front, before SendTo runs, so a bad out-param fails before
  // the packet is sent. NULL stays legitimate for `to_ptr` (connected
  // socket) and for `num_bytes_sent` (caller does not want the count).
  if (to_ptr && !GuestRangeReadable(to_ptr.guest_address(), sizeof(XSOCKADDR_IN))) {
    // WSAEFAULT
    XThread::SetLastError(0x271E);
    return -1;
  }
  if (num_bytes_sent &&
      !GuestRangeWritable(num_bytes_sent.guest_address(), sizeof(uint32_t))) {
    // WSAEFAULT
    XThread::SetLastError(0x271E);
    return -1;
  }

  // (Hunt v1.4.6, ronda 3, A3-R3-01.) A NULL destination is legitimate
  // Winsock use (send on the connected socket); the old unconditional
  // N_XSOCKADDR_IN constructor dereferenced it and SIGSEGVd the host.
  // XSocket::SendTo already takes a null `to` -- pass it through.
  N_XSOCKADDR_IN native_to;
  if (to_ptr) {
    native_to = *to_ptr;
  }
  int bytes_sent = socket->SendTo(combined_buffer_mem.data(),
                                  static_cast<uint32_t>(combined_buffer_size), flags,
                                  to_ptr ? &native_to : nullptr, to_len);

  // (Hunt v1.4.6, ronda 3, A3-R3-16.) The out-param was never written:
  // the guest read stale memory after a "successful" send.
  if (num_bytes_sent) {
    *num_bytes_sent = bytes_sent < 0 ? 0u : static_cast<uint32_t>(bytes_sent);
  }

  // TODO: Instantly complete overlapped

  return 0;
}

u32 NetDll_WSAWaitForMultipleEvents_entry(u32 num_events, mapped_u32 events, u32 wait_all,
                                          u32 timeout, u32 alertable) {
  if (num_events > 64) {
    XThread::SetLastError(87);  // ERROR_INVALID_PARAMETER
    return ~0u;
  }

  // (Hunt v1.4.6, verificación profunda, segundo barrido, V-FE-12.)
  // Same shape as FE-04 (WSASendTo): the count is capped at 64 above,
  // but the events array itself (num_events * 4 bytes) was never
  // range-validated -- xeNtWaitForMultipleObjectsEx reads handles[n]
  // for n < count. An array crossing the end of the mapping SIGSEGVs
  // the host on that read. The cap above bounds the validated length
  // to 256 bytes, so it cannot overflow.
  if (num_events &&
      !GuestRangeReadable(events.guest_address(),
                          static_cast<size_t>(num_events) * sizeof(uint32_t))) {
    XThread::SetLastError(0x271E);  // WSAEFAULT
    return ~0u;
  }

  uint64_t timeout_wait = (uint64_t)timeout;

  X_STATUS result = 0;
  do {
    result = xboxkrnl::xeNtWaitForMultipleObjectsEx(num_events, events, wait_all, 1, alertable,
                                                    timeout != -1 ? &timeout_wait : nullptr);
  } while (result == X_STATUS_ALERTED);

  if (XFAILED(result)) {
    uint32_t error = xboxkrnl::xeRtlNtStatusToDosError(result);
    XThread::SetLastError(error);
    return ~0u;
  }
  return 0;
}

u32 NetDll_WSACreateEvent_entry() {
  XEvent* ev = new XEvent(REX_KERNEL_STATE());
  ev->Initialize(true, false);
  return ev->handle();
}

u32 NetDll_WSACloseEvent_entry(u32 event_handle) {
  X_STATUS result = REX_KERNEL_OBJECTS()->ReleaseHandle(event_handle);
  if (XFAILED(result)) {
    uint32_t error = xboxkrnl::xeRtlNtStatusToDosError(result);
    XThread::SetLastError(error);
    return 0;
  }
  return 1;
}

u32 NetDll_WSAResetEvent_entry(u32 event_handle) {
  X_STATUS result = xboxkrnl::xeNtClearEvent(event_handle);
  if (XFAILED(result)) {
    uint32_t error = xboxkrnl::xeRtlNtStatusToDosError(result);
    XThread::SetLastError(error);
    return 0;
  }
  return 1;
}

u32 NetDll_WSASetEvent_entry(u32 event_handle) {
  X_STATUS result = xboxkrnl::xeNtSetEvent(event_handle, nullptr);
  if (XFAILED(result)) {
    uint32_t error = xboxkrnl::xeRtlNtStatusToDosError(result);
    XThread::SetLastError(error);
    return 0;
  }
  return 1;
}

struct XnAddrStatus {
  // Address acquisition is not yet complete
  static const uint32_t XNET_GET_XNADDR_PENDING = 0x00000000;
  // XNet is uninitialized or no debugger found
  static const uint32_t XNET_GET_XNADDR_NONE = 0x00000001;
  // Host has ethernet address (no IP address)
  static const uint32_t XNET_GET_XNADDR_ETHERNET = 0x00000002;
  // Host has statically assigned IP address
  static const uint32_t XNET_GET_XNADDR_STATIC = 0x00000004;
  // Host has DHCP assigned IP address
  static const uint32_t XNET_GET_XNADDR_DHCP = 0x00000008;
  // Host has PPPoE assigned IP address
  static const uint32_t XNET_GET_XNADDR_PPPOE = 0x00000010;
  // Host has one or more gateways configured
  static const uint32_t XNET_GET_XNADDR_GATEWAY = 0x00000020;
  // Host has one or more DNS servers configured
  static const uint32_t XNET_GET_XNADDR_DNS = 0x00000040;
  // Host is currently connected to online service
  static const uint32_t XNET_GET_XNADDR_ONLINE = 0x00000080;
  // Network configuration requires troubleshooting
  static const uint32_t XNET_GET_XNADDR_TROUBLESHOOT = 0x00008000;
};

u32 NetDll_XNetGetTitleXnAddr_entry(u32 caller, ppc_ptr_t<XNADDR> addr_ptr) {
  // (Hunt v1.4.6, ronda 2 second sweep, LOW-4.) Null guest pointer: same
  // R6-06 class as the GetOpt guard — return NONE (the graceful "no address"
  // status) instead of faulting the host on the dereference.
  if (!addr_ptr) {
    return XnAddrStatus::XNET_GET_XNADDR_NONE;
  }
  // (Hunt v1.4.6, ronda 7, A3-R7-08.) sizeof(XNADDR) (36) bytes are
  // written (fields plus the abEnet/abOnline memsets) with only a
  // NULL-check.
  if (!GuestRangeWritable(addr_ptr.guest_address(), sizeof(XNADDR))) {
    return XnAddrStatus::XNET_GET_XNADDR_NONE;
  }
  // Just return a loopback address atm.
  addr_ptr->ina.s_addr = htonl(INADDR_LOOPBACK);
  addr_ptr->inaOnline.s_addr = 0;
  addr_ptr->wPortOnline = 0;

  // TODO(gibbed): A proper mac address.
  // RakNet's 360 version appears to depend on abEnet to create "random" 64-bit
  // numbers. A zero value will cause RakPeer::Startup to fail. This causes
  // 58411436 to crash on startup.
  // The 360-specific code is scrubbed from the RakNet repo, but there's still
  // traces of what it's doing which match the game code.
  // https://github.com/facebookarchive/RakNet/blob/master/Source/RakPeer.cpp#L382
  // https://github.com/facebookarchive/RakNet/blob/master/Source/RakPeer.cpp#L4527
  // https://github.com/facebookarchive/RakNet/blob/master/Source/RakPeer.cpp#L4467
  // "Mac address is a poor solution because you can't have multiple connections
  // from the same system"
  std::memset(addr_ptr->abEnet, 0xCC, 6);

  std::memset(addr_ptr->abOnline, 0, 20);

  return XnAddrStatus::XNET_GET_XNADDR_STATIC;
}

u32 NetDll_XNetGetDebugXnAddr_entry(u32 caller, ppc_ptr_t<XNADDR> addr_ptr) {
  // (Hunt v1.4.6, ronda 2 second sweep, LOW-4.) See XNetGetTitleXnAddr above.
  if (!addr_ptr) {
    return XnAddrStatus::XNET_GET_XNADDR_NONE;
  }
  // (Hunt v1.4.6, ronda 7, A3-R7-08.) Zero() writes the whole
  // sizeof(XNADDR) struct with only the NULL-check above.
  if (!GuestRangeWritable(addr_ptr.guest_address(), sizeof(XNADDR))) {
    return XnAddrStatus::XNET_GET_XNADDR_NONE;
  }
  addr_ptr.Zero();

  // XNET_GET_XNADDR_NONE causes caller to gracefully return.
  return XnAddrStatus::XNET_GET_XNADDR_NONE;
}

u32 NetDll_XNetXnAddrToMachineId_entry(u32 caller, ppc_ptr_t<XNADDR> addr_ptr, mapped_u32 id_ptr) {
  // Tell the caller we're not signed in to live (non-zero ret)
  return 1;
}

void NetDll_XNetInAddrToString_entry(u32 caller, u32 in_addr, mapped_string string_out,
                                     u32 string_size) {
  // (Hunt v1.4.6, ronda 7, A3-R7-08.) The only copy_truncating caller
  // in the area without even a NULL-check: with string_out == NULL and
  // string_size > 0 the memcpy wrote to guest address 0, and a
  // non-NULL pointer at the end of the mapping wrote past it.
  // copy_truncating writes at most string_size bytes.
  if (!string_out || !string_size ||
      !GuestRangeWritable(string_out.guest_address(), string_size)) {
    return;
  }
  rex::string::copy_truncating(string_out, "666.666.666.666", string_size);
}

// This converts a XNet address to an IN_ADDR. The IN_ADDR is used for
// subsequent socket calls (like a handle to a XNet address)
u32 NetDll_XNetXnAddrToInAddr_entry(u32 caller, ppc_ptr_t<XNADDR> xn_addr, mapped_void xid,
                                    mapped_void in_addr) {
  return 1;
}

// Does the reverse of the above.
// FIXME: Arguments may not be correct.
u32 NetDll_XNetInAddrToXnAddr_entry(u32 caller, mapped_void in_addr, ppc_ptr_t<XNADDR> xn_addr,
                                    mapped_void xid) {
  return 1;
}

// https://www.google.com/patents/WO2008112448A1?cl=en
// Reserves a port for use by system link
u32 NetDll_XNetSetSystemLinkPort_entry(u32 caller, u32 port) {
  return 1;
}

// https://github.com/ILOVEPIE/Cxbx-Reloaded/blob/master/src/CxbxKrnl/EmuXOnline.h#L39
struct XEthernetStatus {
  static const uint32_t XNET_ETHERNET_LINK_ACTIVE = 0x01;
  static const uint32_t XNET_ETHERNET_LINK_100MBPS = 0x02;
  static const uint32_t XNET_ETHERNET_LINK_10MBPS = 0x04;
  static const uint32_t XNET_ETHERNET_LINK_FULL_DUPLEX = 0x08;
  static const uint32_t XNET_ETHERNET_LINK_HALF_DUPLEX = 0x10;
};

u32 NetDll_XNetGetEthernetLinkStatus_entry(u32 caller) {
  return 0;
}

u32 NetDll_XNetDnsLookup_entry(u32 caller, mapped_string host, u32 event_handle, mapped_u32 pdns) {
  // TODO(gibbed): actually implement this
  uint32_t result = 0;
  // (Hunt v1.4.6, ronda 10, A3-R10-12.) *pdns is written below with
  // only the NULL check: validate the 4-byte range first.
  if (pdns && !GuestRangeWritable(pdns.guest_address(), sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  if (pdns) {
    auto dns_guest = REX_KERNEL_MEMORY()->SystemHeapAlloc(sizeof(XNDNS));
    // (Hunt v1.4.6, ronda 4, A3-R4-22.) SystemHeapAlloc returns 0 on
    // failure: the old code translated 0 (membase) and wrote the status
    // there, handing the game a DNS struct at guest address 0. Report
    // out-of-memory instead and hand back a null pointer.
    if (!dns_guest) {
      *pdns = 0;
      result = X_STATUS_NO_MEMORY;
    } else {
      auto dns = REX_KERNEL_MEMORY()->TranslateVirtual<XNDNS*>(dns_guest);
      dns->status = 1;  // non-zero = error
      *pdns = dns_guest;
    }
  }
  if (event_handle) {
    auto ev = REX_KERNEL_OBJECTS()->LookupObject<XEvent>(event_handle);
    // (Hunt v1.4.6, ronda 2, A3-R2-02.) LookupObject returns nullptr
    // for an invalid/closed handle and assert_not_null is a no-op in
    // Release; ev->Set on null used to SIGSEGV the host.
    if (!ev) {
      return X_ERROR_INVALID_HANDLE;
    }
    ev->Set(0, false);
  }
  return result;
}

u32 NetDll_XNetDnsRelease_entry(u32 caller, ppc_ptr_t<XNDNS> dns) {
  if (!dns) {
    return X_STATUS_INVALID_PARAMETER;
  }
  // (Hunt v1.4.6, ronda 10, A3-R10-04.) Same class as XamFree: the
  // old code freed any guest-supplied address in the system heap.
  // Only a live region start may be freed.
  if (!GuestSystemHeapRegionStart(dns.guest_address())) {
    return X_STATUS_INVALID_PARAMETER;
  }
  REX_KERNEL_MEMORY()->SystemHeapFree(dns.guest_address());
  return 0;
}

u32 NetDll_XNetQosServiceLookup_entry(u32 caller, u32 flags, u32 event_handle, mapped_u32 pqos) {
  // Set pqos as some games will try accessing it despite non-successful result
  uint32_t result = 0;
  // (Hunt v1.4.6, ronda 10, A3-R10-12.) *pqos is written below with
  // only the NULL check: validate the 4-byte range first.
  if (pqos && !GuestRangeWritable(pqos.guest_address(), sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  if (pqos) {
    auto qos_guest = REX_KERNEL_MEMORY()->SystemHeapAlloc(sizeof(XNQOS));
    // (Hunt v1.4.6, ronda 4, A3-R4-22.) See XNetDnsLookup above: a
    // failed alloc used to fabricate a QoS struct at guest address 0.
    if (!qos_guest) {
      *pqos = 0;
      result = X_STATUS_NO_MEMORY;
    } else {
      auto qos = REX_KERNEL_MEMORY()->TranslateVirtual<XNQOS*>(qos_guest);
      qos->count = qos->count_pending = 0;
      *pqos = qos_guest;
    }
  }
  if (event_handle) {
    auto ev = REX_KERNEL_OBJECTS()->LookupObject<XEvent>(event_handle);
    // (Hunt v1.4.6, ronda 2, A3-R2-02.) Same as NetDll_XNetDnsLookup
    // above: a null event used to SIGSEGV the host on ev->Set.
    if (!ev) {
      return X_ERROR_INVALID_HANDLE;
    }
    ev->Set(0, false);
  }
  return result;
}

u32 NetDll_XNetQosRelease_entry(u32 caller, ppc_ptr_t<XNQOS> qos) {
  if (!qos) {
    return X_STATUS_INVALID_PARAMETER;
  }
  // (Hunt v1.4.6, ronda 10, A3-R10-04.) Same class as
  // XNetDnsRelease above: only a live region start may be freed.
  if (!GuestSystemHeapRegionStart(qos.guest_address())) {
    return X_STATUS_INVALID_PARAMETER;
  }
  REX_KERNEL_MEMORY()->SystemHeapFree(qos.guest_address());
  return 0;
}

u32 NetDll_XNetQosListen_entry(u32 caller, mapped_void id, mapped_void data, u32 data_size, u32 r7,
                               u32 flags) {
  return X_ERROR_FUNCTION_FAILED;
}

u32 NetDll_inet_addr_entry(mapped_string addr_ptr) {
  if (!addr_ptr) {
    return -1;
  }

  // (Hunt v1.4.6, ronda 10, A3-R10-03.) Bounded read: the old code
  // called addr_ptr.value() TWICE (two unbounded NUL scans). Read
  // once, bounded, and reuse the result.
  std::string addr_str;
  if (!ReadGuestCString(addr_ptr.guest_address(), &addr_str)) {
    return -1;
  }
  uint32_t addr = inet_addr(addr_str.c_str());
  // https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-inet_addr#return-value
  // Based on console research it seems like x360 uses old version of inet_addr
  // In case of empty string it return 0 instead of -1
  if (addr == -1 && addr_str.empty()) {
    return 0;
  }

  return rex::byte_swap(addr);
}

u32 NetDll_socket_entry(u32 caller, u32 af, u32 type, u32 protocol) {
  XSocket* socket = new XSocket(REX_KERNEL_STATE());
  X_STATUS result =
      socket->Initialize(XSocket::AddressFamily((uint32_t)af), XSocket::Type((uint32_t)type),
                         XSocket::Protocol((uint32_t)protocol));

  if (XFAILED(result)) {
    socket->Release();

    uint32_t error = xboxkrnl::xeRtlNtStatusToDosError(result);
    XThread::SetLastError(error);
    return -1;
  }

  return socket->handle();
}

u32 NetDll_closesocket_entry(u32 caller, u32 socket_handle) {
  auto socket = REX_KERNEL_OBJECTS()->LookupObject<XSocket>(socket_handle);
  if (!socket) {
    // WSAENOTSOCK
    XThread::SetLastError(0x2736);
    return -1;
  }

  // TODO: Absolutely delete this object. It is no longer valid after calling
  // closesocket.
  socket->Close();
  socket->ReleaseHandle();
  return 0;
}

i32 NetDll_shutdown_entry(u32 caller, u32 socket_handle, i32 how) {
  auto socket = REX_KERNEL_OBJECTS()->LookupObject<XSocket>(socket_handle);
  if (!socket) {
    // WSAENOTSOCK
    XThread::SetLastError(0x2736);
    return -1;
  }

  auto ret = socket->Shutdown(how);
  if (ret == -1) {
#if REX_PLATFORM_WIN32
    uint32_t error_code = WSAGetLastError();
    XThread::SetLastError(error_code);
#else
    XThread::SetLastError(0x0);
#endif
  }
  return ret;
}

u32 NetDll_setsockopt_entry(u32 caller, u32 socket_handle, u32 level, u32 optname,
                            mapped_void optval_ptr, u32 optlen) {
  auto socket = REX_KERNEL_OBJECTS()->LookupObject<XSocket>(socket_handle);
  if (!socket) {
    // WSAENOTSOCK
    XThread::SetLastError(0x2736);
    return -1;
  }

  // (Hunt v1.4.6, ronda 4, segundo barrido, V-A3-02.) The host
  // setsockopt reads optlen bytes from the guest option value; validate
  // the source range first (an optlen of 0 needs no buffer).
  if (optlen && !GuestRangeReadable(optval_ptr.guest_address(), optlen)) {
    // WSAEFAULT
    XThread::SetLastError(0x271E);
    return -1;
  }

  X_STATUS status = socket->SetOption(level, optname, optval_ptr, optlen);
  return XSUCCEEDED(status) ? 0 : -1;
}

u32 NetDll_ioctlsocket_entry(u32 caller, u32 socket_handle, u32 cmd, mapped_void arg_ptr) {
  auto socket = REX_KERNEL_OBJECTS()->LookupObject<XSocket>(socket_handle);
  if (!socket) {
    // WSAENOTSOCK
    XThread::SetLastError(0x2736);
    return -1;
  }

  // (Hunt v1.4.6, caza ronda 6, A3-R6-03.) arg_ptr used to go straight
  // to the host ioctl() with no range check: for FIONBIO/FIONREAD the
  // kernel touches 4 bytes at arg, so an arg_ptr less than 4 bytes from
  // the end of the mapping SIGSEGVs the host inside ioctl(). The
  // commands are Winsock values from the guest (no FIONBIO/FIONREAD
  // constants exist in this tree); every socket ioctl the guest can
  // reach here takes a 4-byte u_long. Unknown commands are rejected
  // rather than passed through with an unvalidated size -- add the
  // command and its arg size to this table first.
  constexpr uint32_t kIoctlFionbio = 0x8004667E;    // FIONBIO
  constexpr uint32_t kIoctlFionread = 0x4004667F;   // FIONREAD
  constexpr uint32_t kIoctlSiocatmark = 0x40047307;  // SIOCATMARK
  uint32_t arg_size = 0;
  switch (cmd) {
    case kIoctlFionbio:
    case kIoctlFionread:
    case kIoctlSiocatmark:
      arg_size = sizeof(uint32_t);
      break;
    default:
      // WSAEINVAL: unknown ioctl command.
      XThread::SetLastError(0x2726);
      return -1;
  }
  // Writable covers both directions: FIONREAD writes the result, FIONBIO
  // reads the flag. A NULL arg is rejected the same way (the kernel
  // would only EFAULT on it, so no working caller loses anything).
  if (!GuestRangeWritable(arg_ptr.guest_address(), arg_size)) {
    // WSAEFAULT
    XThread::SetLastError(0x271E);
    return -1;
  }

  X_STATUS status = socket->IOControl(cmd, arg_ptr);
  if (XFAILED(status)) {
    XThread::SetLastError(xboxkrnl::xeRtlNtStatusToDosError(status));
    return -1;
  }

  // TODO
  return 0;
}

u32 NetDll_bind_entry(u32 caller, u32 socket_handle, ppc_ptr_t<XSOCKADDR_IN> name, u32 namelen) {
  auto socket = REX_KERNEL_OBJECTS()->LookupObject<XSocket>(socket_handle);
  if (!socket) {
    // WSAENOTSOCK
    XThread::SetLastError(0x2736);
    return -1;
  }

  // (Hunt v1.4.6, ronda 3, A3-R3-01.) A NULL name used to crash the
  // host twice over: the N_XSOCKADDR_IN constructor dereferences it,
  // and XSocket::Bind reads name->sin_port. bind with no address is
  // invalid input, not a connected-socket send -- WSAEFAULT.
  if (!name) {
    // WSAEFAULT
    XThread::SetLastError(0x271E);
    return -1;
  }
  // (Hunt v1.4.6, verificación profunda, segundo barrido, V-FE-10.)
  // Same class as FE-05 (recvfrom/sendto): R3-01 above only covered the
  // NULL case, but the N_XSOCKADDR_IN constructor below reads
  // sin_family/sin_port/sin_addr (16 bytes) from the guest struct. A
  // non-NULL name outside the mapping SIGSEGVs the host on that read.
  if (!GuestRangeReadable(name.guest_address(), sizeof(XSOCKADDR_IN))) {
    // WSAEFAULT
    XThread::SetLastError(0x271E);
    return -1;
  }

  N_XSOCKADDR_IN native_name(name);
  X_STATUS status = socket->Bind(&native_name, namelen);
  if (XFAILED(status)) {
    XThread::SetLastError(xboxkrnl::xeRtlNtStatusToDosError(status));
    return -1;
  }

  return 0;
}

u32 NetDll_connect_entry(u32 caller, u32 socket_handle, ppc_ptr_t<XSOCKADDR> name, u32 namelen) {
  auto socket = REX_KERNEL_OBJECTS()->LookupObject<XSocket>(socket_handle);
  if (!socket) {
    // WSAENOTSOCK
    XThread::SetLastError(0x2736);
    return -1;
  }

  // (Hunt v1.4.6, ronda 3, A3-R3-01.) As in bind above: the
  // N_XSOCKADDR constructor dereferences a NULL name. connect with no
  // address is invalid input -- WSAEFAULT.
  if (!name) {
    // WSAEFAULT
    XThread::SetLastError(0x271E);
    return -1;
  }
  // (Hunt v1.4.6, verificación profunda, segundo barrido, V-FE-10.)
  // Same class as FE-05 and bind above: only NULL was covered, but the
  // N_XSOCKADDR constructor below copies address_family + sa_data
  // (16 bytes) from the guest struct. A non-NULL name outside the
  // mapping SIGSEGVs the host on that read.
  if (!GuestRangeReadable(name.guest_address(), sizeof(XSOCKADDR))) {
    // WSAEFAULT
    XThread::SetLastError(0x271E);
    return -1;
  }

  N_XSOCKADDR native_name(name);
  X_STATUS status = socket->Connect(&native_name, namelen);
  if (XFAILED(status)) {
    XThread::SetLastError(xboxkrnl::xeRtlNtStatusToDosError(status));
    return -1;
  }

  return 0;
}

u32 NetDll_listen_entry(u32 caller, u32 socket_handle, i32 backlog) {
  auto socket = REX_KERNEL_OBJECTS()->LookupObject<XSocket>(socket_handle);
  if (!socket) {
    // WSAENOTSOCK
    XThread::SetLastError(0x2736);
    return -1;
  }

  X_STATUS status = socket->Listen(backlog);
  if (XFAILED(status)) {
    XThread::SetLastError(xboxkrnl::xeRtlNtStatusToDosError(status));
    return -1;
  }

  return 0;
}

u32 NetDll_accept_entry(u32 caller, u32 socket_handle, ppc_ptr_t<XSOCKADDR> addr_ptr,
                        mapped_u32 addrlen_ptr) {
  // (Audit A3, ronda 6, R6-06.) addrlen_ptr is read (*addrlen_ptr) and
  // written back, but only addr_ptr was checked; a NULL addrlen_ptr
  // used to read/write guest address 0.
  if (!addr_ptr || !addrlen_ptr) {
    // WSAEFAULT
    XThread::SetLastError(0x271E);
    return -1;
  }
  // (Hunt v1.4.6, verificación profunda, segundo barrido, V-FE-10.)
  // Same class as FE-05 (recvfrom): R6-06 above only covered NULL, but
  // the N_XSOCKADDR constructor below reads 16 bytes from `addr_ptr`,
  // *addrlen_ptr is read for native_len, and on success both are
  // written back (address_family/sa_data + the length). A non-NULL
  // pointer outside the mapping SIGSEGVs the host on the first read.
  if (!GuestRangeReadable(addr_ptr.guest_address(), sizeof(XSOCKADDR)) ||
      !GuestRangeWritable(addr_ptr.guest_address(), sizeof(XSOCKADDR))) {
    // WSAEFAULT
    XThread::SetLastError(0x271E);
    return -1;
  }
  if (!GuestRangeWritable(addrlen_ptr.guest_address(), sizeof(uint32_t))) {
    // WSAEFAULT
    XThread::SetLastError(0x271E);
    return -1;
  }

  auto socket = REX_KERNEL_OBJECTS()->LookupObject<XSocket>(socket_handle);
  if (!socket) {
    // WSAENOTSOCK
    XThread::SetLastError(0x2736);
    return -1;
  }

  N_XSOCKADDR native_addr(addr_ptr);
  int native_len = *addrlen_ptr;
  auto new_socket = socket->Accept(&native_addr, &native_len);
  if (new_socket) {
    addr_ptr->address_family = native_addr.address_family;
    // (Hunt v1.4.6, ronda 3, A3-R3-03.) *addrlen_ptr is guest-controlled:
    // 0 or 1 used to wrap `*addrlen_ptr - 2` to ~4 GiB in the memcpy,
    // and > 16 over-read the 14-byte host sa_data. Copy at most what
    // fits, and only when the guest length holds an address family.
    uint32_t addrlen = static_cast<uint32_t>(*addrlen_ptr);
    if (addrlen >= 2) {
      std::memcpy(addr_ptr->sa_data, native_addr.sa_data,
                  std::min<uint32_t>(addrlen - 2, (uint32_t)sizeof(addr_ptr->sa_data)));
    }
    *addrlen_ptr = native_len;

    return new_socket->handle();
  } else {
    return -1;
  }
}

struct x_fd_set {
  rex::be<uint32_t> fd_count;
  rex::be<uint32_t> fd_array[64];
};

struct host_set {
  uint32_t count;
  object_ref<XSocket> sockets[64];

  void Load(const x_fd_set* guest_set) {
    // (Hunt v1.4.6, ronda 2, A3-R2-01.) fd_count is guest-controlled
    // and assert_true is a no-op in Release, so the old uncapped
    // assignment let a count > 64 overflow sockets[64] on the host
    // stack. Clamp to the array size (same pattern as
    // NetDll___WSAFDIsSet below); an invalid/closed handle resolves
    // to a null socket, which is skipped instead of stored -- Store()
    // and UpdateFrom() dereference every stored socket.
    const uint32_t fd_count = std::min((uint32_t)guest_set->fd_count, uint32_t(64));
    uint32_t stored = 0;
    for (uint32_t i = 0; i < fd_count; ++i) {
      auto socket_handle = static_cast<X_HANDLE>(guest_set->fd_array[i]);
      if (socket_handle == -1) {
        break;
      }
      // Convert from Xenia -> native
      auto socket = REX_KERNEL_OBJECTS()->LookupObject<XSocket>(socket_handle);
      if (!socket) {
        continue;
      }
      this->sockets[stored++] = socket;
    }
    this->count = stored;
  }

  void Store(x_fd_set* guest_set) {
    guest_set->fd_count = 0;
    for (uint32_t i = 0; i < this->count; ++i) {
      auto socket = this->sockets[i];
      guest_set->fd_array[guest_set->fd_count++] = socket->handle();
    }
  }

  void Store(fd_set* native_set) {
    FD_ZERO(native_set);
    for (uint32_t i = 0; i < this->count; ++i) {
      // (Hunt v1.4.6, ronda 3, A3-R3-21.) FD_SET on a host fd >=
      // FD_SETSIZE writes past the stack fd_set (undefined behaviour).
      // Host fds come from socket() and are normally small; skip any
      // that are not representable instead of corrupting the stack.
      uint64_t native_handle = this->sockets[i]->native_handle();
      if (native_handle < (uint64_t)FD_SETSIZE) {
        FD_SET((int)native_handle, native_set);
      }
    }
  }

  void UpdateFrom(fd_set* native_set) {
    uint32_t new_count = 0;
    for (uint32_t i = 0; i < this->count; ++i) {
      auto socket = this->sockets[i];
      // (Hunt v1.4.6, ronda 3, A3-R3-21.) FD_ISSET has the same
      // FD_SETSIZE bound as FD_SET; a skipped fd was never set.
      uint64_t native_handle = socket->native_handle();
      if (native_handle < (uint64_t)FD_SETSIZE && FD_ISSET((int)native_handle, native_set)) {
        this->sockets[new_count++] = socket;
      }
    }
    this->count = new_count;
  }
};

i32 NetDll_select_entry(i32 caller, i32 nfds, ppc_ptr_t<x_fd_set> readfds,
                        ppc_ptr_t<x_fd_set> writefds, ppc_ptr_t<x_fd_set> exceptfds,
                        mapped_void timeout_ptr) {
  // (Hunt v1.4.6, verificación profunda, segundo barrido, V-FE-11.)
  // Same shape as FE-04 (WSASendTo): R2-01 capped fd_count at 64 inside
  // host_set::Load, but the x_fd_set structs themselves (fd_count +
  // 64 entries, 260 bytes) were never range-validated -- Load reads
  // fd_count/fd_array and Store/UpdateFrom write them back -- and the
  // timeout is read as 2 x int32 below. A struct pointer near the end
  // of the mapping SIGSEGVs the host on the first read. Validate each
  // non-NULL set readable AND writable (they are read and written back)
  // and the timeout readable before any Load runs. NULL stays legitimate
  // (no set / no timeout) and is still covered by the `if` checks below.
  auto fd_set_range_ok = [](ppc_ptr_t<x_fd_set> set) {
    return !set || (GuestRangeReadable(set.guest_address(), sizeof(x_fd_set)) &&
                    GuestRangeWritable(set.guest_address(), sizeof(x_fd_set)));
  };
  if (!fd_set_range_ok(readfds) || !fd_set_range_ok(writefds) ||
      !fd_set_range_ok(exceptfds)) {
    return -1;
  }
  if (timeout_ptr &&
      !GuestRangeReadable(timeout_ptr.guest_address(), 2 * sizeof(int32_t))) {
    return -1;
  }
  host_set host_readfds = {};
  fd_set native_readfds = {};
  if (readfds) {
    host_readfds.Load(readfds);
    host_readfds.Store(&native_readfds);
  }
  host_set host_writefds = {};
  fd_set native_writefds = {};
  if (writefds) {
    host_writefds.Load(writefds);
    host_writefds.Store(&native_writefds);
  }
  host_set host_exceptfds = {};
  fd_set native_exceptfds = {};
  if (exceptfds) {
    host_exceptfds.Load(exceptfds);
    host_exceptfds.Store(&native_exceptfds);
  }
  timeval* timeout_in = nullptr;
  timeval timeout;
  if (timeout_ptr) {
    timeout = {static_cast<int32_t>(timeout_ptr.as_array<int32_t>()[0]),
               static_cast<int32_t>(timeout_ptr.as_array<int32_t>()[1])};
    chrono::Clock::ScaleGuestDurationTimeval(reinterpret_cast<int32_t*>(&timeout.tv_sec),
                                             reinterpret_cast<int32_t*>(&timeout.tv_usec));
    timeout_in = &timeout;
  }
  // (Hunt v1.4.6, ronda 3, A3-R3-21.) nfds is guest-controlled and was
  // passed straight to the host select(): out of range is undefined
  // for select() (Linux returns EINVAL, but the contract is not
  // portable). Reject it here with the same -1 the host would give.
  if (nfds < 0 || nfds > FD_SETSIZE) {
    return -1;
  }
  int ret = select(nfds, readfds ? &native_readfds : nullptr, writefds ? &native_writefds : nullptr,
                   exceptfds ? &native_exceptfds : nullptr, timeout_in);
  if (readfds) {
    host_readfds.UpdateFrom(&native_readfds);
    host_readfds.Store(readfds);
  }
  if (writefds) {
    host_writefds.UpdateFrom(&native_writefds);
    host_writefds.Store(writefds);
  }
  if (exceptfds) {
    host_exceptfds.UpdateFrom(&native_exceptfds);
    host_exceptfds.Store(exceptfds);
  }

  // TODO(gibbed): modify ret to be what's actually copied to the guest fd_sets?
  return ret;
}

u32 NetDll_recv_entry(u32 caller, u32 socket_handle, mapped_void buf_ptr, u32 buf_len, u32 flags) {
  auto socket = REX_KERNEL_OBJECTS()->LookupObject<XSocket>(socket_handle);
  if (!socket) {
    // WSAENOTSOCK
    XThread::SetLastError(0x2736);
    return -1;
  }

  // (Hunt v1.4.6, ronda 4, segundo barrido, V-A3-02.) Same class as
  // A3-R4-09 (WSASendTo), on the receive side: the host recv() writes
  // buf_len bytes into a guest buffer that was never range-validated.
  if (!GuestRangeWritable(buf_ptr.guest_address(), buf_len)) {
    // WSAEFAULT
    XThread::SetLastError(0x271E);
    return -1;
  }

  return socket->Recv(buf_ptr, buf_len, flags);
}

u32 NetDll_recvfrom_entry(u32 caller, u32 socket_handle, mapped_void buf_ptr, u32 buf_len,
                          u32 flags, ppc_ptr_t<XSOCKADDR_IN> from_ptr, mapped_u32 fromlen_ptr) {
  auto socket = REX_KERNEL_OBJECTS()->LookupObject<XSocket>(socket_handle);
  if (!socket) {
    // WSAENOTSOCK
    XThread::SetLastError(0x2736);
    return -1;
  }

  // (Hunt v1.4.6, verificación profunda, FE-05.) `buf` is validated
  // below, but the address out-params were read/written unvalidated:
  // `from_ptr` is read here and written back after RecvFrom
  // (sin_family/sin_port/sin_addr + x_sin_zero), and `fromlen_ptr` is
  // read and written back too. A non-NULL pointer outside the mapping
  // SIGSEGVs the host either way. Validate both before their first use;
  // NULL stays legitimate (no address wanted) and is still covered by
  // the `if` checks below.
  if (from_ptr &&
      (!GuestRangeReadable(from_ptr.guest_address(), sizeof(XSOCKADDR_IN)) ||
       !GuestRangeWritable(from_ptr.guest_address(), sizeof(XSOCKADDR_IN)))) {
    // WSAEFAULT
    XThread::SetLastError(0x271E);
    return -1;
  }
  if (fromlen_ptr &&
      !GuestRangeWritable(fromlen_ptr.guest_address(), sizeof(uint32_t))) {
    // WSAEFAULT
    XThread::SetLastError(0x271E);
    return -1;
  }

  N_XSOCKADDR_IN native_from;
  if (from_ptr) {
    native_from = *from_ptr;
  }
  uint32_t native_fromlen = fromlen_ptr ? fromlen_ptr.value() : 0;
  // (Hunt v1.4.6, ronda 4, segundo barrido, V-A3-02.) See recv above.
  if (!GuestRangeWritable(buf_ptr.guest_address(), buf_len)) {
    // WSAEFAULT
    XThread::SetLastError(0x271E);
    return -1;
  }
  int ret =
      socket->RecvFrom(buf_ptr, buf_len, flags, &native_from, fromlen_ptr ? &native_fromlen : 0);

  if (from_ptr) {
    from_ptr->sin_family = native_from.sin_family;
    from_ptr->sin_port = native_from.sin_port;
    from_ptr->sin_addr = native_from.sin_addr;
    std::memset(from_ptr->x_sin_zero, 0, sizeof(from_ptr->x_sin_zero));
  }
  if (fromlen_ptr) {
    *fromlen_ptr = native_fromlen;
  }

  if (ret == -1) {
// TODO: Better way of getting the error code
#if REX_PLATFORM_WIN32
    uint32_t error_code = WSAGetLastError();
    XThread::SetLastError(error_code);
#else
    XThread::SetLastError(0x0);
#endif
  }

  return ret;
}

u32 NetDll_send_entry(u32 caller, u32 socket_handle, mapped_void buf_ptr, u32 buf_len, u32 flags) {
  auto socket = REX_KERNEL_OBJECTS()->LookupObject<XSocket>(socket_handle);
  if (!socket) {
    // WSAENOTSOCK
    XThread::SetLastError(0x2736);
    return -1;
  }

  // (Hunt v1.4.6, ronda 4, segundo barrido, V-A3-02.) Same class as
  // A3-R4-09: the host send() reads buf_len bytes from a guest buffer
  // that was never range-validated.
  if (!GuestRangeReadable(buf_ptr.guest_address(), buf_len)) {
    // WSAEFAULT
    XThread::SetLastError(0x271E);
    return -1;
  }

  return socket->Send(buf_ptr, buf_len, flags);
}

u32 NetDll_sendto_entry(u32 caller, u32 socket_handle, mapped_void buf_ptr, u32 buf_len, u32 flags,
                        ppc_ptr_t<XSOCKADDR_IN> to_ptr, u32 to_len) {
  auto socket = REX_KERNEL_OBJECTS()->LookupObject<XSocket>(socket_handle);
  if (!socket) {
    // WSAENOTSOCK
    XThread::SetLastError(0x2736);
    return -1;
  }

  // (Hunt v1.4.6, verificación profunda, FE-05.) Same class as recvfrom
  // above: `to_ptr` was dereferenced without a range check (only the
  // NULL case was covered by A3-R3-01). A non-NULL pointer outside the
  // mapping SIGSEGVs the host on the read below. NULL stays legitimate
  // (send on the connected socket).
  if (to_ptr && !GuestRangeReadable(to_ptr.guest_address(), sizeof(XSOCKADDR_IN))) {
    // WSAEFAULT
    XThread::SetLastError(0x271E);
    return -1;
  }
  // (Hunt v1.4.6, ronda 3, A3-R3-01.) A NULL destination is legitimate
  // Winsock use (send on the connected socket); XSocket::SendTo
  // already takes a null `to` -- pass it through instead of crashing
  // the host in the N_XSOCKADDR_IN constructor.
  N_XSOCKADDR_IN native_to;
  if (to_ptr) {
    native_to = *to_ptr;
  }
  // (Hunt v1.4.6, ronda 4, segundo barrido, V-A3-02.) See send above.
  if (!GuestRangeReadable(buf_ptr.guest_address(), buf_len)) {
    // WSAEFAULT
    XThread::SetLastError(0x271E);
    return -1;
  }
  return socket->SendTo(buf_ptr, buf_len, flags, to_ptr ? &native_to : nullptr, to_len);
}

u32 NetDll___WSAFDIsSet_entry(u32 socket_handle, ppc_ptr_t<x_fd_set> fd_set) {
  // (Hunt v1.4.6, ronda 3, A3-R3-04.) A NULL fd_set used to be
  // dereferenced for fd_count below. Not a member -> not in the set.
  if (!fd_set) {
    return 0;
  }
  // (Hunt v1.4.6, verificación profunda, segundo barrido, V-FE-11.)
  // Same as select above: only NULL was covered, but fd_count and up to
  // 64 fd_array entries (260 bytes) are read below. A non-NULL fd_set
  // outside the mapping SIGSEGVs the host on the first read.
  if (!GuestRangeReadable(fd_set.guest_address(), sizeof(x_fd_set))) {
    return 0;
  }
  const uint8_t max_fd_count = std::min((uint32_t)fd_set->fd_count, uint32_t(64));
  for (uint8_t i = 0; i < max_fd_count; i++) {
    if (fd_set->fd_array[i] == socket_handle) {
      return 1;
    }
  }
  return 0;
}

void NetDll_WSASetLastError_entry(u32 error_code) {
  XThread::SetLastError(error_code);
}

}  // namespace xam
}  // namespace kernel
}  // namespace rex

REX_EXPORT(__imp__NetDll_XNetStartup, rex::kernel::xam::NetDll_XNetStartup_entry)
REX_EXPORT(__imp__NetDll_XNetCleanup, rex::kernel::xam::NetDll_XNetCleanup_entry)
REX_EXPORT(__imp__NetDll_XNetGetOpt, rex::kernel::xam::NetDll_XNetGetOpt_entry)
REX_EXPORT(__imp__NetDll_XNetRandom, rex::kernel::xam::NetDll_XNetRandom_entry)
REX_EXPORT(__imp__NetDll_WSAStartup, rex::kernel::xam::NetDll_WSAStartup_entry)
REX_EXPORT(__imp__NetDll_WSACleanup, rex::kernel::xam::NetDll_WSACleanup_entry)
REX_EXPORT(__imp__NetDll_WSAGetLastError, rex::kernel::xam::NetDll_WSAGetLastError_entry)
REX_EXPORT(__imp__NetDll_WSARecvFrom, rex::kernel::xam::NetDll_WSARecvFrom_entry)
REX_EXPORT(__imp__NetDll_WSASendTo, rex::kernel::xam::NetDll_WSASendTo_entry)
REX_EXPORT(__imp__NetDll_WSAWaitForMultipleEvents,
           rex::kernel::xam::NetDll_WSAWaitForMultipleEvents_entry)
REX_EXPORT(__imp__NetDll_WSACreateEvent, rex::kernel::xam::NetDll_WSACreateEvent_entry)
REX_EXPORT(__imp__NetDll_WSACloseEvent, rex::kernel::xam::NetDll_WSACloseEvent_entry)
REX_EXPORT(__imp__NetDll_WSAResetEvent, rex::kernel::xam::NetDll_WSAResetEvent_entry)
REX_EXPORT(__imp__NetDll_WSASetEvent, rex::kernel::xam::NetDll_WSASetEvent_entry)
REX_EXPORT(__imp__NetDll_XNetGetTitleXnAddr, rex::kernel::xam::NetDll_XNetGetTitleXnAddr_entry)
REX_EXPORT(__imp__NetDll_XNetGetDebugXnAddr, rex::kernel::xam::NetDll_XNetGetDebugXnAddr_entry)
REX_EXPORT(__imp__NetDll_XNetXnAddrToMachineId,
           rex::kernel::xam::NetDll_XNetXnAddrToMachineId_entry)
REX_EXPORT(__imp__NetDll_XNetInAddrToString, rex::kernel::xam::NetDll_XNetInAddrToString_entry)
REX_EXPORT(__imp__NetDll_XNetXnAddrToInAddr, rex::kernel::xam::NetDll_XNetXnAddrToInAddr_entry)
REX_EXPORT(__imp__NetDll_XNetInAddrToXnAddr, rex::kernel::xam::NetDll_XNetInAddrToXnAddr_entry)
REX_EXPORT(__imp__NetDll_XNetSetSystemLinkPort,
           rex::kernel::xam::NetDll_XNetSetSystemLinkPort_entry)
REX_EXPORT(__imp__NetDll_XNetGetEthernetLinkStatus,
           rex::kernel::xam::NetDll_XNetGetEthernetLinkStatus_entry)
REX_EXPORT(__imp__NetDll_XNetDnsLookup, rex::kernel::xam::NetDll_XNetDnsLookup_entry)
REX_EXPORT(__imp__NetDll_XNetDnsRelease, rex::kernel::xam::NetDll_XNetDnsRelease_entry)
REX_EXPORT(__imp__NetDll_XNetQosServiceLookup, rex::kernel::xam::NetDll_XNetQosServiceLookup_entry)
REX_EXPORT(__imp__NetDll_XNetQosRelease, rex::kernel::xam::NetDll_XNetQosRelease_entry)
REX_EXPORT(__imp__NetDll_XNetQosListen, rex::kernel::xam::NetDll_XNetQosListen_entry)
REX_EXPORT(__imp__NetDll_inet_addr, rex::kernel::xam::NetDll_inet_addr_entry)
REX_EXPORT(__imp__NetDll_socket, rex::kernel::xam::NetDll_socket_entry)
REX_EXPORT(__imp__NetDll_closesocket, rex::kernel::xam::NetDll_closesocket_entry)
REX_EXPORT(__imp__NetDll_shutdown, rex::kernel::xam::NetDll_shutdown_entry)
REX_EXPORT(__imp__NetDll_setsockopt, rex::kernel::xam::NetDll_setsockopt_entry)
REX_EXPORT(__imp__NetDll_ioctlsocket, rex::kernel::xam::NetDll_ioctlsocket_entry)
REX_EXPORT(__imp__NetDll_bind, rex::kernel::xam::NetDll_bind_entry)
REX_EXPORT(__imp__NetDll_connect, rex::kernel::xam::NetDll_connect_entry)
REX_EXPORT(__imp__NetDll_listen, rex::kernel::xam::NetDll_listen_entry)
REX_EXPORT(__imp__NetDll_accept, rex::kernel::xam::NetDll_accept_entry)
REX_EXPORT(__imp__NetDll_select, rex::kernel::xam::NetDll_select_entry)
REX_EXPORT(__imp__NetDll_recv, rex::kernel::xam::NetDll_recv_entry)
REX_EXPORT(__imp__NetDll_recvfrom, rex::kernel::xam::NetDll_recvfrom_entry)
REX_EXPORT(__imp__NetDll_send, rex::kernel::xam::NetDll_send_entry)
REX_EXPORT(__imp__NetDll_sendto, rex::kernel::xam::NetDll_sendto_entry)
REX_EXPORT(__imp__NetDll___WSAFDIsSet, rex::kernel::xam::NetDll___WSAFDIsSet_entry)
REX_EXPORT(__imp__NetDll_WSASetLastError, rex::kernel::xam::NetDll_WSASetLastError_entry)

REX_EXPORT_STUB(__imp__NetDll_UpnpActionCalculateWorkBufferSize);
REX_EXPORT_STUB(__imp__NetDll_UpnpActionCreate);
REX_EXPORT_STUB(__imp__NetDll_UpnpActionGetResults);
REX_EXPORT_STUB(__imp__NetDll_UpnpCleanup);
REX_EXPORT_STUB(__imp__NetDll_UpnpCloseHandle);
REX_EXPORT_STUB(__imp__NetDll_UpnpDescribeCreate);
REX_EXPORT_STUB(__imp__NetDll_UpnpDescribeGetResults);
REX_EXPORT_STUB(__imp__NetDll_UpnpDoWork);
REX_EXPORT_STUB(__imp__NetDll_UpnpEventCreate);
REX_EXPORT_STUB(__imp__NetDll_UpnpEventGetCurrentState);
REX_EXPORT_STUB(__imp__NetDll_UpnpEventUnsubscribe);
REX_EXPORT_STUB(__imp__NetDll_UpnpSearchCreate);
REX_EXPORT_STUB(__imp__NetDll_UpnpSearchGetDevices);
REX_EXPORT_STUB(__imp__NetDll_UpnpStartup);
REX_EXPORT_STUB(__imp__NetDll_WSACancelOverlappedIO);
REX_EXPORT_STUB(__imp__NetDll_WSAEventSelect);
REX_EXPORT_STUB(__imp__NetDll_WSAGetOverlappedResult);
REX_EXPORT_STUB(__imp__NetDll_WSARecv);
REX_EXPORT_STUB(__imp__NetDll_WSASend);
REX_EXPORT_STUB(__imp__NetDll_WSAStartupEx);
REX_EXPORT_STUB(__imp__NetDll_XHttpCloseHandle);
REX_EXPORT_STUB(__imp__NetDll_XHttpConnect);
REX_EXPORT_STUB(__imp__NetDll_XHttpCrackUrl);
REX_EXPORT_STUB(__imp__NetDll_XHttpCrackUrlW);
REX_EXPORT_STUB(__imp__NetDll_XHttpCreateUrl);
REX_EXPORT_STUB(__imp__NetDll_XHttpCreateUrlW);
REX_EXPORT_STUB(__imp__NetDll_XHttpDoWork);
REX_EXPORT_STUB(__imp__NetDll_XHttpGetPerfCounters);
REX_EXPORT_STUB(__imp__NetDll_XHttpOpen);
REX_EXPORT_STUB(__imp__NetDll_XHttpOpenRequest);
REX_EXPORT_STUB(__imp__NetDll_XHttpOpenRequestUsingMemory);
REX_EXPORT_STUB(__imp__NetDll_XHttpQueryAuthSchemes);
REX_EXPORT_STUB(__imp__NetDll_XHttpQueryHeaders);
REX_EXPORT_STUB(__imp__NetDll_XHttpQueryOption);
REX_EXPORT_STUB(__imp__NetDll_XHttpReadData);
REX_EXPORT_STUB(__imp__NetDll_XHttpReceiveResponse);
REX_EXPORT_STUB(__imp__NetDll_XHttpResetPerfCounters);
REX_EXPORT_STUB(__imp__NetDll_XHttpSendRequest);
REX_EXPORT_STUB(__imp__NetDll_XHttpSetCredentials);
REX_EXPORT_STUB(__imp__NetDll_XHttpSetOption);
REX_EXPORT_STUB(__imp__NetDll_XHttpSetStatusCallback);
REX_EXPORT_STUB(__imp__NetDll_XHttpShutdown);
REX_EXPORT_STUB_RETURN(__imp__NetDll_XHttpStartup, 0);
REX_EXPORT_STUB(__imp__NetDll_XHttpWriteData);
REX_EXPORT_STUB(__imp__NetDll_XNetConnect);
REX_EXPORT_STUB(__imp__NetDll_XNetCreateKey);
REX_EXPORT_STUB(__imp__NetDll_XNetDnsReverseLookup);
REX_EXPORT_STUB(__imp__NetDll_XNetDnsReverseRelease);
REX_EXPORT_STUB(__imp__NetDll_XNetGetBroadcastVersionStatus);
REX_EXPORT_STUB(__imp__NetDll_XNetGetConnectStatus);
REX_EXPORT_STUB(__imp__NetDll_XNetGetSystemLinkPort);
REX_EXPORT_STUB(__imp__NetDll_XNetGetXnAddrPlatform);
REX_EXPORT_STUB(__imp__NetDll_XNetInAddrToServer);
REX_EXPORT_STUB(__imp__NetDll_XNetQosGetListenStats);
REX_EXPORT_STUB(__imp__NetDll_XNetQosLookup);
REX_EXPORT_STUB(__imp__NetDll_XNetRegisterKey);
REX_EXPORT_STUB(__imp__NetDll_XNetReplaceKey);
REX_EXPORT_STUB(__imp__NetDll_XNetServerToInAddr);
REX_EXPORT_STUB(__imp__NetDll_XNetSetOpt);
REX_EXPORT_STUB(__imp__NetDll_XNetStartupEx);
REX_EXPORT_STUB(__imp__NetDll_XNetTsAddrToInAddr);
REX_EXPORT_STUB(__imp__NetDll_XNetUnregisterInAddr);
REX_EXPORT_STUB(__imp__NetDll_XNetUnregisterKey);
REX_EXPORT_STUB(__imp__NetDll_XmlDownloadContinue);
REX_EXPORT_STUB(__imp__NetDll_XmlDownloadGetParseTime);
REX_EXPORT_STUB(__imp__NetDll_XmlDownloadGetReceivedDataSize);
REX_EXPORT_STUB(__imp__NetDll_XmlDownloadStart);
REX_EXPORT_STUB(__imp__NetDll_XmlDownloadStop);
REX_EXPORT_STUB(__imp__NetDll_XnpCapture);
REX_EXPORT_STUB(__imp__NetDll_XnpConfig);
REX_EXPORT_STUB(__imp__NetDll_XnpConfigUPnP);
REX_EXPORT_STUB(__imp__NetDll_XnpConfigUPnPPortAndExternalAddr);
REX_EXPORT_STUB(__imp__NetDll_XnpEthernetInterceptRecv);
REX_EXPORT_STUB(__imp__NetDll_XnpEthernetInterceptSetCallbacks);
REX_EXPORT_STUB(__imp__NetDll_XnpEthernetInterceptSetExtendedReceiveCallback);
REX_EXPORT_STUB(__imp__NetDll_XnpEthernetInterceptXmit);
REX_EXPORT_STUB(__imp__NetDll_XnpEthernetInterceptXmitAsIp);
REX_EXPORT_STUB(__imp__NetDll_XnpGetActiveSocketList);
REX_EXPORT_STUB(__imp__NetDll_XnpGetConfigStatus);
REX_EXPORT_STUB(__imp__NetDll_XnpGetKeyList);
REX_EXPORT_STUB(__imp__NetDll_XnpGetQosLookupList);
REX_EXPORT_STUB(__imp__NetDll_XnpGetSecAssocList);
REX_EXPORT_STUB(__imp__NetDll_XnpGetVlanXboxName);
REX_EXPORT_STUB(__imp__NetDll_XnpLoadConfigParams);
REX_EXPORT_STUB(__imp__NetDll_XnpLoadMachineAccount);
REX_EXPORT_STUB(__imp__NetDll_XnpLogonClearChallenge);
REX_EXPORT_STUB(__imp__NetDll_XnpLogonClearQEvent);
REX_EXPORT_STUB(__imp__NetDll_XnpLogonGetChallenge);
REX_EXPORT_STUB(__imp__NetDll_XnpLogonGetQFlags);
REX_EXPORT_STUB(__imp__NetDll_XnpLogonGetQVals);
REX_EXPORT_STUB(__imp__NetDll_XnpLogonGetStatus);
REX_EXPORT_STUB(__imp__NetDll_XnpLogonSetChallengeResponse);
REX_EXPORT_STUB(__imp__NetDll_XnpLogonSetPState);
REX_EXPORT_STUB(__imp__NetDll_XnpLogonSetQEvent);
REX_EXPORT_STUB(__imp__NetDll_XnpLogonSetQFlags);
REX_EXPORT_STUB(__imp__NetDll_XnpLogonSetQVals);
REX_EXPORT_STUB(__imp__NetDll_XnpNoteSystemTime);
REX_EXPORT_STUB(__imp__NetDll_XnpPersistTitleState);
REX_EXPORT_STUB(__imp__NetDll_XnpQosHistoryGetAggregateMeasurement);
REX_EXPORT_STUB(__imp__NetDll_XnpQosHistoryGetEntries);
REX_EXPORT_STUB(__imp__NetDll_XnpQosHistoryLoad);
REX_EXPORT_STUB(__imp__NetDll_XnpQosHistorySaveMeasurements);
REX_EXPORT_STUB(__imp__NetDll_XnpRegisterKeyForCallerType);
REX_EXPORT_STUB(__imp__NetDll_XnpReplaceKeyForCallerType);
REX_EXPORT_STUB(__imp__NetDll_XnpSaveConfigParams);
REX_EXPORT_STUB(__imp__NetDll_XnpSaveMachineAccount);
REX_EXPORT_STUB(__imp__NetDll_XnpSetVlanXboxName);
REX_EXPORT_STUB(__imp__NetDll_XnpToolIpProxyInject);
REX_EXPORT_STUB(__imp__NetDll_XnpToolSetCallbacks);
REX_EXPORT_STUB(__imp__NetDll_XnpUnregisterKeyForCallerType);
REX_EXPORT_STUB(__imp__NetDll_XnpUpdateConfigParams);
REX_EXPORT_STUB(__imp__NetDll_getpeername);
REX_EXPORT_STUB(__imp__NetDll_getsockname);
REX_EXPORT_STUB(__imp__NetDll_getsockopt);

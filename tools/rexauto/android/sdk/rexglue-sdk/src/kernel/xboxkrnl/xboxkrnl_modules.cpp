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

#include <rex/kernel/xboxkrnl/private.h>
#include <rex/logging.h>
#include <rex/hook.h>
#include <rex/thread/mutex.h>
#include <rex/types.h>
#include <rex/system/kernel_state.h>
#include <rex/system/user_module.h>
#include <rex/system/xexception.h>
#include <rex/system/xthread.h>
#include <rex/system/xtypes.h>

namespace rex::kernel::xboxkrnl {
using namespace rex::system;

// (Hunt v1.4.6, ronda 12, A3-R12-01.) This file had no range helper:
// every entry below only NULL-checked its guest pointers, and
// TranslateVirtual never validates or returns null, so a wild
// pointer SIGSEGVd the host. Same heap validation as A3-R4-07
// (xam_app.cpp): reject a range that wraps past 4 GiB, starts or
// ends outside any heap, or spans heaps of different kinds (or
// two physical heaps); inside a single heap require the pages to
// be accessible; across a heap boundary validate both ends
// (A3-R8-13); a range spanning more than two heaps is rejected
// outright (A3-R9-10).
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
  bool end_physical =
      end_heap->heap_type() == rex::memory::HeapType::kGuestPhysical;
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
  auto range_ok = [&](rex::memory::PageAccess access) {
    if (start_physical) {
      return access == rex::memory::PageAccess::kReadWrite;
    }
    return writable ? access == rex::memory::PageAccess::kReadWrite
                    : access != rex::memory::PageAccess::kNoAccess;
  };
  uint32_t start_heap_end = start_heap->heap_base() + start_heap->heap_size() - 1;
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

// (Hunt v1.4.6, ronda 12, A3-R12-01.) Bounded guest C-string read,
// the R10-03 pattern from crt/file.cpp: MappedPtr<char>::value()
// builds a string_view straight off the host pointer -- a strlen to
// NUL with no cap -- so a guest name with no NUL in its page ran the
// host scan into unmapped memory. Read page by page (each chunk
// validated readable first), stop at the first NUL, truncate at 4096
// chars if there is none. Returns false on an invalid range.
// Callers pass a null guest address as "empty" (the MappedPtr<char>
// null convention); that case is handled by the caller, not here.
constexpr size_t kMaxGuestNameChars = 4096;

static bool ReadGuestCString(uint32_t guest_address, std::string* out) {
  out->clear();
  size_t remaining = kMaxGuestNameChars;
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

u32 XexCheckExecutablePrivilege_entry(u32 privilege) {
  REXKRNL_IMPORT_TRACE("XexCheckExecutablePrivilege", "priv={}", (uint32_t)privilege);
  // BOOL
  // DWORD Privilege

  // Privilege is bit position in xe_xex2_system_flags enum - so:
  // Privilege=6 -> 0x00000040 -> XEX_SYSTEM_INSECURE_SOCKETS
  uint32_t mask = 1 << privilege;

  auto module = REX_KERNEL_STATE()->GetExecutableModule();
  if (!module) {
    return 0;
  }

  uint32_t flags = 0;
  module->GetOptHeader<uint32_t>(XEX_HEADER_SYSTEM_FLAGS, &flags);

  return (flags & mask) > 0;
}

u32 XexGetModuleHandle_entry(mapped_string module_name, mapped_u32 hmodule_ptr) {
  // (Audit A3, ronda 6, R6-06.) A NULL hmodule_ptr used to write the
  // handle (or 0, on the not-found path) to guest address 0.
  if (!hmodule_ptr) {
    return X_ERROR_INVALID_PARAMETER;
  }
  // (Hunt v1.4.6, ronda 12, A3-R12-01.) *hmodule_ptr was written
  // with only the null check above (R10-09 class): a wild non-null
  // pointer SIGSEGVd the host on the 4-byte writes below.
  if (!GuestRangeWritable(hmodule_ptr.guest_address(), sizeof(uint32_t))) {
    return X_ERROR_INVALID_PARAMETER;
  }

  object_ref<XModule> module;

  // (Hunt v1.4.6, ronda 12, A3-R12-01.) module_name.value() is an
  // unbounded NUL scan (MappedPtr<char>::value() builds a string_view
  // straight off the host pointer, R10-03 class): a guest name with
  // no NUL in its page ran the host scan into unmapped memory. Read
  // it bounded first. A null name still means the executable module
  // (GetModule("") does the same), matching the old branch.
  std::string module_name_str;
  if (!module_name) {
    module = REX_KERNEL_STATE()->GetExecutableModule();
  } else {
    if (!ReadGuestCString(module_name.guest_address(), &module_name_str)) {
      return X_ERROR_INVALID_PARAMETER;
    }
    module = REX_KERNEL_STATE()->GetModule(module_name_str);
  }

  if (!module) {
    *hmodule_ptr = 0;
    return X_ERROR_NOT_FOUND;
  }

  // NOTE: we don't retain the handle for return.
  *hmodule_ptr = module->hmodule_ptr();

  return X_ERROR_SUCCESS;
}

u32 XexGetModuleSection_entry(mapped_void hmodule, mapped_string name, mapped_u32 data_ptr,
                              mapped_u32 size_ptr) {
  // (Audit A3, ronda 6, R6-06.) NULL data/size pointers used to write
  // the section address/size to guest address 0 on success.
  if (!data_ptr || !size_ptr) {
    return X_STATUS_INVALID_PARAMETER;
  }
  // (Hunt v1.4.6, ronda 12, A3-R12-02.) *data_ptr / *size_ptr were
  // written with only the null check above (R10-09 class): a wild
  // non-null pointer SIGSEGVd the host on the 4-byte writes below.
  if (!GuestRangeWritable(data_ptr.guest_address(), sizeof(uint32_t)) ||
      !GuestRangeWritable(size_ptr.guest_address(), sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }

  X_STATUS result = X_STATUS_SUCCESS;

  auto module = XModule::GetFromHModule(REX_KERNEL_STATE(), hmodule);
  if (module) {
    uint32_t section_data = 0;
    uint32_t section_size = 0;
    // (Hunt v1.4.6, ronda 12, A3-R12-02.) name.value() is an
    // unbounded NUL scan (R10-03 class, see A3-R12-01): read it
    // bounded first. A null name stays an empty lookup, as before.
    std::string name_str;
    if (name && !ReadGuestCString(name.guest_address(), &name_str)) {
      return X_STATUS_INVALID_PARAMETER;
    }
    result = module->GetSection(name_str, &section_data, &section_size);
    if (XSUCCEEDED(result)) {
      *data_ptr = section_data;
      *size_ptr = section_size;
    }
  } else {
    result = X_STATUS_INVALID_HANDLE;
  }

  return result;
}

u32 XexLoadImage_entry(mapped_string module_name, u32 module_flags, u32 min_version,
                       mapped_u32 hmodule_ptr) {
  // (Audit A3, ronda 6, R6-06.) A NULL hmodule_ptr used to write the
  // loaded handle to guest address 0.
  if (!hmodule_ptr) {
    return X_STATUS_INVALID_PARAMETER;
  }
  // (Hunt v1.4.6, ronda 12, A3-R12-03.) *hmodule_ptr was written
  // with only the null check above (R10-09 class): a wild non-null
  // pointer SIGSEGVd the host on the 4-byte write below.
  if (!GuestRangeWritable(hmodule_ptr.guest_address(), sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }

  // (Hunt v1.4.6, ronda 12, A3-R12-03.) module_name.value() is an
  // unbounded NUL scan (R10-03 class, see A3-R12-01), called twice
  // below (GetModule and LoadUserModule). Read it bounded once and
  // reuse it. A null name stays an empty lookup, as before.
  std::string module_name_str;
  if (module_name &&
      !ReadGuestCString(module_name.guest_address(), &module_name_str)) {
    return X_STATUS_NO_SUCH_FILE;
  }

  X_STATUS result = X_STATUS_NO_SUCH_FILE;

  uint32_t hmodule = 0;
  {
    // Lookup + load_count++ must be atomic vs XexUnloadImage to prevent
    // resurrecting a module between the read of hmodule and the increment.
    // The fresh-load path can't share this lock: LoadUserModule runs
    // DllMain ATTACH outside the global lock by design.
    auto lock = rex::thread::global_critical_region::AcquireDirect();
    auto module = REX_KERNEL_STATE()->GetModule(module_name_str);
    if (module) {
      hmodule = module->hmodule_ptr();
      auto ldr_data = REX_KERNEL_MEMORY()->TranslateVirtual<X_LDR_DATA_TABLE_ENTRY*>(hmodule);
      ldr_data->load_count++;
      result = X_STATUS_SUCCESS;
    }
  }

  if (!hmodule) {
    auto user_module = REX_KERNEL_STATE()->LoadUserModule(module_name_str);
    if (user_module) {
      // Released by the last XexUnloadImage call.
      auto user_module_raw = user_module.release();
      hmodule = user_module_raw->hmodule_ptr();
      auto lock = rex::thread::global_critical_region::AcquireDirect();
      auto ldr_data = REX_KERNEL_MEMORY()->TranslateVirtual<X_LDR_DATA_TABLE_ENTRY*>(hmodule);
      ldr_data->load_count++;
      result = X_STATUS_SUCCESS;
    }
  }

  *hmodule_ptr = hmodule;

  return result;
}

u32 XexUnloadImage_entry(mapped_void hmodule) {
  auto module = XModule::GetFromHModule(REX_KERNEL_STATE(), hmodule);
  if (!module) {
    return X_STATUS_INVALID_HANDLE;
  }
  if (module->module_type() == XModule::ModuleType::kKernelModule) {
    return X_STATUS_SUCCESS;
  }

  // Decrement-and-check under the global lock so concurrent unloads can't both
  // observe zero and double-free.
  bool last_ref;
  {
    auto lock = rex::thread::global_critical_region::AcquireDirect();
    auto ldr_data = hmodule.as<X_LDR_DATA_TABLE_ENTRY*>();
    last_ref = (--ldr_data->load_count == 0);
  }

  if (last_ref) {
    module->Release();
    REX_KERNEL_STATE()->UnloadUserModule(
        object_ref<UserModule>(reinterpret_cast<UserModule*>(module.release())));
  }

  return X_STATUS_SUCCESS;
}

u32 XexGetProcedureAddress_entry(mapped_void hmodule, u32 ordinal, mapped_u32 out_function_ptr) {
  // (Audit A3, ronda 6, R6-06.) A NULL out_function_ptr used to write
  // the procedure address (or 0, on the not-found path) to guest
  // address 0.
  if (!out_function_ptr) {
    return X_STATUS_INVALID_PARAMETER;
  }
  // (Hunt v1.4.6, ronda 12, A3-R12-04.) *out_function_ptr was written
  // with only the null check above (R10-09 class): a wild non-null
  // pointer SIGSEGVd the host on the 4-byte writes below.
  if (!GuestRangeWritable(out_function_ptr.guest_address(), sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }

  // May be entry point?
  assert_not_zero(ordinal);

  uint32_t caller_address = 0;
  auto* thread = XThread::GetCurrentThread();
  if (thread && thread->thread_state() && thread->thread_state()->context()) {
    caller_address = static_cast<uint32_t>(thread->thread_state()->context()->lr);
  }

  bool is_string_name = (ordinal & 0xFFFF0000) != 0;
  // (Hunt v1.4.6, ronda 12, A3-R12-04.) When is_string_name, ordinal
  // is a guest address, and GetProcAddressByName(std::string_view)
  // builds the view from the raw pointer with strlen -- an unbounded
  // scan off a wild pointer (R10-03 class). TranslateVirtual never
  // validates, so the scan ran before any lookup. Read the name
  // bounded first; an invalid range fails the lookup.
  std::string string_name;
  if (is_string_name && !ReadGuestCString(ordinal, &string_name)) {
    return X_STATUS_INVALID_PARAMETER;
  }

  X_STATUS result = X_STATUS_INVALID_HANDLE;

  object_ref<XModule> module;
  if (!hmodule) {
    module = REX_KERNEL_STATE()->GetExecutableModule();
  } else {
    module = XModule::GetFromHModule(REX_KERNEL_STATE(), hmodule);
  }
  if (module) {
    uint32_t ptr;
    if (is_string_name) {
      ptr = module->GetProcAddressByName(string_name);
    } else {
      ptr = module->GetProcAddressByOrdinal(ordinal, caller_address);
    }
    if (ptr) {
      *out_function_ptr = ptr;
      result = X_STATUS_SUCCESS;
    } else {
      if (is_string_name) {
        REXKRNL_WARN("ERROR: XexGetProcedureAddress export '{}' in '{}' not found!", string_name,
                     module->name());
      } else {
        REXKRNL_WARN(
            "ERROR: XexGetProcedureAddress ordinal {} (0x{:X}) in '{}' not "
            "found!",
            ordinal, ordinal, module->name());
      }
      *out_function_ptr = 0;
      result = X_STATUS_DRIVER_ENTRYPOINT_NOT_FOUND;
    }
  }

  return result;
}

void ExRegisterTitleTerminateNotification_entry(ppc_ptr_t<X_EX_TITLE_TERMINATE_REGISTRATION> reg,
                                                u32 create) {
  // (Hunt v1.4.6, ronda 12, A3-R12-05.) reg is dereferenced below
  // with no check at all (R10-13 class): a null or wild pointer
  // SIGSEGVd the host on the 16-byte struct read. Validate it first.
  if (!reg || !GuestRangeReadable(reg.guest_address(),
                                 sizeof(X_EX_TITLE_TERMINATE_REGISTRATION))) {
    return;
  }
  if (create) {
    // Adding.
    REX_KERNEL_STATE()->RegisterTitleTerminateNotification(reg->notification_routine,
                                                           reg->priority);
  } else {
    // Removing.
    REX_KERNEL_STATE()->RemoveTitleTerminateNotification(reg->notification_routine);
  }
}

u32 XexLoadImageHeaders_entry(mapped_string path, mapped_void headers) {
  // (Hunt v1.4.6, caza ronda 14, A3-R14-04.) path.value() is an
  // unbounded NUL scan; the DEBUG macro only evaluates its arguments
  // when debug logging is on (the default level is info), so this
  // only crashes the host with debug logging enabled -- but a stub
  // must not SIGSEGV the host for a wild pointer under any log
  // level. Bounded-read the path first and log that instead.
  std::string path_str;
  if (path && !ReadGuestCString(path.guest_address(), &path_str)) {
    REXKRNL_DEBUG("XexLoadImageHeaders(<invalid>) - stub");
    return X_STATUS_NOT_IMPLEMENTED;
  }
  REXKRNL_DEBUG("XexLoadImageHeaders({}) - stub", path_str);
  return X_STATUS_NOT_IMPLEMENTED;
}

}  // namespace rex::kernel::xboxkrnl

REX_EXPORT(__imp__XexCheckExecutablePrivilege,
           rex::kernel::xboxkrnl::XexCheckExecutablePrivilege_entry)
REX_EXPORT(__imp__XexGetModuleHandle, rex::kernel::xboxkrnl::XexGetModuleHandle_entry)
REX_EXPORT(__imp__XexGetModuleSection, rex::kernel::xboxkrnl::XexGetModuleSection_entry)
REX_EXPORT(__imp__XexLoadImage, rex::kernel::xboxkrnl::XexLoadImage_entry)
REX_EXPORT(__imp__XexUnloadImage, rex::kernel::xboxkrnl::XexUnloadImage_entry)
REX_EXPORT(__imp__XexGetProcedureAddress, rex::kernel::xboxkrnl::XexGetProcedureAddress_entry)
REX_EXPORT(__imp__ExRegisterTitleTerminateNotification,
           rex::kernel::xboxkrnl::ExRegisterTitleTerminateNotification_entry)
REX_EXPORT(__imp__XexLoadImageHeaders, rex::kernel::xboxkrnl::XexLoadImageHeaders_entry)

REX_EXPORT_STUB(__imp__XexLoadExecutable);
REX_EXPORT_STUB(__imp__XexLoadImageFromMemory);
REX_EXPORT_STUB(__imp__XexPcToFileHeader);
REX_EXPORT_STUB(__imp__XexRegisterPatchDescriptor);
REX_EXPORT_STUB(__imp__XexSendDeferredNotifications);
REX_EXPORT_STUB(__imp__XexStartExecutable);
REX_EXPORT_STUB(__imp__XexUnloadImageAndExitThread);
REX_EXPORT_STUB(__imp__XexUnloadTitleModules);
REX_EXPORT_STUB(__imp__XexVerifyImageHeaders);
REX_EXPORT_STUB(__imp__XexGetModuleImportVersions);
REX_EXPORT_STUB(__imp__XexActivationGetNonce);
REX_EXPORT_STUB(__imp__XexActivationSetLicense);
REX_EXPORT_STUB(__imp__XexActivationVerifyOwnership);
REX_EXPORT_STUB(__imp__XexDisableVerboseDbgPrint);
REX_EXPORT_STUB(__imp__XexImportTraceEnable);
REX_EXPORT_STUB(__imp__XexSetExecutablePrivilege);
REX_EXPORT_STUB(__imp__XexSetLastKdcTime);
REX_EXPORT_STUB(__imp__XexTransformImageKey);
REX_EXPORT_STUB(__imp__XexShimDisable);
REX_EXPORT_STUB(__imp__XexShimEnable);
REX_EXPORT_STUB(__imp__XexShimEntryDisable);
REX_EXPORT_STUB(__imp__XexShimEntryEnable);
REX_EXPORT_STUB(__imp__XexShimEntryRegister);
REX_EXPORT_STUB(__imp__XexShimLock);
REX_EXPORT_STUB(__imp__XexTitleHash);
REX_EXPORT_STUB(__imp__XexTitleHashClose);
REX_EXPORT_STUB(__imp__XexTitleHashContinue);
REX_EXPORT_STUB(__imp__XexTitleHashOpen);
REX_EXPORT_STUB(__imp__XexReserveCodeBuffer);
REX_EXPORT_STUB(__imp__XexCommitCodeBuffer);
REX_EXPORT_STUB(__imp__XexRegisterUsermodeModule);
REX_EXPORT_STUB(__imp__LDICreateDecompression);
REX_EXPORT_STUB(__imp__LDIDecompress);
REX_EXPORT_STUB(__imp__LDIDestroyDecompression);
REX_EXPORT_STUB(__imp__LDIResetDecompression);

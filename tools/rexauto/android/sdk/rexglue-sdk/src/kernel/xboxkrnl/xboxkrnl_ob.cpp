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

#include <rex/assert.h>
#include <rex/kernel/xboxkrnl/private.h>
#include <rex/logging.h>
#include <rex/hook.h>
#include <rex/types.h>
#include <rex/system/kernel_state.h>
#include <rex/system/util/string_utils.h>
#include <rex/system/xevent.h>
#include <rex/system/xobject.h>
#include <rex/system/xsemaphore.h>
#include <rex/system/xthread.h>
#include <rex/system/xtypes.h>

namespace rex::kernel::xboxkrnl {
using namespace rex::system;

// (Hunt v1.4.6, ronda 8, A3-R8-02.) This file had no range helper:
// every entry below only NULL-checked its guest pointers, and
// TranslateVirtual never validates or returns null, so a wild
// pointer SIGSEGVd the host. Same heap validation as A3-R4-07
// (xam_app.cpp): reject a range that wraps past 4 GiB, starts or
// ends outside any heap, or spans heaps of different kinds (or
// two physical heaps); inside a single heap require the pages to
// be accessible; across a heap boundary validate both ends
// (A3-R8-13).
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

// (Hunt v1.4.6, ronda 8, A3-R8-02.) An X_ANSI_STRING guest struct
// plus the bytes it points at: the 8-byte header first, then
// length bytes at pointer. A NULL pointer or zero length means
// "empty", which TranslateAnsiString* already tolerates.
static bool GuestAnsiStringReadable(uint32_t guest_address) {
  if (!guest_address) {
    return true;
  }
  if (!GuestRangeReadable(guest_address, sizeof(X_ANSI_STRING))) {
    return false;
  }
  auto* ansi = REX_KERNEL_MEMORY()->TranslateVirtual<const X_ANSI_STRING*>(guest_address);
  uint32_t length = ansi->length;
  if (!length) {
    return true;
  }
  uint32_t pointer = ansi->pointer;
  if (!pointer) {
    return false;
  }
  return GuestRangeReadable(pointer, length);
}


u32 ObOpenObjectByName_entry(mapped_void obj_attributes_ptr, mapped_void object_type_ptr, u32 unk,
                             mapped_u32 handle_ptr) {
  // (Audit A3, ronda 6, R6-06.) A NULL handle_ptr used to write the
  // handle to guest address 0 on the success path.
  if (!handle_ptr) {
    return X_STATUS_INVALID_PARAMETER;
  }
  if (!GuestRangeWritable(handle_ptr.guest_address(), sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }

  // r3 = ptr to info?
  //   +0 = -4
  //   +4 = name ptr
  //   +8 = 0
  // r4 = ExEventObjectType | ExSemaphoreObjectType | ExTimerObjectType
  // r5 = 0
  // r6 = out_ptr (handle?)

  if (!obj_attributes_ptr) {
    return X_STATUS_INVALID_PARAMETER;
  }
  // (Hunt v1.4.6, ronda 8, A3-R8-02.) The attributes struct (16 B)
  // and the name string it points at are guest memory: validate
  // both before the first read below.
  if (!GuestRangeReadable(obj_attributes_ptr.guest_address(),
                          sizeof(X_OBJECT_ATTRIBUTES))) {
    return X_STATUS_INVALID_PARAMETER;
  }

  auto obj_attributes = REX_KERNEL_MEMORY()->TranslateVirtual<X_OBJECT_ATTRIBUTES*>(
      obj_attributes_ptr.guest_address());
  assert_true(obj_attributes->name_ptr != 0);
  if (!GuestAnsiStringReadable(obj_attributes->name_ptr)) {
    return X_STATUS_INVALID_PARAMETER;
  }
  auto name = util::TranslateAnsiStringAddress(REX_KERNEL_MEMORY(), obj_attributes->name_ptr);

  X_HANDLE handle = X_INVALID_HANDLE_VALUE;
  X_STATUS result = REX_KERNEL_OBJECTS()->GetObjectByName(name, &handle);
  if (XSUCCEEDED(result)) {
    *handle_ptr = handle;
  }

  return result;
}

u32 ObOpenObjectByPointer_entry(mapped_void object_ptr, mapped_u32 out_handle_ptr) {
  // (Hunt v1.4.6, ronda 8, A3-R8-02.) GetNativeObject reads the
  // 16-byte dispatch header before any type check.
  if (!GuestRangeReadable(object_ptr.guest_address(), sizeof(X_DISPATCH_HEADER))) {
    return X_STATUS_UNSUCCESSFUL;
  }
  auto object = XObject::GetNativeObject<XObject>(REX_KERNEL_STATE(), object_ptr);
  if (!object) {
    return X_STATUS_UNSUCCESSFUL;
  }

  // (Audit A3, ronda 6, R6-06.) Checked before RetainHandle: a NULL
  // out_handle_ptr used to write the handle to guest address 0, and
  // retaining first would have leaked the handle on that path.
  if (!out_handle_ptr) {
    return X_STATUS_INVALID_PARAMETER;
  }

  // Retain the handle. Will be released in NtClose.
  object->RetainHandle();
  *out_handle_ptr = object->handle();
  return X_STATUS_SUCCESS;
}

u32 ObLookupThreadByThreadId_entry(u32 thread_id, mapped_u32 out_object_ptr) {
  auto thread = REX_KERNEL_STATE()->GetThreadByID(thread_id);
  if (!thread) {
    return X_STATUS_NOT_FOUND;
  }

  // (Audit A3, ronda 6, R6-06.) Checked before RetainHandle: a NULL
  // out_object_ptr used to write the object pointer to guest address 0,
  // and retaining first would have leaked the reference on that path.
  if (!out_object_ptr) {
    return X_STATUS_INVALID_PARAMETER;
  }
  if (!GuestRangeWritable(out_object_ptr.guest_address(), sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }

  // Retain the object. Will be released in ObDereferenceObject.
  thread->RetainHandle();
  *out_object_ptr = thread->guest_object();
  return X_STATUS_SUCCESS;
}

u32 ObReferenceObjectByHandle_entry(u32 handle, u32 object_type_ptr, mapped_u32 out_object_ptr) {
  REXKRNL_IMPORT_TRACE("ObReferenceObjectByHandle", "handle={:#x} type={:#x}", (uint32_t)handle,
                       (uint32_t)object_type_ptr);

  object_ref<XObject> object;

  // Handle pseudo-handles.
  uint32_t handle_val = static_cast<uint32_t>(handle);
  if (handle_val == 0xFFFFFFFE) {
    // CurrentThread pseudo-handle.
    auto thread = XThread::GetCurrentThread();
    if (!thread) {
      return X_STATUS_INVALID_HANDLE;
    }
    object = retain_object(static_cast<XObject*>(thread));
  } else {
    object = REX_KERNEL_OBJECTS()->LookupObject<XObject>(handle);
  }

  if (!object) {
    return X_STATUS_INVALID_HANDLE;
  }

  uint32_t native_ptr = object->guest_object();

  // Type check using real KernelGuestGlobals addresses.
  if (object_type_ptr) {
    uint32_t globals_base = REX_KERNEL_STATE()->GetKernelGuestGlobals();
    uint32_t expected_type = 0;
    switch (object->type()) {
      case XObject::Type::Thread:
        expected_type = globals_base + offsetof(KernelGuestGlobals, ExThreadObjectType);
        break;
      case XObject::Type::Event:
        expected_type = globals_base + offsetof(KernelGuestGlobals, ExEventObjectType);
        break;
      case XObject::Type::Mutant:
        expected_type = globals_base + offsetof(KernelGuestGlobals, ExMutantObjectType);
        break;
      case XObject::Type::Semaphore:
        expected_type = globals_base + offsetof(KernelGuestGlobals, ExSemaphoreObjectType);
        break;
      case XObject::Type::Timer:
        expected_type = globals_base + offsetof(KernelGuestGlobals, ExTimerObjectType);
        break;
      default:
        break;
    }
    if (expected_type && object_type_ptr != expected_type) {
      return X_STATUS_OBJECT_TYPE_MISMATCH;
    }
  }

  // Caller takes the reference.
  // It's released in ObDereferenceObject.
  // (Hunt v1.4.6, ronda 3, A3-R3-14.) Checked before RetainHandle: a
  // NULL out_object_ptr used to retain the handle and then skip the
  // write, leaking the reference on a call that still returned
  // SUCCESS. Same order the sibling entries already document.
  if (!out_object_ptr.guest_address()) {
    return X_STATUS_INVALID_PARAMETER;
  }
  // (Hunt v1.4.6, ronda 8, A3-R8-02.) Validated before RetainHandle,
  // so an invalid out-pointer cannot leak the reference.
  if (!GuestRangeWritable(out_object_ptr.guest_address(), sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  object->RetainHandle();
  *out_object_ptr = native_ptr;
  REXKRNL_IMPORT_RESULT("ObReferenceObjectByHandle", "0x0 obj={:#x}", native_ptr);
  return X_STATUS_SUCCESS;
}

u32 ObReferenceObjectByName_entry(mapped_string name, u32 attributes, u32 object_type_ptr,
                                  mapped_void parse_context, mapped_u32 out_object_ptr) {
  X_HANDLE handle = X_INVALID_HANDLE_VALUE;
  X_STATUS result = REX_KERNEL_OBJECTS()->GetObjectByName(name.value(), &handle);
  if (XSUCCEEDED(result)) {
    return ObReferenceObjectByHandle_entry(handle, object_type_ptr, out_object_ptr);
  }

  return result;
}

u32 ObDereferenceObject_entry(u32 native_ptr) {
  REXKRNL_IMPORT_TRACE("ObDereferenceObject", "ptr={:#x}", (uint32_t)native_ptr);
  // Check if a dummy value from ObReferenceObjectByHandle.
  if (native_ptr == 0xDEADF00D) {
    return 0;
  }

  // (Hunt v1.4.6, ronda 8, A3-R8-02.) The u32 is an arbitrary guest
  // address: GetNativeObject reads its 16-byte dispatch header.
  if (!GuestRangeReadable(native_ptr, sizeof(X_DISPATCH_HEADER))) {
    return 0;
  }

  auto object = XObject::GetNativeObject<XObject>(
      REX_KERNEL_STATE(), REX_KERNEL_MEMORY()->TranslateVirtual(native_ptr));
  if (object) {
    object->ReleaseHandle();
  }

  return 0;
}

u32 ObCreateSymbolicLink_entry(ppc_ptr_t<X_ANSI_STRING> path_ptr,
                               ppc_ptr_t<X_ANSI_STRING> target_ptr) {
  // (Hunt v1.4.6, ronda 8, A3-R8-02.) Both ANSI strings (8-byte
  // header + bytes) are read by TranslateAnsiPath below.
  if (!GuestAnsiStringReadable(path_ptr.guest_address()) ||
      !GuestAnsiStringReadable(target_ptr.guest_address())) {
    return X_STATUS_INVALID_PARAMETER;
  }
  auto path = rex::string::utf8_canonicalize_guest_path(
      util::TranslateAnsiPath(REX_KERNEL_MEMORY(), path_ptr));
  auto target = rex::string::utf8_canonicalize_guest_path(
      util::TranslateAnsiPath(REX_KERNEL_MEMORY(), target_ptr));

  if (rex::string::utf8_starts_with(path, u8"\\??\\")) {
    path = path.substr(4);  // Strip the full qualifier
  }

  if (!REX_KERNEL_FS()->RegisterSymbolicLink(path, target)) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

u32 ObDeleteSymbolicLink_entry(ppc_ptr_t<X_ANSI_STRING> path_ptr) {
  // (Hunt v1.4.6, ronda 8, A3-R8-02.) See ObCreateSymbolicLink.
  if (!GuestAnsiStringReadable(path_ptr.guest_address())) {
    return X_STATUS_INVALID_PARAMETER;
  }
  auto path = util::TranslateAnsiPath(REX_KERNEL_MEMORY(), path_ptr);
  if (!REX_KERNEL_FS()->UnregisterSymbolicLink(path)) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

u32 NtDuplicateObject_entry(u32 handle, mapped_u32 new_handle_ptr, u32 options) {
  // (Hunt v1.4.6, ronda 8, A3-R8-02.) new_handle_ptr is written
  // below; fail fast on an invalid pointer (NULL means "just
  // close", and stays allowed -- no handle is duplicated or
  // closed on this path).
  if (new_handle_ptr &&
      !GuestRangeWritable(new_handle_ptr.guest_address(), sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }
  // NOTE: new_handle_ptr can be zero to just close a handle.
  // NOTE: this function seems to be used to get the current thread handle
  //       (passed handle=-2).
  // This function actually just creates a new handle to the same object.
  // Most games use it to get real handles to the current thread or whatever.

  X_HANDLE new_handle = X_INVALID_HANDLE_VALUE;
  X_STATUS result = REX_KERNEL_OBJECTS()->DuplicateHandle(handle, &new_handle);

  if (new_handle_ptr) {
    *new_handle_ptr = new_handle;
  }

  if (options == 1 /* DUPLICATE_CLOSE_SOURCE */) {
    // Always close the source object.
    REX_KERNEL_OBJECTS()->RemoveHandle(handle);
  }

  return result;
}

u32 NtClose_entry(u32 handle) {
  REXKRNL_IMPORT_TRACE("NtClose", "handle={:#x}", (uint32_t)handle);
  auto result = REX_KERNEL_OBJECTS()->ReleaseHandle(handle);
  REXKRNL_IMPORT_RESULT("NtClose", "{:#x}", result);
  return result;
}

u32 NtQueryEvent_entry(u32 handle, mapped_u32 out_struc) {
  // (Hunt v1.4.6, ronda 3, A3-R3-11.) The handle lookup below is
  // guarded but out_struc was not: a NULL out-pointer wrote the event
  // type/state through a null host pointer.
  if (!out_struc) {
    return X_STATUS_INVALID_PARAMETER;
  }
  // (Hunt v1.4.6, ronda 8, A3-R8-02.) 8 bytes are written below.
  if (!GuestRangeWritable(out_struc.guest_address(), 2 * sizeof(uint32_t))) {
    return X_STATUS_INVALID_PARAMETER;
  }

  X_STATUS result = X_STATUS_SUCCESS;

  auto ev = REX_KERNEL_OBJECTS()->LookupObject<XEvent>(handle);
  if (ev) {
    uint32_t type_tmp, state_tmp;
    ev->Query(&type_tmp, &state_tmp);
    out_struc[0] = type_tmp;
    out_struc[1] = state_tmp;
  } else {
    result = X_STATUS_INVALID_HANDLE;
  }

  return result;
}

}  // namespace rex::kernel::xboxkrnl

REX_EXPORT(__imp__ObOpenObjectByName, rex::kernel::xboxkrnl::ObOpenObjectByName_entry)
REX_EXPORT(__imp__ObOpenObjectByPointer, rex::kernel::xboxkrnl::ObOpenObjectByPointer_entry)
REX_EXPORT(__imp__ObLookupThreadByThreadId, rex::kernel::xboxkrnl::ObLookupThreadByThreadId_entry)
REX_EXPORT(__imp__ObReferenceObjectByHandle, rex::kernel::xboxkrnl::ObReferenceObjectByHandle_entry)
REX_EXPORT(__imp__ObReferenceObjectByName, rex::kernel::xboxkrnl::ObReferenceObjectByName_entry)
REX_EXPORT(__imp__ObDereferenceObject, rex::kernel::xboxkrnl::ObDereferenceObject_entry)
REX_EXPORT(__imp__ObCreateSymbolicLink, rex::kernel::xboxkrnl::ObCreateSymbolicLink_entry)
REX_EXPORT(__imp__ObDeleteSymbolicLink, rex::kernel::xboxkrnl::ObDeleteSymbolicLink_entry)
REX_EXPORT(__imp__NtDuplicateObject, rex::kernel::xboxkrnl::NtDuplicateObject_entry)
REX_EXPORT(__imp__NtClose, rex::kernel::xboxkrnl::NtClose_entry)
REX_EXPORT(__imp__NtQueryEvent, rex::kernel::xboxkrnl::NtQueryEvent_entry)

REX_EXPORT_STUB(__imp__ObCreateObject);
// (Audit A3, ronda 6, R6-03.) Was a bare stub: r3 came back as the
// handle argument, a bogus non-NULL "waitable object" pointer.
REX_EXPORT_STUB_RETURN(__imp__ObGetWaitableObject, 0);
REX_EXPORT_STUB(__imp__ObInsertObject);
// (Audit A3, ronda 6, R6-03.) Was a bare stub: r3 came back as the
// object pointer, i.e. a lying BOOL TRUE for any object.
REX_EXPORT_STUB_RETURN(__imp__ObIsTitleObject, 0);
REX_EXPORT_STUB(__imp__ObLookupAnyThreadByThreadId);
REX_EXPORT_STUB(__imp__ObMakeTemporaryObject);
REX_EXPORT_STUB(__imp__ObReferenceObject);
REX_EXPORT_STUB(__imp__ObTranslateSymbolicLink);
REX_EXPORT_STUB(__imp__NtCreateDirectoryObject);
REX_EXPORT_STUB(__imp__NtCreateSymbolicLinkObject);
REX_EXPORT_STUB(__imp__NtMakeTemporaryObject);
REX_EXPORT_STUB(__imp__NtOpenDirectoryObject);
REX_EXPORT_STUB(__imp__NtQueryDirectoryObject);
REX_EXPORT_STUB(__imp__NtQueryIoCompletion);
REX_EXPORT_STUB(__imp__NtQueryMutant);
REX_EXPORT_STUB(__imp__NtQuerySemaphore);
REX_EXPORT_STUB(__imp__NtQueryTimer);

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

#include <array>
#include <cstdio>
#include <cstring>
#include <queue>
#include <string>
#include <vector>

#include <fmt/format.h>

#include <rex/filesystem.h>
#include <rex/filesystem/devices/host_path_device.h>
#include <rex/filesystem/devices/stfs_container_device.h>
#include <rex/logging.h>
#include <rex/string.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xam/content_device.h>
#include <rex/system/xam/content_manager.h>
#include <rex/system/xfile.h>
#include <rex/system/xobject.h>

namespace rex {
namespace system {
namespace xam {

static const char* kThumbnailFileName = "__thumbnail.png";

static const char* kGameUserContentDirName = "profile";

static const char* kGameContentHeaderDirName = "Headers";

static int content_device_id_ = 0;

ContentPackage::ContentPackage(KernelState* kernel_state, const std::string_view root_name,
                               const XCONTENT_AGGREGATE_DATA& data,
                               const std::filesystem::path& package_path)
    : kernel_state_(kernel_state), root_name_(root_name), package_path_(package_path), license_(0) {
  device_path_ = fmt::format("\\Device\\Content\\{0}\\", ++content_device_id_);
  content_data_ = data;

  auto fs = kernel_state_->file_system();
  auto device = std::make_unique<rex::filesystem::HostPathDevice>(device_path_, package_path, false,
                                                                  /*allow_share_delete=*/true);
  // (Hunt v1.4.6, A2-R3-15.) The return value used to be ignored, unlike
  // Runtime::SetupVfs and InstallContent, which both check it:
  // Initialize() leaves root_entry_ null when the path does not exist
  // and the device is read-only, and HostPathDevice::ResolvePath then
  // dereferences it. Do not register a device that failed to initialize
  // (read_only is false today so it effectively always succeeds, but one
  // flag flip or one failed create_directories away from a registered
  // device with a null root). The destructor's unregisters are safe on
  // an unregistered device/symlink (both return false when not found).
  if (!device->Initialize()) {
    REXLOG_ERROR("ContentPackage: failed to initialize device for '{}'", package_path_.string());
    return;
  }
  fs->RegisterDevice(std::move(device));
  fs->RegisterSymbolicLink(root_name_ + ":", device_path_);
  device_registered_ = true;
}

ContentPackage::~ContentPackage() {
  auto fs = kernel_state_->file_system();
  // (Hunt v1.4.6, A2-R4-12.) The losing CreateContent/OpenContent racer
  // is destroyed while the winner's package (same root_name_) is open:
  // RegisterSymbolicLink overwrote this package's link with the winner's
  // target (insert_or_assign), so an unconditional unregister here
  // erased the WINNER's symlink. Only unregister the link when it still
  // points at this package's own device. The device unregister below is
  // already safe (device_path_ is unique per package), and gating both
  // on device_registered_ keeps the old no-op behaviour for a package
  // whose constructor failed before registering anything.
  if (device_registered_) {
    std::string current_target;
    if (fs->FindSymbolicLink(root_name_ + ":", current_target) &&
        rex::string::utf8_equal_case(current_target, device_path_)) {
      fs->UnregisterSymbolicLink(root_name_ + ":");
    }
    fs->UnregisterDevice(device_path_);
  }
}

void ContentPackage::LoadPackageLicenseMask(const std::filesystem::path header_path) {
  std::error_code ec;
  if (!std::filesystem::exists(header_path, ec)) {
    return;
  }

  auto file = rex::filesystem::OpenFile(header_path, "rb");
  if (!file) {
    return;
  }

  // (Hunt v1.4.6, A2-R3-16.) Non-throwing file_size(): on error treat
  // the header as unreadable instead of terminating the process.
  std::error_code size_ec;
  auto file_size = std::filesystem::file_size(header_path, size_ec);
  if (size_ec || file_size < sizeof(XCONTENT_AGGREGATE_DATA) + sizeof(license_)) {
    fclose(file);
    return;
  }

  // R4-F1: fseek/fread used to be unchecked. A failed seek (or a short
  // read on a header truncated between the file_size check above and this
  // read) silently left license_ at whatever fread managed -- a seek
  // failure would even have read the first 4 bytes of the aggregate data
  // as the license. The file_size pre-check makes this near-unreachable,
  // but a failed read must keep the license at 0, not at garbage.
  if (fseek(file, sizeof(XCONTENT_AGGREGATE_DATA), SEEK_SET) != 0 ||
      fread(&license_, 1, sizeof(license_), file) != sizeof(license_)) {
    license_ = 0;
    fclose(file);
    return;
  }
  fclose(file);
}

ContentManager::ContentManager(KernelState* kernel_state, const std::filesystem::path& root_path)
    : kernel_state_(kernel_state), root_path_(root_path) {}

ContentManager::~ContentManager() = default;

std::filesystem::path ContentManager::ResolvePackageRoot(uint64_t xuid, XContentType content_type,
                                                         uint32_t title_id) {
  if (title_id == kCurrentlyRunningTitleId) {
    title_id = kernel_state_->title_id();
  }
  auto xuid_str = fmt::format("{:016X}", xuid);
  auto title_id_str = fmt::format("{:08X}", title_id);
  auto content_type_str = fmt::format("{:08X}", uint32_t(content_type));

  // Package root path:
  // content_root/xuid/title_id/content_type/
  return root_path_ / xuid_str / title_id_str / content_type_str;
}

std::filesystem::path ContentManager::ResolvePackagePath(uint64_t xuid,
                                                         const XCONTENT_AGGREGATE_DATA& data) {
  uint64_t used_xuid = (data.xuid != uint64_t(-1) && data.xuid != 0) ? uint64_t(data.xuid) : xuid;

  // DLCs are stored in common directory
  if (data.content_type == XContentType::kMarketplaceContent) {
    used_xuid = 0;
  }

  // Content path:
  // content_root/xuid/title_id/content_type/data_file_name/
  auto package_root = ResolvePackageRoot(used_xuid, data.content_type, data.title_id);
  return package_root / rex::to_path(data.file_name());
}

std::filesystem::path ContentManager::ResolvePackageHeaderPath(const std::string_view file_name,
                                                               uint64_t xuid, uint32_t title_id,
                                                               XContentType content_type) const {
  if (title_id == kCurrentlyRunningTitleId) {
    title_id = kernel_state_->title_id();
  }

  if (content_type == XContentType::kMarketplaceContent) {
    xuid = 0;
  }

  auto xuid_str = fmt::format("{:016X}", xuid);
  auto title_id_str = fmt::format("{:08X}", title_id);
  auto content_type_str = fmt::format("{:08X}", uint32_t(content_type));
  std::string final_name = std::string(file_name) + ".header";

  // Header root path:
  // content_root/xuid/title_id/Headers/content_type/filename.header
  return root_path_ / xuid_str / title_id_str / kGameContentHeaderDirName / content_type_str /
         final_name;
}

std::vector<XCONTENT_AGGREGATE_DATA> ContentManager::ListContent(uint32_t device_id, uint64_t xuid,
                                                                 XContentType content_type,
                                                                 uint32_t title_id) {
  std::vector<XCONTENT_AGGREGATE_DATA> result;

  if (title_id == kCurrentlyRunningTitleId) {
    title_id = kernel_state_->title_id();
  }

  // Search path:
  // content_root/xuid/title_id/type_name/*
  auto package_root = ResolvePackageRoot(xuid, content_type, title_id);
  auto file_infos = rex::filesystem::ListFiles(package_root);
  for (const auto& file_info : file_infos) {
    if (file_info.type != rex::filesystem::FileInfo::Type::kDirectory) {
      // Directories only.
      continue;
    }

    XCONTENT_AGGREGATE_DATA content_data;
    if (XSUCCEEDED(ReadContentHeaderFile(rex::path_to_utf8(file_info.name), xuid, title_id,
                                         content_type, content_data))) {
      result.emplace_back(std::move(content_data));
    } else if (content_type == XContentType::kMarketplaceContent) {
      // (Ronda 6, auditor E — R6-E6.) A marketplace dir without a readable
      // .header is a phantom, not content: the old fallback listed it
      // anyway (display name = the 40-hex dir name) and OpenContent then
      // succeeded on it with license 0, so the game saw a DLC with no
      // files. Every legitimate DLC install writes its .header
      // (InstallContent), and a headerless dir with its source still
      // present is reinstalled by InstallDlcPackages before the game ever
      // lists content (OnPostSetup) — so skipping it here only hides dirs
      // whose source is gone or whose install never finished, which the
      // game cannot use anyway. Game-created content is never marketplace
      // type, so the fallback below still covers saves and other content
      // the game creates itself (CreateContent writes no .header).
      REXLOG_WARN("ListContent: skipping marketplace dir '{}' with no readable .header",
                  rex::path_to_utf8(file_info.name));
    } else {
      content_data.device_id = device_id;
      content_data.content_type = content_type;
      content_data.set_display_name(rex::path_to_utf16(file_info.name));
      content_data.set_file_name(rex::path_to_utf8(file_info.name));
      content_data.title_id = title_id;
      content_data.xuid = xuid;
      result.emplace_back(std::move(content_data));
    }
  }

  return result;
}

std::unique_ptr<ContentPackage> ContentManager::ResolvePackage(
    const std::string_view root_name, uint64_t xuid, const XCONTENT_AGGREGATE_DATA& data) {
  std::error_code ec;
  auto package_path = ResolvePackagePath(xuid, data);
  if (!std::filesystem::exists(package_path, ec)) {
    return nullptr;
  }
  auto package = std::make_unique<ContentPackage>(kernel_state_, root_name, data, package_path);
  // (Hunt v1.4.6, A2-R3-15.) The device may have failed to initialize
  // (see the ctor): do not hand out a phantom package whose device was
  // never registered. Callers fail honestly instead.
  if (!package->is_open()) {
    return nullptr;
  }
  return package;
}

bool ContentManager::ContentExists(uint64_t xuid, const XCONTENT_AGGREGATE_DATA& data) {
  auto path = ResolvePackagePath(xuid, data);
  std::error_code ec;
  return std::filesystem::exists(path, ec);
}

X_RESULT ContentManager::WriteContentHeaderFile(uint64_t xuid, XCONTENT_AGGREGATE_DATA data,
                                                uint32_t license_mask, uint64_t source_size) {
  if (data.title_id == uint32_t(-1)) {
    data.title_id = kernel_state_->title_id();
  }
  if (data.xuid == uint64_t(-1)) {
    data.xuid = xuid;
  }
  std::error_code ec_r316_3;
  uint64_t used_xuid = (data.xuid != uint64_t(-1) && data.xuid != 0) ? uint64_t(data.xuid) : xuid;

  auto header_path =
      ResolvePackageHeaderPath(data.file_name(), used_xuid, data.title_id, data.content_type);
  auto parent_path = header_path.parent_path();

  if (!std::filesystem::exists(parent_path, ec_r316_3)) {
    std::error_code ec;
    // (Second sweep, V-A2-02.) Same already-exists class as A2-R4-16:
    // create_directories returns false with a clean error_code when the
    // directory already exists (a racing thread created it after the
    // exists() check above) -- that is success, not failure.
    if (!std::filesystem::create_directories(parent_path, ec) && ec) {
      return X_ERROR_ACCESS_DENIED;
    }
  }

  rex::filesystem::CreateEmptyFile(header_path);

  auto file = rex::filesystem::OpenFile(header_path, "wb");
  if (!file) {
    return X_ERROR_FILE_NOT_FOUND;
  }
  // F-round3 (F3-2): both fwrites used to be unchecked. A short .header
  // (disk full, kill mid-write) stayed on disk and still satisfied
  // IsInstalledMarketplaceContent -- which only checks that the file
  // exists -- leaving the DLC "installed" forever with a per-package
  // license of 0 (LoadPackageLicenseMask needs the full data + the 4
  // trailing license bytes, and silently keeps 0 otherwise). Drop the
  // partial header so the next launch re-extracts: the same self-heal
  // as a failed ExtractEntry (no .header, no "installed").
  // R4-F4: when the caller knows the installed package's size
  // (InstallContent), it is appended after the license (8 bytes, native
  // endianness -- the file is only ever read back on this device).
  // IsInstalledMarketplaceContent compares it against the staged file:
  // a DLC updated in place (same content_id, new bytes) used to be
  // skipped forever because the old check only asked "dir + .header
  // exist". The license is written even when 0 in that case, so the
  // layout stays unambiguous: [data][license 4][size 8]. Callers that
  // pass source_size == 0 (game-created content, XamContentCreate) keep
  // the old layout byte-identical, and LoadPackageLicenseMask /
  // ReadContentHeaderFile only read the leading bytes, so the trailing
  // field is invisible to them.
  bool write_ok =
      fwrite(&data, 1, sizeof(XCONTENT_AGGREGATE_DATA), file) ==
      sizeof(XCONTENT_AGGREGATE_DATA);
  if (write_ok && (license_mask != 0 || source_size != 0)) {
    write_ok = fwrite(&license_mask, 1, sizeof(license_mask), file) ==
               sizeof(license_mask);
  }
  if (write_ok && source_size != 0) {
    write_ok = fwrite(&source_size, 1, sizeof(source_size), file) ==
               sizeof(source_size);
  }
  if (!write_ok) {
    fclose(file);
    std::error_code remove_ec;
    std::filesystem::remove(header_path, remove_ec);
    return X_ERROR_ACCESS_DENIED;
  }
  // (Ronda 6, auditor E — R6-E5.) Same fclose() hole as ExtractEntry: the
  // 340-byte header fits in one stdio buffer, so a full disk can pass
  // every fwrite() above and only fail the flush. A short .header would
  // be caught as stale by InstalledHeaderMatchesPackage and re-extracted
  // next launch, so this is belt-and-braces: fail here so no partial
  // header ever lands on disk and the failure surfaces at the point it
  // happened instead of as a mysterious re-extraction.
  if (std::fclose(file) != 0) {
    std::error_code remove_ec;
    std::filesystem::remove(header_path, remove_ec);
    return X_ERROR_ACCESS_DENIED;
  }
  return X_ERROR_SUCCESS;
}

X_RESULT ContentManager::ReadContentHeaderFile(const std::string_view file_name, uint64_t xuid,
                                               uint32_t title_id, XContentType content_type,
                                               XCONTENT_AGGREGATE_DATA& data) const {
  std::error_code ec;
  auto header_file_path = ResolvePackageHeaderPath(file_name, xuid, title_id, content_type);
  constexpr uint32_t header_size = sizeof(XCONTENT_AGGREGATE_DATA);

  if (!std::filesystem::exists(header_file_path, ec)) {
    return X_ERROR_FILE_NOT_FOUND;
  }

  auto file = rex::filesystem::OpenFile(header_file_path, "rb");
  if (!file) {
    return X_ERROR_FILE_NOT_FOUND;
  }

  // (Hunt v1.4.6, A2-R3-16.) Non-throwing file_size(), as above.
  std::error_code size_ec;
  auto file_size = std::filesystem::file_size(header_file_path, size_ec);
  if (size_ec || file_size < header_size) {
    fclose(file);
    return X_ERROR_FILE_NOT_FOUND;
  }

  std::array<uint8_t, header_size> buffer;
  size_t result = fread(buffer.data(), 1, header_size, file);
  fclose(file);

  if (result != header_size) {
    return X_ERROR_FILE_NOT_FOUND;
  }

  std::memcpy(&data, buffer.data(), buffer.size());
  return X_ERROR_SUCCESS;
}

X_RESULT ContentManager::CreateContent(const std::string_view root_name, uint64_t xuid,
                                       const XCONTENT_AGGREGATE_DATA& data) {
  {
    auto global_lock = global_critical_region_.Acquire();
    if (open_packages_.count(string::string_key_case(root_name))) {
      return X_ERROR_ALREADY_EXISTS;
    }
  }
  std::error_code ec_r316_2;

  auto package_path = ResolvePackagePath(xuid, data);
  if (std::filesystem::exists(package_path, ec_r316_2)) {
    return X_ERROR_ALREADY_EXISTS;
  }
  std::error_code ec;
  // (Second sweep, V-A2-02.) Same already-exists class as A2-R4-16:
  // create_directories returns false with a clean error_code when the
  // directory already exists (a racing thread created it after the
  // exists() check above, which already returns ALREADY_EXISTS) -- that
  // is success, not ACCESS_DENIED.
  if (!std::filesystem::create_directories(package_path, ec) && ec) {
    return X_ERROR_ACCESS_DENIED;
  }
  auto package = ResolvePackage(root_name, xuid, data);
  // (Hunt v1.4.6, A2-R3-15.) ResolvePackage returns nullptr when the
  // package device failed to initialize; the old assert_not_null is a
  // no-op in Release and package.release() on a null unique_ptr would
  // have inserted a null package into open_packages_.
  if (!package) {
    return X_ERROR_ACCESS_DENIED;
  }

  {
    auto global_lock = global_critical_region_.Acquire();
    if (open_packages_.count(string::string_key_case(root_name))) {
      return X_ERROR_ALREADY_EXISTS;
    }
    open_packages_.insert({string::string_key_case::create(root_name), package.release()});
  }
  return X_ERROR_SUCCESS;
}

X_RESULT ContentManager::OpenContent(const std::string_view root_name, uint64_t xuid,
                                     const XCONTENT_AGGREGATE_DATA& data,
                                     uint32_t& content_license) {
  {
    auto global_lock = global_critical_region_.Acquire();
    if (open_packages_.count(string::string_key_case(root_name))) {
      return X_ERROR_ALREADY_EXISTS;
    }
  }
  std::error_code ec;

  auto package_path = ResolvePackagePath(xuid, data);
  if (!std::filesystem::exists(package_path, ec)) {
    return X_ERROR_FILE_NOT_FOUND;
  }
  auto package = ResolvePackage(root_name, xuid, data);
  // (Hunt v1.4.6, A2-R3-15.) Same nullptr guard as CreateContent above.
  if (!package) {
    return X_ERROR_ACCESS_DENIED;
  }
  package->LoadPackageLicenseMask(ResolvePackageHeaderPath(
      data.file_name(), xuid, kernel_state_->title_id(), data.content_type));
  content_license = package->GetPackageLicense();

  {
    auto global_lock = global_critical_region_.Acquire();
    if (open_packages_.count(string::string_key_case(root_name))) {
      return X_ERROR_ALREADY_EXISTS;
    }
    open_packages_.insert({string::string_key_case::create(root_name), package.release()});
  }
  return X_ERROR_SUCCESS;
}

X_RESULT ContentManager::CloseContent(const std::string_view root_name) {
  ContentPackage* package = nullptr;
  {
    auto global_lock = global_critical_region_.Acquire();
    // Some games use different casing between Create and Close (e.g. "save" vs "SAVE")
    auto it = open_packages_.find(string::string_key_case(root_name));
    if (it == open_packages_.end()) {
      return X_ERROR_FILE_NOT_FOUND;
    }
    package = DetachPackage(it);
  }
  delete package;
  return X_ERROR_SUCCESS;
}

X_RESULT ContentManager::GetContentThumbnail(uint64_t xuid, const XCONTENT_AGGREGATE_DATA& data,
                                             std::vector<uint8_t>* buffer) {
  std::error_code ec;
  auto global_lock = global_critical_region_.Acquire();
  auto package_path = ResolvePackagePath(xuid, data);
  auto thumb_path = package_path / kThumbnailFileName;
  if (std::filesystem::exists(thumb_path, ec)) {
    // R4-F1: OpenFile is plain fopen and returns nullptr on failure, and
    // this used to dereference it unchecked (fseek(nullptr) -> SIGSEGV).
    // Reachable from the game via XamContentGetThumbnail_entry, e.g. if
    // the file is deleted between the exists() check above and the open,
    // or the process runs out of file descriptors. The fread result was
    // unchecked too, and the size came from an unchecked ftell: a planted
    // multi-GB __thumbnail.png would resize() the buffer to that size
    // (bad_alloc -> terminate). Thumbnails the game writes are small
    // PNGs; cap the read at 16 MiB and fail cleanly above it.
    auto file = rex::filesystem::OpenFile(thumb_path, "rb");
    if (!file) {
      return X_ERROR_FILE_NOT_FOUND;
    }
    constexpr size_t kMaxThumbnailBytes = 16 * 1024 * 1024;
    if (fseek(file, 0, SEEK_END) != 0) {
      fclose(file);
      return X_ERROR_ACCESS_DENIED;
    }
    long file_len_long = ftell(file);
    if (file_len_long < 0 || size_t(file_len_long) > kMaxThumbnailBytes) {
      fclose(file);
      return X_ERROR_ACCESS_DENIED;
    }
    size_t file_len = size_t(file_len_long);
    if (fseek(file, 0, SEEK_SET) != 0) {
      fclose(file);
      return X_ERROR_ACCESS_DENIED;
    }
    buffer->resize(file_len);
    if (file_len != 0 &&
        fread(const_cast<uint8_t*>(buffer->data()), 1, buffer->size(), file) !=
            buffer->size()) {
      buffer->clear();
      fclose(file);
      return X_ERROR_ACCESS_DENIED;
    }
    fclose(file);
    return X_ERROR_SUCCESS;
  } else {
    return X_ERROR_FILE_NOT_FOUND;
  }
}

X_RESULT ContentManager::SetContentThumbnail(uint64_t xuid, const XCONTENT_AGGREGATE_DATA& data,
                                             std::vector<uint8_t> buffer) {
  std::error_code ec_r316_1;
  auto global_lock = global_critical_region_.Acquire();
  auto package_path = ResolvePackagePath(xuid, data);
  std::error_code ec;
  std::filesystem::create_directories(package_path, ec);
  if (std::filesystem::exists(package_path, ec_r316_1)) {
    auto thumb_path = package_path / kThumbnailFileName;
    // R4-F1: same unchecked-OpenFile hole as GetContentThumbnail (fopen
    // returns nullptr; fwrite(nullptr) crashes), reachable from the game
    // via XamContentSetThumbnail_entry, and the fwrite itself was
    // unchecked, so a disk-full thumbnail reported success. Fail loudly
    // instead; the game retries or carries on without a thumbnail.
    auto file = rex::filesystem::OpenFile(thumb_path, "wb");
    if (!file) {
      return X_ERROR_ACCESS_DENIED;
    }
    if (fwrite(buffer.data(), 1, buffer.size(), file) != buffer.size()) {
      fclose(file);
      return X_ERROR_ACCESS_DENIED;
    }
    // (Ronda 8, auditor E — R8-E4.) El ultimo fclose() sin comprobar
    // de este archivo (mismo patron que R6-E5 en ExtractEntry y R7-E5
    // en el restore del thumbnail): en disco lleno el fwrite() va al
    // buffer stdio y solo el fclose() falla, asi que un
    // __thumbnail.png truncado quedaba en disco con SUCCESS devuelto
    // al juego — que cree que su miniatura esta guardada y la vuelve a
    // pedir. Borrar el parcial y fallar en voz alta: el juego
    // reintenta o sigue sin miniatura (el comentario R4-F1 de arriba
    // ya lo dice).
    if (std::fclose(file) != 0) {
      std::error_code remove_ec;
      std::filesystem::remove(thumb_path, remove_ec);
      return X_ERROR_ACCESS_DENIED;
    }
    return X_ERROR_SUCCESS;
  } else {
    return X_ERROR_FILE_NOT_FOUND;
  }
}

X_RESULT ContentManager::DeleteContent(uint64_t xuid, const XCONTENT_AGGREGATE_DATA& data) {
  auto global_lock = global_critical_region_.Acquire();

  if (IsContentOpen(data)) {
    // TODO(Gliniak): Get real error code for this case.
    return X_ERROR_ACCESS_DENIED;
  }

  auto package_path = ResolvePackagePath(xuid, data);
  std::error_code ec;
  auto dir_removed = std::filesystem::remove_all(package_path, ec);
  if (ec) {
    return X_ERROR_ACCESS_DENIED;
  }

  uint64_t used_xuid = (data.xuid != uint64_t(-1) && data.xuid != 0) ? uint64_t(data.xuid) : xuid;
  auto header_path =
      ResolvePackageHeaderPath(data.file_name(), used_xuid, data.title_id, data.content_type);
  std::error_code ec2;
  bool header_removed = std::filesystem::remove(header_path, ec2);

  if (dir_removed > 0 || header_removed) {
    return X_ERROR_SUCCESS;
  }
  return X_ERROR_FILE_NOT_FOUND;
}

X_RESULT ContentManager::UnmountContent(uint64_t xuid, const XCONTENT_AGGREGATE_DATA& data) {
  ContentPackage* package = nullptr;
  {
    auto global_lock = global_critical_region_.Acquire();
    auto it = FindOpenPackageByData(data);
    if (it == open_packages_.end()) {
      return X_ERROR_FILE_NOT_FOUND;
    }
    package = DetachPackage(it);
  }
  delete package;
  return X_ERROR_SUCCESS;
}

X_RESULT ContentManager::UnmountAndDeleteContent(uint64_t xuid,
                                                 const XCONTENT_AGGREGATE_DATA& data) {
  // Unmount phase: tolerant of not-mounted state
  ContentPackage* package = nullptr;
  {
    auto global_lock = global_critical_region_.Acquire();
    auto it = FindOpenPackageByData(data);
    if (it != open_packages_.end()) {
      package = DetachPackage(it);
    }
  }
  delete package;

  // Delete phase: remove package directory and .header file
  auto package_path = ResolvePackagePath(xuid, data);

  uint64_t used_xuid = (data.xuid != uint64_t(-1) && data.xuid != 0) ? uint64_t(data.xuid) : xuid;
  auto header_path =
      ResolvePackageHeaderPath(data.file_name(), used_xuid, data.title_id, data.content_type);

  std::error_code ec;
  auto dir_removed = std::filesystem::remove_all(package_path, ec);
  if (ec) {
    return X_ERROR_ACCESS_DENIED;
  }

  std::error_code ec2;
  bool header_removed = std::filesystem::remove(header_path, ec2);

  if (dir_removed > 0 || header_removed) {
    return X_ERROR_SUCCESS;
  }
  return X_ERROR_FILE_NOT_FOUND;
}

std::filesystem::path ContentManager::ResolveGameUserContentPath() {
  auto title_id = fmt::format("{:08X}", kernel_state_->title_id());
  auto user_name = rex::to_path(kernel_state_->user_profile()->name());

  // Per-game per-profile data location:
  // content_root/title_id/profile/user_name
  return root_path_ / title_id / kGameUserContentDirName / user_name;
}

std::unordered_map<string::string_key_case, ContentPackage*,
                   string::string_key_case::Hash>::iterator
ContentManager::FindOpenPackageByData(const XCONTENT_AGGREGATE_DATA& data) {
  // Resolve kCurrentlyRunningTitleId so both sides compare actual title IDs.
  uint32_t query_title = data.title_id;
  if (query_title == kCurrentlyRunningTitleId) {
    query_title = kernel_state_->title_id();
  }

  for (auto it = open_packages_.begin(); it != open_packages_.end(); ++it) {
    const auto& pkg = it->second->GetPackageContentData();

    uint32_t pkg_title = pkg.title_id;
    if (pkg_title == kCurrentlyRunningTitleId) {
      pkg_title = kernel_state_->title_id();
    }

    // Match on content_type + file_name + resolved title_id.
    // device_id is a virtual storage selector, not a content identifier.
    if (data.content_type == pkg.content_type && data.file_name() == pkg.file_name() &&
        query_title == pkg_title) {
      return it;
    }
  }
  return open_packages_.end();
}

ContentPackage* ContentManager::DetachPackage(
    std::unordered_map<string::string_key_case, ContentPackage*,
                       string::string_key_case::Hash>::iterator it) {
  CloseOpenedFilesFromContent(it->first.view());
  ContentPackage* package = it->second;
  open_packages_.erase(it);
  return package;
}

bool ContentManager::IsContentOpen(const XCONTENT_AGGREGATE_DATA& data) const {
  return std::any_of(open_packages_.cbegin(), open_packages_.cend(), [&data](const auto& content) {
    return data == content.second->GetPackageContentData();
  });
}

std::filesystem::path ContentManager::GetOpenPackagePath(const std::string_view root_name) const {
  auto it = open_packages_.find(string::string_key_case(root_name));
  if (it == open_packages_.end()) {
    return {};
  }
  return it->second->package_path();
}

void ContentManager::CloseOpenedFilesFromContent(const std::string_view root_name) {
  // TODO(Gliniak): Cleanup this code to care only about handles
  // related to provided content
  const std::vector<object_ref<XFile>> all_files_handles =
      kernel_state_->object_table()->GetObjectsByType<XFile>(XObject::Type::File);

  std::string resolved_path = "";
  // (Hunt v1.4.6, A2-R4-08.) The FindSymbolicLink return used to be
  // ignored: when the symlink is not registered, resolved_path stays
  // "" and utf8_starts_with(x, "") is true, so EVERY open XFile in the
  // process got its handle released. Nothing belongs to this content
  // when its symlink is missing -- release nothing.
  if (!kernel_state_->file_system()->FindSymbolicLink(std::string(root_name) + ':', resolved_path)) {
    return;
  }

  for (const object_ref<XFile>& file : all_files_handles) {
    std::string file_path = file->entry()->absolute_path();
    bool is_file_inside_content = rex::string::utf8_starts_with(file_path, resolved_path);

    if (is_file_inside_content) {
      file->ReleaseHandle();
    }
  }
}

static X_RESULT ExtractEntry(rex::filesystem::Entry* entry,
                             const std::filesystem::path& base_path) {
  // F-round3 (F3-1): STFS entry names are raw bytes from the package --
  // ReadSTFS/ReadEntrySVOD never validate them -- so a crafted package can
  // carry "..", a leading separator, or an embedded NUL in a name. The
  // guest path is joined verbatim onto the install dir below, so without
  // this check one entry could write outside the DLC folder (base / ".."
  // climbs out; base / "/abs" replaces base entirely). VFS reads are not
  // affected (Entry::ResolvePath treats ".." as a literal child name and
  // finds nothing). The 7 bundled DLCs and the game package all have
  // plain names (verified by binary parse), so no legitimate package
  // trips this; a rejected entry fails the install loudly and the next
  // launch retries, like any other ExtractEntry failure.
  const std::string fixed_guest_path =
      rex::string::utf8_fix_path_separators(entry->path());
  const std::filesystem::path guest_path = rex::to_path(fixed_guest_path);
  if (guest_path.is_absolute()) {
    return X_ERROR_ACCESS_DENIED;
  }
  for (const auto& part : guest_path) {
    if (part == ".." || part.string().find('\0') != std::string::npos) {
      return X_ERROR_ACCESS_DENIED;
    }
  }
  auto dest_path = base_path / guest_path;

  if (entry->attributes() & rex::filesystem::kFileAttributeDirectory) {
    std::error_code ec;
    std::filesystem::create_directories(dest_path, ec);
    if (ec) {
      return X_ERROR_ACCESS_DENIED;
    }
    return X_ERROR_SUCCESS;
  }

  // Ensure parent directory exists
  std::error_code ec;
  std::filesystem::create_directories(dest_path.parent_path(), ec);

  rex::filesystem::File* in_file = nullptr;
  X_STATUS status = entry->Open(rex::filesystem::FileAccess::kFileReadData, &in_file);
  if (status != X_STATUS_SUCCESS) {
    return X_ERROR_ACCESS_DENIED;
  }

  auto out_file = rex::filesystem::OpenFile(dest_path, "wb");
  if (!out_file) {
    in_file->Destroy();
    return X_ERROR_ACCESS_DENIED;
  }

  constexpr size_t kBufferSize = 4 * 1024 * 1024;  // 4 MiB
  auto buffer = std::make_unique<uint8_t[]>(kBufferSize);
  size_t remaining = entry->size();
  size_t offset = 0;

  while (remaining > 0) {
    size_t bytes_read = 0;
    size_t to_read = std::min(remaining, kBufferSize);
    // Hunt 2 DLC, P1-3 (residual): ReadSync's status was ignored, a short
    // read (bytes_read == 0) silently ended the loop as success, and
    // fwrite's result was ignored too. A truncated file then returned
    // SUCCESS, InstallContent wrote the .header, and the DLC stayed broken
    // forever (IsInstalled only checks dir + .header). Fail loudly instead:
    // no .header is written and the next launch retries the install.
    X_STATUS read_status = in_file->ReadSync(
        std::span<uint8_t>(buffer.get(), to_read), offset, &bytes_read);
    if (read_status != X_STATUS_SUCCESS || bytes_read == 0) {
      fclose(out_file);
      in_file->Destroy();
      return X_ERROR_ACCESS_DENIED;
    }
    if (fwrite(buffer.get(), 1, bytes_read, out_file) != bytes_read) {
      fclose(out_file);
      in_file->Destroy();
      return X_ERROR_ACCESS_DENIED;
    }
    offset += bytes_read;
    remaining -= bytes_read;
  }

  // (Ronda 6, auditor E — R6-E5.) fclose() flushes the stdio buffer: on a
  // full disk fwrite() can succeed into the buffer and only the close
  // fails, so an unchecked close silently ships a truncated file and
  // InstallContent still writes the .header — and IsInstalled only
  // compares the SOURCE package size, never the extracted files, so the
  // broken DLC would stay "installed" forever with no retry. Fail the
  // install instead (no .header): the next launch re-extracts.
  if (std::fclose(out_file) != 0) {
    in_file->Destroy();
    return X_ERROR_ACCESS_DENIED;
  }
  in_file->Destroy();
  return X_ERROR_SUCCESS;
}

X_RESULT ContentManager::InstallContent(const std::filesystem::path& package_path) {
  std::error_code ec;
  if (!std::filesystem::exists(package_path, ec)) {
    return X_ERROR_FILE_NOT_FOUND;
  }

  // Mount the STFS package as a virtual filesystem device
  auto device = std::make_unique<rex::filesystem::StfsContainerDevice>("", package_path);
  if (!device->Initialize()) {
    return X_ERROR_ACCESS_DENIED;
  }

  // Derive install destination:
  // root_path_/0000000000000000/{title_id}/00000002/{filename}/
  auto file_name = rex::path_to_utf8(package_path.filename());

  XCONTENT_AGGREGATE_DATA content_data;
  content_data.device_id = static_cast<uint32_t>(DummyDeviceId::HDD);
  content_data.content_type = XContentType::kMarketplaceContent;
  content_data.title_id = kernel_state_->title_id();
  content_data.xuid = 0;
  content_data.set_file_name(file_name);

  // Read display name from STFS metadata
  auto display_name = device->header().metadata.display_name(rex::system::XLanguage::kEnglish);
  if (!display_name.empty()) {
    content_data.set_display_name(display_name);
  } else {
    content_data.set_display_name(rex::path_to_utf16(package_path.filename()));
  }

  auto install_path = ResolvePackagePath(0, content_data);

  // R4-F4: record the staged package's size so IsInstalled can tell a
  // stale install from a current one (same content_id, new bytes). If the
  // size cannot be stat'ed, fail now: installing without the record would
  // write an old-format .header that IsInstalled treats as stale, and the
  // DLC would re-extract on every launch.
  std::error_code size_ec;
  const uint64_t source_size = std::filesystem::file_size(package_path, size_ec);
  if (size_ec) {
    return X_ERROR_ACCESS_DENIED;
  }

  // R4-F4: a re-install (updated DLC) used to extract over the old files
  // without removing anything, so files the new package no longer ships
  // stayed behind forever. Wipe the destination first: InstallContent
  // only runs when the package is not installed (or is stale), so the
  // old copy is either partial (failed install, no .header) or stale by
  // definition. A failed extraction after the wipe leaves no .header,
  // and the next launch retries from scratch, like any failed install.
  // (Ronda 5, auditor E — R5-F1.) The game writes its own thumbnail
  // into the installed package dir (SetContentThumbnail: <install_path>/
  // __thumbnail.png), and this wipe deletes it on every re-install —
  // including the one-time migration re-extract of all 7 DLCs after
  // updating. The thumbnail is regenerable, but deleting it silently is
  // still data loss; keep it aside and restore it after a successful
  // extraction (only if the new package does not ship one of its own).
  // Also fail loudly if the wipe itself errors: the old code ignored
  // wipe_ec and extracted over leftovers, so a half-deleted directory
  // kept orphaned files while the new .header (written below) marked
  // the install fresh forever. No .header is written on this path, so
  // the next launch retries from scratch.
  std::vector<uint8_t> preserved_thumbnail;
  {
    std::error_code thumb_ec;
    const auto thumb_path = install_path / kThumbnailFileName;
    if (std::filesystem::exists(thumb_path, thumb_ec) && !thumb_ec) {
      auto thumb_file = rex::filesystem::OpenFile(thumb_path, "rb");
      if (thumb_file) {
        // (Hunt v1.4.6, A2-R4-09.) Same 16 MiB cap as GetContentThumbnail
        // in this file: the thumbnail size used to come straight from an
        // uncapped ftell into resize(), so a multi-GB __thumbnail.png
        // threw std::bad_alloc, uncaught, and terminated the install.
        // An oversized (or unreadable) thumbnail is simply not
        // preserved -- it is regenerable, and losing it must not fail
        // the install. A failed seek leaves thumb_size at -1, same path.
        constexpr size_t kMaxThumbnailBytes = 16 * 1024 * 1024;
        long thumb_size = -1;
        if (std::fseek(thumb_file, 0, SEEK_END) == 0) {
          thumb_size = std::ftell(thumb_file);
          std::fseek(thumb_file, 0, SEEK_SET);
        }
        if (thumb_size > 0 && static_cast<size_t>(thumb_size) <= kMaxThumbnailBytes) {
          preserved_thumbnail.resize(static_cast<size_t>(thumb_size));
          if (std::fread(preserved_thumbnail.data(), 1, preserved_thumbnail.size(), thumb_file) !=
              preserved_thumbnail.size()) {
            preserved_thumbnail.clear();
          }
        }
        std::fclose(thumb_file);
      }
    }
  }
  std::error_code wipe_ec;
  std::filesystem::remove_all(install_path, wipe_ec);
  if (wipe_ec) {
    REXLOG_ERROR("InstallContent: failed to wipe stale install at {}: {}", install_path.string(),
                 wipe_ec.message());
    return X_ERROR_ACCESS_DENIED;
  }

  // Create destination directory
  std::filesystem::create_directories(install_path, ec);
  if (ec) {
    return X_ERROR_ACCESS_DENIED;
  }

  // Extract all files breadth-first
  auto* root = device->ResolvePath("");
  if (!root) {
    return X_ERROR_ACCESS_DENIED;
  }

  std::queue<rex::filesystem::Entry*> queue;
  queue.push(root);

  while (!queue.empty()) {
    auto* entry = queue.front();
    queue.pop();

    for (auto& child : entry->children()) {
      queue.push(child.get());
    }

    auto result = ExtractEntry(entry, install_path);
    if (result != X_ERROR_SUCCESS) {
      return result;
    }
  }

  // (Ronda 5, auditor E — R5-F1, continued.) Restore the preserved
  // thumbnail, but only if the new package did not ship one of its own
  // (ExtractEntry above would have written it). Best effort: a failed
  // restore just loses the thumbnail, it must not fail the install.
  if (!preserved_thumbnail.empty()) {
    const auto thumb_path = install_path / kThumbnailFileName;
    std::error_code thumb_ec;
    if (!std::filesystem::exists(thumb_path, thumb_ec) && !thumb_ec) {
      auto thumb_file = rex::filesystem::OpenFile(thumb_path, "wb");
      if (thumb_file) {
        // (Ronda 7, auditor E — R7-E5.) El mismo hueco de escritura sin
        // comprobar que R6-E5 cerró en ExtractEntry y en el .header: en
        // disco lleno el fwrite() puede ir al buffer y solo el fclose()
        // falla, dejando un __thumbnail.png truncado en el dir instalado
        // mientras la instalación sale como éxito. Best effort sigue
        // siendo best effort (un restore fallido no debe fallar la
        // instalación), pero un thumbnail parcial no debe aterrizar en
        // disco: se borra y se sigue sin él.
        const bool thumb_ok =
            std::fwrite(preserved_thumbnail.data(), 1, preserved_thumbnail.size(),
                        thumb_file) == preserved_thumbnail.size();
        if (std::fclose(thumb_file) != 0 || !thumb_ok) {
          std::error_code remove_ec;
          std::filesystem::remove(thumb_path, remove_ec);
        }
      }
    }
  }

  // Compute license mask from STFS header licenses
  uint32_t license_mask = 0;
  for (size_t i = 0; i < 0x10; i++) {
    if (device->header().header.licenses[i].license_flags) {
      license_mask |= device->header().header.licenses[i].license_bits;
    }
  }

  // Write .header file (with the source size, so a later update of this
  // same content_id is detected -- see R4-F4 above).
  return WriteContentHeaderFile(0, content_data, license_mask, source_size);
}

}  // namespace xam
}  // namespace system
}  // namespace rex

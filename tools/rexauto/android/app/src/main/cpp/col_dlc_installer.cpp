// DLC installer for the Child of Light native port (M1, v1.4.2).
//
// Adapts the Skate 3 port's InstallDlcPackages
// (tools/rexauto/ports/skate3/src/skate3_app_common.cpp:1151-1254). The
// differences from Skate 3 are, in order of importance:
//
//  - P1-1: the staged file is named by the STFS header content ID (40
//    uppercase hex digits from offset 0x32C), NOT by the dump filename.
//    InstallContent uses filename() as the installed folder name, so a
//    package staged as "Golem-775B..." would install under that wrong name.
//    The content ID is derived from the header already read for validation.
//  - P0-1b: license_mask is forced to 0xFFFFFFFF before scanning. The game
//    checks bit 0 of the GLOBAL mask before enumerating marketplace content
//    (sub_82A4DD10, recomp/ppc/ppc_recomp.262.cpp:16364); settings.txt
//    already writes the same value, this is defense in depth.
//  - The packages are staged by the Java side (DlcAssets): the full build
//    script injects the 7 STFS files as APK assets assets/dlc/<content_id>
//    and DlcAssets copies them to <user_data>/dlc/ on every launch, so
//    that folder is the normal source. The configured root (col_dlc_root)
//    adds folders for packages dropped in by hand.
//  - The installed-content header lives where the SDK writes it:
//    <user_data>/0000000000000000/<title_id>/Headers/00000002/<name>.header
//    (Skate 3's InstalledMarketplaceHeaderPath), NOT beside the install dir.

#include "col_dlc_installer.h"

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

#include <rex/cvar.h>
#include <rex/filesystem.h>
#include <rex/filesystem/devices/stfs_container_device.h>
#include <rex/logging.h>
#include <rex/runtime.h>
#include <rex/system/flags.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xam/content_manager.h>
#include <rex/system/xcontent.h>

namespace col_dlc {
namespace {

// Feature flag + configurable source root, mirroring Skate 3's
// skate3_auto_install_dlc / skate3_dlc_root. The staging folder
// <user_data>/dlc is always scanned; the root adds extra folders.
REXCVAR_DEFINE_BOOL(col_auto_install_dlc, true, "DLC",
                    "Install DLC packages found in the configured DLC folders");
REXCVAR_DEFINE_STRING(col_dlc_root, "", "DLC",
                      "Extra directory to scan for DLC package files");

constexpr char kDlcDirectoryName[] = "dlc";

std::string Hex8(uint32_t value) {
  std::ostringstream stream;
  stream << std::uppercase << std::hex << std::setw(8) << std::setfill('0')
         << value;
  return stream.str();
}

// The 20-byte content ID from the STFS header (offset 0x32C), as 40
// uppercase hex digits. This is the name the installed folder must carry:
// the filename suffix of a dump is NOT the content ID (hunt 2, P1-1).
std::string ContentIdHex(const rex::filesystem::StfsHeader& header) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string out;
  out.reserve(40);
  for (uint8_t byte : header.header.content_id) {
    out.push_back(kHex[byte >> 4]);
    out.push_back(kHex[byte & 0xF]);
  }
  return out;
}

std::filesystem::path InstalledMarketplaceContentPath(
    const std::filesystem::path& content_root, uint32_t title_id,
    const std::filesystem::path& package_path) {
  return content_root / "0000000000000000" / Hex8(title_id) / "00000002" /
         package_path.filename();
}

std::filesystem::path InstalledMarketplaceHeaderPath(
    const std::filesystem::path& content_root, uint32_t title_id,
    const std::filesystem::path& package_path) {
  return content_root / "0000000000000000" / Hex8(title_id) / "Headers" /
         "00000002" / (package_path.filename().string() + ".header");
}

// R4-F4: the .header written by InstallContent ends with the staged
// package's size (8 bytes after the 4 license bytes; see
// WriteContentHeaderFile). Compare it with the staged file: a DLC updated
// in place -- same content_id, new bytes, which DlcAssets re-copies on the
// Java side because the MD5 changed -- used to be skipped forever here,
// because this check only asked "dir + .header exist" and the installed
// copy stayed stale. A header in the old format (no size field: 328 or
// 332 bytes) is treated as stale, so existing installs re-extract exactly
// once after the update and then carry the size field. Any stat/read
// failure also counts as not installed: the safe direction is to
// re-install, never to trust a header that cannot be checked.
bool InstalledHeaderMatchesPackage(const std::filesystem::path& header_path,
                                   uint64_t staged_size) {
  std::error_code ec;
  const auto header_size = std::filesystem::file_size(header_path, ec);
  if (ec) {
    return false;
  }
  constexpr uint64_t kHeaderSize =
      sizeof(rex::system::XCONTENT_AGGREGATE_DATA) + sizeof(uint32_t) +
      sizeof(uint64_t);
  if (header_size != kHeaderSize) {
    return false;
  }
  auto file = rex::filesystem::OpenFile(header_path, "rb");
  if (!file) {
    return false;
  }
  uint64_t stored_size = 0;
  const long size_offset =
      long(sizeof(rex::system::XCONTENT_AGGREGATE_DATA) + sizeof(uint32_t));
  bool ok = std::fseek(file, size_offset, SEEK_SET) == 0 &&
            std::fread(&stored_size, 1, sizeof(stored_size), file) ==
                sizeof(stored_size);
  std::fclose(file);
  return ok && stored_size == staged_size;
}

// P1-4: InstallContent has no already-installed guard of its own —
// without this, every launch would re-extract every package.
bool IsInstalledMarketplaceContent(const std::filesystem::path& content_root,
                                   uint32_t title_id,
                                   const std::filesystem::path& package_path) {
  // Hunt 4 P1-1: error_code overloads -- the throwing forms would abort
  // the app at startup (uncaught -> std::terminate) on a real stat error.
  std::error_code ec;
  if (!std::filesystem::is_directory(
          InstalledMarketplaceContentPath(content_root, title_id,
                                          package_path),
          ec) ||
      ec) {
    return false;
  }
  const auto header_path = InstalledMarketplaceHeaderPath(
      content_root, title_id, package_path);
  if (!std::filesystem::is_regular_file(header_path, ec) || ec) {
    return false;
  }
  std::error_code size_ec;
  const auto staged_size = std::filesystem::file_size(package_path, size_ec);
  if (size_ec) {
    return false;
  }
  return InstalledHeaderMatchesPackage(header_path, staged_size);
}

// (Ronda 9, auditor E — R9-E1.) Un nombre de fichero/directorio es un
// content ID cuando son exactamente 40 hex en mayusculas (el formato de
// ContentIdHex y del nombre staged de P1-1). Se usa en dos sitios: la
// poda solo borra directorios con ese nombre, y el scan protege la copia
// instalada de una fuente presente pero ilegible cuyo nombre YA es el
// content ID.
bool IsContentIdName(const std::string& name) {
  if (name.size() != 40) {
    return false;
  }
  for (char c : name) {
    if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))) {
      return false;
    }
  }
  return true;
}

// (Ronda 8, auditor E — R8-E2, mitad nativa de la poda R5-F2.)
// Borra los DLCs instalados cuya fuente ya no existe en ninguna
// carpeta de origen. Solo se podan directorios cuyo nombre es un
// content ID (40 hex en mayusculas): cualquier otro nombre (una
// instalacion anterior a P1-1 bajo su nombre de dump, un directorio
// puesto a mano) se deja en paz — ya es invisible para el juego
// (sin .header bajo el nombre de content ID, R6-E6 lo salta) y
// borrar un nombre desconocido podria llevarse datos del usuario.
// Solo pierde ficheros re-derivables de la fuente (el instalado se
// re-extrae si la fuente vuelve) y la miniatura, que el juego
// regenera. Corre solo cuando el scan corrio (auto-install
// activado): con col_auto_install_dlc=false InstallDlcPackages
// retorna antes y no se poda nada. Corre en OnPostSetup, antes de
// LaunchModule, asi que ningun hilo del juego esta leyendo todavia.
// Devuelve cuantos DLCs podo.
size_t PruneInstalledDlcWithoutSource(
    const std::filesystem::path& content_root, uint32_t title_id,
    const std::unordered_set<std::string>& expected) {
  const auto installed_root = content_root / "0000000000000000" / Hex8(title_id) / "00000002";
  std::error_code dir_ec;
  if (!std::filesystem::is_directory(installed_root, dir_ec) || dir_ec) {
    return 0;
  }
  size_t pruned = 0;
  std::error_code iter_ec;
  // (Caza ronda 11, auditor A - R11-A2.) Igual que el scan de arriba:
  // el range-for usa operator++(), que lanza filesystem_error ante un
  // fallo a mitad del recorrido en vez de fijar iter_ec; increment(ec)
  // lo reporta sin lanzar y el break ya existente deja la poda parcial
  // (se reintenta el proximo lanzamiento).
  auto dir_it = std::filesystem::directory_iterator(installed_root, iter_ec);
  const auto dir_end = std::filesystem::directory_iterator();
  for (; dir_it != dir_end; dir_it.increment(iter_ec)) {
    if (iter_ec) {
      break;
    }
    const auto& entry = *dir_it;
    std::error_code entry_ec;
    if (!entry.is_directory(entry_ec) || entry_ec) {
      continue;
    }
    const std::string name = entry.path().filename().string();
    if (!IsContentIdName(name) || expected.count(name) != 0) {
      continue;
    }
    std::error_code remove_ec;
    std::filesystem::remove_all(entry.path(), remove_ec);
    if (remove_ec) {
      REXLOG_WARN("Could not prune installed DLC {} without a source: {}", name,
                  remove_ec.message());
      continue;
    }
    std::error_code header_ec;
    std::filesystem::remove(
        InstalledMarketplaceHeaderPath(content_root, title_id, entry.path()), header_ec);
    if (header_ec) {
      // (Ronda 9, auditor E — R9-E2.) El borrado del .header se
      // ignoraba: la poda se contaba y se logueaba como hecha aunque
      // el .header siguiera en disco. El dir ya no existe, asi que el
      // juego no lista el DLC (ListContent enumera directorios, R6-E6)
      // y el .header huerfano es inerte — pero queda para siempre,
      // porque el proximo lanzamiento ya no ve el dir y no reintenta
      // borrarlo. Que al menos quede en el log en voz alta.
      REXLOG_WARN("Pruned installed DLC {} but could not remove its .header: {}",
                  name, header_ec.message());
    }
    REXLOG_INFO("Pruned installed DLC {} (its source package is gone)", name);
    ++pruned;
  }
  return pruned;
}

std::vector<std::filesystem::path> DiscoverDlcSourceDirectories(
    const std::filesystem::path& executable_root,
    const std::filesystem::path& game_data_root,
    const std::filesystem::path& user_data_root) {
  std::vector<std::filesystem::path> dirs;
  auto add_dir = [&](std::filesystem::path dir) {
    if (dir.empty()) {
      return;
    }
    std::error_code ec;
    dir = std::filesystem::absolute(dir, ec);
    if (ec) {
      return;
    }
    for (const auto& existing : dirs) {
      if (std::filesystem::equivalent(existing, dir, ec)) {
        return;
      }
      ec.clear();
    }
    dirs.push_back(std::move(dir));
  };

  const std::string configured_root = REXCVAR_GET(col_dlc_root);
  if (!configured_root.empty()) {
    add_dir(configured_root);
  }
  add_dir(executable_root / std::string(kDlcDirectoryName));
  add_dir(game_data_root / std::string(kDlcDirectoryName));
  add_dir(user_data_root / std::string(kDlcDirectoryName));
  return dirs;
}

}  // namespace

void InstallDlcPackages(rex::Runtime* runtime) {
  if (!runtime || !runtime->kernel_state() ||
      !runtime->kernel_state()->content_manager()) {
    return;
  }

  // P0-1b (defense in depth): the game checks bit 0 of the GLOBAL license
  // mask before it enumerates marketplace content, and settings.txt already
  // writes license_mask=4294967295. Set it here too so the DLCs are accepted
  // even if the settings line is ever lost. Set unconditionally (not only
  // when a package installs): already-installed DLCs are enumerated by the
  // game on later launches too.
  // F-round3 (F3-3): this used to sit below the col_auto_install_dlc
  // early-return, which left a hole: auto-install off AND the settings.txt
  // line ever lost meant mask 0 and already-installed DLCs invisible to
  // the game. The set is now before that check (still after the null
  // checks above). Setting it when nothing is installed changes nothing:
  // the game enumerates zero packages, exactly like settings.txt does
  // today on every launch.
  REXCVAR_SET(license_mask, 0xFFFFFFFF);

  if (!REXCVAR_GET(col_auto_install_dlc)) {
    return;
  }

  const uint32_t title_id = runtime->kernel_state()->title_id();
  if (title_id == 0) {
    REXLOG_WARN("Skipping DLC install; title ID is not available");
    return;
  }

  // (Ronda 9, auditor A - R9-A2.) La poda de R8-E2 trata "content ID
  // no esta en el set esperado" como "su fuente ya no existe". Eso solo
  // es verdad si el scan COMPLETO. El caso "fuente presente pero con
  // cabecera ilegible" ya lo cubre R9-E1 (mete el nombre en el set
  // esperado); lo que queda sin cubrir es un scan INCOMPLETO: un error
  // de iteracion a mitad del recorrido (o al construir el iterador) o
  // un drop folder que no se pudo crear dejan carpetas enteras fuera
  // del set, y la poda borraria DLCs instalados cuya fuente SIGUE en
  // disco. Con el scan incompleto la poda se salta este lanzamiento y
  // se reintenta en el siguiente; en builds FULL el staged se repone
  // desde los assets, y un DLC puesto a mano no se pierde por un error
  // transitorio de lectura.
  bool scan_complete = true;
  const std::filesystem::path user_dlc_root =
      runtime->user_data_root() / std::string(kDlcDirectoryName);
  std::error_code create_ec;
  std::filesystem::create_directories(user_dlc_root, create_ec);
  if (create_ec) {
    REXLOG_WARN("Could not create DLC drop folder {}: {}",
                user_dlc_root.string(), create_ec.message());
    scan_complete = false;
  }

  const auto source_dirs = DiscoverDlcSourceDirectories(
      rex::filesystem::GetExecutableFolder(), runtime->game_data_root(),
      runtime->user_data_root());
  // (Caza ronda 11, auditor A - R11-A2.) Si la lista sale vacia (todas
  // las add_dir fallaron: absolute() solo falla si current_path()
  // falla), el set esperado quedaria vacio y la poda borraria TODOS los
  // DLCs instalados con scan_complete=true. No hay fuentes que escanear,
  // asi que el scan esta incompleto por definicion: saltar la poda.
  if (source_dirs.empty()) {
    scan_complete = false;
  }
  std::unordered_set<std::string> seen_packages;
  // (Ronda 8, auditor E — R8-E2.) El set esperado para la poda de
  // abajo: content IDs de los paquetes marketplace validos para este
  // titulo encontrados en las fuentes de ESTE lanzamiento. Un DLC
  // instalado cuyo content ID no esta aqui es que su fuente ya no
  // existe (quitado del build — la mitad Java borro su staged — o
  // borrado a mano por el usuario).
  std::unordered_set<std::string> expected_content_ids;
  size_t installed_count = 0;
  size_t skipped_count = 0;

  for (const auto& source_dir : source_dirs) {
    std::error_code dir_ec;
    if (!std::filesystem::is_directory(source_dir, dir_ec) || dir_ec) {
      // (Caza ronda 10, auditor A - R10-A2.) R9-A2 no cubria esta salida:
      // una carpeta de origen que EXISTE pero no se puede leer (EACCES,
      // EIO) se saltaba en silencio y sus paquetes nunca llegaban al set
      // esperado, asi que la poda borraba sus copias instaladas. Una
      // carpeta que FALTA (ENOENT) o un camino que no es directorio
      // (ENOTDIR) es normal -- esas carpetas no tienen fuentes -- y NO
      // debe marcar el scan: un is_directory() sobre una carpeta que
      // falta fija ec a ENOENT (verificado contra libstdc++), asi que
      // marcarlo desactivaria la poda en casi cada lanzamiento. Solo un
      // error real de stat marca el scan incompleto.
      if (dir_ec && dir_ec != std::errc::no_such_file_or_directory &&
          dir_ec != std::errc::not_a_directory) {
        REXLOG_WARN("Could not access DLC source directory {}: {}",
                    source_dir.string(), dir_ec.message());
        scan_complete = false;
      }
      continue;
    }

    std::error_code iter_ec;
    // (Caza ronda 11, auditor A - R11-A2.) El range-for usa
    // operator++(), que LANZA filesystem_error ante un fallo a mitad
    // del recorrido (subcarpeta ilegible EACCES, borrada a mitad del
    // scan ENOENT, EIO) en vez de fijar iter_ec: el check post-bucle
    // de R9-A2 nunca lo veia y la excepcion abortaba todo
    // InstallDlcPackages (OnPostSetup la caza y sigue sin DLCs, pero
    // sin instalar nada este lanzamiento). increment(iter_ec) es
    // noexcept y reporta en iter_ec (verificado contra libstdc++; el
    // estandar exige lo mismo de operator++ / increment en libc++):
    // el check post-bucle ya existente marca el scan incompleto y el
    // bucle exterior sigue con la siguiente carpeta.
    auto dir_it =
        std::filesystem::recursive_directory_iterator(source_dir, iter_ec);
    const auto dir_end = std::filesystem::recursive_directory_iterator();
    for (; dir_it != dir_end; dir_it.increment(iter_ec)) {
      if (iter_ec) {
        REXLOG_WARN("Could not scan DLC folder {}: {}", source_dir.string(),
                    iter_ec.message());
        break;
      }
      const auto& entry = *dir_it;
      std::error_code entry_ec;
      if (!entry.is_regular_file(entry_ec) || entry_ec) {
        // (Caza ronda 10, auditor A - R10-A2.) Misma salida un nivel mas
        // abajo: una entrada cuyo stat falla (fichero ilegible, bucle de
        // symlinks) nunca llega a ReadPackageHeader, asi que su content
        // ID nunca llega al set esperado. Un symlink roto o un fichero
        // borrado a mitad del scan (ENOENT) NO se marca: su fuente ya no
        // existe, y marcarlo desactivaria la poda en cada lanzamiento
        // mientras el symlink siga ahi.
        if (entry_ec && entry_ec != std::errc::no_such_file_or_directory) {
          REXLOG_WARN("Could not stat DLC entry {}: {}",
                      entry.path().string(), entry_ec.message());
          scan_complete = false;
        }
        continue;
      }

      const auto package_path = entry.path();
      // Hunt 4 P2-1: never scan our own staging leftovers -- a .tmp is a
      // byte prefix of its package, so its header reads as valid.
      if (package_path.extension() == ".tmp") {
        continue;
      }
      std::error_code canonical_ec;
      auto package_key =
          std::filesystem::weakly_canonical(package_path, canonical_ec)
              .string();
      if (canonical_ec) {
        std::error_code abs_ec;
      auto abs_path = std::filesystem::absolute(package_path, abs_ec);
      package_key = abs_ec ? package_path.string() : abs_path.string();
      }
      if (!seen_packages.insert(package_key).second) {
        continue;
      }

      const auto header =
          rex::filesystem::StfsContainerDevice::ReadPackageHeader(
              package_path);
      if (!header) {
        // (Ronda 9, auditor E — R9-E1.) Una fuente PRESENTE pero
        // ilegible no es una fuente AUSENTE: antes de R8-E2 la copia
        // instalada sobrevivía a un staged corrupto/truncado (el scan
        // solo lo saltaba), pero la poda la borra porque su content ID
        // no entra en el set esperado. Si el nombre del fichero YA es
        // el content ID (el caso staged de P1-1: DlcAssets nombra por
        // content ID), proteger la copia instalada metiéndolo en el set
        // esperado: la fuente sigue ahí y la copia buena es la única
        // que queda. Con un nombre de dump no se puede saber a qué
        // content ID pertenece sin la cabecera, así que ahí no hay
        // nada que proteger (limitación documentada).
        if (IsContentIdName(package_path.filename().string())) {
          expected_content_ids.insert(package_path.filename().string());
          REXLOG_WARN(
              "Skipping DLC candidate with invalid STFS header (keeping its installed copy): {}",
              package_path.string());
        } else {
          REXLOG_WARN("Skipping DLC candidate with invalid STFS header: {}",
                      package_path.string());
        }
        ++skipped_count;
        continue;
      }

      // (Ronda 9, auditor E — R9-E1.) El content ID entra en el set
      // esperado en cuanto la cabecera se lee, ANTES de los filtros de
      // tipo/título: una fuente presente pero no instalable en este
      // lanzamiento (tipo no-marketplace, título distinto) sigue siendo
      // una fuente presente, y su copia instalada no debe podarse por
      // un filtro. Mismo content ID = mismo paquete, así que protegerlo
      // no esconde ningún DLC ajeno.
      const std::string content_id = ContentIdHex(*header);
      expected_content_ids.insert(content_id);
      const auto content_type =
          static_cast<rex::system::XContentType>(header->metadata.content_type);
      if (content_type != rex::system::XContentType::kMarketplaceContent) {
        REXLOG_WARN("Skipping non-DLC content package {} with type {:08X}",
                    package_path.filename().string(),
                    static_cast<uint32_t>(content_type));
        ++skipped_count;
        continue;
      }

      const uint32_t package_title_id =
          header->metadata.execution_info.title_id;
      if (package_title_id != 0 && package_title_id != title_id) {
        REXLOG_WARN("Skipping DLC package {} for title {:08X}; running title is {:08X}",
                    package_path.filename().string(), package_title_id,
                    title_id);
        ++skipped_count;
        continue;
      }

      // P1-1: InstallContent uses filename() as the installed folder name,
      // so the staged file must be named by the STFS header content ID (40
      // uppercase hex), not by whatever the dump file was called. Copy
      // (never rename: the source may be a package the user dropped in).
      // The Java staging already names files by content ID, so this copy
      // only triggers for hand-dropped packages.
      // Hunt 3, P2-1: the copy is atomic and verified. A launch killed
      // mid-copy used to leave a partial <content_id> behind, and the old
      // is_regular_file() check then kept it forever (every later launch
      // failed the same install). Now: copy to <content_id>.tmp, check
      // the size against the source, then rename. A staged file whose
      // size differs from the source is re-copied the same way.
      std::filesystem::path staged_path = package_path;
      if (package_path.filename().string() != content_id) {
        staged_path = package_path.parent_path() / content_id;
        std::error_code size_ec;
        const auto source_size =
            std::filesystem::file_size(package_path, size_ec);
        if (size_ec) {
          REXLOG_WARN("Could not stat DLC package {}: {}",
                      package_path.string(), size_ec.message());
          ++skipped_count;
          continue;
        }
        std::error_code staged_size_ec;
        const bool staged_ok =
            std::filesystem::is_regular_file(staged_path, staged_size_ec) &&
            !staged_size_ec &&
            std::filesystem::file_size(staged_path, staged_size_ec) ==
                source_size;
        if (!staged_ok) {
          const auto tmp_path =
              package_path.parent_path() / (content_id + ".tmp");
          std::error_code copy_ec;
          std::filesystem::copy_file(
              package_path, tmp_path,
              std::filesystem::copy_options::overwrite_existing, copy_ec);
          if (copy_ec) {
            std::error_code remove_ec;
            std::filesystem::remove(tmp_path, remove_ec);
            REXLOG_WARN("Could not stage DLC package {} as {}: {}",
                        package_path.string(), content_id,
                        copy_ec.message());
            ++skipped_count;
            continue;
          }
          std::error_code tmp_size_ec;
          if (std::filesystem::file_size(tmp_path, tmp_size_ec) !=
              source_size) {
            std::error_code remove_ec;
            std::filesystem::remove(tmp_path, remove_ec);
            REXLOG_WARN(
                "Staged DLC package {} has the wrong size after copy; will retry next launch",
                content_id);
            ++skipped_count;
            continue;
          }
          std::error_code rename_ec;
          std::filesystem::rename(tmp_path, staged_path, rename_ec);
          if (rename_ec) {
            std::error_code remove_ec;
            std::filesystem::remove(tmp_path, remove_ec);
            REXLOG_WARN("Could not stage DLC package {} as {}: {}",
                        package_path.string(), content_id,
                        rename_ec.message());
            ++skipped_count;
            continue;
          }
        }
        // The copy sits in the folder being scanned: mark it seen so the
        // walk does not process it a second time.
        std::error_code staged_ec;
        seen_packages.insert(
            std::filesystem::weakly_canonical(staged_path, staged_ec)
                .string());
      }

      if (IsInstalledMarketplaceContent(runtime->user_data_root(), title_id,
                                        staged_path)) {
        REXLOG_INFO("DLC package already installed: {}", content_id);
        ++skipped_count;
        continue;
      }

      REXLOG_INFO("Installing DLC package: {}", content_id);
      const auto result = runtime->kernel_state()
                              ->content_manager()
                              ->InstallContent(staged_path);
      if (result == 0) {
        ++installed_count;
        REXLOG_INFO("Installed DLC package: {}", content_id);
      } else {
        ++skipped_count;
        REXLOG_WARN("Failed to install DLC package {}: {:08X}", content_id,
                    static_cast<uint32_t>(result));
      }
    }
    // (Ronda 9, auditor A - R9-A2; WARN movido aqui en ronda 12,
    // R12-A1.) El error de iteracion se detecta AQUI, no en el break
    // de dentro: un increment(iter_ec) fallido deja el iterador en end
    // (exigido por el estandar, verificado contra libstdc++ 13), asi
    // que el cuerpo del bucle -- y su WARN "Could not scan DLC folder"
    // -- no llega a ejecutarse nunca, ni ante un fallo a mitad del
    // recorrido ni ante un fallo al CONSTRUIRSE (ahi el bucle no
    // ejecuta ni una vuelta). iter_ec queda fijado y el recorrido de
    // esta carpeta no aporto nada al set esperado: avisar aqui, que es
    // el unico sitio que lo observa siempre, y marcar incompleto.
    if (iter_ec) {
      REXLOG_WARN("Could not scan DLC folder {}: {}", source_dir.string(),
                  iter_ec.message());
      scan_complete = false;
    }
  }

  const size_t pruned_count =
      scan_complete
          ? PruneInstalledDlcWithoutSource(runtime->user_data_root(),
                                           title_id, expected_content_ids)
          : 0;
  if (!scan_complete) {
    REXLOG_WARN(
        "Skipping installed-DLC prune: the DLC scan did not complete, so "
        "the expected set may be incomplete (see warnings above)");
  }

  if (installed_count || skipped_count || pruned_count) {
    REXLOG_INFO("DLC scan complete: {} installed, {} skipped, {} pruned",
                installed_count, skipped_count, pruned_count);
  } else {
    REXLOG_INFO("No DLC packages found. Drop DLC package files in {}",
                user_dlc_root.string());
  }
}

}  // namespace col_dlc

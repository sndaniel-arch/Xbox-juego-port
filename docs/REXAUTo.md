# rexauto para el título — integración

**Fecha:** 2026-11-13.
**Proyecto:** port nativo del título (Xbox 360 → Android) por recompilación estática.
**Repo de trabajo:** `sndaniel-arch/Xbox-juego-port` (**público desde 2026-11-15**; estuvo en privado 2026-11-14–2026-11-15 por decisión del usuario hasta que la cuenta volviera a servir — ver R9-B4. Modelo vigente: código público + APK solo como artefacto con retención de 7 días, nunca Release público — ver `docs/DMCA.md` y §7.3).
**Entrada del usuario:** el juego de Xbox 360 (paquete XBLA-STFS propio, en Drive).
**Fuentes verificadas (leídas enteras el 13-11-2026):** README de rexauto, `.github/workflows/android.yml` (650 líneas), `.github/workflows/recompile.yml` (638 líneas), `extract.py` (1.832 líneas), listado del directorio `.github/workflows` (solo existen esos 2 workflows).

---

## 1. Qué es rexauto (datos verificados)

| Dato | Valor |
|---|---|
| Repo | https://github.com/Player124413/rexauto |
| Creado | 2026-09-05 |
| Licencia | MIT |
| Estado a 13-11-2026 | 7 estrellas, 6 forks, 163 commits |
| Commit verificado | `dac49b331f2632f0b050f469e35747721300b8b2` |
| **Rama por defecto** | **`arena/01a07629-rexauto` (NO `main` — `/tree/main/` da 404)** |
| Releases | 0 (el README dice "Grab `rexauto.exe` from the latest release", pero no hay releases publicadas) |
| Tags | 52 |

**Qué es:** orquestador + front-end del recompilador estático **ReXGlue**. Apuntas a un contenedor del juego (ISO, GoD, STFS o carpeta extraída) y ejecuta el pipeline que de otro modo es "un día de trabajo a mano": extraer, andamiar, recuperar jump tables, compilar y los dos bucles de auto-curación. No es un emulador: traduce el PowerPC de Xbox 360 a C++ **una vez** y lo compila a código nativo.

**Límite declarado por el propio autor (README):** *"rexauto gets you to a booting, guest-code-executing build, automatically. It does NOT close per-title GPU/emulation gaps."* — rexauto llega a un build que arranca; los huecos de GPU/runtime por título siguen siendo trabajo manual.

**Títulos llevados por su pipeline (tabla honesta del README):** Skate 3 (playable), GTA San Andreas HD (gameplay), GTA V (reaches gameplay), Dragon Ball Z: Budokai 3 HD (battle running), Captain America: Super Soldier (gameplay), WWE SmackDown vs. Raw 2007 (playable to menu), Gears of War: Judgment (boots, converges), Crash of the Titans (boots). Flota de regresión de ~30 títulos. **el título no está entre ellos ni en su base de gabaritos** (14 filas / 13 títulos; el el motor más cercano es `rayman3hd` con 14 curas). el título partiría de cero: heal completo desde el principio.

---

## 2. El pipeline (7 etapas)

1. **extract** — contenedor → `default.xex` + assets. Acepta **STFS** (`CON`/`LIVE`/`PIRS` — XBLA/DLC), **ISO** (GDFX/XDVDFS de disco), **GoD** (SVOD de un archivo) o carpeta ya extraída. Implementación propia en `extract.py` (Python puro, 1.832 líneas): lector STFS nativo, lector GoD/SVOD y lector ISO (GDFX). Una carpeta que ya contiene `default.xex` se usa directamente como raíz del juego.
2. **init** — `rexglue init` andamia el proyecto.
3. **setjmp** — localiza el `setjmp`/`longjmp` del CRT estático y lo registra en el manifiesto (sin él, los títulos con excepciones crashean al arrancar).
4. **jumptables** — con IDA Pro (opcional, comercial) recupera tablas `bctr` a `switch_tables.toml` (xenon-jumptables, vendorizado). Sin IDA se salta limpiamente.
5. **build** — codegen + clang/CMake. Si el recompiler parte una función a mitad de flujo, rexauto **auto-extiende el límite y reconstruye** hasta que compile.
6. **runheal** — ejecuta el juego; cada `invalid or unregistered function at 0xADDR` que encuentra el dispatcher se registra, se reconstruye y se re-ejecuta, hasta que no quede ninguna.
7. **run** — lo lanza.

**Base de datos compartida de "curas" (`gabaritos/`):** una vez que un título converge, sus `functions.toml` (clave SHA-256 del `default.xex`) se publican y el siguiente que recompile ese binario exacto las siembra por adelantado. Para el título no hay gabarito: el primer run hace el heal completo.

**SDK fijado por hash:** rexauto se niega a correr con un SDK distinto al fijado, sin override (en la GUI). En CI existe el input `sdk_url` para sobreescribirlo. El SDK fijado es **ReXGlue v0.10.0**.

---

## 3. Los dos workflows de rexauto (leídos enteros)

### 3.1 `recompile.yml` — "Recompile game" (PC, Windows)

| | |
|---|---|
| Runner | `windows-latest`, timeout 350 min |
| Inputs | `url` (requerida: default.xex / ISO / GoD / STFS / .zip, directa, Google Drive o Dropbox), `name` (requerida, `[a-z0-9_]{1,40}`, por defecto `game`), `runheal` (bool, **por defecto `true`**), `heal_iters` (por defecto `"6"`), `patches` (por defecto `""`), `sdk_url` (por defecto `""`) |
| Pasos | Validar inputs → checkout → Python 3.12 → pip pillow → toolchain (vswhere → vcvars64.bat, clang) → resolver URL del SDK fijado (`tools/ci_sdk.py url`) → caché del SDK → instalar SDK → verificar pin → descargar el juego (`tools/ci_fetch.py`) → `python rexauto.py <container> --name <n> --no-jumptables --heal-iters <n> --publish-gabarito` (+ `--until build` si runheal es false; + `--patch` por cada parche) → recolectar el port |
| Artefactos | `port-<name>` (exe + DLLs + `play <name>.cmd` + `<Title> Launcher.exe` vía PyInstaller + `assets/PUT_GAME_FILES_HERE.txt`), `logs-<name>`, `gabarito-<name>` (retención 30 días), `source-<name>` (proyecto completo: C++ generado + `src/` + `*.toml` + CMake, retención 14 días) |
| Nota clave | **Jump tables SIEMPRE saltadas en CI** (`--no-jumptables`; IDA no está en el runner). El run-heal funciona en el runner (el juego abre una ventana en el escritorio del runner), pero es lento. |

### 3.2 `android.yml` — "Recompile for Android" (APK)

Dos jobs encadenados:

**Job 1 — `recompile` (windows-latest, timeout 350 min):** el mismo pipeline hasta `build` (extract, setjmp, deepextract, codegen + curas estáticas + build de comprobación). Inputs propios: `url` (requerida), `name` (requerida), `baseline_arm` (bool, por defecto `false`; `true` = ARMv8.0 plano para SoCs 2016–2017 — **el Helio G99 es ARMv8.2-A, así que `false`**), `runheal` (bool, por defecto `false` — al contrario que en PC**), `heal_iters` (por defecto `"4"` en rexauto; nuestro workflow lo sube a `"6"`, ver §7.5). Metadatos del título con `tools/title_meta.py` (outputs `title` y `title_id`, leídos del XEX). **Falla explícito si no existe `generated/default/sources.cmake`.** Artefactos: `port-src-<name>` (`generated/` + `src/` + `*.toml` + `*.cmake`, retención 7 días), `logs-windows-<name>` (14 días).

**Job 2 — `apk` (ubuntu-24.04, timeout 300 min, `needs: recompile`):**

| Paso | Detalle |
|---|---|
| Descargar + desempaquetar | `port-src-<name>` → `autoports/<name>/port` |
| Host toolchain | `ninja-build libx11-xcb-dev libwayland-dev libwayland-client0 unzip zip` |
| Java | Temurin 17 |
| SDK Android | `tools/android_sdk.sh` → **ReXGlue SDK v0.10.0 + parches Android de `deivid22srk/hells-gate-recomp-android`** (caché con clave `android-sdk-v0.10.0-` + hash de los parches de `android/patches` y de `tools/android_sdk.sh`) |
| NDK/CMake | sdkmanager: **CMake 3.31.1 + NDK 27.2.12479018** |
| Assets | `tools/xbox360_titles.json` + portada → icono Android (`tools/android_icon.py`) |
| Firma | Paso "CI signing key" (ver §6 — **la inconsistencia**) |
| Build | `./gradlew assembleRelease --no-daemon` con `-PrexName`, `-PrexTitle`, `-PrexTitleId`, `-PrexPortDir`, `-PrexSdkDir`, `-PrexVersionCode=<run_number>`, `-PrexVersionName=1.<run_number>` |
| Verificación del APK | Debe contener `lib/arm64-v8a/libmain.so`, `lib/arm64-v8a/librexgpu-xenos*.so` y `assets/xbox360_titles.json` |
| Artefactos | `<name>-android-apk` (**APK firmada instalable**, retención 7 días), `source-<name>` (proyecto Android Studio completo, retención 7 días), `logs-android-<name>` solo en fallo (14 días) |

**El launcher Android que genera** (README + workflow + árbol `android/`): importa en el propio teléfono ISO / paquete XBLA-STFS / `default.xex` (desempaqueta STFS en almacenamiento privado) o carpeta (GoD multipart); **rechaza un dump de otro título por Title ID**. Ajustes: presets Performance / Balanced / Accuracy (Performance por defecto), cap 30/60 fps como cap de vblank del guest, escala de resolución, modo de vídeo del guest hasta 1920x1080 (1280x720, 1920x1080, 1024x576, 960x540), vsync, letterbox, orientación, "tolerant mode". Build nativo -O3 + ThinLTO, ARMv8.2-A (+fp16/dotprod). **Drivers GPU:** Turnip en Snapdragon y PanVK experimental en Mali (importar zip vía libadrenotools, detrás del interruptor `experimental_gpu_driver`; ronda 2, E P0-1/P0-2); en Mali sin zip se usa el Vulkan del sistema. Controles: gamepad en pantalla (tamaño y opacidad ajustables, hápticos; los botones no se pueden mover de sitio) + mandos Bluetooth vía SDL.

**Advertencia del propio workflow (cabecera de `android.yml`, líneas 32-34):** *"The APK embeds code recompiled from the game you supplied; artifacts on a public repo are publicly downloadable. Keep this on a private fork."* — ver §7.

---

## 4. La entrada: la ISO del usuario

- **Lo que acepta rexauto:** ISO (GDFX/XDVDFS), GoD (SVOD), STFS (CON/LIVE/PIRS), `default.xex` suelto, `.zip` con uno de ellos, o carpeta extraída. La URL puede ser directa, de Google Drive o de Dropbox (`tools/ci_fetch.py` la resuelve).
- **Matiz importante del título:** en Xbox 360 el título fue **solo digital (XBLA, ~1,47 GB); no hubo disco físico**. Por tanto la "ISO" del usuario es casi seguro una de estas tres cosas: (a) un paquete GoD convertido a ISO (p. ej. con GOD2ISO), (b) un paquete XBLA reempaquetado como ISO, o (c) una ISO construida desde los archivos extraídos. **Al pipeline no le importa cuál sea** — rexauto acepta las tres formas — pero hay que verificarlo al recibirla: extraer y comprobar que dentro está `default.xex` (ver §8).
- **Title ID:** rexauto lo lee del XEX (`tools/title_meta.py`) y lo usa para el nombre del paquete y para rechazar dumps de otro título. El Title ID citado en fuentes secundarias es **`[redactado]`** (Media ID `27A6BF29`), **NO verificado** — la confirmación definitiva es el dump. El workflow adaptado NO hardcodea el Title ID; lo toma de los outputs del job 1 y lo deja como TODO a confirmar tras el primer run.
- **Nombre del proyecto:** `childoflight` (rexauto exige `[a-z0-9_]{1,40}`; `child-of-light` con guiones es inválido).
- **Sin title update:** recompilar primero **sin TU** (build retail base). Existe TU2 (anuncio de trainer Ko-fi); los parches cambian direcciones e invalidan los hints — se evalúa después.

---

## 5. Los dos caminos (en paralelo)

| Camino | Para qué | Tiempo estimado | Base |
|---|---|---|---|
| **A. rexauto** (workflow adaptado `.github/workflows/recompile-android-rexauto.yml`) | "¿Bootea?" — primer arranque en el teléfono, con GPU Xenos **emulada** (`librexgpu-xenos.so`) | **Días** una vez llegue la ISO | rexauto tal cual (SDK v0.10.0 + parches hells-gate, NDK r27) |
| **B. Fork de RaymanOriginsRecomp** | "¿Jugable a 60 fps?" — renderer nativo Vulkan + perfil Mali-G57 | **Semanas** | Los 7 parches Android de Origins (`android/rexglue-patches/0001–0007`), `android/app/` + `build_apk.sh`, pack tools, fontanería del renderer nativo, detector de jump tables |

El camino A no sustituye al B: el APK de rexauto usa la GPU emulada (más lenta, pero suficiente para saber si el juego arranca, abre sus `.ipk` y llega al menú). El camino B es el que puede dar 60 fps reales. El trabajo por título (jump tables, límites de función, imports kernel/XAM, shaders el motor, Igniculus en el stick derecho, DLCs) es el mismo en ambos y parte de cero.

---

## 6. La inconsistencia de la clave CI — VERIFICADA (el README se equivoca)

**Lo que dice el README** (líneas 389-390): *"Every APK of the same project is signed with the same CI key, so a new run installs over the previous one and keeps saves."*

**Lo que hace el YAML** (`android.yml`, paso "CI signing key (stable across runs)", líneas 470-478):

```yaml
- name: CI signing key (stable across runs)
  run: |
    keytool -genkeypair -v -keystore android/ci-release.jks -storepass "<redacted>" -keypass "<redacted>" \
      -alias rexauto -keyalg RSA -keysize 2048 -validity 10000 \
      -dname "CN=rexauto ${{ inputs.name }}, O=rexauto" >/dev/null 2>&1
```

Ese paso genera el keystore **de nuevo en cada run, sobre un checkout limpio, sin ningún paso de caché ni restauración** (el único caché del job `apk` es el del SDK, `android/sdk`; y la recolección de `source-<name>` excluye explícitamente los `*.jks`). **Conclusión: cada run firma con una clave distinta.** Una APK nueva NO instalaría encima de la anterior conservando datos (Android exige la misma clave de firma para actualizar): habría que desinstalar y perder los guardados. El nombre del paso ("stable across runs") es falso tal como está el YAML.

**Cómo lo corrige nuestro workflow adaptado:** keystore estable vía secretos de GitHub Actions:
- Si existen los secretos `CI_KEYSTORE_BASE64` (keystore en base64), `CI_KEYSTORE_STORE_PASSWORD` y `CI_KEYSTORE_KEY_PASSWORD`, se restaura ese keystore y se firma con él → la misma clave en todos los runs, las APK actualizan conservando datos. (P1-7, ronda 2: el secreto antiguo `CI_KEYSTORE_PASSWORD` nunca se leyó en ningún paso del workflow; es legado.)
- Si no existen, el job falla con `::error::` antes de compilar (ronda 3, B-R3-1:
  la rama antigua generaba un keystore nuevo con contraseña aleatoria y la APK
  salía firmada en verde, pero con otra llave: no actualizaba sobre builds
  anteriores y el único aviso era un `::warning::`).
- **HECHO 2026-11-13 (llave personalizada con corazón):** keystore generado y
  guardado como secreto. Alias `childoflight<3`, `CN="Child of Light <3",
  OU=Aurora, O=Child of Light Recomp`, RSA 4096, SHA384withRSA, válido
  hasta 2054-03-31. **Dos hashes distintos, no confundir (ronda 3, auditor B):**
  el SHA-256 del certificado — lo que `apksigner verify --print-certs` muestra
  y lo que Android compara al actualizar — es
  `3768a83d38837f424138c1570f77e111bd1777ff6df049d476e562a46bb189ab`
  (verificado en las APK v1.1, v1.2, v1.3, v1.4 y v1.4.1-full); el `8ea1eb60…`
  que antes figuraba aquí como "SHA-256 del certificado" es en realidad el
  SHA-256 del ARCHIVO `ci-release.jks`
  (`8ea1eb6023be480b8f92a852c90aac80538c82befea3af559fe487647f0f29d4`), que
  CAMBIA al rotar la contraseña aunque la llave sea la misma. Comando (el `<` se escapa como
  `\<`, si no keytool lo rechaza; la contraseña NUNCA va en este documento (antes estaba aquí en claro: P1-7, ronda 2, auditor B). La actual vive solo en los secretos de CI y en el entorno local (ver ROTATION-PLAN-keystore.md)):
  ```bash
  keytool -genkeypair -v -keystore ci-release.jks -storepass "<redacted>" -keypass "<redacted>" \
    -alias 'childoflight<3' -keyalg RSA -keysize 4096 -sigalg SHA384withRSA -validity 10000 \
    -dname 'CN=el título \<3, OU=Aurora, O=el port'
  base64 -w0 ci-release.jks   # → secreto CI_KEYSTORE_BASE64
  # CI_KEYSTORE_PASSWORD =<redacted>
  ```
  Secretos `CI_KEYSTORE_BASE64` + `CI_KEYSTORE_PASSWORD` creados 2026-11-13
  03:18; `CI_KEYSTORE_BASE64` actualizado a la llave del corazón 03:24
  (confirmado en la lista de secretos del repo). El `ci-release.jks`
  original vive en `private/` (respaldo local, nunca se sube al repo).
- **P1-7 (ronda 2, 2026-11-14):** la contraseña del keystore estaba en claro en este documento (los dos comandos `keytool` de arriba), en `build.gradle.kts`, en los 4 scripts full y en el workflow. Ya no: va por variables de entorno / secretos (ver `ROTATION-PLAN-keystore.md`). La contraseña antigua sigue siendo pública en el historial de git: hay que ROTARLA, no basta con borrarla de los archivos.
  Respaldos sin usar: llave bonita sin corazón (alias `childoflight`) y
  llave genérica rexauto. (Los `35cd9717…` y `8413a761…` que antes figuraban
  como sus "SHA-256" son también hashes del ARCHIVO .jks, no de sus
  certificados.)
  Guardar el `ci-release.jks` original en un lugar seguro (si se pierde,
  las APK futuras ya no podrán actualizar sobre las anteriores).

---

## 7. Decisiones pendientes

| # | Decisión | Estado |
|---|---|---|
| 1 | **URL de la ISO** (directa / Drive / Dropbox) + SHA-256 opcional | **RESUELTO 2026-11-13:** el paquete XBLA está en Drive y el run #1 ya lo usó como `iso_url` (STFS 1.585.451.008 B, MD5 `ad88061a06fba28e3434945f37cb3d57` — ver §7.7). El workflow sigue pidiéndolo como input `iso_url` en cada run. |
| 2 | **Keystore CI** (secretos `CI_KEYSTORE_BASE64` + `CI_KEYSTORE_STORE_PASSWORD` + `CI_KEYSTORE_KEY_PASSWORD`; `CI_KEYSTORE_PASSWORD` es legado y se borra tras rotar) | **RESUELTO 2026-11-13 (llave) / PENDIENTE (secretos nuevos):** llave personalizada `childoflight<3` (RSA 4096, certificado SHA-256 `3768a83d…`; `8ea1eb60…` es el hash del archivo .jks, ver §6), `CI_KEYSTORE_BASE64` actualizado a la llave del corazón 03:24. Los 3 secretos nuevos (`STORE_PASSWORD` / `KEY_PASSWORD` / `KEY_ALIAS` opcional) hay que crearlos ANTES del push del workflow (ronda 3, §8); sin ellos el primer run falla en "CI signing key". Ver §6 y `ROTATION-PLAN-keystore.md`. |
| 3 | **Repositorio privado vs público** | **CAMBIÓ 2026-11-15: PÚBLICO de nuevo** — estuvo en privado 2026-11-14–2026-11-15 por decisión del usuario (cuenta marcada por GitHub); al ser público de nuevo, el modelo es el previsto: código público, APK **nunca** como Release público, solo artefacto de Actions con retención de 7 días (ver `docs/DMCA.md`). |
| 4 | **ReXGlue v0.10.0 (pin de rexauto) vs v0.10.1** | **CAMBIÓ 2026-11-14: el codegen ya usa la v0.10.1** — el fork xdzleo (v0.10.0-rexauto.2) desapareció de GitHub (404) y el workflow (`recompile-android-rexauto.yml`, job `recompile`) baja el repack oficial v0.10.1 de este repo (release `sdk-v0.10.1-repack`) con `REXAUTO_SDK_PIN=0`. La v0.10.1 trae fix de vídeo `vpkuwus`/`vpkuhus` (relevante para las cinemáticas) e input de Xbox 360. El SDK **Android** sigue en **v0.10.0 + 12 parches (11 de rexglue + 1 de libadrenotools)** (`tools/rexauto/tools/android_sdk.sh`): esa es la parte que aún no sube, no el codegen. |
| 5 | **`runheal` en Android** | rexauto lo pone en `false` por defecto en Android (en PC es `true`). Nuestra adaptación lo deja en **`false` por defecto + `heal_iters: 6`** (workflow `recompile-android-rexauto.yml`, inputs `runheal`/`heal_iters`): la frase anterior que decia `true` contradecia el workflow. Sin gabarito previo del título, el heal en Windows es la única fuente de curas; activarlo es mas lento, pero es lo que hace converger un título nuevo. |
| 6 | **Jump tables sin IDA en CI** | **RESUELTO 2026-11-13 (Fase 0):** scanner de wivi514 (`find_jumptables.py`) sobre la imagen plana del XEX del título con el rango real de .text → **192 tablas (98 absolute + 44 offset16 + 50 offset8), 4.380 labels, 0 sin resolver** (`analysis/col-jumptables.toml`). XenonAnalyse stock da 0 (fallo de detección conocido). Ver `analysis/FASE0.md`. |
| 7 | **Title ID** | **CONFIRMADO 2026-11-13 por la carpeta real en Drive**: `[redactado]` (`el título (World) (XBLA)/[redactado]/000D0000/FB24D252…`, 1.585.451.008 B, MD5 `ad88061a06fba28e3434945f37cb3d57`). |
| 8 | **DLCs del título** | No verificado cómo se añaden DLCs STFS adicionales al mismo Title ID en el launcher de rexauto (importa UN paquete XBLA por título). TODO. |
| 9 | **Igniculus** | El gamepad de rexauto es genérico; el control de Igniculus (stick derecho, como en Vita) no existe. **Verificado en la segunda ronda (2026-11-13): la versión 360 SÍ permite controlar a Igniculus con el 2º mando** (stick derecho + mantener LT, 5 fuentes). Falta implementarlo en el port. |
| 10 | **Renderer nativo vs emulado** | El APK de rexauto usa GPU emulada. Para 60 fps en Mali probablemente haga falta el renderer nativo (camino B). El perfil Mali-G57 (Vulkan 1.1, 4 descriptor sets, sin `shaderInt64`) y la receta anti-DEVICE_LOST (validación de Vulkan + PanVK) van en el camino B. |

---

## 8. ISO → `default.xex` → PE en Linux (comandos exactos)

Cadena completa, con fuentes. Todo se hace en el runner de GitHub Actions (Ubuntu) o en cualquier Linux; nada de esto necesita la consola Xbox 360.

### 8.1 Paso 1: identificar el contenedor

```bash
file ChildOfLight.iso
ls -lh ChildOfLight.iso        # se esperan ~1,5 GB (XBLA, ~1,47 GB)
sha256sum ChildOfLight.iso
```

Si el archivo no es una ISO de disco sino un paquete STFS (magia `CON `, `LIVE` o `PIRS` en los primeros 4 bytes) o un GoD (SVOD), rexauto lo acepta igual — no hace falta convertirlo.

### 8.2 Paso 2: extraer la ISO (el `default.xex` + assets)

**Opción A — rexauto, sin herramientas externas (recomendada en CI).** `extract.py` de rexauto lee ISO (GDFX), GoD (SVOD) y STFS en Python puro:

```bash
python3 extract.py ChildOfLight.iso ./col-game
# → ./col-game/default.xex + assets
```

Fuente: `extract.py` de rexauto (líneas 18-31: "Xbox 360 ISOs (GDFX) likewise… For an already-extracted game (a folder that contains default.xex) the folder is used directly"). Es lo que usa el propio pipeline en el runner de Windows; en Linux funciona igual (Python puro, sin dependencias).

**Opción B — extract-xiso (clásico, CLI).**

```bash
./extract-xiso ./salida ./ChildOfLight.iso
```

Fuente: ConsoleMods Wiki, "Xbox: ISO Extraction & Repacking" — https://consolemods.org/wiki/index.php?title=Xbox:ISO_Extraction_%26_Repacking — Funciona con ISOs de Xbox 360. Ojo: **los releases de GitHub no traen binarios precompilados para Linux/macOS — hay que compilarlo desde el fuente**.

**Opción C — xdvdfs (Rust, moderno) — NO FIABLE para Xbox 360.**

```bash
xdvdfs unpack ChildOfLight.iso ./salida
```

Fuente: ConsoleMods Wiki (misma página). **Advertencia:** la propia wiki se contradice entre revisiones — una dice que xdvdfs maneja ISOs de Xbox 360 y otra dice textual: *"This tool is only compatible with original Xbox ISOs, NOT Xbox 360 ISOs!"*. El listado de velocityra lo describe como herramienta para imágenes XDVDFS/XISO **de la Xbox original**. No usar xdvdfs para una ISO de 360 sin verificarlo antes con la ISO real.

**Otras herramientas (contexto):** Velocity (navegador/editor STFS multiplataforma, más orientado a Windows); `god2iso` (convierte paquetes GoD a ISO); XISO Studio v3.0.1 (GUI multiplataforma, 01-10-2026). Ninguna necesaria si se usa la opción A.

### 8.3 Paso 3: inspeccionar el XEX y sacar el PE desencriptado

El `default.xex` extraído sigue siendo un **XEX2 cifrado** (AES-128-CBC + compresión LZX). XenonRecomp/ReXGlue piden el XEX desencriptado (el PE). Herramienta moderna: **xex2ool** (crate 0.2.0, 2026, sobre el crate `xex2`).

```bash
cargo install xex2ool            # o: pip install xex2  (bindings de Python)
xex2ool info default.xex         # cabeceras, Title ID, cifrado/compresión
xex2ool basefile default.xex -o default.pe   # PE desencriptado y descomprimido
sha256sum default.xex default.pe
```

Fuente: crates.io `xex2ool` / `xex2` 0.2.0 — https://crates.io/crates/xex2ool — "Extract the decrypted, decompressed PE payload"; `xex2ool basefile game.xex -o game.pe`. Equivalente en Python: `x = xex2.Xex2.parse(data)` → `open("game.pe","wb").write(x.extract_basefile())` (PyPI `xex2` 0.2.0). Alternativa clásica: **XexTool** de xorloser (`xextool -b default.xex default.pe`).

**Verificación tras extraer:** `xex2ool info` debe mostrar el Title ID (esperado `[redactado]`, a confirmar) y `file default.pe` debe mostrar un PE. El SHA-256 del `default.xex` es la clave de cualquier gabarito futuro.

### 8.4 Resumen de la cadena

```
ISO (usuario)
  → extract.py de rexauto  (o extract-xiso)  →  default.xex + assets  [XEX2 cifrado]
  → xex2ool basefile                          →  default.pe            [PE desencriptado]
  → XenonAnalyse / rexauto codegen            →  C++ generado + APK
```

---

## 9. Qué queda como TODO (nada inventado)

1. **URL de la ISO + SHA-256** (**resuelto**: el paquete XBLA está en Drive y el run #1 ya lo usó — ver §7.1).
2. **Keystore CI** como secretos (ver §6); sin ellos, cada APK firma con clave nueva.
3. **Title ID** — confirmado `[redactado]` con el dump en Drive.
4. **Jump tables sin IDA** (ver §7.6): elegir detector y probarlo con el XEX del título.
5. **ReXGlue v0.10.1 en Android**: el codegen ya corre la v0.10.1 (repack, ver §7.4); queda evaluar subir el SDK **Android** (hoy v0.10.0 + 12 parches: 11 de rexglue + 1 de libadrenotools) a v0.10.1, no subir en silencio.
6. **DLCs, Igniculus, renderer nativo Mali** (ver §7.8–7.10): trabajo del camino B.
7. **El workflow adaptado YA se ejecutó (run #1, 2026-11-13 23:53 CST, ID 43563682217): falló en ~29 s en «Install ReXGlue SDK» (HTTP 404: el fork xdzleo/rexglue-sdk desapareció — ver §7.4). El run #2, con el repack sdk-v0.10.1 y `REXAUTO_SDK_PIN=0`, validará el checkout doble (nuestro repo + rexauto en `rexauto/`), el pin del SDK y la generación de la APK.
8. **Codegen de CI con register-as-local (cableado 2026-11-13, sin ejecutar):** el job `recompile` inyecta las 6 claves `*_as_local = true` (top-level) en el manifest que rexauto autora (fase `init`), resume con `--from setjmp`, corre `tools/localize_fix_col.py` sobre `generated/default/ppc_recomp.*.cpp` y verifica manifest + `*_init.cpp` + marcadores `LOCALIZE_FIX`. **Pendiente:** adaptar el script a la sintaxis del SDK (`DEFINE_REX_FUNC` / `REX_CALL_INDIRECT_FUNC`); el tripwire falla el job hasta entonces. **Corrección importante:** rexauto NO usa XenonRecomp (el codegen es `rexglue.exe` del SDK); los parches 0015–0022 no aplican al árbol del SDK y `recomp/col.toml` no se lee en CI. (Informe local, no en el repo: `ci-codegen-2026-11-13.md`.)

---

## 10. Fuentes

- https://github.com/Player124413/rexauto (README leído entero, 13-11-2026; commit `dac49b33`)
- https://github.com/Player124413/rexauto/blob/arena/01a07629-rexauto/.github/workflows/android.yml (leído entero, 650 líneas)
- https://github.com/Player124413/rexauto/blob/arena/01a07629-rexauto/.github/workflows/recompile.yml (leído entero, 638 líneas)
- https://github.com/Player124413/rexauto/blob/arena/01a07629-rexauto/extract.py (leídas las primeras 575 líneas de 1.832; estructura STFS/GoD/ISO y `extract_container`)
- https://crates.io/crates/xex2ool (0.2.0) · https://pypi.org/project/xex2/0.2.0/
- https://consolemods.org/wiki/index.php?title=Xbox:ISO_Extraction_%26_Repacking (extract-xiso, xdvdfs — con la contradicción sobre Xbox 360 anotada)
- https://github.com/rexglue/rexglue-sdk (ReXGlue v0.10.0 fijado en Android; codegen en v0.10.1 repack de este repo, release `sdk-v0.10.1-repack`, desde 2026-11-14)
- https://github.com/deivid22srk/hells-gate-recomp-android (parches Android usados por el job `apk`)
- Informes previos del proyecto (locales, no en el repo): `plan-port-nativo-col-2026-11-13.md`, `port-col-investigacion-completa-2026-11-13.md` (§4, rexauto a fondo), `metodos-mas-rapidos-port-col-2026-11-13.md`

---

## 11. Reconstruir la copia de trabajo (hunt 2, P1-4, 2026-11-13)

La copia de trabajo local (`tools/rexauto/` en el checkout) es un árbol
ENSAMBLADO (checkout rexauto@dac49b33 + overlay del repo + SDK + keystore),
no un repo git. Si la VM se borra, se reconstruye con:

    tools/assemble-android-tree.sh <dest> [--verify-against <arbol-vivo>]

El script clona rexauto en el pin, copia SOLO los archivos trackeados del
repo (vía `git ls-files`, o un clon temporal si el checkout no es git),
corre nuestro `android_sdk.sh` (12 parches: 11 de rexglue + 1 de libadrenotools) y compara el resultado con el
árbol vivo excluyendo build/, .cxx/, .gradle/, .git/, out/, el keystore y los archivos
locales. Un diff no vacío = un archivo modificado en local que no está en
el repo (el bug P0-2 de la caza: VirtualPadView.java con el fix del pulso).

**Hallazgo de la prueba 1 (2026-11-13): los archivos SDK trackeados NO
los reproduce ningún parche.** `android_sdk.sh` hace `rm -rf` del SDK y
lo reconstruye solo desde los parches; los 17 archivos SDK trackeados y
los 4 nuevos del STFS de Fase 5 (`stfs_data_file.h/cpp`, `stfs_asset.h`,
`stfs_asset_source.cpp`) con sus ediciones a mano (STFS VFS, WaitMultiple,
mprotect...) se perderían en un árbol reconstruido. Por eso el script hace
un SEGUNDO overlay de los archivos trackeados DESPUÉS del SDK (los
trackeados ganan a los parches por diseño) y el workflow de CI tiene el
paso equivalente ("Re-overlay tracked SDK files"). La clave de caché del
SDK incluye también `tools/rexauto/android/sdk/**`. Regla: si editas el
SDK a mano, el archivo queda trackeado y el overlay lo preserva; el set
de parches NO necesita reproducirlo.

NO reconstruye: `autoports/childoflight/port` (código generado, no
trackeado: regenerar con XenonRecomp/rexauto o copiarlo de un backup) ni
`ci-release.jks` (keystore privado: copiarlo de su backup o restaurarlo
del secreto CI_KEYSTORE_BASE64).

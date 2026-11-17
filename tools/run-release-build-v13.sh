#!/bin/bash
# Fase 4 (v1.3): full release build (local, offline). Log: analysis/fase4-build-1.log
# Cambios frente a v1.2: controles verificados del original (sin Y/LB/RB/Back),
# horizontal bloqueado (hint SDL_ORIENTATIONS + override setOrientationBis),
# espanol por defecto (user_language=5) y port oficial (home descartada:
# tocar el icono entra directo al juego).
# (Caza extra X-B-1, ronda 2.) Sin `set -e` un Gradle sin firmar salia con
# exit 0 y el script no lo cazaba: pipefail + verify final al pie.
set -euo pipefail
cd /home/hatch/workspace/col-recomp/tools/rexauto/android
# Keystore local (P1-7, ronda 2, auditor B): el keystore corazón
# (ci-release.jks) trae el alias de CI_KEYSTORE_KEY_ALIAS y sus contraseñas
# se leen de CI_KEYSTORE_STORE_PASSWORD / CI_KEYSTORE_KEY_PASSWORD (ver la
# guarda al inicio del script). build.gradle.kts lee el alias (por defecto
# "childoflight<3") y las contraseñas de esas mismas variables de entorno, así que
# ya no hace falta el sed + trap que cambiaba y revertía build.gradle.kts
# en cada build.
# P1-7 (ronda 2, auditor B): la contraseña del keystore NUNCA va en este
# script (antes estaba en claro en la línea de `apksigner sign` y en
# build.gradle.kts). Se lee de variables de entorno, las mismas que usa
# Gradle para firmar durante el build. Exportarlas antes de ejecutar el
# script (p. ej. en la misma línea de comandos o en ~/.bashrc):
#   CI_KEYSTORE_STORE_PASSWORD='...' CI_KEYSTORE_KEY_PASSWORD='...' ./tools/run-release-build-v13.sh
# Tras la rotación (ver ROTATION-PLAN-keystore.md) hay que usar la contraseña
# NUEVA. Con `set -u`, ${VAR:?mensaje} falla con un error claro si falta o está vacía
# la variable; sin él, Gradle firmaría con una contraseña vacía o dejaría
# la APK sin firmar.
: "${CI_KEYSTORE_STORE_PASSWORD:?Falta CI_KEYSTORE_STORE_PASSWORD: exportarla antes de ejecutar este script (ver cabecera)}"
: "${CI_KEYSTORE_KEY_PASSWORD:?Falta CI_KEYSTORE_KEY_PASSWORD: exportarla antes de ejecutar este script (ver cabecera)}"
# Alias de la llave corazón (público, no es secreto). Se puede sobreescribir
# con CI_KEYSTORE_KEY_ALIAS si el keystore local usa otro alias.
CI_KEYSTORE_KEY_ALIAS="${CI_KEYSTORE_KEY_ALIAS:-childoflight<3}"
export CI_KEYSTORE_STORE_PASSWORD CI_KEYSTORE_KEY_PASSWORD CI_KEYSTORE_KEY_ALIAS
# Pre-chequeo (ronda 3, auditor B, B-R3-3): sin keystore, Gradle construye
# una APK SIN FIRMAR con exit 0 y solo lo caza el verify del final, tras
# todo el build. Fallar aqui, como ya hace run-release-build-v141.sh.
test -f ci-release.jks || { echo "ERROR: ci-release.jks no encontrado en $PWD"; exit 1; }
export ANDROID_HOME=$HOME/workspace/android-sdk
export JAVA_HOME=$HOME/workspace/tools/jdk-17
export GRADLE_USER_HOME=$HOME/.gradle
export GRADLE_OPTS="-Djava.net.preferIPv4Stack=true"
export CMAKE_BUILD_PARALLEL_LEVEL=1
export PATH=$JAVA_HOME/bin:$HOME/workspace/tools/gradle-8.14/bin:$PATH
/home/hatch/workspace/tools/gradle-8.14/bin/gradle :app:assembleRelease \
  --no-daemon --max-workers=1 --offline \
  -x lintVitalAnalyzeRelease -x lintVitalReportRelease -x lintVitalRelease \
  -PrexName=childoflight -PrexTitle="Child of Light" -PrexTitleId=5841140D \
  -PrexPortDir=$HOME/workspace/col-recomp/autoports/childoflight/port \
  -PrexSdkDir=$HOME/workspace/col-recomp/tools/rexauto/android/sdk/rexglue-sdk \
  -PrexVersionCode=3 -PrexVersionName=1.3

# Verificacion final (caza extra X-B-1, ronda 2): la APK existe y esta
# firmada. Con pipefail el fallo de verify mata el script; sin esto, un
# build sin keystore "exitoso" pasaba desapercibido (el mismo fallo que
# v141 ya caza en run-release-build-v141.sh).
APK=app/build/outputs/apk/release/app-release.apk
test -f "$APK" || { echo "ERROR: APK no generada: $APK"; exit 1; }
"$HOME/workspace/android-sdk/build-tools/34.0.0/apksigner" verify --print-certs "$APK" | tee /home/hatch/workspace/col-recomp/private/verify-v13.txt
echo "[v13] APK verificada: $APK ($(stat -c%s "$APK") B)"

#!/bin/bash
# Subida de la v1.4.1-full a Drive (privado, sin compartir) — Fase 5.1
# Partes de 100 MiB + MD5SUMS + README, carpeta nueva "Child of Light recomp v1.4.1-full"
# Log: analysis/fase5.1-drive-upload.log
# (Ronda 5, auditor F — R5-F6.) set -u solo: sin -e ni pipefail, un split
# fallido, un FOLDER_ID vacio o una subida fallida x3 seguian adelante y el
# script terminaba con exit 0 ("== fin ==") como si todo se hubiera subido.
set -euo pipefail
RECOMP=/home/hatch/workspace/col-recomp
APK=$RECOMP/private/ChildOfLight-recomp-v1.4.1-full.apk
PARTS=$RECOMP/private/v141-full-parts
CLI=/opt/hatch/bin/hatch_gws_cli
LOG=$RECOMP/analysis/fase5.1-drive-upload.log
exec >> "$LOG" 2>&1
echo "== inicio $(date) =="
mkdir -p "$PARTS"

echo "-- partiendo APK --"
split -b 104857600 -d "$APK" "$PARTS/ChildOfLight-recomp-v1.4.1-full.apk.part"
ls -l "$PARTS"

echo "-- MD5SUMS --"
(cd "$PARTS" && md5sum ChildOfLight-recomp-v1.4.1-full.apk.part* > ChildOfLight-recomp-v1.4.1-full-MD5SUMS.txt)
echo "APK MD5: $(md5sum "$APK" | cut -d' ' -f1)" >> "$PARTS/ChildOfLight-recomp-v1.4.1-full-MD5SUMS.txt"
cat "$PARTS/ChildOfLight-recomp-v1.4.1-full-MD5SUMS.txt"

echo "-- README --"
cat > "$PARTS/README-v1.4.1-full.txt" <<'EOF'
Child of Light recomp — v1.4.1-full (PRUEBA, no terminada)
==========================================================
APK: ChildOfLight-recomp-v1.4.1-full.apk — 1.610.028.992 B
MD5 de la APK: 4a6da2f85d24393a95e4e784be92a622
SHA-256: 30d0e90216b6b78880cdfc0bc48d3dee59b2358427c69d1e432afa4985a2f222
Versión: 1.4.1-full (versionCode 5). Arreglo: super.onCreate() primero en
MainActivity (el crasheo al entrar de la v1.4).

INSTALACIÓN (en el teléfono, con Termux, dentro de esta carpeta):
1. Desinstala la v1.4-full antes de instalar esta.
2. cat ChildOfLight-recomp-v1.4.1-full.apk.part* > ChildOfLight-recomp-v1.4.1-full.apk
3. md5sum ChildOfLight-recomp-v1.4.1-full.apk
   Tiene que dar EXACTAMENTE: 4a6da2f85d24393a95e4e784be92a622
   (si no da eso, no la instales; vuelve a descargar las partes).
4. Instala la APK, ábrela y el juego debe arrancar DIRECTO, sin importar nada.
   Tamaño total ~1,6-1,7 GB. Datos debe quedar en MB, no en 1,58 GB:
   si Datos muestra ~1,58 GB, el montaje desde dentro de la APK no está
   activo — manda el log (childoflight.log).
5. Comprueba: ¿entra sin que te vote? ¿el título sigue cortado? ¿la banda
   blanca sigue? ¿el "Cargando..." de la 2ª entrada es más rápido?

NO compartir este enlace ni estos archivos con nadie. Solo para pruebas.
EOF
cat "$PARTS/README-v1.4.1-full.txt"

echo "-- creando carpeta en Drive --"
FOLDER_JSON=$($CLI drive files create --params '{"ignoreDefaultVisibility":true}' --json '{"name":"Child of Light recomp v1.4.1-full","mimeType":"application/vnd.google-apps.folder","parents":["root"]}')
echo "$FOLDER_JSON"
FOLDER_ID=$(echo "$FOLDER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
echo "FOLDER_ID=$FOLDER_ID"
echo "$FOLDER_ID" > "$PARTS/folder_id.txt"

echo "-- subiendo archivos (con reintentos x3) --"
upload_one() {
  local f="$1"
  local name
  name=$(basename "$f")
  local attempt=1
  while [ $attempt -le 3 ]; do
    echo "upload $name (intento $attempt)..."
    if $CLI drive files create --params '{"ignoreDefaultVisibility":true}' --json "{\"name\":\"$name\",\"parents\":[\"$FOLDER_ID\"]}" --upload "$f"; then
      echo "OK $name"
      return 0
    fi
    echo "FALLO $name intento $attempt, reintentando en 10 s..."
    sleep 10
    attempt=$((attempt+1))
  done
  echo "ERROR FINAL: no se pudo subir $name"
  return 1
}
FAILED=0
for f in "$PARTS"/ChildOfLight-recomp-v1.4.1-full.apk.part* "$PARTS/ChildOfLight-recomp-v1.4.1-full-MD5SUMS.txt" "$PARTS/README-v1.4.1-full.txt"; do
  upload_one "$f" || { echo "SEGUIR CON EL RESTO TRAS FALLO DE $(basename "$f")"; FAILED=1; }
done
echo "== fin $(date) =="
# (R5-F6.) El bucle sigue con el resto a proposito, pero el exit code ya no
# miente: si alguna parte no subio, el script sale 1 y el log lo dice.
if [ "$FAILED" -ne 0 ]; then echo "ERROR: al menos un archivo no se subio (ver log)"; exit 1; fi

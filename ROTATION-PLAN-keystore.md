# Plan de rotación de la contraseña del keystore — Child of Light (port nativo)

- **Auditor:** B (ronda 2 de caza, 2026-11-14/15; corregido en ronda 3, 2026-11-14/15: la huella del certificado es `3768a83d…`, ver §0)
- **Alcance:** keystore corazón del port (alias `childoflight<3`, RSA 4096,
  SHA-256 del certificado `3768a83d…` — verificado con
  `apksigner verify --print-certs` sobre las APK v1.1–v1.4.1; el `8ea1eb60…`
  que figuraba aquí en la ronda 2 es el SHA-256 del ARCHIVO .jks, no del
  certificado — válido hasta 2054-03-31 según `docs/REXAUTo.md` §6), cuya
  contraseña estuvo en claro en el repo (público hasta 2026-11-14; retirada de los archivos vivos en ronda 2, queda en el historial de git).
- **Estado:** **EJECUTADO 2026-11-15** (pasos 1–5: contraseñas rotadas en
  local, secretos CI_KEYSTORE_* creados en GitHub 14:21–14:22 CST; huella del
  certificado sin cambio `3768a83d…`). Pendientes: paso 6 (verificar en CI),
  paso 7 (instalar la APK post-rotación encima, sin desinstalar) y paso 8
  (borrar el secreto legado `CI_KEYSTORE_PASSWORD`).
- **Corrección PKCS12 (2026-11-15):** el keystore es PKCS12, no JKS:
  `keytool -keypasswd` no existe para PKCS12 (la contraseña del store ES la
  de la llave, una sola). La rotación se hizo con UNA contraseña nueva para
  ambas; `CI_KEYSTORE_KEY_PASSWORD` tiene el mismo valor que
  `CI_KEYSTORE_STORE_PASSWORD`. El §1 y el paso 1 de este documento describen
  el caso JKS (dos contraseñas distintas); para este keystore no aplica.
- **Regla de este documento:** ningún valor de contraseña aparece aquí. Donde
  hace falta un valor se escribe `<nueva-contraseña-...>` o `<antigua-...>`.
  Las contraseñas nuevas se generan en el momento y se guardan en un gestor
  de contraseñas, nunca en el repo, ni en el chat, ni en un archivo del
  workspace.

## 0. La idea clave: se rota la CONTRASEÑA, no la LLAVE

Rotar la contraseña **no cambia la llave de firma**. `keytool -storepasswd`
y `keytool -keypasswd` re-cifran el keystore y la entrada de la llave con
contraseñas nuevas, pero la pareja de claves RSA y el certificado son los
mismos: el SHA-256 del certificado sigue siendo `3768a83d…` (el `8ea1eb60…`
es el hash del ARCHIVO .jks y CAMBIA al re-cifrar: nunca usarlo como criterio
de que la llave es la misma).

Consecuencia para los usuarios que ya instalaron APKs firmadas con la llave
corazón: **pueden actualizar sin desinstalar**. Android compara la firma
(certificado), no la contraseña del keystore. La rotación es invisible para
ellos: la APK nueva instala encima de la anterior y conserva partidas,
ajustes y DLC instalados.

Lo que SÍ rompería las actualizaciones sería generar un keystore NUEVO
(llave distinta): Android rechazaría la actualización por firma distinta y
habría que desinstalar y perder los datos. **No generar un keystore nuevo.**
La única excepción sería si el propio archivo `.jks` se filtrase (ver §7).

## 1. Qué hay que rotar (y qué NO)

| Elemento | Estado | Acción |
|---|---|---|
| Contraseña del keystore (store) | Estuvo en claro en el repo (20 ocurrencias del mismo valor en 9 archivos); retirada de los archivos vivos en ronda 2, queda en el historial de git | Cambiar con `keytool -storepasswd` |
| Contraseña de la llave (key) | Estuvo en claro en el repo (mismo valor que la del store); retirada de los archivos vivos en ronda 2, queda en el historial de git | Cambiar con `keytool -keypasswd` |
| Secreto `CI_KEYSTORE_BASE64` | Contiene el `.jks` en base64; el archivo cambia al cambiar las contraseñas | Re-generar desde el archivo actualizado y actualizar el secreto |
| Secretos nuevos `CI_KEYSTORE_STORE_PASSWORD` / `CI_KEYSTORE_KEY_PASSWORD` | No existen aún | Crear con los valores nuevos |
| Secreto `CI_KEYSTORE_KEY_ALIAS` | No existe aún (opcional; el código usa el alias corazón por defecto) | Crear con el alias corazón, o dejarlo sin crear |
| Secreto antiguo `CI_KEYSTORE_PASSWORD` | Existe, pero **ningún paso del workflow lo lee** (legado) | Borrar tras verificar la rotación (paso 8) |
| Llave RSA / certificado (`3768a83d…`) | NO comprometida (el `.jks` no está en el repo) | **No tocar** |
| Contraseña que estuvo en claro en `docs/REXAUTo.md` como valor de `CI_KEYSTORE_PASSWORD` | Hoy el documento muestra `<redacted>` (arreglo B, ronda 2); el valor antiguo sigue en el historial de git y en el secreto `CI_KEYSTORE_PASSWORD` | Queda neutralizada por la rotación |

## 2. Pre-requisitos (antes de tocar nada)

1. Tener a mano el keystore actual: `~/workspace/col-recomp/private/ci-release.jks`
   (respaldo local) y/o `~/workspace/col-recomp/tools/rexauto/android/ci-release.jks`.
2. Verificar que es la llave corazón antes de rotarla:
   `keytool -list -v -keystore <archivo> -storepass <antigua>` y comprobar
   que el alias es el corazón y que el SHA-256 del certificado empieza por
   `3768a83d…` (verificado con `apksigner verify --print-certs` sobre las APK
   locales; el `8ea1eb60…` es el hash del archivo .jks, no el fingerprint: si
   lo comparas con `keytool -list -v` nunca coincidirá). Si el fingerprint no
   coincide, PARAR: ese no es el keystore
   que firman los builds.
3. Hacer una SEGUNDA copia offline del keystore actual (p. ej. USB o disco
   aparte, fuera del workspace) y anotar en el gestor de contraseñas la
   contraseña antigua junto a esa copia. Es el único salvavidas si algo sale
   mal en el paso 4.
4. Tener fusionados los archivos del arreglo B de la ronda 2 (`recomp-fix2/`)
   con el árbol de la ronda 1 (`recomp-fix/`, que incluye el cambio de versión
   P2-12 en `run-release-build-full-v141.sh`), con el bloque de cross-check
   DLC_TABLE/DlcAssets del auditor F en ese mismo script, y con el workflow
   de la ronda 3 (fail-fast sin keystore estable + gate de huella B-R3-1).
   Sin el arreglo B aplicado, el workflow seguiría leyendo la contraseña
   antigua en claro y la rotación no serviría de nada; sin el workflow de
   la ronda 3, el paso 6 no podría comprobar la huella del certificado.
5. Generar las contraseñas nuevas: dos valores distintos, aleatorios, de al
   menos 32 caracteres (p. ej. `head -c 32 /dev/urandom | base64`). Una para
   el store (`<nueva-store>`) y otra para la llave (`<nueva-key>`).
   Guardarlas en el gestor de contraseñas ANTES de usarlas.

## 3. Pasos, en orden

### Paso 1 — Rotar las contraseñas sobre una COPIA del keystore

Trabajar sobre una copia, nunca sobre el único original:

```bash
cp ~/workspace/col-recomp/private/ci-release.jks /tmp/ci-release-nuevo.jks
keytool -storepasswd -keystore /tmp/ci-release-nuevo.jks \
  -storepass <antigua> -new <nueva-store>
keytool -keypasswd -alias 'childoflight<3' -keystore /tmp/ci-release-nuevo.jks \
  -keypass <antigua> -storepass <nueva-store> -new <nueva-key>
```

### Paso 2 — Verificar que la llave es la misma

```bash
keytool -list -v -keystore /tmp/ci-release-nuevo.jks -storepass <nueva-store>
```

Comprobar: el alias es el corazón y el **SHA-256 del certificado sigue
siendo `3768a83d…`** (igual que antes; `keytool -list -v` lo muestra como
`SHA256: 37:68:A8:3D:...`). Si el fingerprint cambió, algo salió mal:
descartar la copia y volver al paso 1 con el respaldo del §2.3. Si coincide,
la rotación es correcta y las actualizaciones seguirán funcionando.
Comprobar ADEMÁS que el hash del ARCHIVO sí cambió (`sha256sum` ya NO debe
dar `8ea1eb60…`): re-cifrar el keystore cambia sus bytes aunque la llave sea
la misma; si el hash del archivo no cambió, la rotación no se aplicó.

### Paso 3 — Sustituir el keystore en local

```bash
cp /tmp/ci-release-nuevo.jks ~/workspace/col-recomp/private/ci-release.jks
cp /tmp/ci-release-nuevo.jks ~/workspace/col-recomp/tools/rexauto/android/ci-release.jks
rm /tmp/ci-release-nuevo.jks
```

La copia pre-rotación del §2.3 se conserva offline, etiquetada, hasta el
paso 8. Los keystores de respaldo sin usar (`ci-release-pretty.jks`,
`ci-release-rexauto.jks` en `private/`): si no se usan, **borrarlos** para
reducir superficie; si se quieren conservar, rotarlos igual o anotar que
siguen con la contraseña antigua (y que por tanto no deben usarse para
firmar nada distribuido).

### Paso 4 — Actualizar los secretos de GitHub (repo `Xbox-juego-port`)

En Settings → Secrets and variables → Actions:

1. `CI_KEYSTORE_BASE64`: re-generar desde el archivo actualizado y
   sustituir el valor:
   `base64 -w0 ~/workspace/col-recomp/private/ci-release.jks`
   (el archivo cambió al re-cifrarlo: el secreto antiguo ya no corresponde
   al archivo nuevo).
2. `CI_KEYSTORE_STORE_PASSWORD`: crear con `<nueva-store>`.
3. `CI_KEYSTORE_KEY_PASSWORD`: crear con `<nueva-key>`.
4. `CI_KEYSTORE_KEY_ALIAS` (opcional): crear con el alias corazón. Si no se
   crea, el workflow usa ese alias por defecto.
5. `CI_KEYSTORE_PASSWORD`: **no tocar todavía**; se borra en el paso 8,
   tras verificar que nada lo necesita.

### Paso 5 — Actualizar el entorno local

```bash
export CI_KEYSTORE_STORE_PASSWORD='<nueva-store>'
export CI_KEYSTORE_KEY_PASSWORD='<nueva-key>'
# CI_KEYSTORE_KEY_ALIAS ya tiene el alias corazón por defecto; exportarlo
# solo si el keystore local usa otro alias.
```

Guardarlas en `~/.bashrc` (o donde el usuario guarde sus variables) para no
tener que exportarlas en cada build. Nunca escribirlas en un archivo dentro
del repo ni del workspace.

### Paso 6 — Pushear el arreglo y vigilar el CI

Pushear los archivos fusionados (arreglo B + ronda 1 + bloque F) por el
navegador, como siempre. En el siguiente run del workflow:

1. El paso "CI signing key" restaura el keystore del secreto
   `CI_KEYSTORE_BASE64` y pasa las contraseñas nuevas a Gradle por
   `GITHUB_ENV`.
2. `Gradle assembleRelease` firma con la llave corazón y las contraseñas
   nuevas.
3. El paso "Verify APK" (`apksigner verify --print-certs`) debe salir en
   verde. Además, comprobar en su salida que el SHA-256 del certificado es
   `3768a83d…` (la misma llave de siempre; el paso lo comprueba solo desde la
   ronda 3, B-R3-1, y falla el job si es otro).

Si el job falla en "CI signing key" con el error de secretos ausentes, es
que falta crear `CI_KEYSTORE_STORE_PASSWORD` / `CI_KEYSTORE_KEY_PASSWORD`
(paso 4): crearlo y re-lanzar el workflow. Si falla en "Verify APK", NO
subir el artefacto: la APK podría estar sin firmar.

### Paso 7 — Verificación en el teléfono (imprescindible)

1. Instalar la APK del run post-rotación **encima de la instalación
   existente, sin desinstalar**.
2. Debe instalar y arrancar conservando partidas, ajustes y DLC.
3. Si Android rechaza la instalación por firma distinta: PARAR, no
   desinstalar. Significa que la llave cambió en algún punto (paso 2 mal
   verificado o secreto `CI_KEYSTORE_BASE64` con otro keystore). Volver al
   respaldo del §2.3 y repetir desde el paso 1.
4. Probar además un build full local con las variables nuevas exportadas
   (`tools/run-release-build-full-v141.sh`): debe firmar con `apksigner`
   sin pedir la contraseña antigua. Sin las variables, el script debe fallar
   al inicio con el mensaje claro de variable ausente (nunca dejar una APK
   sin firmar en silencio).

### Paso 8 — Limpieza (solo tras el paso 7 en verde)

1. Borrar el secreto legado `CI_KEYSTORE_PASSWORD` del repo.
2. Borrar la copia pre-rotación del §2.3 **solo si** se tiene por escrito en
   el gestor de contraseñas que la llave actual es la rotada y dónde está su
   respaldo. Recomendación: conservar UNA copia offline del keystore rotado
   (con sus contraseñas nuevas anotadas aparte) y destruir la copia con la
   contraseña antigua.
3. Re-generar los `.b64` de `private/` desde el archivo actualizado
   (`ci-release.jks.b64`, `ci-release-pretty.jks.b64` si se conserva alguno)
   para que los respaldos locales correspondan al archivo vigente.
4. Verificación final: `grep` en el repo (archivos + historial reciente) de
   los patrones de contraseña en claro debe dar 0 en el HEAD; la contraseña
   antigua sigue en el historial de git antiguo (ver §4), pero ya no abre
   ningún keystore vigente.

## 4. Lo que NO se puede deshacer: el historial de git

La contraseña antigua queda para siempre en los commits antiguos del repo
(estuvo público hasta 2026-11-14 y el historial ya la contiene). Reescribir el
historial (`filter-repo` / `filter-branch`) para borrarla:

- rompería todos los clones y copias locales (incluidas las de trabajo del
  coordinador y los árboles de auditoría),
- no borraría las copias que cualquiera haya podido hacer ya del repo,
- y no es necesario: **una vez rotada, la contraseña antigua no abre ningún
  keystore vigente**. Es un valor muerto.

Por eso este plan no incluye reescritura del historial. Lo que sí debe
hacerse es no volver a introducir nunca una contraseña en el repo (el
arreglo B lo impide por diseño: Gradle y los scripts solo leen variables de
entorno).

## 5. Qué pasa con los artefactos y APKs viejos

- **APKs ya distribuidas (firmadas con la llave corazón):** siguen siendo
  válidas. La misma llave las firmó y la misma llave firma las nuevas: no
  hay que re-firmarlas ni retirarlas.
- **Artefactos de Actions (retención 7 días):** caducan solos; no hace falta
  borrarlos a mano. Una APK vieja instalada encima de una nueva (o al revés)
  funciona igual, porque la firma es la misma llave.
- **Si alguna vez se filtrase el archivo `.jks` en sí:** ahí sí habría que
  generar una llave NUEVA, y entonces todos los usuarios tendrían que
  desinstalar y perder los datos (partidas en `<external>/data`, DLC
  instalados, caché). Por eso el `.jks` solo vive en el secreto
  `CI_KEYSTORE_BASE64`, en `private/` local y en la copia offline del §2.3,
  nunca en el repo ni en Drive compartido.

## 6. Si algo sale mal (rollback)

- **La rotación falla a mitad (paso 1-2):** descartar `/tmp/ci-release-nuevo.jks`.
  Nada cambió: el keystore vigente sigue siendo el antiguo y los secretos
  antiguos siguen en su sitio.
- **Los secretos ya se actualizaron pero el CI falla:** el secreto
  `CI_KEYSTORE_BASE64` puede revertirse al valor anterior (base64 del
  respaldo del §2.3) y las contraseñas a las antiguas; el workflow volvería
  a firmar como antes. Hacerlo solo si el paso 7 aún no se verificó en el
  teléfono.
- **Se pierde la contraseña nueva:** sin ella no se puede firmar nada más
  con esa llave. Recuperación: usar la copia pre-rotación del §2.3 (con la
  contraseña antigua) y repetir la rotación con otra contraseña nueva. Por
  eso el §2.3 es obligatorio, no opcional.

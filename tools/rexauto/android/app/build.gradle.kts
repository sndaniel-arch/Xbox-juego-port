plugins {
    id("com.android.application")
}

// Per-title identity, handed over by the workflow (or a local build):
//   -PrexName=scottpilgrim -PrexTitle="Scott Pilgrim vs. The World" -PrexTitleId=58410A2C
//   -PrexPortDir=/abs/path/autoports/<name>/port  -PrexSdkDir=/abs/path/rexglue-sdk
val rexName: String = (project.findProperty("rexName") as String?) ?: "game"
val rexTitle: String = (project.findProperty("rexTitle") as String?) ?: rexName
val rexTitleId: String = (project.findProperty("rexTitleId") as String?) ?: "00000000"
val rexPortDir: String = (project.findProperty("rexPortDir") as String?)
    ?: "${rootProject.projectDir.parentFile}/autoports/$rexName/port"
val rexSdkDir: String = (project.findProperty("rexSdkDir") as String?)
    ?: "${rootProject.projectDir}/sdk/rexglue-sdk"
// (A5-R7-02, ronda 7.) rexVersionCode has NO silent fallback: a missing
// -PrexVersionCode used to default to 1, and nothing verified the APK's
// real versionCode, so a FULL (or CI) APK could ship as versionCode 1 and
// refuse to install over any previous FULL (INSTALL_FAILED_VERSION_DOWNGRADE)
// while every guard stayed green. A local build without -PrexVersionCode
// now FAILS HERE, on purpose, with this message -- pass
// -PrexVersionCode=<run_number> (CI) or -PrexVersionCode=1010406 (FULL
// v1.4.6) explicitly. The workflow "Verify APK" step and the FULL script
// also check the built APK's versionCode with aapt2 dump badging.
val rexVersionCode: Int = (project.findProperty("rexVersionCode") as String?)
    ?.toIntOrNull()
    ?: throw GradleException("A5-R7-02: missing or non-numeric -PrexVersionCode (CI: -PrexVersionCode=<github.run_number>; FULL v1.4.6: -PrexVersionCode=1010406). Refusing the silent default versionCode 1: an APK built as 1 would not install over any previous FULL.")
val rexVersionName: String = (project.findProperty("rexVersionName") as String?) ?: "1.0"
// Full variant (private only, never CI): the game ships inside the APK as an
// asset and the launcher auto-imports it on first launch (-PrexFull=true).
val rexFull: Boolean = (project.findProperty("rexFull") as String?)?.toBoolean() ?: false

android {
    namespace = "com.rexauto.port"
    compileSdk = 35
    ndkVersion = "27.2.12479018"

    defaultConfig {
        applicationId = "com.rexauto.port.$rexName"
        minSdk = 28
        targetSdk = 35
        versionCode = rexVersionCode
        versionName = rexVersionName

        resValue("string", "app_name", rexTitle)
        buildConfigField("String", "GAME_TITLE", "\"${rexTitle.replace("\"", "\\\"")}\"")
        buildConfigField("String", "TITLE_ID", "\"$rexTitleId\"")
        buildConfigField("String", "PROJECT", "\"$rexName\"")
        buildConfigField("boolean", "FULL", rexFull.toString())

        ndk { abiFilters += "arm64-v8a" }

        externalNativeBuild {
            cmake {
                arguments += listOf(
                    "-DANDROID_STL=c++_shared",
                    "-DCMAKE_BUILD_TYPE=Release",
                    "-DREX_PROJECT_ROOT=${rootProject.projectDir.parentFile.absolutePath}",
                    "-DREXSDK_DIR=$rexSdkDir",
                    "-DREX_PORT_DIR=$rexPortDir",
                    "-DREX_APP_NAME=$rexName",
                )
                cppFlags += listOf("-std=c++23")
            }
        }
    }

    buildFeatures { buildConfig = true }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.31.1"
        }
    }

    sourceSets {
        getByName("main") {
            // title DB + per-title cover are staged by the workflow into app/src/main/assets
            assets.srcDirs("src/main/assets")
        }
    }

    // P1-7 (ronda 2, auditor B): las contraseñas del keystore NUNCA van en
    // este archivo. Se leen de variables de entorno (en CI, el workflow las
    // pasa desde los secretos CI_KEYSTORE_STORE_PASSWORD /
    // CI_KEYSTORE_KEY_PASSWORD; en local, se exportan antes de llamar a
    // Gradle, ver tools/run-release-build-*.sh). El alias también viene del
    // entorno (CI_KEYSTORE_KEY_ALIAS); por defecto "childoflight<3", el alias
    // del keystore corazón de este proyecto (ver docs/REXAUTo.md §6). CI y
    // los scripts siempre fijan la variable, así que el default solo afecta
    // a un `gradlew` directo en local.
    //
    // Fallback seguro: si el keystore existe pero faltan las variables, la
    // signing config "ci" NO se crea y el build release NO se firma (el
    // build en sí sigue configurando y corriendo: un build local sin
    // secretos no debe fallar en tiempo de configuración). La APK sin
    // firmar NO escapa: los scripts locales fallan antes (pre-chequeo del
    // keystore + apksigner verify) y el workflow la caza en el paso
    // "Verify APK" (apksigner verify falla el job). En CI el workflow
    // SIEMPRE fija estas variables desde los secretos (ronda 3, B-R3-1:
    // si CI_KEYSTORE_BASE64 falta, el job falla con ::error:: antes de
    // Gradle en vez de generar un keystore fresco), así que una APK de CI
    // nunca queda sin firmar por este fallback.
    val ciKeystoreFile = file("${rootProject.projectDir}/ci-release.jks")
    val ciStorePassword: String? = System.getenv("CI_KEYSTORE_STORE_PASSWORD")
    val ciKeyPassword: String? = System.getenv("CI_KEYSTORE_KEY_PASSWORD")
    // (Caza extra X-B-3, ronda 2.) El default era "rexauto" (upstream) y no
    // existe en el keystore corazón, así que un `gradlew` directo fallaba en
    // la firma; `?:` tampoco cubría una variable exportada vacía.
    val ciKeyAlias: String = System.getenv("CI_KEYSTORE_KEY_ALIAS")?.ifEmpty { null } ?: "childoflight<3"
    // Deterministic debug-style key so every CI APK of the same title can
    // be installed over the previous one (a fresh random debug key per
    // runner would force an uninstall each time).
    val ciSigningReady: Boolean = ciKeystoreFile.exists()
        && !ciStorePassword.isNullOrEmpty()
        && !ciKeyPassword.isNullOrEmpty()

    signingConfigs {
        if (ciSigningReady) {
            create("ci") {
                storeFile = ciKeystoreFile
                storePassword = requireNotNull(ciStorePassword)
                keyAlias = ciKeyAlias
                keyPassword = requireNotNull(ciKeyPassword)
            }
        }
        // else: no "ci" signing config at all (see the comment above).
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (ciSigningReady) {
                signingConfig = signingConfigs.getByName("ci")
            } else {
                // Signing disabled on purpose (see the comment above
                // signingConfigs): the build still runs, but the APK is
                // UNSIGNED. Local scripts and the workflow's Verify APK step
                // fail the build if the APK ends up unsigned.
                project.logger.warn("P1-7: release signing disabled -- CI_KEYSTORE_STORE_PASSWORD / CI_KEYSTORE_KEY_PASSWORD not set or ci-release.jks missing. The release APK will be UNSIGNED.")
            }
        }
        debug { isJniDebuggable = true }
    }

    packaging {
        jniLibs { useLegacyPackaging = true }
    }

    androidResources {
        // Full variant: the 1.5 GB game asset must stay uncompressed so the
        // VFS can open it by fd (AssetManager.openFd fails on compressed
        // entries) -- and aapt2 doesn't try to deflate 1.5 GB in this VM's RAM.
        // (Before Fase 5 this comment said "stream-copy it out": since v1.4
        // there is no stream-copy, the VFS mounts the STFS from inside the
        // APK. Hunt 2, P2-12.)
        noCompress += "stfs"
        // JPEGs are already compressed: deflating hero_bg.jpg gains nothing
        // and the compress task OOMs on this VM's 1 GB daemon heap (v1.2
        // rebuild, :app:compressReleaseAssets -> Java heap space).
        noCompress += "jpg"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

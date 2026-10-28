import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// ---- Configuración local (no se sube al repositorio) -------------------------------
// Orden de prioridad: variable de entorno > local.properties > valor por defecto.
val localProps = Properties().apply {
    val f = rootProject.file("local.properties")
    if (f.isFile) f.inputStream().use { load(it) }
}
fun cfg(name: String, default: String = ""): String =
    (System.getenv(name) ?: localProps.getProperty(name) ?: default).trim()

// Feed de firmas de amenazas (HTTPS). Vacío = actualización desactivada por defecto.
val threatFeedUrl = cfg("HYDRA_THREAT_FEED_URL", "https://raw.githubusercontent.com/hydraroot/Hydra_Firewall/threat-pack/hydra_threat_pack.json")
// Clave pública P-256 (X.509 DER en Base64) que verifica el pack. Vacío = clave original del proyecto.
val threatPublicKey = cfg("HYDRA_THREAT_PUBLIC_KEY", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENTRk3PVkMi+VV6Wx3K/Q1bskCvterMtBMY8kPTAuN1ME6p2HIdn/hv4fii7xFOpL9Ha5pqenDnT4u8UDWRb0Bg==")

android {
    namespace = "com.hydra.firewall"
    compileSdk = 35

    defaultConfig {
        // ID de la app instalada. OJO: cambiarlo hace que Android la vea como OTRA app (no actualiza la anterior).
        // El código sigue en el paquete com.hydra.firewall (namespace); solo cambia el ID instalable.
        applicationId = cfg("HYDRA_APPLICATION_ID", "com.hydraroot.firewall")
        // minSdk 24 (Android 7.0 Nougat): V1.1-legacy soporta API 24-28 mediante
        // el fallback /proc/net/* (ProcNetUidResolver) y API 29+ mediante
        // ConnectivityManager.getConnectionOwnerUid(). El despacho ocurre en
        // tiempo de ejecución según Build.VERSION.SDK_INT (ver UidResolver.kt).
        minSdk = 24
        targetSdk = 35
        versionCode = 161
        versionName = "1.5-beta6-final-r13-fix172"
        buildConfigField("String", "BUILD_LABEL", "\"Hydra Firewall - V1.5-beta6-final-r13\"")
        buildConfigField("String", "THREAT_FEED_URL", "\"${threatFeedUrl.replace("\"", "")}\"")
        buildConfigField("String", "THREAT_PUBLIC_KEY", "\"${threatPublicKey.replace("\"", "")}\"")
    }

    // Firma de release: define HYDRA_KEYSTORE_FILE, HYDRA_KEYSTORE_PASSWORD, HYDRA_KEY_ALIAS
    // y HYDRA_KEY_PASSWORD (entorno o local.properties). Sin keystore, release queda SIN firmar
    // (usá assembleDebug para probar en el celular).
    val ksFile = cfg("HYDRA_KEYSTORE_FILE")
    val hasReleaseKeystore = ksFile.isNotEmpty() && rootProject.file(ksFile).isFile
    signingConfigs {
        if (hasReleaseKeystore) {
            create("hydraRelease") {
                storeFile = rootProject.file(ksFile)
                storePassword = cfg("HYDRA_KEYSTORE_PASSWORD")
                keyAlias = cfg("HYDRA_KEY_ALIAS")
                keyPassword = cfg("HYDRA_KEY_PASSWORD").ifEmpty { cfg("HYDRA_KEYSTORE_PASSWORD") }
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (hasReleaseKeystore) signingConfig = signingConfigs.getByName("hydraRelease")
        }
        debug {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    testOptions {
        // DiagnosticLogger calls android.util.Log; return defaults instead of throwing in JVM unit tests.
        unitTests.isReturnDefaultValues = true
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.fragment:fragment-ktx:1.8.5")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.biometric:biometric:1.1.0")

    val composeBom = platform("androidx.compose:compose-bom:2024.10.01")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.foundation:foundation")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")


    testImplementation("junit:junit:4.13.2")
}

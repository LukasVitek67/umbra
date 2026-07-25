plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "org.umbra.umbra"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        applicationId = "org.umbra.umbra"
        // Tor needs API 21+; Flutter's floor is higher still.
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    packaging {
        jniLibs {
            // `tor` is a program, not a library: it has to be unpacked on disk
            // for us to execute it, so it cannot stay compressed in the APK.
            useLegacyPackaging = true
        }
    }

    buildTypes {
        release {
            // Debug keys for now — the release APK is signed for distribution by
            // tools/release.ps1 together with the desktop build.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}

dependencies {
    // The official tor daemon, built for Android by the Guardian Project (the
    // people behind Orbot). Ships as libtor.so for every ABI; we do not build
    // our own Tor, exactly as on the desktop.
    implementation("info.guardianproject:tor-android:0.4.9.11")
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}

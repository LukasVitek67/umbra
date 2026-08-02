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
            // Tink, underneath androidx.security-crypto, references Error Prone
            // annotations that are compile-time only; R8 cannot resolve them and
            // stops. See proguard-rules.pro for why not warning is the fix.
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }
}

dependencies {
    // The official tor daemon, built for Android by the Guardian Project (the
    // people behind Orbot). Ships as libtor.so for every ABI; we do not build
    // our own Tor, exactly as on the desktop.
    //
    // Pinned to the 0.4.8 line on purpose: from 0.4.9.5 on, the package demands
    // compileSdk 37, which needs an Android Gradle Plugin that cargokit cannot
    // build with yet (Gradle 9 dropped Project.exec()). Worth revisiting once
    // flutter_rust_bridge ships a cargokit that runs on Gradle 9.
    implementation("info.guardianproject:tor-android:0.4.8.22")

    // Holds a remembered passphrase in EncryptedSharedPreferences, keyed from
    // the Android Keystore. Done here rather than with a Flutter plugin because
    // the plugins for this ship a Windows implementation that needs Visual
    // Studio's ATL headers, and the Windows build neither has them nor wants
    // the code — see MainActivity.
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace  = "net.tunmux"
    compileSdk = 35

    defaultConfig {
        applicationId = "net.tunmux"
        minSdk        = 26
        targetSdk     = 35
        versionCode   = 1
        versionName   = "0.1.0"
        ndkVersion    = libs.versions.ndk.get()

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    buildTypes {
        debug   { }
        release { isMinifyEnabled = false }
    }

    buildFeatures { compose = true }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    kotlinOptions { jvmTarget = "11" }
}

apply(plugin = "org.mozilla.rust-android-gradle.rust-android")

configure<com.nishtahir.CargoExtension> {
    module  = "../rust-lib"
    libname = "tunmux_android"
    targets = listOf("arm64", "arm", "x86_64")
}

tasks.whenTaskAdded {
    if (name == "mergeDebugJniLibFolders" || name == "mergeReleaseJniLibFolders") {
        dependsOn("cargoBuild")
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.activity.compose)
    debugImplementation(libs.androidx.ui.tooling)
}

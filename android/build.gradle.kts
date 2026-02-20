buildscript {
    repositories {
        maven { url = uri("https://plugins.gradle.org/m2/") }
        google()
        mavenCentral()
    }
    dependencies {
        classpath("org.mozilla.rust-android-gradle:plugin:0.9.6")
    }
}

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.compose) apply false
}

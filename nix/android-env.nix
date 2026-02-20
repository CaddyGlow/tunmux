{ pkgs, android-sdk, buildToolsVersion, ndkVersion, minSdkVersion }:
let
  hostPlatform =
    if pkgs.stdenv.isLinux && pkgs.stdenv.isx86_64 then "linux-x86_64"
    else if pkgs.stdenv.isDarwin then "darwin-x86_64"
    else throw "Unsupported platform: ${pkgs.stdenv.hostPlatform.system}";

  sdkRoot      = "${android-sdk}/share/android-sdk";
  ndkRoot      = "${sdkRoot}/ndk/${ndkVersion}";
  toolchainDir = "${ndkRoot}/toolchains/llvm/prebuilt/${hostPlatform}/bin";
in
[
  { name = "JAVA_HOME";         value = "${pkgs.jdk17}"; }
  { name = "ANDROID_HOME";      value = sdkRoot; }
  { name = "ANDROID_SDK_ROOT";  value = sdkRoot; }
  { name = "ANDROID_NDK_ROOT";  value = ndkRoot; }
  { name = "ANDROID_NDK_HOME";  value = ndkRoot; }
  { name = "NDK_TOOLCHAIN_DIR"; value = toolchainDir; }
  { name = "GRADLE_OPTS";
    value = "-Dorg.gradle.project.android.aapt2FromMavenOverride=${sdkRoot}/build-tools/${buildToolsVersion}/aapt2"; }

  # aarch64
  { name = "AR_aarch64_linux_android";                  value = "${toolchainDir}/llvm-ar"; }
  { name = "CC_aarch64_linux_android";                  value = "${toolchainDir}/aarch64-linux-android${minSdkVersion}-clang"; }
  { name = "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"; value = "${toolchainDir}/aarch64-linux-android${minSdkVersion}-clang"; }

  # armv7
  { name = "AR_armv7_linux_androideabi";                   value = "${toolchainDir}/llvm-ar"; }
  { name = "CC_armv7_linux_androideabi";                   value = "${toolchainDir}/armv7a-linux-androideabi${minSdkVersion}-clang"; }
  { name = "CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER";  value = "${toolchainDir}/armv7a-linux-androideabi${minSdkVersion}-clang"; }

  # x86_64
  { name = "AR_x86_64_linux_android";                  value = "${toolchainDir}/llvm-ar"; }
  { name = "CC_x86_64_linux_android";                  value = "${toolchainDir}/x86_64-linux-android${minSdkVersion}-clang"; }
  { name = "CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER"; value = "${toolchainDir}/x86_64-linux-android${minSdkVersion}-clang"; }

  # i686
  { name = "AR_i686_linux_android";                  value = "${toolchainDir}/llvm-ar"; }
  { name = "CC_i686_linux_android";                  value = "${toolchainDir}/i686-linux-android${minSdkVersion}-clang"; }
  { name = "CARGO_TARGET_I686_LINUX_ANDROID_LINKER"; value = "${toolchainDir}/i686-linux-android${minSdkVersion}-clang"; }
]
++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
  { name = "LIBRARY_PATH"; value = "${pkgs.libiconv}/lib"; }
  { name = "CPATH";        value = "${pkgs.libiconv}/include"; }
  { name = "RUSTFLAGS";    value = "-L${pkgs.libiconv}/lib"; }
]

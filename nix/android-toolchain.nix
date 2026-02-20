{
  pkgs,
  nixpkgs,
  android-nixpkgs,
  system,
  common-toolchain,
}:
let
  versionsToml = builtins.fromTOML (builtins.readFile ../android/gradle/libs.versions.toml);
  versions = versionsToml.versions;

  compileSdkVersion = versions."compile-sdk";
  buildToolsVersion = versions."build-tools";
  minSdkVersion = versions."min-sdk";
  ndkVersion = versions.ndk;

  android-sdk = android-nixpkgs.sdk.${system} (
    sdkPkgs: with sdkPkgs; [
      (builtins.getAttr "platforms-android-${compileSdkVersion}" sdkPkgs)
      (builtins.getAttr "build-tools-${builtins.replaceStrings [ "." ] [ "-" ] buildToolsVersion}" sdkPkgs)
      # AGP's Java compile pipeline also requires build-tools 34 internally
      build-tools-34-0-0
      (builtins.getAttr "ndk-${builtins.replaceStrings [ "." ] [ "-" ] ndkVersion}" sdkPkgs)
      cmdline-tools-latest
      platform-tools
    ]
  );

  rust-toolchain = common-toolchain.rust-toolchain-base.override {
    extensions = [
      "rust-analyzer"
      "clippy"
      "rustfmt"
    ];
    targets = [
      "aarch64-linux-android"
      "armv7-linux-androideabi"
      "x86_64-linux-android"
      "i686-linux-android"
    ];
  };
in
{
  inherit
    android-sdk
    rust-toolchain
    buildToolsVersion
    ndkVersion
    minSdkVersion
    ;

  packages =
    common-toolchain.commonPackages
    ++ [
      android-sdk
      rust-toolchain
      pkgs.jdk17
      pkgs.gradle
    ]
    ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [ pkgs.libiconv ];
}

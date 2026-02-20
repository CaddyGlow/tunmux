{ pkgs, android-toolchain }:
pkgs.devshell.mkShell {
  name = "tunmux-android";
  inherit (android-toolchain) packages;

  env = import ./android-env.nix {
    inherit pkgs;
    inherit (android-toolchain) android-sdk buildToolsVersion ndkVersion minSdkVersion;
  };

  devshell.startup.prepare.text = ''
    export FLAKE_ROOT=$(git rev-parse --show-toplevel)
    export ANDROID_ROOT="$FLAKE_ROOT/android"
    # Write local.properties so Gradle finds the SDK.
    # ndk.dir is intentionally omitted -- ndkVersion in build.gradle.kts + ANDROID_NDK_ROOT handle NDK location.
    cat > "$ANDROID_ROOT/local.properties" <<EOF
sdk.dir=$ANDROID_HOME
EOF
  '';

  commands = [
    { name = "build-debug";   command = "$ANDROID_ROOT/gradlew -p $ANDROID_ROOT assembleDebug"; }
    { name = "build-release"; command = "$ANDROID_ROOT/gradlew -p $ANDROID_ROOT assembleRelease"; }
    { name = "install-debug"; command = "$ANDROID_ROOT/gradlew -p $ANDROID_ROOT installDebug"; }
    { name = "gradle-wrapper";
      command = "gradle -p $ANDROID_ROOT wrapper --gradle-version 8.9"; }
    { name = "cargo-build-android";
      command = "cargo build --target aarch64-linux-android --package tunmux-android \"$@\""; }
  ];
}

let
  pkgs = import <nixpkgs> { config = { android_sdk.accept_license = true; allowUnfree = true; }; };
  android = pkgs.androidenv.composeAndroidPackages {
    platformVersions = [ "35" ];
    includeEmulator = true;
    includeSystemImages = true;
    systemImageTypes = [ "default" ];   # AOSP image, no Google Play
    abiVersions = [ "x86_64" ];
    includeNDK = false;
  };
in android.androidsdk

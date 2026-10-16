{ pkgs ? import <nixpkgs> {} }:
pkgs.renode-unstable.overrideAttrs (old: {
  version = "1.17.0-unstable-2026-10-16";
  src = pkgs.fetchFromGitHub {
    owner = "renode";
    repo = "renode";
    rev = "4c0d973e83addd2d60b2d12139015fbb4a7fc7d0";   # infra aa26d0d -> tlib 5eafb5d (renode#884 fix)
    hash = "sha256-Xu8GycCSqjjh+2tLufk8wQeE3aU+IO0XXRcyc1kAH8M=";
    fetchSubmodules = true;
  };
  # only the Cortex-M core (nRF52840); the other 15 cores are unused here
  preBuild = builtins.replaceStrings
    [ "CORES=(arm.le arm.be arm64.le arm-m.le arm-m.be ppc.le ppc.be ppc64.le ppc64.be i386.le x86_64.le riscv.le riscv64.le sparc.le sparc.be xtensa.le)" ]
    [ "CORES=(arm-m.le)" ] old.preBuild;
})

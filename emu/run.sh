#!/usr/bin/env bash
# MeshCore L1 companion emulation: real S140 + firmware in Renode, the stock MeshCore
# Android app in the Android emulator, joined over emulated BLE. See README.md.
#
#   run.sh render                 expand src/ templates into local/ (absolute paths)
#   run.sh build-renode           fetch the pinned Renode, apply the patch, build (~10 min)
#   run.sh node <name> [elf] [internal-fs.bin]   write local/emu/<name>.resc
#   run.sh air <name>...          run Renode: Zephyr HCI controller + the named nodes
#                                 (foreground; HCI on local/emu/hci.pty)
#   run.sh android                (re)start the HCI shim + Android emulator, wait for BT
#   run.sh connect [name]         open the app, connect, pair with the node's PIN
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$HERE/local
E=$ROOT/emu
ELF_DEFAULT=$HERE/../.pio/build/WioTrackerL1_companion_radio_ble_5k_emu/firmware.elf
RENODE_REV=4c0d973e83addd2d60b2d12139015fbb4a7fc7d0

render() {
  mkdir -p "$E/host" "$ROOT/android"
  (cd "$HERE/src" && find . -type f) | while read -r f; do
    sed "s#__ROOT__#$ROOT#g" "$HERE/src/$f" > "$ROOT/$f"
    case "$f" in *.sh|*.py) chmod +x "$ROOT/$f" ;; esac
  done
  [ -f "$E/ff1m.bin" ] || head -c $((0x100000)) /dev/zero | tr '\0' '\377' > "$E/ff1m.bin"
  [ -f "$E/ff4k.bin" ] || head -c 4096 /dev/zero | tr '\0' '\377' > "$E/ff4k.bin"
  [ -e "$ROOT/android/sdk" ] || nix-build "$ROOT/android/sdk.nix" -o "$ROOT/android/sdk"
  local missing=0
  for f in emu/s140_7.3.0_mbr_sd.hex emu/zephyr-hci-uart.elf android/meshcore.apk; do
    [ -f "$ROOT/$f" ] || { echo "missing local/$f (see README.md, 'Inputs')"; missing=1; }
  done
  [ -x "$E/renode-src/renode" ] || echo "Renode not built yet: run.sh build-renode"
  return $missing
}

build_renode() {
  local R=$E/renode-src
  if [ ! -d "$R" ]; then
    git clone --recurse-submodules https://github.com/renode/renode "$R"
    git -C "$R" checkout "$RENODE_REV"
    git -C "$R" submodule update --init --recursive
    git -C "$R/src/Infrastructure" apply "$E/renode-nrf52-ble.patch"
  fi
  (cd "$R" && nix-shell -p dotnet-sdk_8 cmake gcc gnumake python3 which --run ./build.sh)
}

node() {
  local name=$1 elf=${2:-$ELF_DEFAULT} ifs=${3:--}
  "$E/mcnode.sh" "$name" "$(realpath "$elf")" "$ifs" > "$E/$name.resc"
  echo "wrote $E/$name.resc"
}

air() {
  {
    echo 'emulation CreateBLEMedium "wireless"'
    echo "emulation CreateUartPtyTerminal \"hcipty\" \"$E/hci.pty\" true"
    echo 'emulation SetGlobalQuantum "0.00001"'
    echo "logFile @$E/renode.log true"
    echo 'logLevel 2'
    echo 'mach create "ctrl"'
    echo "machine LoadPlatformDescription @$E/nrf52840-local.repl"
    echo 'connector Connect sysbus.radio wireless'
    echo 'connector Connect sysbus.uart1 hcipty'
    echo "sysbus LoadELF @$E/zephyr-hci-uart.elf"
    echo "sysbus.uart0 CreateFileBackend @$E/ctrl-uart0.log true"
    for n in "$@"; do
      [ -f "$E/$n.resc" ] || node "$n" >&2
      echo "include @$E/$n.resc"
    done
    echo 'start'
  } > "$E/air.resc"
  rm -f "$E/hci.pty"
  # Renode's console exits on stdin EOF: keep it open
  sleep infinity | nix-shell -p dotnet-sdk_8 --run "$E/renode-src/renode --console --disable-gui -e 'include @$E/air.resc'"
}

case "${1:-}" in
  render) render ;;
  build-renode) build_renode ;;
  node) shift; node "$@" ;;
  air) shift; air "$@" ;;
  android) WAIT=${WAIT:-15} "$E/host/cycle.sh" ;;
  connect) CDC="$E/${2:-node1}-cdc.log" "$ROOT/android/app-connect.sh" ;;
  *) sed -n '2,13p' "$0"; exit 2 ;;
esac

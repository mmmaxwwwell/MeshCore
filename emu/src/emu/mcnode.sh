#!/usr/bin/env bash
# mcnode.sh <machine-name> <firmware.elf> [internal-fs.bin|-] [qspi.img] > node.resc
# Emits a Renode script for one MeshCore Wio Tracker L1 node (real S140 + app).
# - FICR: <dir>/<name>-ficr.bin, generated from the name on first use (gen-ficr.py), so
#   each node has its own BLE address and root keys, stable across runs.
# - Internal flash: blank by default (the firmware formats it and mints a new identity);
#   pass a dump of 0xD4000.. to start from an existing node's state.
# - QSPI flash: backed by qspi.img (default <dir>/<name>-qspi.img), loaded if present
#   and autosaved while the node runs. Delete it to start from blank flash.
set -eu
NAME=$1 ELF=$2 IFS_IMG=${3:--}
E=$(cd "$(dirname "$0")" && pwd)
FICR=$E/$NAME-ficr.bin
[ -f "$FICR" ] || python3 "$E/gen-ficr.py" "$NAME" "$FICR"
QSPI_IMG=${4:-$E/$NAME-qspi.img}
NM="nix shell nixpkgs#gcc-arm-embedded -c arm-none-eabi-nm"
sym() { $NM -C "$ELF" | awk -v s="$1" 'index($0, s) { print "0x" $1; exit }'; }
HEX=${ELF%.elf}.hex
CDCW=$(sym 'Adafruit_USBD_CDC::write(unsigned char const*, unsigned int)')
CDC1=$(sym 'Adafruit_USBD_CDC::write(unsigned char)')
TICKLESS=$(sym 'vPortSuppressTicksAndSleep')
TICKLESS2=$(printf "0x%x" $((TICKLESS + 2)))
ERRCB=$(sym 'nrf_error_cb(unsigned long, unsigned long, unsigned long)')
LOG=$E/$NAME-cdc.log
cat <<R
mach create "$NAME"
machine LoadPlatformDescription @$E/wio-l1.repl
sysbus LoadBinary @$E/ff1m.bin 0x0
R
[ "$IFS_IMG" != - ] && echo "sysbus LoadBinary @$IFS_IMG 0xD4000"
cat <<R
sysbus LoadBinary @$E/ff4k.bin 0x10001000
sysbus LoadBinary @$FICR 0x10000000
sysbus LoadHEX @$E/s140_7.3.0_mbr_sd.hex
sysbus LoadHEX @$HEX
sysbus LoadSymbolsFrom @$ELF
R
echo "qspi ImagePath \"$QSPI_IMG\""
PATH=$(nix shell nixpkgs#gcc-arm-embedded -c sh -c 'dirname $(command -v arm-none-eabi-nm)'):$PATH python3 $E/cc310_hooks.py "$ELF"
cat <<R
# tickless idle: replace vPortSuppressTicksAndSleep with "wfi; bx lr" (sleep until the
# next interrupt, RTC1 tick keeps running); a Python hook here ran on every idle pass
sysbus WriteWord $TICKLESS 0xBF30
sysbus WriteWord $TICKLESS2 0x4770
cpu AddHook $CDCW "f = open('$LOG', 'ab'); f.write(bytes(bytearray(machine.SystemBus.ReadBytes(self.GetRegister(1).RawValue, int(self.GetRegister(2).RawValue))))); f.close()"
cpu AddHook $CDC1 "f = open('$LOG', 'ab'); f.write(bytes(bytearray([int(self.GetRegister(1).RawValue) & 0xff]))); f.close()"
cpu AddHook $ERRCB "self.ErrorLog('CRASH nrf_error_cb id=0x%x pc=0x%x' % (self.GetRegister(0).RawValue, self.GetRegister(1).RawValue))"
cpu VectorTableOffset 0x0
sysbus.clock VbusPresent false
sysbus.uart0 CreateFileBackend @$E/$NAME-uart0.log true
connector Connect sysbus.radio wireless
R

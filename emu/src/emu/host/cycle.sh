#!/usr/bin/env bash
# restart HCI shim + Android emulator, wait for boot, report BT state and fatal aborts
S=__ROOT__; E=$S/emu; A=$S/android; . $A/env.sh
adb emu kill >/dev/null 2>&1
[ -f $E/host/shim.pid ] && kill $(cat $E/host/shim.pid) 2>/dev/null
for i in $(seq 30); do pgrep -x qemu-system-x86 >/dev/null || pgrep -f qemu-system-x86_64-headless >/dev/null || break; sleep 1; done
PY=$(nix build --no-link --print-out-paths --impure --expr 'with import (builtins.getFlake "nixpkgs") {}; python3.withPackages (p: [p.bumble])')/bin/python3
PYTHONUNBUFFERED=1 setsid $PY $E/host/hcishim.py android-netsim:_:8877,mode=controller serial:$E/hci.pty,1000000 > $E/host/shim.log 2>&1 < /dev/null &
echo $! > $E/host/shim.pid
sleep 6
setsid emulator -avd mc -no-window -no-audio -no-boot-anim -no-snapshot -gpu swiftshader_indirect -packet-streamer-endpoint localhost:8877 > $A/emulator.log 2>&1 < /dev/null &
sleep 10; timeout 300 adb wait-for-device
for i in $(seq 150); do [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] && break; sleep 2; done
sleep ${WAIT:-40}
echo "== shim"; grep -v -E 'cmd 0x|Unexpected request' $E/host/shim.log | sort | uniq -c | sort -rn | head -20
echo "== bt"; adb shell dumpsys bluetooth_manager | grep -E '^ *(state|enabled):' | head -2
echo "== fatal"; adb logcat -d -b all | grep -E 'F bluetooth|Abort message' | sort | uniq -c | tail -5 | cut -c1-250

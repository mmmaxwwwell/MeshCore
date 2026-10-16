#!/usr/bin/env bash
# Open the MeshCore app, connect to the emulated node, and complete PIN pairing.
# The PIN comes from the firmware's BOOT_TRACE line "DBG ble pin NNNNNN".
S=$(cd "$(dirname "$0")/.." && pwd); . $S/android/env.sh; . $S/android/ui.sh
CDC=${CDC:-$S/emu/rover-cdc.log}
PIN=$(tr -d '\r' < $CDC | sed -n 's/^DBG ble pin \([0-9]*\)/\1/p' | tail -1)
echo "pin=$PIN"
# forget earlier emulated bonds (every emulated node uses Rover's FICR, so one address)
if [ "${KEEP_BONDS:-}" = "" ]; then
  adb root >/dev/null 2>&1; sleep 2
  adb shell 'cmd bluetooth_manager disable; sleep 3; rm -f /data/misc/bluedroid/bt_config.conf /data/misc/bluedroid/bt_config.bak; cmd bluetooth_manager enable' >/dev/null 2>&1
  sleep 8
fi
adb shell am force-stop com.liamcottle.meshcore.android
adb shell monkey -p com.liamcottle.meshcore.android -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
sleep 10; tap_text 'text="Wait"' >/dev/null; sleep 1
tap_text 'Connect'; sleep 12; tap_text 'MeshCore-'
n0=$(grep -c 'passkey request' $CDC)
for i in $(seq 90); do [ "$(grep -c 'passkey request' $CDC)" -gt "$n0" ] && break; sleep 1; done
echo "passkey requested after ${i}s"
for i in $(seq 20); do
  adb shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1
  adb shell cat /sdcard/ui.xml | grep -q -i 'Pair with' && break
  # Android posts the request as a notification when it decides not to pop a dialog
  if [ $i = 4 ]; then adb shell cmd statusbar expand-notifications; sleep 2; tap_text 'Pairing request' || tap_text 'pair'; fi
  sleep 1
done
adb shell input text "$PIN"; sleep 1; tap_text 'text="OK"' || tap_text 'text="Pair"'

# source me: tap_text "<text>" taps the centre of the first node whose text/desc contains it
tap_text() {
  adb shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1
  local b; b=$(adb shell cat /sdcard/ui.xml | tr '>' '\n' | grep -F "$1" | grep -o 'bounds="[^"]*"' | head -1)
  [ -z "$b" ] && { echo "no node: $1"; return 1; }
  set -- $(echo "$b" | grep -o '[0-9]\+')
  adb shell input tap $(( ($1+$3)/2 )) $(( ($2+$4)/2 )); echo "tapped ($(( ($1+$3)/2 )),$(( ($2+$4)/2 )))"
}
screen_text() { adb shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1; adb shell cat /sdcard/ui.xml | grep -o 'text="[^"]\+"' | sort -u; }

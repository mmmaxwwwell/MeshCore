#pragma once
// Debug only (RAM_TRACE): breadcrumbs kept in RAM, printed by a FreeRTOS timer whenever a USB
// host raises DTR. Lets a boot that ran with NO reader attached be inspected afterwards,
// even if the loop task is stuck (the timer task is separate).
#if defined(NRF52_PLATFORM) && defined(RAM_TRACE)
#include <Arduino.h>
#include <Adafruit_TinyUSB.h>
#include <utility/debug.h>
namespace RamTrace {
  extern char buf[4096];
  extern volatile int len;
  inline void add(const char* s) {
    char line[110];
    int n = snprintf(line, sizeof(line), "[%lu] heap %d/%d %s\n", (unsigned long)millis(), dbgHeapUsed(), dbgHeapTotal(), s);
    if (len + n < (int)sizeof(buf)) { memcpy(buf + len, line, n); len += n; }
  }
  inline void tick(TimerHandle_t) {
    static int sent = -1;   // -1 = not connected
    if (!tud_cdc_connected()) { sent = -1; return; }
    if (sent < 0) sent = 0;
    if (sent < len) { sent += tud_cdc_write(buf + sent, len - sent); tud_cdc_write_flush(); }
  }
  inline void begin() {
    static TimerHandle_t t = NULL;
    if (!t) { t = xTimerCreate("rtrace", pdMS_TO_TICKS(20), pdTRUE, NULL, tick); if (t) xTimerStart(t, 0); }
  }
}
#define RTRACE(s) RamTrace::add(s)
#else
#define RTRACE(s)
#endif

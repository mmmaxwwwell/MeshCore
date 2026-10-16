#pragma once
// USB serial must never stall the firmware. Adafruit_USBD_CDC::write() loops for as long as the
// host holds DTR up: a host that opened the port and does not read (seen from a Linux laptop)
// fills the TX FIFO and the next print blocks forever -- in setup() that is a watchdog reset
// every 60 s, with BLE never started. A FreeRTOS timer drops the TX FIFO once it has been full
// for CDC_GUARD_STUCK_MS, so the blocked writer moves on (that output is lost; the radio isn't).
#if defined(NRF52_PLATFORM) && defined(USB_CDC_GUARD)
#include <Arduino.h>
#include <Adafruit_TinyUSB.h>

#ifndef CDC_GUARD_STUCK_MS
  #define CDC_GUARD_STUCK_MS  2000
#endif

namespace CdcGuard {
  inline void tick(TimerHandle_t) {
    static uint32_t full_ticks = 0;
    if (tud_cdc_connected() && tud_cdc_write_available() == 0) {
      if (++full_ticks * 500 >= CDC_GUARD_STUCK_MS) {
        tud_cdc_write_clear();
        full_ticks = 0;
      }
    } else {
      full_ticks = 0;
    }
  }
  inline void begin() {   // before anything prints
    static TimerHandle_t t = NULL;
    if (t == NULL) {
      t = xTimerCreate("cdcguard", pdMS_TO_TICKS(500), pdTRUE, NULL, tick);
      if (t) xTimerStart(t, 0);
    }
  }
}
#endif

#pragma once
// Crash-loop guard for nRF52 builds whose radio sits where nobody can double-tap reset.
//
//  - A hardware watchdog (SAFE_BOOT_WDT_SECS) resets a hung firmware.
//  - GPREGRET2 counts boots that never reached SAFE_BOOT_HEALTHY_MS of uptime. It survives soft,
//    pin and watchdog resets; only power-on clears it (the UF2 bootloader uses GPREGRET only).
//  - SAFE_BOOT_MAX_FAILS unhealthy boots in a row -> straight into the UF2 bootloader, so a
//    broken build can be replaced over USB without touching the board.
//
// The bootloader feeds a running watchdog (Adafruit bootloader.c). A watchdog survives soft
// resets, so a firmware without it flashed afterwards gets one watchdog reset, which stops it.
#ifdef NRF52_PLATFORM
#include <Arduino.h>
#include <nrf_soc.h>

#ifndef SAFE_BOOT_WDT_SECS
  #define SAFE_BOOT_WDT_SECS   60
#endif
#ifndef SAFE_BOOT_HEALTHY_MS
  #define SAFE_BOOT_HEALTHY_MS 30000
#endif
#ifndef SAFE_BOOT_MAX_FAILS
  #define SAFE_BOOT_MAX_FAILS  3
#endif
#define SAFE_BOOT_UF2_MAGIC    0x57   // DFU_MAGIC_UF2_RESET

namespace SafeBoot {
  inline bool sdEnabled() { uint8_t en = 0; sd_softdevice_is_enabled(&en); return en; }

  // call first thing in setup(), before the SoftDevice is enabled
  inline void begin() {
    uint8_t fails = NRF_POWER->GPREGRET2;
    if (fails >= SAFE_BOOT_MAX_FAILS) {
      NRF_POWER->GPREGRET2 = 0;
      NRF_POWER->GPREGRET = SAFE_BOOT_UF2_MAGIC;
      NVIC_SystemReset();
    }
    NRF_POWER->GPREGRET2 = fails + 1;
    if (!NRF_WDT->RUNSTATUS) {
      NRF_WDT->CONFIG = (WDT_CONFIG_SLEEP_Run << WDT_CONFIG_SLEEP_Pos) | (WDT_CONFIG_HALT_Pause << WDT_CONFIG_HALT_Pos);
      NRF_WDT->CRV = SAFE_BOOT_WDT_SECS * 32768;
      NRF_WDT->RREN = WDT_RREN_RR0_Msk;
      NRF_WDT->TASKS_START = 1;
    }
  }

  inline void feed() { NRF_WDT->RR[0] = WDT_RR_RR_Reload; }   // harmless while not running

  // call every loop() pass
  inline void loop() {
    static bool healthy = false;
    feed();
    if (!healthy && millis() > SAFE_BOOT_HEALTHY_MS) {
      healthy = true;
      if (sdEnabled()) sd_power_gpregret_clr(1, 0xFF);
      else NRF_POWER->GPREGRET2 = 0;
    }
  }
}
#endif

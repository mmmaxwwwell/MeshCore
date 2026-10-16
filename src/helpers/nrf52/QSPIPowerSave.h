#pragma once
// Powers the QSPI flash path down between filesystem bursts (nRF52840 + LittleFS on QSPI).
// A QSPI peripheral left active draws ~1-2 mA in sleep (nRF52840 anomaly 122). Each access
// re-activates it; QSPI_IDLE_MS after the last one, loop() deactivates the peripheral with the
// 122 workaround. The flash chip itself stays in standby (see sleep()).
#if defined(NRF52_PLATFORM) && (defined(QSPI_POWERSAVE) || defined(QSPI_RELEASE_DPD_AT_BOOT))
#include <Arduino.h>
// The flash chip keeps its power across MCU resets: if it was left in deep power-down (by our
// own sleep, or by another firmware -- Meshtastic powers it down), it never answers the status
// poll that QSPI activation waits on and nrfx_qspi_init() times out (0x0BAD0007). Bit-bang the
// release command on the QSPI pins before the driver's begin().
void qspiReleaseDeepPowerDown();
#endif
#if defined(NRF52_PLATFORM) && defined(QSPI_POWERSAVE)
#include <Adafruit_LittleFS.h>

#ifndef QSPI_IDLE_MS
  #define QSPI_IDLE_MS  50
#endif

namespace QSPIPowerSave {
  void install(Adafruit_LittleFS& fs);   // after the filesystem's begin()
  void loop();
  uint32_t sleeps();                     // times powered down (a proof-of-path counter)
}
#endif

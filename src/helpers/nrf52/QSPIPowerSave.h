#pragma once
// Powers the QSPI flash path down between filesystem bursts (nRF52840 + LittleFS on QSPI).
// A QSPI peripheral left active draws ~1-2 mA in sleep (nRF52840 anomaly 122). Each access
// wakes it (activate + release the chip from deep power-down); QSPI_IDLE_MS after the last one,
// loop() puts the chip in deep power-down and deactivates the peripheral with the 122 workaround.
#if defined(NRF52_PLATFORM) && defined(QSPI_POWERSAVE)
#include <Arduino.h>
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

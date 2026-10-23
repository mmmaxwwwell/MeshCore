#pragma once

#include <MeshCore.h>
#include <Arduino.h>
#include <helpers/nrf54/NRF54Board.h>
#include <nrf54l15_hal.h>

// XIAO nRF54L15: no PMIC (unlike the LM20A's nPM1300). VBAT is a divider on P1.14 that the core
// switches on (P1.15) only for the sampling window; the charger is a hardware one with no status pin.
class XiaoNrf54L15Board : public NRF54Board {
public:
  XiaoNrf54L15Board() : NRF54Board("XIAO_NRF54_OTA") { }

  void begin() override {
    NRF54Board::begin();
#if defined(P_LORA_TX_LED)
    pinMode(P_LORA_TX_LED, OUTPUT);
    digitalWrite(P_LORA_TX_LED, HIGH);   // active low: off
#endif
  }

#if defined(P_LORA_TX_LED)
  void onBeforeTransmit() override {
    digitalWrite(P_LORA_TX_LED, LOW);   // turn TX LED on
  }
  void onAfterTransmit() override {
    digitalWrite(P_LORA_TX_LED, HIGH);   // turn TX LED off
  }
#endif

  uint16_t getBattMilliVolts() override {
    int32_t mv = 0;
    if (!xiao_nrf54l15::BoardControl::sampleBatteryMilliVolts(&mv) || mv < 0) return 0;
    return mv > 0xFFFF ? 0xFFFF : (uint16_t)mv;
  }

  const char* getManufacturerName() const override {
    return "Seeed Xiao-nrf54l15";
  }
};

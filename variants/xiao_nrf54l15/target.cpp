#include <Arduino.h>
#include "target.h"
#include <helpers/ArduinoHelpers.h>

XiaoNrf54L15Board board;

RADIO_CLASS radio = new Module(P_LORA_NSS, P_LORA_DIO_1, P_LORA_RESET, P_LORA_BUSY, SPI);

WRAPPER_CLASS radio_driver(radio, board);

VolatileRTCClock rtc_clock;  // no I2C bus for an external RTC

SensorManager sensors;

#ifdef P_LORA2_NSS
SX1262 radio2 = new Module(P_LORA2_NSS, P_LORA2_DIO_1, P_LORA2_RESET, P_LORA2_BUSY, SPI);
bool radio2_ok = false;

// Same module setup as radio 1 (Wio-SX1262: TCXO on DIO3, DIO2 + RXEN switch),
// then standby: nothing transmits or listens until the app says so.
static bool radio2_init() {
  pinMode(P_LORA2_NSS, OUTPUT);
  digitalWrite(P_LORA2_NSS, HIGH);   // deselected while radio 1 owns the bus
  int16_t st = radio2.begin(LORA2_FREQ, 125.0, 9, 7, RADIOLIB_SX126X_SYNC_WORD_PRIVATE, 0, 8, SX126X_DIO3_TCXO_VOLTAGE);
  if (st != RADIOLIB_ERR_NONE) {
    MESH_DEBUG_PRINTLN("radio2: init failed: %d", st);
    return false;
  }
  radio2.setCurrentLimit(SX126X_CURRENT_LIMIT);
  radio2.setDio2AsRfSwitch(true);
  radio2.setRfSwitchPins(P_LORA2_RXEN, RADIOLIB_NC);
  radio2.standby();
  return true;
}
#endif

bool radio_init() {
  bool ok = radio.std_init(&SPI);   // also starts the shared SPI bus
#ifdef P_LORA2_NSS
  if (ok) radio2_ok = radio2_init();
#endif
  return ok;
}

mesh::LocalIdentity radio_new_identity() {
  RadioNoiseListener rng(radio);
  return mesh::LocalIdentity(&rng); // create new random identity
}

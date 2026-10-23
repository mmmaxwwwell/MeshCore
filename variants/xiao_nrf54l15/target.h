#pragma once

#define RADIOLIB_STATIC_ONLY 1
#include <RadioLib.h>
#include <helpers/radiolib/RadioLibWrappers.h>
#include <XiaoNrf54L15Board.h>
#include <helpers/radiolib/CustomSX1262Wrapper.h>
#include <helpers/ArduinoHelpers.h>
#include <helpers/SensorManager.h>

extern XiaoNrf54L15Board board;
extern WRAPPER_CLASS radio_driver;
extern VolatileRTCClock rtc_clock;
extern SensorManager sensors;

bool radio_init();

#ifdef P_LORA2_NSS
// A second SX1262, owned by whatever the app builds on it (not MeshCore's radio):
// initialised by radio_init() after radio 1, then left in standby. Optional:
// radio2_ok is false if it did not answer, and radio 1 still runs.
extern SX1262 radio2;
extern bool radio2_ok;
#endif
mesh::LocalIdentity radio_new_identity();

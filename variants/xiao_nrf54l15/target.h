#pragma once

#define RADIOLIB_STATIC_ONLY 1
#include <RadioLib.h>
#include <helpers/radiolib/RadioLibWrappers.h>
#include <XiaoNrf54L15Board.h>
#include <helpers/radiolib/CustomSX1262Wrapper.h>
#include <helpers/ArduinoHelpers.h>
#include <helpers/SensorManager.h>
#include "RadioRoles.h"

// MeshCore's radio, re-pointable at boot: the mesh role may sit on either SX1262.
class MeshRadioWrapper : public CustomSX1262Wrapper {
public:
  MeshRadioWrapper(CustomSX1262& radio, mesh::MainBoard& board) : CustomSX1262Wrapper(radio, board) { }
  void bindTo(CustomSX1262& radio) { _radio = &radio; }   // before the mesh starts
};

extern XiaoNrf54L15Board board;
extern MeshRadioWrapper radio_driver;
extern VolatileRTCClock rtc_clock;
extern SensorManager sensors;

// Radio roles (RadioRoles.h): radio_init() reads the saved map, puts MeshCore on
// its `mesh` radio (the other SX1262 if that one does not answer) and brings the
// `aux` radio up in standby for the app. The `radio` CLI command changes the map.
extern RadioRolesState radio_roles;   // saved map + what this boot runs
SX1262* aux_lora();              // the aux role's SX1262, if it is one and it answered; else NULL

bool radio_init();
mesh::LocalIdentity radio_new_identity();

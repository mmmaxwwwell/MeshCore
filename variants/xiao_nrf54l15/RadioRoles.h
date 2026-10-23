#pragma once

#include <stdint.h>

// Which radio does which job. Radios: the Wio-SX1262 on the header (lora1), an
// optional second SX1262 on the spare pins (lora2, builds with P_LORA2_NSS), and
// the nRF54's own 2.4 GHz radio (rf24: Nordic proprietary 1/2/4 Mbit, nRF24
// class; it takes turns with BLE, the core gives the RADIO to one owner at a
// time). Roles: mesh (MeshCore) and aux (whatever the app runs: voice, bursts,
// another protocol). The map lives in its own RRAM page, readable before the
// filesystem is up and kept across firmware updates and FS formats.
enum RadioId : uint8_t { RADIO_LORA1 = 0, RADIO_LORA2 = 1, RADIO_RF24 = 2, RADIO_NONE = 0xFF };

struct RadioRoles {
  uint8_t mesh;   // RadioId
  uint8_t aux;    // RadioId
};

struct RadioRolesState {
  RadioRoles saved;    // the map (defaults if none saved)
  RadioRoles running;  // this boot
  bool mesh_fallback;  // the saved mesh radio did not answer: mesh runs on the other SX1262
  bool aux_ok;         // the aux radio answered (always true for rf24 / none)
};

#define RADIO_ROLES_ADDR   0x14A000UL   // free RRAM page (arch/nrf54l/ldscripts/xiao_nrf54l15_bootloader.ld)
#define RADIO_ROLES_MAGIC  0x50414D52UL // "RMAP"

const char* radioName(uint8_t id);
bool radioParse(const char* s, uint8_t* id);
RadioRoles radioRolesDefault();
RadioRoles radioRolesLoad();               // the saved map, or the defaults
bool radioRolesSave(const RadioRoles& r);

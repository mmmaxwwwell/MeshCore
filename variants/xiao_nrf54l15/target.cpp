#include <Arduino.h>
#include "target.h"
#include <helpers/ArduinoHelpers.h>
#include <helpers/nrf54/NRF54Rram.h>

XiaoNrf54L15Board board;

RADIO_CLASS radio = new Module(P_LORA_NSS, P_LORA_DIO_1, P_LORA_RESET, P_LORA_BUSY, SPI);   // lora1
#ifdef P_LORA2_NSS
RADIO_CLASS lora2 = new Module(P_LORA2_NSS, P_LORA2_DIO_1, P_LORA2_RESET, P_LORA2_BUSY, SPI);
#endif

MeshRadioWrapper radio_driver(radio, board);

VolatileRTCClock rtc_clock;  // no I2C bus for an external RTC

SensorManager sensors;

RadioRolesState radio_roles;
static CustomSX1262* mesh_lora = &radio;
static CustomSX1262* aux_sx = NULL;

// ---------------------------------------------------------------- the map

const char* radioName(uint8_t id) {
  switch (id) {
    case RADIO_LORA1: return "lora1";
    case RADIO_LORA2: return "lora2";
    case RADIO_RF24:  return "rf24";
    default:          return "off";
  }
}

bool radioParse(const char* s, uint8_t* id) {
  if (strcmp(s, "lora1") == 0) *id = RADIO_LORA1;
  else if (strcmp(s, "lora2") == 0) *id = RADIO_LORA2;
  else if (strcmp(s, "rf24") == 0) *id = RADIO_RF24;
  else if (strcmp(s, "off") == 0) *id = RADIO_NONE;
  else return false;
  return true;
}

static bool haveLora2() {
#ifdef P_LORA2_NSS
  return true;
#else
  return false;
#endif
}

RadioRoles radioRolesDefault() {
  RadioRoles r;
  r.mesh = RADIO_LORA1;
  r.aux = haveLora2() ? RADIO_LORA2 : RADIO_NONE;
  return r;
}

struct StoredRoles { uint32_t magic; RadioRoles r; uint8_t pad[2]; };

static bool valid(const RadioRoles& r) {
  bool mesh_ok = r.mesh == RADIO_LORA1 || (r.mesh == RADIO_LORA2 && haveLora2());   // rf24 mesh: not yet
  bool aux_ok = r.aux == RADIO_NONE || r.aux == RADIO_RF24 || r.aux == RADIO_LORA1 ||
                (r.aux == RADIO_LORA2 && haveLora2());
  return mesh_ok && aux_ok && r.mesh != r.aux;
}

RadioRoles radioRolesLoad() {
  StoredRoles s;
  memcpy(&s, (const void*)RADIO_ROLES_ADDR, sizeof(s));
  if (s.magic == RADIO_ROLES_MAGIC && valid(s.r)) return s.r;
  return radioRolesDefault();   // none saved, or saved by a build this one cannot honour
}

bool radioRolesSave(const RadioRoles& r) {
  StoredRoles s;
  memset(&s, 0xFF, sizeof(s));
  s.magic = RADIO_ROLES_MAGIC;
  s.r = r;
  return nrf54RramWrite(RADIO_ROLES_ADDR, (const uint8_t*)&s, sizeof(s));
}

// ---------------------------------------------------------------- bring-up

static CustomSX1262* sx(uint8_t id) {
#ifdef P_LORA2_NSS
  if (id == RADIO_LORA2) return &lora2;
#endif
  return id == RADIO_LORA1 ? &radio : NULL;
}

static uint8_t rxenOf(uint8_t id) {
#ifdef P_LORA2_RXEN
  if (id == RADIO_LORA2) return P_LORA2_RXEN;
#endif
  return SX126X_RXEN;
}

// MeshCore's setup (CustomSX1262::std_init, which uses lora1's pin macros for
// the RF switch), then the switch pin this module really has
static bool initMesh(uint8_t id) {
  CustomSX1262* r = sx(id);
  if (!r || !r->std_init(&SPI)) return false;
  r->setRfSwitchPins(rxenOf(id), RADIOLIB_NC);
  return true;
}

// Same module setup (Wio-SX1262: TCXO on DIO3, DIO2 + RXEN switch), then
// standby: nothing transmits or listens until the app says so.
static bool initAux(uint8_t id) {
  CustomSX1262* r = sx(id);
  if (!r) return false;
  int16_t st = r->begin(LORA_FREQ, LORA_BW, LORA_SF, 5, RADIOLIB_SX126X_SYNC_WORD_PRIVATE, 0, 8,
                        SX126X_DIO3_TCXO_VOLTAGE);
  if (st != RADIOLIB_ERR_NONE) {
    MESH_DEBUG_PRINTLN("radio %s: aux init failed: %d", radioName(id), st);
    return false;
  }
  r->setCurrentLimit(SX126X_CURRENT_LIMIT);
  r->setDio2AsRfSwitch(true);
  r->setRfSwitchPins(rxenOf(id), RADIOLIB_NC);
  r->standby();
  return true;
}

bool radio_init() {
  // every chip select high first: two SX1262s share the bus
  pinMode(P_LORA_NSS, OUTPUT);
  digitalWrite(P_LORA_NSS, HIGH);
#ifdef P_LORA2_NSS
  pinMode(P_LORA2_NSS, OUTPUT);
  digitalWrite(P_LORA2_NSS, HIGH);
#endif
  radio_roles.saved = radioRolesLoad();
  radio_roles.running = radio_roles.saved;
  radio_roles.mesh_fallback = false;

  uint8_t mesh = radio_roles.saved.mesh;
  bool ok = initMesh(mesh);
  if (!ok && haveLora2()) {   // the mesh comes first: try the other SX1262 rather than halt
    uint8_t other = mesh == RADIO_LORA1 ? RADIO_LORA2 : RADIO_LORA1;
    MESH_DEBUG_PRINTLN("radio %s: mesh init failed, trying %s", radioName(mesh), radioName(other));
    if (initMesh(other)) {
      ok = true;
      radio_roles.mesh_fallback = true;
      if (radio_roles.running.aux == other) radio_roles.running.aux = RADIO_NONE;   // it is the mesh's now
      mesh = other;
    }
  }
  if (!ok) return false;
  radio_roles.running.mesh = mesh;
  mesh_lora = sx(mesh);
  radio_driver.bindTo(*mesh_lora);

  uint8_t aux = radio_roles.running.aux;
  radio_roles.aux_ok = true;
  if (aux == RADIO_LORA1 || aux == RADIO_LORA2) {
    radio_roles.aux_ok = initAux(aux);
    if (radio_roles.aux_ok) aux_sx = sx(aux);
  }
  return true;
}

SX1262* aux_lora() { return aux_sx; }

mesh::LocalIdentity radio_new_identity() {
  RadioNoiseListener rng(*mesh_lora);
  return mesh::LocalIdentity(&rng); // create new random identity
}

// ---------------------------------------------------------------- `radio` CLI command

static void describe(char* reply) {
  const RadioRoles& s = radio_roles.saved;
  const RadioRoles& r = radio_roles.running;
  int n = sprintf(reply, "mesh %s, aux %s", radioName(r.mesh), radioName(r.aux));
  if (radio_roles.mesh_fallback) n += sprintf(reply + n, " (%s failed)", radioName(s.mesh));
  if (!radio_roles.aux_ok) n += sprintf(reply + n, " (aux not answering)");
  if (s.mesh != r.mesh || s.aux != r.aux) {
    n += sprintf(reply + n, "; saved mesh %s, aux %s", radioName(s.mesh), radioName(s.aux));
  }
}

// radio                         show the roles
// radio mesh lora1|lora2        MeshCore's radio (rf24 not yet)
// radio aux lora1|lora2|rf24|off
// Saved at once, applied at the next boot. Giving a role the other role's radio swaps them.
bool XiaoNrf54L15Board::handleCommand(const char* command, uint32_t sender_timestamp, char* reply) {
  if (strcmp(command, "radio") == 0) {
    describe(reply);
    return true;
  }
  bool is_mesh = strncmp(command, "radio mesh ", 11) == 0;
  bool is_aux = strncmp(command, "radio aux ", 10) == 0;
  if (!is_mesh && !is_aux) return false;

  uint8_t id;
  if (!radioParse(command + (is_mesh ? 11 : 10), &id)) {
    strcpy(reply, "Err - radio: lora1, lora2, rf24 or off");
    return true;
  }
  if (id == RADIO_LORA2 && !haveLora2()) {
    strcpy(reply, "Err - this build has no lora2");
    return true;
  }
  RadioRoles r = radio_roles.saved;
  if (is_mesh) {
    if (id == RADIO_RF24 || id == RADIO_NONE) {
      strcpy(reply, "Err - mesh runs on lora1 or lora2 (rf24 not yet)");
      return true;
    }
    if (r.aux == id) r.aux = r.mesh;   // swap
    r.mesh = id;
  } else {
    if (id == r.mesh) {
      strcpy(reply, "Err - that is the mesh radio (move the mesh first)");
      return true;
    }
    r.aux = id;
  }
  if (!radioRolesSave(r)) {
    strcpy(reply, "Err - could not save");
    return true;
  }
  radio_roles.saved = r;
  sprintf(reply, "OK - mesh %s, aux %s: reboot to apply", radioName(r.mesh), radioName(r.aux));
  return true;
}

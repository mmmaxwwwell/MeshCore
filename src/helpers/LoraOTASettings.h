#pragma once

// Signed settings over LoRa: the owner signs a small bundle of node settings
// (radio preset, regions, flood limits, advert intervals, tx power, ...) with
// the SAME ed25519 key as the firmware images (LORA_OTA_PUBKEY) and pushes it
// in REQ datagrams. The node checks the signature, its target and its
// version, applies it on probation, and puts the old values back by itself
// unless a CONFIRM arrives in time (or if it reboots first).
//
// Platform-neutral like LoraOTA.cpp: the app supplies a Target (its prefs,
// file storage and radio), so the same code runs on the radio and in the host
// simulator (tools/lora-ota/sim). Protocol: tools/lora-ota/README.md.

#include <stdint.h>
#include <stddef.h>
#include "LoraOTA.h"

#define LORA_OTA_REQ_SET_DATA   0x67   // total u16, offset u16, bytes            -> status, have u16
#define LORA_OTA_REQ_SET_APPLY  0x68   // total u16, sha256(bundle)[0:8]          -> status [, version u32]
#define LORA_OTA_REQ_SET_CTRL   0x69   // op u8 (STATUS / CONFIRM / REVERT / GET) -> see README

#define LORA_OTA_SET_OP_STATUS   0
#define LORA_OTA_SET_OP_CONFIRM  1
#define LORA_OTA_SET_OP_REVERT   2
#define LORA_OTA_SET_OP_GET      3   // + start index u8 -> status, next u8 (0xFF = end), "key=value\n" text

#define LORA_OTA_SET_MAX_BUNDLE  512
#define LORA_OTA_SET_MAX_ENTRIES 24
#define LORA_OTA_SET_MIN_PREFIX  6       // a pubkey-prefix target names at least 6 bytes
#define LORA_OTA_SET_DOMAIN      "MCSET1"   // signed message = DOMAIN || body (firmware uses "MCOTA1")
#define LORA_OTA_SET_SWITCH_MS   1500    // radio changes take effect this long after the OK reply
#define LORA_OTA_SET_SWITCH_MAX_MS 10000 // ... or this long after the apply, if no one asks for the result
#define LORA_OTA_SET_GET_TEXT    110     // GET reply text budget

#define LORA_OTA_SET_REBOOT_MS  6000    // a bundle with reboot=1: reboot this long after its CONFIRM
#define LORA_OTA_SET_POSREPORT_MAX 1440  // posreport.interval minutes (companion POSREPORT_MAX_MIN)
#define LORA_OTA_SET_NAME_LEN    32      // name: the companion's node_name[32] (1-31 bytes + NUL)
#define LORA_OTA_SET_TELEM_MAX   2       // telemetry.*: TELEM_MODE_DENY 0, _ALLOW_FLAGS 1, _ALLOW_ALL 2
#define LORA_OTA_SET_ADV_LOC_MAX 1       // adv.loc: ADVERT_LOC_NONE 0, ADVERT_LOC_SHARE 1
#define LORA_OTA_SET_AUTOADD_BITS 0x1F   // autoadd: the companion's AUTO_ADD_* bits (overwrite oldest, chat,
                                         // repeater, room server, sensor); any other bit is refused

#ifndef LORA_OTA_SET_CONFIRM_SECS
  #define LORA_OTA_SET_CONFIRM_SECS 60   // same rule as a new firmware image
#endif

namespace lora_ota_settings {

// status codes 16+ (0-12 are lora_ota::Status, which this reuses where they fit)
enum Status : uint8_t {
  STALE_VERSION = 16,   // version not newer than the last applied bundle
  WRONG_TARGET = 17,    // bundle is for another node / board
  NOT_ALLOWED = 18,     // a key that is not on the whitelist
  BAD_VALUE = 19,       // a whitelisted key with a value out of range
  BAD_FORMAT = 20,      // the bundle does not parse
  SET_PENDING = 21,     // another bundle is still on probation: confirm or revert it first
  NOT_SUPPORTED = 22,   // whitelisted, but this role has no such setting
  STORE_ERROR = 23,     // could not save the probation record
};

// The whitelist. Names are the CLI's `set` names. Nothing else can be changed
// this way: no passwords, no keys, no owner info, no Wi-Fi, nothing about OTA
// itself (see README "Signed settings").
enum Key : uint8_t {
  K_RADIO = 0,           // freq,bw,sf,cr   (MHz, kHz)
  K_TX,                  // dBm
  K_AF,                  // airtime factor 0-9
  K_RXDELAY,             // 0-20
  K_TXDELAY,             // 0-2
  K_DIRECT_TXDELAY,      // 0-2
  K_MULTI_ACKS,          // 0-1
  K_PATH_HASH_MODE,      // 0-2
  K_INT_THRESH,          // 0-255
  K_AGC_RESET_INTERVAL,  // seconds 0-1020 (stored /4)
  K_RXGAIN,              // on/off
  K_FLOOD_MAX,           // 0-64       repeater
  K_FLOOD_MAX_UNSCOPED,  // 0-64       repeater
  K_FLOOD_MAX_ADVERT,    // 0-64       repeater
  K_ADVERT_INTERVAL,     // minutes: 0 or 60-240   repeater
  K_FLOOD_ADVERT_INTERVAL, // hours: 0 or 3-168    repeater
  K_LOOP_DETECT,         // off/minimal/moderate/strict  repeater
  K_REPEAT,              // on/off     repeater
  K_REGIONS,             // comma list of region names (or *) to exist with flood allowed  repeater
  // our own companion features: on the whitelist ONLY in builds that have them
  K_POSREPORT_INTERVAL,  // minutes 0-1440, 0 = off            POSITION_REPORT builds
  K_OVERLAY,             // "off" | "on #<name> <0|1>" (as #ovlset; the name is the overlay's secret)  OVERLAY_MESH builds
  // stock companion prefs (a repeater has none of them: "no such setting")
  K_NAME,                // node/advert name, 1-31 bytes (as CMD_SET_ADVERT_NAME / `set name`)
  K_ADV_LOC,             // advert_loc_policy 0-1
  K_TELEM_BASE,          // telemetry_mode_base 0-2
  K_TELEM_LOC,           // telemetry_mode_loc 0-2
  K_TELEM_ENV,           // telemetry_mode_env 0-2
  K_MANUAL_ADD,          // manual_add_contacts 0-1
  K_AUTOADD,             // autoadd_config bitmask (LORA_OTA_SET_AUTOADD_BITS)
  K_GPS,                 // on/off: gps_enabled, as CMD_SET_CUSTOM_VAR "gps" (nodes with a GPS only)
  K_LOCATION,            // "lat,lon", 6 decimals at most (as CMD_SET_ADVERT_LATLON)
  K_BLE_PIN,             // 0 (the build's default) or 100000-999999 (as CMD_SET_DEVICE_PIN); live at the next boot
  K_COUNT
};
static_assert(K_COUNT <= 32, "keys are a 32-bit mask");
#define LORA_OTA_SET_RADIO_KEYS ((1u << K_RADIO) | (1u << K_TX) | (1u << K_RXGAIN))
#define LORA_OTA_SET_REPEATER_KEYS ((1u << (lora_ota_settings::K_REGIONS + 1)) - 1)   // every stock key, no fork features
// the stock companion prefs: on every build's whitelist, supported by companions only
#define LORA_OTA_SET_COMPANION_KEYS (((1u << lora_ota_settings::K_COUNT) - 1) & ~((1u << lora_ota_settings::K_NAME) - 1))
// the "reboot" control entry: not a setting. Value "1": reboot once, a little
// after the bundle's CONFIRM (never before it, never after a revert)
#define LORA_OTA_SET_REBOOT_KEY "reboot"

// keys this build compiled in (the feature keys only with their feature)
uint32_t compiledKeys();

const char* keyName(int k);
int keyByName(const char* name, size_t len);   // -1 = not whitelisted

// every whitelisted setting except the regions, in a fixed form
struct Values {
  uint32_t freq_khz, bw_hz;
  uint8_t sf, cr;
  int8_t tx;
  uint16_t af_milli, rxdelay_milli, txdelay_milli, direct_txdelay_milli;
  uint8_t multi_acks, path_hash_mode, int_thresh, rxgain;
  uint16_t agc_reset_secs;
  uint8_t flood_max, flood_max_unscoped, flood_max_advert;
  uint8_t advert_interval_min, flood_advert_interval_h;
  uint8_t loop_detect, repeat;
  uint16_t posreport_min;
  uint8_t overlay;           // 1 = on (some region name configured), 0 = off. The NAME is never in
                             // Values: Values go into the state file, and the name is a secret
  // stock companion prefs (public, or the owner's own: nothing here is a key or a password)
  char name[LORA_OTA_SET_NAME_LEN];   // NUL-terminated
  uint8_t adv_loc;
  uint8_t telem_base, telem_loc, telem_env;
  uint8_t manual_add, autoadd, gps;
  int32_t lat_micro, lon_micro;       // degrees * 1e6, as CMD_SET_ADVERT_LATLON
  uint32_t ble_pin;
};

// persisted by the app (a small file): replay counter + probation record.
// The version sits right after the magic and is kept from a record of any
// size, so a future firmware with a longer State keeps refusing old bundles.
#define LORA_OTA_SET_STATE_MAGIC 0x3154534Du   // "MST1"
struct State {
  uint32_t magic;
  uint32_t version;          // last bundle applied (confirmed or not): anything not newer is refused
  uint32_t pending_version;  // 0 = nothing on probation
  uint32_t pending_mask;     // keys the pending bundle changed
  Values snapshot;           // their values before it
};

class Target {
public:
  virtual uint32_t supported() = 0;                 // bitmask of Keys this role has
  virtual void read(Values& v) = 0;                 // current prefs
  virtual bool write(const Values& v, uint32_t mask) = 0;   // set the masked prefs, save them, re-arm timers (not the radio)
  virtual void applyRadio() = 0;                    // radio hardware from the prefs: freq/bw/sf/cr, tx power, rx gain
  virtual int8_t maxTxPower() = 0;
  virtual bool acceptable(const Values& v, uint32_t mask) { (void)v; (void)mask; return true; }   // role rules, e.g. client-repeat bands
  virtual const uint8_t* selfPubKey() = 0;          // 32 bytes
  // the State record as a small file: bytes read (0 / -1 = none yet), and write it
  virtual int loadState(uint8_t* buf, size_t max) = 0;
  virtual bool saveState(const uint8_t* buf, size_t len) = 0;
  // region table (repeaters): snapshot to a file, apply a list, restore the snapshot
  virtual bool regionsSnapshot() { return false; }
  virtual bool regionsApply(const char* names) { (void)names; return false; }   // comma separated
  virtual bool regionsRestore() { return false; }
  virtual int regionsExport(char* out, int max) { (void)max; if (max) out[0] = 0; return 0; }   // allowed names, comma list
  // overlay (companions, OVERLAY_MESH): keep a copy of the overlay config ON THE NODE before
  // a bundle turns it off, put it back on a revert, delete the copy once the bundle is
  // confirmed or reverted (the region name is the overlay's key: no stray copies)
  virtual bool overlaySnapshot() { return false; }
  virtual bool overlayApply(const char* name) { (void)name; return false; }   // "#..." = on with that name, "" = off
  virtual bool overlayRestore() { return false; }
  virtual void dropSnapshots(uint32_t mask) { (void)mask; }
  // reboot now (prefs are saved). Called only after a confirmed bundle that asked for it
  virtual void reboot() = 0;
};

// copy the masked keys' fields of src into dst
void copyMasked(Values& dst, const Values& src, uint32_t mask);

// parse "910.525" -> 910525 (3 decimals at most); false on junk
bool parseMilli(const char* s, size_t n, uint32_t& out);
int formatMilli(char* out, uint32_t milli);

// parse and check one entry into v (range checks here; role checks by the caller)
Status parseEntry(int key, const char* val, size_t vlen, Values& v, int8_t max_tx);

// "lat,lon" in degrees, 6 decimals at most -> 1e-6 degrees; false on junk or out of range
bool parseLocation(const char* s, size_t n, int32_t& lat, int32_t& lon);
// a name the companion would take: 1-31 bytes, no control characters, none of AdvertDataParser's
// forbidden []\:,?* , no space at either end
bool validName(const char* s, size_t n);

// "off" | "on #<name> <0|1>" -> on, name (NUL-terminated, < 32 bytes), repeat
#define LORA_OTA_SET_OVERLAY_NAME 32
bool parseOverlay(const char* s, size_t n, bool& on, char name[LORA_OTA_SET_OVERLAY_NAME], bool& rep);

// over-LoRa CLI commands that change a whitelisted setting without a
// signature (blocked when built with LORA_OTA_SETTINGS_SIGNED_ONLY)
bool isUnsignedSettingsCommand(const char* command);

class Settings {
  Target* _t;
  uint8_t _pubkey[32];
  char _board[LORA_OTA_BOARD_LEN + 1];
  State _st;

  uint8_t _buf[LORA_OTA_SET_MAX_BUNDLE];
  uint16_t _total, _have;
  uint8_t _hash[8];        // what the APPLY in flight asked for
  enum { IDLE, VERIFYING, DONE } _phase;
  uint8_t _result;         // outcome of the last verify/apply, for the next APPLY
  uint32_t _result_version;

  bool _switch_pending;    // radio keys changed: applyRadio() still to do
  uint32_t _applied_ms, _switch_at, _confirm_by;
  bool _switch_asked;
  bool _radio_event;
  bool _reboot_asked;      // the bundle on probation carries reboot=1
  bool _reboot_due;        // confirmed: reboot at _reboot_at (0 = not timed yet)
  uint32_t _reboot_at;

  uint8_t verifyAndApply(uint32_t now_ms, bool fw_pending);
  uint8_t verifyAndApplyInner(uint32_t now_ms, bool fw_pending);
  void revert(const char* why);
  int ctrl(const uint8_t* p, size_t len, uint8_t* reply, uint32_t now_ms);
  int statusReply(uint8_t* reply, uint8_t status, uint8_t was, uint32_t now_ms);

public:
  Settings(Target& t, const uint8_t pubkey[32], const char* board);

  static bool isSettingsReq(uint8_t type) { return type >= LORA_OTA_REQ_SET_DATA && type <= LORA_OTA_REQ_SET_CTRL; }

  // at boot, after the app loaded its prefs: a bundle still on probation at
  // a reboot never got its CONFIRM, so its old values come back now
  void begin();
  // req[0] is the type. Reply body (no tag), its length; reply needs 8 + LORA_OTA_SET_GET_TEXT bytes
  int handle(const uint8_t* req, size_t len, uint8_t* reply, uint32_t now_ms);
  void poll(uint32_t now_ms, bool fw_pending);   // signature check + apply, from the main loop
  void loop(uint32_t now_ms);                    // radio switch + probation deadline
  bool pending() const { return _st.pending_version != 0; }
  bool busy() const { return pending() || _phase == VERIFYING || _switch_pending || _reboot_due; }
  bool rebootDue() const { return _reboot_due; }
  bool working() const { return _phase == VERIFYING; }
  bool takeRadioEvent() { bool e = _radio_event; _radio_event = false; return e; }   // the radio was set from the prefs
  uint32_t version() const { return _st.version; }
  uint32_t pendingVersion() const { return _st.pending_version; }
  long secondsLeft(uint32_t now_ms) const;
  bool confirm();      // CLI and CTRL CONFIRM
  bool revertNow();    // CLI and CTRL REVERT: only while pending
};

}

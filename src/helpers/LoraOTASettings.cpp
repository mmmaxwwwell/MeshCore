#include "LoraOTASettings.h"

#if defined(LORA_OTA_ENABLED) || defined(LORA_OTA_HOST_TEST)

#include <string.h>
#include <stdio.h>
#include <SHA256.h>
#include <ed_25519.h>

namespace lora_ota_settings {

static uint32_t rd32(const uint8_t* p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24); }
static uint16_t rd16(const uint8_t* p) { return p[0] | (p[1] << 8); }
static void wr32(uint8_t* p, uint32_t v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }
static void wr16(uint8_t* p, uint16_t v) { p[0] = v; p[1] = v >> 8; }

// index = Key. The names are the CLI's `set` names.
static const char* const KEY_NAMES[K_COUNT] = {
  "radio", "tx", "af", "rxdelay", "txdelay", "direct.txdelay", "multi.acks", "path.hash.mode",
  "int.thresh", "agc.reset.interval", "radio.rxgain", "flood.max", "flood.max.unscoped",
  "flood.max.advert", "advert.interval", "flood.advert.interval", "loop.detect", "repeat", "regions",
  "posreport.interval", "overlay",
  "name", "adv.loc", "telemetry.base", "telemetry.loc", "telemetry.env", "manual.add", "autoadd", "gps", "location",
  "ble.pin",
};
static const char* const LOOP_NAMES[4] = { "off", "minimal", "moderate", "strict" };

const char* keyName(int k) { return k >= 0 && k < K_COUNT ? KEY_NAMES[k] : "?"; }

uint32_t compiledKeys() {
  uint32_t m = LORA_OTA_SET_REPEATER_KEYS | LORA_OTA_SET_COMPANION_KEYS;   // a repeater refuses the companion's as NOT_SUPPORTED
#ifdef POSITION_REPORT
  m |= 1u << K_POSREPORT_INTERVAL;
#endif
#ifdef OVERLAY_MESH
  m |= 1u << K_OVERLAY;
#endif
  return m;
}

int keyByName(const char* name, size_t len) {
  for (int k = 0; k < K_COUNT; k++) {
    if (strlen(KEY_NAMES[k]) == len && memcmp(KEY_NAMES[k], name, len) == 0) {
      return (compiledKeys() & (1u << k)) ? k : -1;   // a feature this build lacks is not on its whitelist
    }
  }
  return -1;
}

void copyMasked(Values& d, const Values& s, uint32_t m) {
  if (m & (1u << K_RADIO)) { d.freq_khz = s.freq_khz; d.bw_hz = s.bw_hz; d.sf = s.sf; d.cr = s.cr; }
  if (m & (1u << K_TX)) d.tx = s.tx;
  if (m & (1u << K_AF)) d.af_milli = s.af_milli;
  if (m & (1u << K_RXDELAY)) d.rxdelay_milli = s.rxdelay_milli;
  if (m & (1u << K_TXDELAY)) d.txdelay_milli = s.txdelay_milli;
  if (m & (1u << K_DIRECT_TXDELAY)) d.direct_txdelay_milli = s.direct_txdelay_milli;
  if (m & (1u << K_MULTI_ACKS)) d.multi_acks = s.multi_acks;
  if (m & (1u << K_PATH_HASH_MODE)) d.path_hash_mode = s.path_hash_mode;
  if (m & (1u << K_INT_THRESH)) d.int_thresh = s.int_thresh;
  if (m & (1u << K_AGC_RESET_INTERVAL)) d.agc_reset_secs = s.agc_reset_secs;
  if (m & (1u << K_RXGAIN)) d.rxgain = s.rxgain;
  if (m & (1u << K_FLOOD_MAX)) d.flood_max = s.flood_max;
  if (m & (1u << K_FLOOD_MAX_UNSCOPED)) d.flood_max_unscoped = s.flood_max_unscoped;
  if (m & (1u << K_FLOOD_MAX_ADVERT)) d.flood_max_advert = s.flood_max_advert;
  if (m & (1u << K_ADVERT_INTERVAL)) d.advert_interval_min = s.advert_interval_min;
  if (m & (1u << K_FLOOD_ADVERT_INTERVAL)) d.flood_advert_interval_h = s.flood_advert_interval_h;
  if (m & (1u << K_LOOP_DETECT)) d.loop_detect = s.loop_detect;
  if (m & (1u << K_REPEAT)) d.repeat = s.repeat;
  if (m & (1u << K_POSREPORT_INTERVAL)) d.posreport_min = s.posreport_min;
  if (m & (1u << K_OVERLAY)) d.overlay = s.overlay;
  if (m & (1u << K_NAME)) memcpy(d.name, s.name, sizeof(d.name));
  if (m & (1u << K_ADV_LOC)) d.adv_loc = s.adv_loc;
  if (m & (1u << K_TELEM_BASE)) d.telem_base = s.telem_base;
  if (m & (1u << K_TELEM_LOC)) d.telem_loc = s.telem_loc;
  if (m & (1u << K_TELEM_ENV)) d.telem_env = s.telem_env;
  if (m & (1u << K_MANUAL_ADD)) d.manual_add = s.manual_add;
  if (m & (1u << K_AUTOADD)) d.autoadd = s.autoadd;
  if (m & (1u << K_GPS)) d.gps = s.gps;
  if (m & (1u << K_LOCATION)) { d.lat_micro = s.lat_micro; d.lon_micro = s.lon_micro; }
  if (m & (1u << K_BLE_PIN)) d.ble_pin = s.ble_pin;
}

bool parseMilli(const char* s, size_t n, uint32_t& out) {
  uint64_t v = 0;
  size_t i = 0;
  int frac = -1;
  if (n == 0) return false;
  for (; i < n; i++) {
    char c = s[i];
    if (c == '.' && frac < 0) { frac = 0; continue; }
    if (c < '0' || c > '9') return false;
    if (frac >= 0 && ++frac > 3) return false;   // never round a value the owner signed
    v = v * 10 + (c - '0');
    if (v > 0xFFFFFFFFull) return false;
  }
  if (frac < 0) frac = 0;
  for (; frac < 3; frac++) v *= 10;
  if (v > 0xFFFFFFFFull) return false;
  out = (uint32_t)v;
  return true;
}

int formatMilli(char* out, uint32_t milli) {
  int n = sprintf(out, "%lu", (unsigned long)(milli / 1000));
  uint32_t f = milli % 1000;
  if (f) {
    n += sprintf(&out[n], ".%03lu", (unsigned long)f);
    while (out[n - 1] == '0') out[--n] = 0;
  }
  return n;
}

// "-41.123456" -> -41123456 (6 decimals at most, never rounded); |value| <= max_deg degrees
static bool parseMicro(const char* s, size_t n, uint32_t max_deg, int32_t& out) {
  bool neg = n > 0 && s[0] == '-';
  uint64_t v = 0;
  int frac = -1;
  size_t digits = 0;
  for (size_t i = neg; i < n; i++) {
    char c = s[i];
    if (c == '.' && frac < 0) { frac = 0; continue; }
    if (c < '0' || c > '9') return false;
    if (frac >= 0 && ++frac > 6) return false;
    v = v * 10 + (c - '0');
    if (v > 1000000000ull) return false;
    digits++;
  }
  if (digits == 0) return false;
  if (frac < 0) frac = 0;
  for (; frac < 6; frac++) v *= 10;
  if (v > (uint64_t)max_deg * 1000000u) return false;
  out = neg ? -(int32_t)v : (int32_t)v;
  return true;
}

bool parseLocation(const char* s, size_t n, int32_t& lat, int32_t& lon) {
  const char* c = (const char*)memchr(s, ',', n);
  if (!c) return false;
  size_t a = c - s;
  return parseMicro(s, a, 90, lat) && parseMicro(c + 1, n - a - 1, 180, lon);
}

static int formatMicro(char* out, int32_t v) {
  uint32_t a = v < 0 ? (uint32_t)(-(int64_t)v) : (uint32_t)v;
  return sprintf(out, "%s%lu.%06lu", v < 0 ? "-" : "", (unsigned long)(a / 1000000), (unsigned long)(a % 1000000));
}

// as `set name` (AdvertDataParser::isValidName), plus: no control characters, no space at either
// end. UTF-8 bytes (0x80 and up) pass, as the app's names have them
bool validName(const char* s, size_t n) {
  static const char FORBIDDEN[] = "[]\\:,?*";
  if (n == 0 || n >= LORA_OTA_SET_NAME_LEN || s[0] == ' ' || s[n - 1] == ' ') return false;
  for (size_t i = 0; i < n; i++) {
    uint8_t c = (uint8_t)s[i];
    if (c < ' ' || c == 0x7F || (c < 0x80 && memchr(FORBIDDEN, c, sizeof(FORBIDDEN) - 1))) return false;
  }
  return true;
}

static bool parseUint(const char* s, size_t n, uint32_t max, uint32_t& out) {
  uint32_t v;
  if (!parseMilli(s, n, v) || v % 1000) return false;   // integers only
  v /= 1000;
  if (v > max) return false;
  out = v;
  return true;
}

static bool parseInt(const char* s, size_t n, int32_t& out) {
  bool neg = n > 0 && s[0] == '-';
  uint32_t v;
  if (!parseUint(s + neg, n - neg, 1000, v)) return false;
  out = neg ? -(int32_t)v : (int32_t)v;
  return true;
}

static bool is(const char* s, size_t n, const char* word) { return strlen(word) == n && memcmp(s, word, n) == 0; }

static bool parseOnOff(const char* s, size_t n, uint8_t& out) {
  if (is(s, n, "on")) { out = 1; return true; }
  if (is(s, n, "off")) { out = 0; return true; }
  return false;
}

static bool isRegionChar(uint8_t c) {   // RegionMap::is_name_char
  return c == '-' || c == '$' || c == '#' || (c >= '0' && c <= '9') || c >= 'A';
}

// "ct,northeast,*": names of at most 30 chars, or the wildcard
static bool validRegions(const char* s, size_t n) {
  size_t start = 0;
  if (n == 0) return false;
  for (size_t i = 0; i <= n; i++) {
    if (i == n || s[i] == ',') {
      size_t len = i - start;
      if (len == 0 || len > 30) return false;
      if (!(len == 1 && s[start] == '*')) {
        for (size_t j = start; j < i; j++) if (!isRegionChar((uint8_t)s[j])) return false;
      }
      start = i + 1;
    }
  }
  return true;
}

Status parseEntry(int key, const char* s, size_t n, Values& v, int8_t max_tx) {
  uint32_t u;
  int32_t i;
  switch (key) {
    case K_RADIO: {   // freq,bw,sf,cr: checked as integers (float checks drift on nRF52)
      const char* part[4];
      size_t plen[4];
      int np = 0;
      size_t start = 0;
      for (size_t j = 0; j <= n; j++) {
        if (j == n || s[j] == ',') {
          if (np == 4) return BAD_VALUE;
          part[np] = &s[start]; plen[np] = j - start; np++;
          start = j + 1;
        }
      }
      uint32_t f, bw, sf, cr;
      if (np != 4 || !parseMilli(part[0], plen[0], f) || !parseMilli(part[1], plen[1], bw) ||
          !parseUint(part[2], plen[2], 12, sf) || !parseUint(part[3], plen[3], 8, cr)) return BAD_VALUE;
      if (f < 150000 || f > 2500000 || bw < 7000 || bw > 500000 || sf < 5 || cr < 5) return BAD_VALUE;
      v.freq_khz = f; v.bw_hz = bw; v.sf = sf; v.cr = cr;
      return (Status)lora_ota::OK;
    }
    case K_TX:
      if (!parseInt(s, n, i) || i < -9 || i > max_tx) return BAD_VALUE;
      v.tx = i;
      return (Status)lora_ota::OK;
    case K_AF:
      if (!parseMilli(s, n, u) || u > 9000) return BAD_VALUE;
      v.af_milli = u;
      return (Status)lora_ota::OK;
    case K_RXDELAY:
      if (!parseMilli(s, n, u) || u > 20000) return BAD_VALUE;
      v.rxdelay_milli = u;
      return (Status)lora_ota::OK;
    case K_TXDELAY:
    case K_DIRECT_TXDELAY:
      if (!parseMilli(s, n, u) || u > 2000) return BAD_VALUE;
      (key == K_TXDELAY ? v.txdelay_milli : v.direct_txdelay_milli) = u;
      return (Status)lora_ota::OK;
    case K_MULTI_ACKS:
      if (!parseUint(s, n, 1, u)) return BAD_VALUE;
      v.multi_acks = u;
      return (Status)lora_ota::OK;
    case K_PATH_HASH_MODE:
      if (!parseUint(s, n, 2, u)) return BAD_VALUE;
      v.path_hash_mode = u;
      return (Status)lora_ota::OK;
    case K_INT_THRESH:
      if (!parseUint(s, n, 255, u)) return BAD_VALUE;
      v.int_thresh = u;
      return (Status)lora_ota::OK;
    case K_AGC_RESET_INTERVAL:
      if (!parseUint(s, n, 1020, u) || u % 4) return BAD_VALUE;   // stored as secs / 4
      v.agc_reset_secs = u;
      return (Status)lora_ota::OK;
    case K_RXGAIN:
      return parseOnOff(s, n, v.rxgain) ? (Status)lora_ota::OK : BAD_VALUE;
    case K_REPEAT:
      return parseOnOff(s, n, v.repeat) ? (Status)lora_ota::OK : BAD_VALUE;
    case K_FLOOD_MAX:
    case K_FLOOD_MAX_UNSCOPED:
    case K_FLOOD_MAX_ADVERT:
      if (!parseUint(s, n, 64, u)) return BAD_VALUE;
      (key == K_FLOOD_MAX ? v.flood_max : key == K_FLOOD_MAX_UNSCOPED ? v.flood_max_unscoped : v.flood_max_advert) = u;
      return (Status)lora_ota::OK;
    case K_ADVERT_INTERVAL:   // CLI: 0 = off, else 60-240 minutes, even (stored / 2)
      if (!parseUint(s, n, 240, u) || (u != 0 && u < 60) || u % 2) return BAD_VALUE;
      v.advert_interval_min = u;
      return (Status)lora_ota::OK;
    case K_FLOOD_ADVERT_INTERVAL:   // CLI: 0 = off, else 3-168 hours
      if (!parseUint(s, n, 168, u) || (u != 0 && u < 3)) return BAD_VALUE;
      v.flood_advert_interval_h = u;
      return (Status)lora_ota::OK;
    case K_LOOP_DETECT:
      for (int m = 0; m < 4; m++) {
        if (is(s, n, LOOP_NAMES[m])) { v.loop_detect = m; return (Status)lora_ota::OK; }
      }
      return BAD_VALUE;
    case K_REGIONS:
      return validRegions(s, n) ? (Status)lora_ota::OK : BAD_VALUE;
    case K_POSREPORT_INTERVAL:   // same range as "#locset <min>"
      if (!parseUint(s, n, LORA_OTA_SET_POSREPORT_MAX, u)) return BAD_VALUE;
      v.posreport_min = u;
      return (Status)lora_ota::OK;
    case K_OVERLAY: {   // the name is checked here and taken by the caller; Values only say on/off
      bool on, rep;
      char name[LORA_OTA_SET_OVERLAY_NAME];
      if (!parseOverlay(s, n, on, name, rep)) return BAD_VALUE;
      memset(name, 0, sizeof(name));
      v.overlay = on;
      return (Status)lora_ota::OK;
    }
    case K_NAME:
      if (!validName(s, n)) return BAD_VALUE;
      memset(v.name, 0, sizeof(v.name));
      memcpy(v.name, s, n);
      return (Status)lora_ota::OK;
    case K_ADV_LOC:
      if (!parseUint(s, n, LORA_OTA_SET_ADV_LOC_MAX, u)) return BAD_VALUE;
      v.adv_loc = u;
      return (Status)lora_ota::OK;
    case K_TELEM_BASE:
    case K_TELEM_LOC:
    case K_TELEM_ENV:
      if (!parseUint(s, n, LORA_OTA_SET_TELEM_MAX, u)) return BAD_VALUE;
      (key == K_TELEM_BASE ? v.telem_base : key == K_TELEM_LOC ? v.telem_loc : v.telem_env) = u;
      return (Status)lora_ota::OK;
    case K_MANUAL_ADD:
      if (!parseUint(s, n, 1, u)) return BAD_VALUE;
      v.manual_add = u;
      return (Status)lora_ota::OK;
    case K_AUTOADD:   // a bit the firmware does not define is refused, never dropped
      if (!parseUint(s, n, 255, u) || (u & ~LORA_OTA_SET_AUTOADD_BITS)) return BAD_VALUE;
      v.autoadd = u;
      return (Status)lora_ota::OK;
    case K_GPS:
      return parseOnOff(s, n, v.gps) ? (Status)lora_ota::OK : BAD_VALUE;
    case K_LOCATION:
      return parseLocation(s, n, v.lat_micro, v.lon_micro) ? (Status)lora_ota::OK : BAD_VALUE;
    case K_BLE_PIN:   // as CMD_SET_DEVICE_PIN: 0 (the build's default PIN) or six digits
      if (!parseUint(s, n, 999999, u) || (u != 0 && u < 100000)) return BAD_VALUE;
      v.ble_pin = u;
      return (Status)lora_ota::OK;
  }
  return NOT_ALLOWED;
}

// As "#ovlset": "off", or "on #<name> <0|1>" (name: '#' then printable ASCII,
// no spaces, shorter than the companion's 32-byte OverlayCfg name)
bool parseOverlay(const char* s, size_t n, bool& on, char name[LORA_OTA_SET_OVERLAY_NAME], bool& rep) {
  name[0] = 0;
  if (is(s, n, "off")) { on = false; rep = false; return true; }
  if (n < 3 + 2 + 2 || memcmp(s, "on ", 3) != 0) return false;
  size_t start = 3, end = start;
  while (end < n && s[end] != ' ') end++;
  size_t len = end - start;
  if (len < 2 || len >= LORA_OTA_SET_OVERLAY_NAME || s[start] != '#') return false;
  for (size_t j = start; j < end; j++) if (s[j] <= ' ' || s[j] > '~') return false;
  if (end + 2 != n || (s[end + 1] != '0' && s[end + 1] != '1')) return false;
  memcpy(name, &s[start], len);
  name[len] = 0;
  on = true;
  rep = s[end + 1] == '1';
  return true;
}

// A command typed over LoRa (admin CLI, sender_timestamp != 0) that changes
// a setting on the whitelist. With LORA_OTA_SETTINGS_SIGNED_ONLY those are
// refused; USB serial (the recovery path) is never affected.
bool isUnsignedSettingsCommand(const char* c) {
  static const char* const PREFIXES[] = {
    "set radio ", "set freq ", "set tx ", "set af ", "set dutycycle ", "set rxdelay ", "set txdelay ",
    "set direct.txdelay ", "set multi.acks ", "set path.hash.mode ", "set int.thresh ",
    "set agc.reset.interval ", "set radio.rxgain ", "set flood.max ", "set flood.max.unscoped ",
    "set flood.max.advert ", "set advert.interval ", "set flood.advert.interval ", "set loop.detect ",
    "set repeat ", "tempradio ",
    "region load", "region save", "region allowf ", "region denyf ", "region home ", "region default ",
    "region put ", "region remove ", "region def ",
  };
  while (*c == ' ') c++;
  for (size_t i = 0; i < sizeof(PREFIXES) / sizeof(PREFIXES[0]); i++) {
    if (strncmp(c, PREFIXES[i], strlen(PREFIXES[i])) == 0) return true;
  }
  return false;
}

Settings::Settings(Target& t, const uint8_t pubkey[32], const char* board) : _t(&t) {
  memcpy(_pubkey, pubkey, 32);
  strncpy(_board, board, LORA_OTA_BOARD_LEN);
  _board[LORA_OTA_BOARD_LEN] = 0;
  memset(&_st, 0, sizeof(_st));
  _st.magic = LORA_OTA_SET_STATE_MAGIC;
  _total = _have = 0;
  _phase = IDLE;
  _result = lora_ota::OK;
  _result_version = 0;
  _switch_pending = _switch_asked = _radio_event = false;
  _applied_ms = _switch_at = _confirm_by = 0;
  _reboot_asked = _reboot_due = false;
  _reboot_at = 0;
}

void Settings::begin() {
  uint8_t buf[sizeof(State)];
  int n = _t->loadState(buf, sizeof(buf));
  if (n >= 8 && rd32(buf) == LORA_OTA_SET_STATE_MAGIC) {
    _st.version = rd32(&buf[4]);
    if (n == (int)sizeof(State)) memcpy(&_st, buf, sizeof(State));
    else _st.pending_version = 0;   // another firmware's record: keep only the version
  }
  _st.magic = LORA_OTA_SET_STATE_MAGIC;
  if (pending()) revert("rebooted before CONFIRM");
}

long Settings::secondsLeft(uint32_t now_ms) const {
  if (!pending()) return 0;
  if (_switch_pending) return LORA_OTA_SET_CONFIRM_SECS + (int32_t)(_switch_at - now_ms) / 1000;
  long left = (int32_t)(_confirm_by - now_ms) / 1000;
  return left > 0 ? left : 0;
}

void Settings::revert(const char* why) {
  (void)why;
  uint32_t mask = _st.pending_mask;
  _t->write(_st.snapshot, mask & ~((1u << K_REGIONS) | (1u << K_OVERLAY)));
  if (mask & (1u << K_REGIONS)) _t->regionsRestore();
  if (mask & (1u << K_OVERLAY)) _t->overlayRestore();   // the name comes back from the node's own copy
  _t->dropSnapshots(mask);
  _reboot_asked = false;   // a reverted bundle never reboots the node
  if (mask & LORA_OTA_SET_RADIO_KEYS) {
    _t->applyRadio();   // even if the switch never happened: the radio follows the restored prefs
    _radio_event = true;
  }
  _switch_pending = false;
  _st.pending_version = 0;
  _st.pending_mask = 0;
  _t->saveState((const uint8_t*)&_st, sizeof(_st));
}

bool Settings::confirm() {
  if (!pending() || _switch_pending) return false;
  uint32_t mask = _st.pending_mask;
  _st.pending_version = 0;
  _st.pending_mask = 0;
  if (!_t->saveState((const uint8_t*)&_st, sizeof(_st))) return false;
  _t->dropSnapshots(mask);
  if (_reboot_asked) {   // only now: the new settings are confirmed and saved
    _reboot_asked = false;
    _reboot_due = true;
    _reboot_at = 0;      // timed from the next loop(), after the CONFIRM reply has been handed over
  }
  return true;
}

bool Settings::revertNow() {
  if (!pending()) return false;
  revert("asked");
  return true;
}

// static: poll() runs on the 4 KB nRF52 loop stack
static uint8_t s_msg[6 + LORA_OTA_SET_MAX_BUNDLE];
static char s_overlay_name[LORA_OTA_SET_OVERLAY_NAME];

uint8_t Settings::verifyAndApply(uint32_t now_ms, bool fw_pending) {
  uint8_t r = verifyAndApplyInner(now_ms, fw_pending);
  // a bundle may carry the overlay name (a secret): no copy of it stays in RAM. A
  // repeated APPLY gets the stored result; a new upload starts at offset 0
  memset(s_msg, 0, sizeof(s_msg));
  memset(s_overlay_name, 0, sizeof(s_overlay_name));
  memset(_buf, 0, sizeof(_buf));
  _have = 0;
  return r;
}

uint8_t Settings::verifyAndApplyInner(uint32_t now_ms, bool fw_pending) {
  if (_total < 64 + 8) return BAD_FORMAT;
  size_t blen = _total - 64;
  const uint8_t* body = _buf;
  const uint8_t* sig = &_buf[blen];

  // 1. the signature, over DOMAIN || body: before anything in the body is believed
  uint8_t* msg = s_msg;
  memcpy(msg, LORA_OTA_SET_DOMAIN, 6);
  memcpy(&msg[6], body, blen);
  if (!ed25519_verify(sig, msg, 6 + blen, _pubkey)) return lora_ota::BAD_SIGNATURE;

  // 2. version u32, target kind u8, target len u8, target, count u8, entries
  size_t i = 0;
  if (blen < 7) return BAD_FORMAT;
  uint32_t version = rd32(body); i = 4;
  uint8_t tkind = body[i++], tlen = body[i++];
  if (i + tlen + 1 > blen) return BAD_FORMAT;
  const uint8_t* tgt = &body[i]; i += tlen;
  uint8_t count = body[i++];
  if (tkind == 1) {   // node: public key prefix
    if (tlen < LORA_OTA_SET_MIN_PREFIX || tlen > 32 || memcmp(tgt, _t->selfPubKey(), tlen) != 0) return WRONG_TARGET;
  } else if (tkind == 2) {   // board tag (LORA_OTA_BOARD)
    if (tlen != strlen(_board) || memcmp(tgt, _board, tlen) != 0) return WRONG_TARGET;
  } else {
    return WRONG_TARGET;
  }
  if (version <= _st.version) return STALE_VERSION;
  if (fw_pending) return lora_ota::PENDING_VERIFY;
  if (pending()) return SET_PENDING;
  if (count == 0 || count > LORA_OTA_SET_MAX_ENTRIES) return BAD_FORMAT;

  Values cur, nv;
  memset(&cur, 0, sizeof(cur));   // a target that reads only its own keys leaves no stack bytes in the record
  _t->read(cur);
  nv = cur;
  uint32_t mask = 0, supported = _t->supported() & compiledKeys();
  bool reboot = false, reboot_seen = false, overlay_rep = false;
  static char regions[LORA_OTA_SET_MAX_BUNDLE];   // static: poll() runs on the 4 KB nRF52 loop stack
  regions[0] = 0;
  for (int e = 0; e < count; e++) {
    if (i + 1 > blen) return BAD_FORMAT;
    uint8_t klen = body[i++];
    if (i + klen + 1 > blen) return BAD_FORMAT;
    const char* key = (const char*)&body[i]; i += klen;
    uint8_t vlen = body[i++];
    if (i + vlen > blen) return BAD_FORMAT;
    const char* val = (const char*)&body[i]; i += vlen;
    if (is(key, klen, LORA_OTA_SET_REBOOT_KEY)) {   // control entry, not a setting
      if (reboot_seen) return BAD_FORMAT;
      if (!is(val, vlen, "1")) return BAD_VALUE;
      reboot = reboot_seen = true;
      continue;
    }
    int k = keyByName(key, klen);
    if (k < 0) return NOT_ALLOWED;
    if (mask & (1u << k)) return BAD_FORMAT;   // twice in one bundle
    if (!(supported & (1u << k))) return NOT_SUPPORTED;
    uint8_t s = parseEntry(k, val, vlen, nv, _t->maxTxPower());
    if (s != lora_ota::OK) return s;
    if (k == K_REGIONS) { memcpy(regions, val, vlen); regions[vlen] = 0; }
    if (k == K_OVERLAY) { bool on; parseOverlay(val, vlen, on, s_overlay_name, overlay_rep); }
    mask |= 1u << k;
  }
  if (i != blen) return BAD_FORMAT;
  if (mask == 0) return BAD_FORMAT;   // a reboot alone is not a bundle
  if (mask & (1u << K_OVERLAY)) {
    // as "#ovlset": off takes client repeat off with it, "on #name <r>" sets it to r
    // (and a revert brings the old value back). Here the band rule (acceptable) refuses
    // the whole bundle where #ovlset would quietly leave repeat off.
    if (!(supported & (1u << K_REPEAT))) return NOT_SUPPORTED;
    uint8_t want = nv.overlay && overlay_rep ? 1 : 0;
    if ((mask & (1u << K_REPEAT)) && nv.repeat != want) return BAD_VALUE;   // contradicts itself
    nv.repeat = want;
    mask |= 1u << K_REPEAT;
  }
  if (!_t->acceptable(nv, mask)) return BAD_VALUE;

  // 3. probation record first: a power cut from here on brings the old values back
  if ((mask & (1u << K_REGIONS)) && !_t->regionsSnapshot()) return STORE_ERROR;
  if ((mask & (1u << K_OVERLAY)) && !_t->overlaySnapshot()) return STORE_ERROR;
  _st.version = version;
  _st.pending_version = version;
  _st.pending_mask = mask;
  _st.snapshot = cur;
  if (!_t->saveState((const uint8_t*)&_st, sizeof(_st))) {
    _st.pending_version = 0;   // nothing changed yet; the version is spent either way
    _st.pending_mask = 0;
    _t->dropSnapshots(mask);
    return STORE_ERROR;
  }
  _reboot_asked = reboot;

  // 4. apply; the radio itself only after the OK reply has gone out
  bool ok = _t->write(nv, mask & ~((1u << K_REGIONS) | (1u << K_OVERLAY)));
  if (ok && (mask & (1u << K_REGIONS))) ok = _t->regionsApply(regions);
  if (ok && (mask & (1u << K_OVERLAY))) ok = _t->overlayApply(nv.overlay ? s_overlay_name : "");
  if (!ok) {
    revert("apply failed");
    return STORE_ERROR;
  }
  _applied_ms = now_ms;
  if (mask & LORA_OTA_SET_RADIO_KEYS) {
    _switch_pending = true;
    _switch_asked = false;
    _switch_at = now_ms + LORA_OTA_SET_SWITCH_MAX_MS;
  } else {
    _confirm_by = now_ms + LORA_OTA_SET_CONFIRM_SECS * 1000UL;
  }
  _result_version = version;
  return lora_ota::OK;
}

int Settings::statusReply(uint8_t* reply, uint8_t status, uint8_t was, uint32_t now_ms) {
  // status, pending u8, was u8, version u32, pending_version u32, secs_left u16
  long left = secondsLeft(now_ms);
  reply[0] = status;
  reply[1] = pending() ? (_switch_pending ? 2 : 1) : 0;   // 2 = new radio settings not switched to yet
  reply[2] = was;
  wr32(&reply[3], _st.version);
  wr32(&reply[7], _st.pending_version);
  wr16(&reply[11], left > 0xFFFF ? 0xFFFF : (uint16_t)left);
  // flags: bit0 = the pending bundle asks for a reboot after its CONFIRM, bit1 = that reboot is due
  reply[13] = (_reboot_asked ? 1 : 0) | (_reboot_due ? 2 : 0);
  return 14;
}

int Settings::ctrl(const uint8_t* p, size_t len, uint8_t* reply, uint32_t now_ms) {
  if (len < 1) { reply[0] = lora_ota::BAD_ARG; return 1; }
  switch (p[0]) {
    case LORA_OTA_SET_OP_STATUS:
      return statusReply(reply, lora_ota::OK, 0, now_ms);
    case LORA_OTA_SET_OP_CONFIRM:
      // only once the new radio settings are live: a CONFIRM must prove the
      // sender reaches the node on them
      if (_switch_pending) return statusReply(reply, lora_ota::WORKING, 0, now_ms);
      if (!pending()) return statusReply(reply, lora_ota::OK, 0, now_ms);
      return statusReply(reply, confirm() ? (uint8_t)lora_ota::OK : (uint8_t)STORE_ERROR, 1, now_ms);
    case LORA_OTA_SET_OP_REVERT: {
      bool was = revertNow();
      return statusReply(reply, lora_ota::OK, was, now_ms);
    }
    case LORA_OTA_SET_OP_GET: {   // start u8 -> status, next u8, "key=value\n"...
      Values v;
      memset(&v, 0, sizeof(v));
      _t->read(v);
      uint32_t sup = _t->supported() & compiledKeys();
      int k = len > 1 ? p[1] : 0;
      char* out = (char*)&reply[2];
      int used = 0;
      for (; k < K_COUNT; k++) {
        if (!(sup & (1u << k))) continue;
        char line[96];
        int n = sprintf(line, "%s=", KEY_NAMES[k]);
        switch (k) {
          case K_RADIO:
            n += formatMilli(&line[n], v.freq_khz);
            line[n++] = ',';
            n += formatMilli(&line[n], v.bw_hz);
            n += sprintf(&line[n], ",%u,%u", v.sf, v.cr);
            break;
          case K_TX: n += sprintf(&line[n], "%d", v.tx); break;
          case K_AF: n += formatMilli(&line[n], v.af_milli); break;
          case K_RXDELAY: n += formatMilli(&line[n], v.rxdelay_milli); break;
          case K_TXDELAY: n += formatMilli(&line[n], v.txdelay_milli); break;
          case K_DIRECT_TXDELAY: n += formatMilli(&line[n], v.direct_txdelay_milli); break;
          case K_MULTI_ACKS: n += sprintf(&line[n], "%u", v.multi_acks); break;
          case K_PATH_HASH_MODE: n += sprintf(&line[n], "%u", v.path_hash_mode); break;
          case K_INT_THRESH: n += sprintf(&line[n], "%u", v.int_thresh); break;
          case K_AGC_RESET_INTERVAL: n += sprintf(&line[n], "%u", v.agc_reset_secs); break;
          case K_RXGAIN: n += sprintf(&line[n], "%s", v.rxgain ? "on" : "off"); break;
          case K_REPEAT: n += sprintf(&line[n], "%s", v.repeat ? "on" : "off"); break;
          case K_FLOOD_MAX: n += sprintf(&line[n], "%u", v.flood_max); break;
          case K_FLOOD_MAX_UNSCOPED: n += sprintf(&line[n], "%u", v.flood_max_unscoped); break;
          case K_FLOOD_MAX_ADVERT: n += sprintf(&line[n], "%u", v.flood_max_advert); break;
          case K_ADVERT_INTERVAL: n += sprintf(&line[n], "%u", v.advert_interval_min); break;
          case K_FLOOD_ADVERT_INTERVAL: n += sprintf(&line[n], "%u", v.flood_advert_interval_h); break;
          case K_LOOP_DETECT: n += sprintf(&line[n], "%s", v.loop_detect < 4 ? LOOP_NAMES[v.loop_detect] : "?"); break;
          case K_POSREPORT_INTERVAL: n += sprintf(&line[n], "%u", v.posreport_min); break;
          case K_OVERLAY: n += sprintf(&line[n], "%s", v.overlay ? "on" : "off"); break;
          case K_NAME: v.name[sizeof(v.name) - 1] = 0; n += sprintf(&line[n], "%s", v.name); break;
          case K_ADV_LOC: n += sprintf(&line[n], "%u", v.adv_loc); break;
          case K_TELEM_BASE: n += sprintf(&line[n], "%u", v.telem_base); break;
          case K_TELEM_LOC: n += sprintf(&line[n], "%u", v.telem_loc); break;
          case K_TELEM_ENV: n += sprintf(&line[n], "%u", v.telem_env); break;
          case K_MANUAL_ADD: n += sprintf(&line[n], "%u", v.manual_add); break;
          case K_AUTOADD: n += sprintf(&line[n], "%u", v.autoadd); break;
          case K_GPS: n += sprintf(&line[n], "%s", v.gps ? "on" : "off"); break;
          case K_LOCATION:   // only where the node advertises it anyway: a favourite is not told where it is
            if (v.adv_loc) {
              n += formatMicro(&line[n], v.lat_micro);
              line[n++] = ',';
              n += formatMicro(&line[n], v.lon_micro);
            } else {
              n += sprintf(&line[n], "hidden");
            }
            break;
          case K_BLE_PIN: n += sprintf(&line[n], "%s", v.ble_pin ? "set" : "0"); break;   // a pairing PIN is never read back
          case K_REGIONS: {
            char r[LORA_OTA_SET_GET_TEXT];
            _t->regionsExport(r, sizeof(r) - 16);
            snprintf(&line[n], sizeof(line) - n, "%s", r);
            n = strlen(line);
            break;
          }
        }
        line[n++] = '\n';
        if (used + n > LORA_OTA_SET_GET_TEXT) {
          if (used == 0) n = LORA_OTA_SET_GET_TEXT;   // one line longer than a reply: cut it
          else break;
        }
        memcpy(&out[used], line, n);
        used += n;
      }
      memset(&v, 0, sizeof(v));   // the PIN and the location were in it
      reply[0] = lora_ota::OK;
      reply[1] = k < K_COUNT ? k : 0xFF;
      return 2 + used;
    }
  }
  reply[0] = lora_ota::BAD_ARG;
  return 1;
}

int Settings::handle(const uint8_t* req, size_t len, uint8_t* reply, uint32_t now_ms) {
  if (len < 1) return 0;
  const uint8_t* p = &req[1];
  len--;
  switch (req[0]) {
    case LORA_OTA_REQ_SET_DATA: {   // total u16, offset u16, n u8, bytes -> status, have u16
      if (len < 5) { reply[0] = lora_ota::BAD_ARG; return 1; }
      uint16_t total = rd16(p), off = rd16(&p[2]);
      uint8_t n = p[4];
      if (total == 0 || total > LORA_OTA_SET_MAX_BUNDLE || n > len - 5 || off + n > total) {
        reply[0] = lora_ota::BAD_ARG; return 1;
      }
      if (_phase == VERIFYING) { reply[0] = lora_ota::WORKING; wr16(&reply[1], _have); return 3; }
      if (off == 0 || total != _total) {   // a new bundle (always sent from offset 0)
        _total = total;
        _have = 0;
        _phase = IDLE;
      }
      if (off <= _have) {   // in order: anything past a gap waits for the resend
        memcpy(&_buf[off], &p[5], n);
        if (off + n > _have) _have = off + n;
      }
      reply[0] = lora_ota::OK;
      wr16(&reply[1], _have);
      return 3;
    }
    case LORA_OTA_REQ_SET_APPLY: {   // total u16, sha256[0:8] -> status [, version u32, secs_left u16]
      if (len < 10) { reply[0] = lora_ota::BAD_ARG; return 1; }
      uint16_t total = rd16(p);
      const uint8_t* h = &p[2];
      if (_phase == VERIFYING && memcmp(h, _hash, 8) == 0) { reply[0] = lora_ota::WORKING; return 1; }
      if (_phase == DONE && memcmp(h, _hash, 8) == 0) {   // the result (again, if a reply got lost)
        reply[0] = _result;
        if (_result == lora_ota::OK && _switch_pending && !_switch_asked) {
          _switch_asked = true;   // the OK goes out now; the radio follows shortly after
          uint32_t at = now_ms + LORA_OTA_SET_SWITCH_MS;
          if ((int32_t)(at - _switch_at) < 0) _switch_at = at;
        }
        wr32(&reply[1], _result_version);
        long left = secondsLeft(now_ms);
        wr16(&reply[5], left > 0xFFFF ? 0xFFFF : (uint16_t)left);
        return 7;
      }
      if (_phase == VERIFYING) { reply[0] = lora_ota::BAD_STATE; return 1; }
      if (total != _total || _have < _total) { reply[0] = lora_ota::INCOMPLETE; wr16(&reply[1], _have); return 3; }
      uint8_t d[32];
      SHA256 sha;
      sha.update(_buf, _total);
      sha.finalize(d, 32);
      if (memcmp(d, h, 8) != 0) { reply[0] = lora_ota::HASH_MISMATCH; return 1; }
      memcpy(_hash, h, 8);
      _phase = VERIFYING;   // the signature check runs from poll(), not in the receive path
      reply[0] = lora_ota::WORKING;
      return 1;
    }
    case LORA_OTA_REQ_SET_CTRL:
      return ctrl(p, len, reply, now_ms);
  }
  return 0;
}

void Settings::poll(uint32_t now_ms, bool fw_pending) {
  if (_phase != VERIFYING) return;
  _result = verifyAndApply(now_ms, fw_pending);
  _phase = DONE;
}

void Settings::loop(uint32_t now_ms) {
  if (_switch_pending && (int32_t)(now_ms - _switch_at) >= 0) {
    _switch_pending = false;
    _t->applyRadio();
    _radio_event = true;
    _confirm_by = now_ms + LORA_OTA_SET_CONFIRM_SECS * 1000UL;   // the window starts on the new settings
  }
  if (pending() && !_switch_pending && (int32_t)(now_ms - _confirm_by) >= 0) {
    revert("no CONFIRM");
  }
  if (_reboot_due) {
    if (_reboot_at == 0) {
      _reboot_at = now_ms + LORA_OTA_SET_REBOOT_MS;
      if (_reboot_at == 0) _reboot_at = 1;
    } else if ((int32_t)(now_ms - _reboot_at) >= 0) {
      _reboot_due = false;
      _reboot_at = 0;
      _t->reboot();   // does not return on the radio
    }
  }
}

}

#endif

#include "FindHubBeacon.h"

#include <string.h>

namespace findhub {

// Beacon Actions data IDs (spec tables 2-6).
enum DataId : uint8_t {
  ID_BEACON_PARAMS = 0x00,
  ID_PROVISIONING_STATE = 0x01,
  ID_SET_EIK = 0x02,
  ID_CLEAR_EIK = 0x03,
  ID_READ_EIK = 0x04,
  ID_RING = 0x05,
  ID_RING_STATE = 0x06,
  ID_UTP_ON = 0x07,
  ID_UTP_OFF = 0x08,
};

static const uint8_t RING_ALL = 0xFF;
static const uint8_t RING_COMPONENTS = 1;      // one buzzer
static const uint8_t UTP_FLAG_SKIP_RING_AUTH = 0x01;
static const uint8_t PROV_FLAG_EIK_SET = 0x01;
static const uint8_t PROV_FLAG_OWNER = 0x02;
static const uint32_t MIN_PLAUSIBLE_UNIX = 1735689600UL;  // 2025-01-01

FindHubBeacon::FindHubBeacon(FindHubPlatform& platform) : _p(platform) {
  _provisioned = false;
  memset(&_prov, 0, sizeof(_prov));
  memset(_conns, 0, sizeof(_conns));
  _eid_valid = false;
  _eid_window = 0;
  memset(_eid, 0, sizeof(_eid));
  _hash_xor = 0;
  _rot_delay = 0;
  _rot_delay_window = 0xFFFFFFFF;
  _ring_comp = 0;
  _ring_until = 0;
  _ring_has_conn = false;
  _ring_conn = 0;
  memset(_ring_nonce, 0, sizeof(_ring_nonce));
  _utp = false;
  _utp_skip_ring_auth = false;
  _last_op = 0xFF;
  _last_status = 0xFF;
}

void FindHubBeacon::load(const Provisioning* p) {
  if (p) {
    _prov = *p;
    _provisioned = true;
  } else {
    memset(&_prov, 0, sizeof(_prov));
    _provisioned = false;
  }
  invalidateEid();
}

bool FindHubBeacon::provision(const Provisioning& p) {
  if (!_p.saveProvisioning(&p)) return false;
  load(&p);
  _utp = false;
  _utp_skip_ring_auth = false;
  return true;
}

bool FindHubBeacon::clear() {
  if (!_p.saveProvisioning(NULL)) return false;
  if (isRinging()) stopRing(RING_STOPPED_GATT);
  load(NULL);
  _utp = false;
  _utp_skip_ring_auth = false;
  return true;
}

bool FindHubBeacon::clockValid() {
  if (!_provisioned) return false;
  uint32_t now = _p.unixTime();
  return now >= MIN_PLAUSIBLE_UNIX && now >= _prov.pair_date;
}

uint32_t FindHubBeacon::counter() {
  return clockValid() ? _p.unixTime() - _prov.pair_date : 0;
}

bool FindHubBeacon::ensureEid(uint32_t adv_counter) {
  uint32_t window = adv_counter >> ROTATION_EXP;
  if (_eid_valid && window == _eid_window) return true;
  _eid_valid = computeEid(_prov.eik, adv_counter, _eid, &_hash_xor);
  _eid_window = window;
  return _eid_valid;
}

uint8_t FindHubBeacon::hashedFlags() {
  // bit 0 (LSB) = UTP mode, bits 1-2 = battery level (spec numbers bits MSB first).
  uint8_t seed = (_utp ? 0x01 : 0x00) | ((uint8_t)(_p.batteryLevel() & 0x03) << 1);
  return seed ^ _hash_xor;
}

size_t FindHubBeacon::buildAdvert(uint8_t out[ADV_FRAME_LEN]) {
  if (!clockValid()) return 0;
  uint32_t c = counter();

  // The switch to a new EID is delayed by a random 1..204 s past each window
  // boundary (spec "ID rotation"). Until then the previous window's EID stays.
  uint32_t window = c >> ROTATION_EXP;
  if (window != _rot_delay_window) {
    uint8_t r[2];
    _p.randomBytes(r, sizeof(r));
    _rot_delay = 1 + (((uint32_t)r[0] << 8 | r[1]) % 204);
    _rot_delay_window = window;
  }
  uint32_t adv_counter = (c >= _rot_delay && (c & ((1UL << ROTATION_EXP) - 1)) < _rot_delay) ? c - _rot_delay : c;
  if (!ensureEid(adv_counter)) return 0;

  size_t i = 0;
  out[i++] = 0x02; out[i++] = 0x01; out[i++] = 0x06;          // flags: LE general disc, no BR/EDR
  out[i++] = 0x19; out[i++] = 0x16;                           // len 25, service data (16-bit UUID)
  out[i++] = 0xAA; out[i++] = 0xFE;                           // 0xFEAA
  out[i++] = _utp ? 0x41 : 0x40;
  memcpy(&out[i], _eid, EID_LEN); i += EID_LEN;
  out[i++] = hashedFlags();
  return i;
}

size_t FindHubBeacon::onRead(uint8_t conn, uint8_t out[1 + NONCE_LEN]) {
  if (conn >= MAX_CONN) return 0;
  Conn& c = _conns[conn];
  _p.randomBytes(c.nonce, NONCE_LEN);
  c.nonce_valid = true;
  out[0] = PROTOCOL_MAJOR;
  memcpy(&out[1], c.nonce, NONCE_LEN);
  return 1 + NONCE_LEN;
}

void FindHubBeacon::onDisconnect(uint8_t conn) {
  if (conn >= MAX_CONN) return;
  memset(&_conns[conn], 0, sizeof(Conn));
  if (_ring_has_conn && _ring_conn == conn) _ring_has_conn = false;   // keep ringing (spec)
}

uint8_t FindHubBeacon::onWrite(uint8_t conn, const uint8_t* buf, size_t len, uint8_t rsp[MAX_NOTIFY_LEN], size_t* rsp_len) {
  _last_op = len ? buf[0] : 0xFE;
  _last_status = dispatch(conn, buf, len, rsp, rsp_len);
  return _last_status;
}

uint8_t FindHubBeacon::dispatch(uint8_t conn, const uint8_t* buf, size_t len, uint8_t* rsp, size_t* rsp_len) {
  *rsp_len = 0;
  if (conn >= MAX_CONN) return ATT_INVALID_VALUE;
  Conn& c = _conns[conn];

  // A nonce is good for exactly one write, failed or not.
  if (!c.nonce_valid) return ATT_UNAUTHENTICATED;
  c.nonce_valid = false;

  if (len < 2) return ATT_INVALID_VALUE;
  uint8_t id = buf[0];
  uint8_t data_len = buf[1];
  if ((size_t)data_len != len - 2 || data_len < AUTH_LEN) return ATT_INVALID_VALUE;
  const uint8_t* payload = &buf[2];

  switch (id) {
    case ID_BEACON_PARAMS:      return opBeaconParams(conn, payload, data_len, rsp, rsp_len);
    case ID_PROVISIONING_STATE: return opProvisioningState(conn, payload, data_len, rsp, rsp_len);
    case ID_SET_EIK:            return opSetEik(conn, payload, data_len, rsp, rsp_len);
    case ID_CLEAR_EIK:          return opClearEik(conn, payload, data_len, rsp, rsp_len);
    case ID_READ_EIK:           return ATT_NO_USER_CONSENT;   // recovery mode not implemented
    case ID_RING:               return opRing(conn, payload, data_len, rsp, rsp_len);
    case ID_RING_STATE:         return opRingState(conn, payload, data_len, rsp, rsp_len);
    case ID_UTP_ON:
    case ID_UTP_OFF:            return opUtp(conn, id, payload, data_len, rsp, rsp_len);
    default:                    return ATT_INVALID_VALUE;
  }
}

// Request authentication: payload = auth(8) || add.
static bool authOk(const uint8_t* key, size_t key_len, const uint8_t nonce[NONCE_LEN],
                   uint8_t id, const uint8_t* payload, size_t n, bool hash_add) {
  uint8_t expect[AUTH_LEN];
  authSegment(key, key_len, nonce, id, (uint8_t)n, &payload[AUTH_LEN], hash_add ? n - AUTH_LEN : 0, false, expect);
  return equalCT(expect, payload, AUTH_LEN);
}

size_t FindHubBeacon::buildResponse(uint8_t* rsp, uint8_t data_id, const uint8_t* key, size_t key_len,
                                    const uint8_t nonce[NONCE_LEN], const uint8_t* add, size_t add_len) {
  rsp[0] = data_id;
  rsp[1] = (uint8_t)(AUTH_LEN + add_len);
  authSegment(key, key_len, nonce, data_id, rsp[1], add, add_len, true, &rsp[2]);
  if (add_len) memcpy(&rsp[2 + AUTH_LEN], add, add_len);
  return 2 + AUTH_LEN + add_len;
}

uint8_t FindHubBeacon::opBeaconParams(uint8_t conn, const uint8_t* p, size_t n, uint8_t* rsp, size_t* rsp_len) {
  if (n != AUTH_LEN) return ATT_INVALID_VALUE;
  if (!_provisioned || !authOk(_prov.ak, AK_LEN, _conns[conn].nonce, ID_BEACON_PARAMS, p, n, false))
    return ATT_UNAUTHENTICATED;

  uint8_t plain[16];
  memset(plain, 0, sizeof(plain));
  uint32_t clk = counter();
  plain[0] = (uint8_t)_p.calibratedPower();
  plain[1] = (uint8_t)(clk >> 24); plain[2] = (uint8_t)(clk >> 16);
  plain[3] = (uint8_t)(clk >> 8);  plain[4] = (uint8_t)clk;
  plain[5] = 0x00;                 // SECP160R1
  plain[6] = RING_COMPONENTS;
  plain[7] = 0x00;                 // no volume selection
  uint8_t enc[16];
  aes128EcbEncrypt(_prov.ak, plain, enc, sizeof(enc));
  *rsp_len = buildResponse(rsp, ID_BEACON_PARAMS, _prov.ak, AK_LEN, _conns[conn].nonce, enc, sizeof(enc));
  return ATT_OK;
}

uint8_t FindHubBeacon::opProvisioningState(uint8_t conn, const uint8_t* p, size_t n, uint8_t* rsp, size_t* rsp_len) {
  if (n != AUTH_LEN) return ATT_INVALID_VALUE;
  // Only the owner account key exists on this device, so a match is always "owner".
  if (!_provisioned || !authOk(_prov.ak, AK_LEN, _conns[conn].nonce, ID_PROVISIONING_STATE, p, n, false))
    return ATT_UNAUTHENTICATED;

  uint8_t add[1 + EID_LEN];
  size_t add_len = 1;
  add[0] = PROV_FLAG_OWNER;
  if (clockValid() && ensureEid(counter())) {
    add[0] |= PROV_FLAG_EIK_SET;
    memcpy(&add[1], _eid, EID_LEN);
    add_len += EID_LEN;
  }
  *rsp_len = buildResponse(rsp, ID_PROVISIONING_STATE, _prov.ak, AK_LEN, _conns[conn].nonce, add, add_len);
  return ATT_OK;
}

uint8_t FindHubBeacon::opSetEik(uint8_t conn, const uint8_t* p, size_t n, uint8_t* rsp, size_t* rsp_len) {
  // First provisioning happens over the bonded companion link (we have no account
  // key before that), so this is only ever a re-key, which carries the hash of
  // the current EIK.
  if (!_provisioned) return ATT_UNAUTHENTICATED;
  if (n != AUTH_LEN + EIK_LEN + 8) return ATT_INVALID_VALUE;
  const uint8_t* nonce = _conns[conn].nonce;
  uint8_t expect[AUTH_LEN];
  authSegment(_prov.ak, AK_LEN, nonce, ID_SET_EIK, (uint8_t)n, &p[AUTH_LEN], n - AUTH_LEN, false, expect);
  if (!equalCT(expect, p, AUTH_LEN)) return ATT_UNAUTHENTICATED;
  uint8_t hash[8];
  sha256Trunc8(_prov.eik, EIK_LEN, nonce, NONCE_LEN, hash);
  if (!equalCT(hash, &p[AUTH_LEN + EIK_LEN], 8)) return ATT_UNAUTHENTICATED;

  Provisioning next = _prov;
  aes128EcbDecrypt(_prov.ak, &p[AUTH_LEN], next.eik, EIK_LEN);
  uint8_t saved_nonce[NONCE_LEN];
  memcpy(saved_nonce, nonce, NONCE_LEN);
  if (!provision(next)) return ATT_INVALID_VALUE;
  memset(next.eik, 0, EIK_LEN);
  // Response auth: HMAC(AK, ver || nonce || id || len || 0x01), no additional data.
  *rsp_len = buildResponse(rsp, ID_SET_EIK, _prov.ak, AK_LEN, saved_nonce, NULL, 0);
  return ATT_OK;
}

uint8_t FindHubBeacon::opClearEik(uint8_t conn, const uint8_t* p, size_t n, uint8_t* rsp, size_t* rsp_len) {
  if (n != AUTH_LEN + 8) return ATT_INVALID_VALUE;
  if (!_provisioned) return ATT_UNAUTHENTICATED;
  const uint8_t* nonce = _conns[conn].nonce;
  if (!authOk(_prov.ak, AK_LEN, nonce, ID_CLEAR_EIK, p, n, true)) return ATT_UNAUTHENTICATED;
  uint8_t hash[8];
  sha256Trunc8(_prov.eik, EIK_LEN, nonce, NONCE_LEN, hash);
  if (!equalCT(hash, &p[AUTH_LEN], 8)) return ATT_UNAUTHENTICATED;

  uint8_t ak[AK_LEN], saved_nonce[NONCE_LEN];
  memcpy(ak, _prov.ak, AK_LEN);
  memcpy(saved_nonce, nonce, NONCE_LEN);
  if (!clear()) return ATT_INVALID_VALUE;
  *rsp_len = buildResponse(rsp, ID_CLEAR_EIK, ak, AK_LEN, saved_nonce, NULL, 0);
  memset(ak, 0, sizeof(ak));
  return ATT_OK;
}

uint8_t FindHubBeacon::opRing(uint8_t conn, const uint8_t* p, size_t n, uint8_t* rsp, size_t* rsp_len) {
  if (n != AUTH_LEN + 4) return ATT_INVALID_VALUE;
  if (!_provisioned) return ATT_UNAUTHENTICATED;
  const uint8_t* nonce = _conns[conn].nonce;
  bool auth = !(_utp && _utp_skip_ring_auth);
  if (auth) {
    uint8_t ring_key[DERIVED_KEY_LEN];
    deriveKey(_prov.eik, KEY_RING, ring_key);
    bool ok = authOk(ring_key, sizeof(ring_key), nonce, ID_RING, p, n, true);
    memset(ring_key, 0, sizeof(ring_key));
    if (!ok) return ATT_UNAUTHENTICATED;
  }
  uint8_t comp = p[AUTH_LEN];
  uint16_t timeout = ((uint16_t)p[AUTH_LEN + 1] << 8) | p[AUTH_LEN + 2];
  // p[AUTH_LEN + 3] = volume: a piezo has one loudness; we advertise no volume selection.
  if (auth && comp != RING_ALL && comp != 0 && __builtin_popcount(comp & 0x07) > RING_COMPONENTS)
    return ATT_UNAUTHENTICATED;      // spec: state must match the components that can ring
  if (comp != 0 && (timeout == 0 || timeout > RING_MAX_DS)) return ATT_INVALID_VALUE;

  // The ring-state notification is authenticated with THIS request's nonce.
  memcpy(_ring_nonce, nonce, NONCE_LEN);
  _ring_has_conn = true;
  _ring_conn = conn;
  if (comp == 0) {
    stopRing(RING_STOPPED_GATT);       // also notifies when already silent (spec)
  } else {
    startRing(timeout);
  }
  return ATT_OK;   // the state notification already went out through the platform
}

uint8_t FindHubBeacon::opRingState(uint8_t conn, const uint8_t* p, size_t n, uint8_t* rsp, size_t* rsp_len) {
  if (n != AUTH_LEN) return ATT_INVALID_VALUE;
  if (!_provisioned) return ATT_UNAUTHENTICATED;
  uint8_t ring_key[DERIVED_KEY_LEN];
  deriveKey(_prov.eik, KEY_RING, ring_key);
  if (!authOk(ring_key, sizeof(ring_key), _conns[conn].nonce, ID_RING_STATE, p, n, false)) {
    memset(ring_key, 0, sizeof(ring_key));
    return ATT_UNAUTHENTICATED;
  }
  uint16_t rem = ringRemainingDs();
  uint8_t add[3] = { _ring_comp, (uint8_t)(rem >> 8), (uint8_t)rem };
  *rsp_len = buildResponse(rsp, ID_RING_STATE, ring_key, sizeof(ring_key), _conns[conn].nonce, add, sizeof(add));
  memset(ring_key, 0, sizeof(ring_key));
  return ATT_OK;
}

uint8_t FindHubBeacon::opUtp(uint8_t conn, uint8_t id, const uint8_t* p, size_t n, uint8_t* rsp, size_t* rsp_len) {
  if (!_provisioned) return ATT_UNAUTHENTICATED;
  const uint8_t* nonce = _conns[conn].nonce;
  uint8_t utp_key[DERIVED_KEY_LEN];
  deriveKey(_prov.eik, KEY_UTP, utp_key);
  uint8_t status = ATT_OK;

  if (id == ID_UTP_ON) {
    if (n != AUTH_LEN && n != AUTH_LEN + 1) status = ATT_INVALID_VALUE;    // flags byte optional
    else if (!authOk(utp_key, sizeof(utp_key), nonce, id, p, n, true)) status = ATT_UNAUTHENTICATED;
    else {
      uint8_t flags = n > AUTH_LEN ? p[AUTH_LEN] : 0;
      if (flags & ~UTP_FLAG_SKIP_RING_AUTH) status = ATT_INVALID_VALUE;
      else { _utp = true; _utp_skip_ring_auth = (flags & UTP_FLAG_SKIP_RING_AUTH) != 0; }
    }
  } else {
    if (n != AUTH_LEN + 8) status = ATT_INVALID_VALUE;
    else if (!authOk(utp_key, sizeof(utp_key), nonce, id, p, n, true)) status = ATT_UNAUTHENTICATED;
    else {
      uint8_t hash[8];
      sha256Trunc8(_prov.eik, EIK_LEN, nonce, NONCE_LEN, hash);
      if (!equalCT(hash, &p[AUTH_LEN], 8)) status = ATT_UNAUTHENTICATED;
      else { _utp = false; _utp_skip_ring_auth = false; }
    }
  }
  if (status == ATT_OK) *rsp_len = buildResponse(rsp, id, utp_key, sizeof(utp_key), nonce, NULL, 0);
  memset(utp_key, 0, sizeof(utp_key));
  return status;
}

// ---------------------------------------------------------------- ringing

uint16_t FindHubBeacon::ringRemainingDs() {
  if (!_ring_comp) return 0;
  int32_t left = (int32_t)(_ring_until - _p.millis());
  return left <= 0 ? 0 : (uint16_t)((left + 99) / 100);
}

void FindHubBeacon::startRing(uint16_t ds) {
  _ring_comp = RING_ALL;
  _ring_until = _p.millis() + (uint32_t)ds * 100;
  _p.ringStart();
  notifyRingState(RING_STARTED);
}

void FindHubBeacon::stopRing(RingTrigger why) {
  bool was = _ring_comp != 0;
  _ring_comp = 0;
  if (was) _p.ringStop();
  notifyRingState(why);
}

void FindHubBeacon::notifyRingState(RingTrigger why) {
  if (!_ring_has_conn || !_provisioned) return;
  uint8_t ring_key[DERIVED_KEY_LEN];
  deriveKey(_prov.eik, KEY_RING, ring_key);
  uint16_t rem = ringRemainingDs();
  uint8_t add[4] = { why, _ring_comp, (uint8_t)(rem >> 8), (uint8_t)rem };
  uint8_t rsp[2 + AUTH_LEN + sizeof(add)];
  size_t len = buildResponse(rsp, ID_RING, ring_key, sizeof(ring_key), _ring_nonce, add, sizeof(add));
  memset(ring_key, 0, sizeof(ring_key));
  _p.notify(_ring_conn, rsp, len);
}

void FindHubBeacon::loop() {
  if (_ring_comp && (int32_t)(_ring_until - _p.millis()) <= 0) stopRing(RING_STOPPED_TIMEOUT);
}

void FindHubBeacon::buttonPressed() {
  if (_ring_comp) stopRing(RING_STOPPED_BUTTON);
}

void FindHubBeacon::ringLocal(uint16_t ds) {
  if (ds == 0) {
    if (_ring_comp) stopRing(RING_STOPPED_GATT);
    return;
  }
  if (ds > RING_MAX_DS) ds = RING_MAX_DS;
  _ring_has_conn = false;       // no GATT peer to notify
  startRing(ds);
}

}  // namespace findhub

#include "FastPair.h"

#include <string.h>

namespace findhub {

enum MsgType : uint8_t {
  MSG_KBP_REQUEST = 0x00,
  MSG_KBP_RESPONSE = 0x01,
  MSG_SEEKER_PASSKEY = 0x02,
  MSG_PROVIDER_PASSKEY = 0x03,
  MSG_ACTION_REQUEST = 0x10,
};

// Key-based Pairing request flags; the spec numbers bits from the MSB.
static const uint8_t KBP_FLAG_RETROACTIVE = 0x10;     // bit 3: retroactively write account key

static const uint32_t KEY_TIMEOUT_MS = 10000;          // spec step 4 / 16.1
static const uint8_t MAX_FAILURES = 10;                 // spec step 3.1
static const uint32_t LOCKOUT_MS = 5UL * 60 * 1000;
static const uint8_t ACCOUNT_KEY_PREFIX = 0x04;

// Advertising structures.
static const uint8_t AD_FLAGS[3] = { 0x02, 0x01, 0x06 };   // LE general discoverable, no BR/EDR
static const uint8_t FIELD_FILTER_HIDE_UI = 0x02;          // Account Key Filter, hide UI indication
static const uint8_t FIELD_SALT = 0x01;

FastPairProvider::FastPairProvider(FindHubPlatform& platform, const FastPairConfig& cfg) : _p(platform), _cfg(cfg) {
  memset(&_keys, 0, sizeof(_keys));
  _keys.owner = 0xFF;
  _pairing_mode = false;
  memset(_conns, 0, sizeof(_conns));
  _failures = 0;
  _lockout_until = 0;
  _ak_written = false;
  _last_result = 0xFF;
  memset(_seen, 0, sizeof(_seen));
  _seen_next = 0;
}

void FastPairProvider::load(const AccountKeyData* d) {
  memset(&_keys, 0, sizeof(_keys));
  _keys.owner = 0xFF;
  if (d && d->count <= MAX_ACCOUNT_KEYS) {
    _keys = *d;
    if (_keys.owner >= _keys.count) _keys.owner = _keys.count ? 0 : 0xFF;
  }
}

bool FastPairProvider::factoryReset() {
  bool ok = _p.saveAccountKeys(NULL);
  memset(&_keys, 0, sizeof(_keys));
  _keys.owner = 0xFF;
  for (size_t i = 0; i < FP_MAX_CONN; i++) dropKey(_conns[i]);
  return ok;
}

bool FastPairProvider::isOwnerKey(const uint8_t* k) const {
  const uint8_t* o = ownerKey();
  return o && k && equalCT(o, k, AK_LEN);
}

void FastPairProvider::onConnect(uint8_t conn, const uint8_t (*addrs)[ADDR_LEN], size_t n) {
  if (conn >= FP_MAX_CONN) return;
  Conn& c = _conns[conn];
  memset(&c, 0, sizeof(c));
  c.n_addrs = n > MAX_LINK_ADDRS ? MAX_LINK_ADDRS : (uint8_t)n;
  for (uint8_t i = 0; i < c.n_addrs; i++) memcpy(c.addrs[i], addrs[i], ADDR_LEN);
  c.pairing_mode = _pairing_mode;
}

void FastPairProvider::onDisconnect(uint8_t conn) {
  if (conn >= FP_MAX_CONN) return;
  dropKey(_conns[conn]);
  memset(&_conns[conn], 0, sizeof(Conn));
}

void FastPairProvider::dropKey(Conn& c) {
  c.state = KEY_NONE;
  memset(c.k, 0, sizeof(c.k));
  c.await_account_key = false;
  c.cmp_pending = false;
  c.cmp_decided = false;
}

void FastPairProvider::loop() {
  uint32_t now = _p.millis();
  for (size_t i = 0; i < FP_MAX_CONN; i++) {
    Conn& c = _conns[i];
    if (c.state != KEY_NONE && (int32_t)(now - c.deadline) >= 0) dropKey(c);
  }
  if (_failures >= MAX_FAILURES && (int32_t)(now - _lockout_until) >= 0) _failures = 0;
}

void FastPairProvider::fail() {
  if (_failures < MAX_FAILURES && ++_failures == MAX_FAILURES) _lockout_until = _p.millis() + LOCKOUT_MS;
}

// A decrypted request is valid when it is a request type we know and names the
// address this link was made on (bytes 2..7, most significant byte first).
bool FastPairProvider::validRequest(Conn& c, const uint8_t req[FP_BLOCK]) {
  if (req[0] != MSG_KBP_REQUEST && req[0] != MSG_ACTION_REQUEST) return false;
  for (uint8_t a = 0; a < c.n_addrs; a++) {
    bool match = true;
    for (size_t i = 0; i < ADDR_LEN; i++) {
      if (req[2 + i] != c.addrs[a][ADDR_LEN - 1 - i]) { match = false; break; }
    }
    if (match) { c.addr_used = a; return true; }
  }
  return false;
}

bool FastPairProvider::tryKey(Conn& c, const uint8_t key[AK_LEN], const uint8_t enc[FP_BLOCK], uint8_t req[FP_BLOCK]) {
  aes128EcbDecrypt(key, enc, req, FP_BLOCK);
  return validRequest(c, req);
}

void FastPairProvider::touchKey(size_t i) {
  if (i == 0 || i >= _keys.count) return;
  uint8_t k[AK_LEN];
  memcpy(k, _keys.keys[i], AK_LEN);
  memmove(_keys.keys[1], _keys.keys[0], i * AK_LEN);
  memcpy(_keys.keys[0], k, AK_LEN);
  memset(k, 0, sizeof(k));
  if (_keys.owner == i) _keys.owner = 0;
  else if (_keys.owner < i) _keys.owner++;
  _p.saveAccountKeys(&_keys);      // order only; a failed write costs nothing but LRU accuracy
}

uint8_t FastPairProvider::onKeyBasedPairing(uint8_t conn, const uint8_t* buf, size_t len, uint8_t rsp[FP_BLOCK], size_t* rsp_len) {
  *rsp_len = 0;
  if (conn >= FP_MAX_CONN) return _last_result = FP_ERR_UNLIKELY;
  Conn& c = _conns[conn];
  if (len != FP_BLOCK && len != FP_BLOCK + P256_PUB_LEN) return _last_result = FP_ERR_INVALID_LEN;
  if (_failures >= MAX_FAILURES) return _last_result = FP_ERR_UNLIKELY;
  if (c.state != KEY_NONE) {          // one procedure at a time per link
    dropKey(c);
    return _last_result = FP_ERR_UNLIKELY;
  }

  uint8_t req[FP_BLOCK];
  bool ok = false;
  if (len == FP_BLOCK + P256_PUB_LEN) {
    // Initial pairing: the Seeker proves nothing yet; we prove the anti-spoofing key.
    if (!c.pairing_mode && !_pairing_mode) return _last_result = FP_ERR_UNLIKELY;   // ignored, not a failure
    uint8_t secret[32];
    if (ecdhP256(_cfg.antispoof_priv, &buf[FP_BLOCK], secret)) {
      aesKeyFromSecret(secret, c.k);
      ok = tryKey(c, c.k, buf, req);
      if (ok) c.state = KEY_ANTISPOOF;
    }
    memset(secret, 0, sizeof(secret));
  } else {
    // Subsequent pairing: any stored account key that decrypts it.
    for (size_t i = 0; i < _keys.count && !ok; i++) {
      if (tryKey(c, _keys.keys[i], buf, req)) {
        memcpy(c.k, _keys.keys[i], AK_LEN);
        c.state = KEY_ACCOUNT;
        ok = true;
        touchKey(i);
      }
    }
  }

  if (ok) {
    for (uint8_t i = 0; i < SEEN; i++) {
      if (equalCT(_seen[i], &req[8], 8)) { ok = false; break; }    // replayed request
    }
  }
  if (!ok) {
    dropKey(c);
    fail();
    memset(req, 0, sizeof(req));
    return _last_result = FP_ERR_UNLIKELY;
  }
  memcpy(_seen[_seen_next], &req[8], 8);
  _seen_next = (_seen_next + 1) % SEEN;
  _failures = 0;

  // Only the plain Key-based Pairing request: no personalized name (action
  // request), no retroactive account key write. Bit 1 (provider-initiated BR/EDR
  // bonding) has no meaning on an LE-only device and is ignored, as NCS does.
  bool supported = req[0] == MSG_KBP_REQUEST && !(req[1] & KBP_FLAG_RETROACTIVE);
  memset(req, 0, sizeof(req));
  if (!supported) {
    dropKey(c);
    return _last_result = FP_ERR_UNLIKELY;
  }

  c.deadline = _p.millis() + KEY_TIMEOUT_MS;

  uint8_t raw[FP_BLOCK];
  raw[0] = MSG_KBP_RESPONSE;
  for (size_t i = 0; i < ADDR_LEN; i++) raw[1 + i] = c.addrs[c.addr_used][ADDR_LEN - 1 - i];
  _p.randomBytes(&raw[1 + ADDR_LEN], FP_BLOCK - 1 - ADDR_LEN);
  aes128EcbEncrypt(c.k, raw, rsp, FP_BLOCK);
  memset(raw, 0, sizeof(raw));
  *rsp_len = FP_BLOCK;
  return _last_result = FP_OK;
}

void FastPairProvider::onNumericComparison(uint8_t conn, uint32_t passkey) {
  if (conn >= FP_MAX_CONN) return;
  Conn& c = _conns[conn];
  c.stack_passkey = passkey;
  c.cmp_pending = c.state != KEY_NONE;
  c.cmp_decided = false;
}

bool FastPairProvider::comparisonResult(uint8_t conn, bool* ok) const {
  if (conn >= FP_MAX_CONN || !_conns[conn].cmp_decided) return false;
  *ok = _conns[conn].cmp_ok;
  return true;
}

uint8_t FastPairProvider::onPasskey(uint8_t conn, const uint8_t* buf, size_t len, uint8_t rsp[FP_BLOCK], size_t* rsp_len) {
  *rsp_len = 0;
  if (conn >= FP_MAX_CONN) return _last_result = FP_ERR_UNLIKELY;
  Conn& c = _conns[conn];
  if (len != FP_BLOCK) return _last_result = FP_ERR_INVALID_LEN;
  if (c.state == KEY_NONE || !c.cmp_pending) return _last_result = FP_ERR_UNLIKELY;

  uint8_t raw[FP_BLOCK];
  aes128EcbDecrypt(c.k, buf, raw, FP_BLOCK);
  if (raw[0] != MSG_SEEKER_PASSKEY) {          // spec step 11: discard K
    memset(raw, 0, sizeof(raw));
    dropKey(c);
    return _last_result = FP_ERR_UNLIKELY;
  }
  uint32_t seeker = ((uint32_t)raw[1] << 16) | ((uint32_t)raw[2] << 8) | raw[3];
  c.cmp_ok = seeker == c.stack_passkey;
  c.cmp_decided = true;
  c.cmp_pending = false;
  c.deadline = _p.millis() + KEY_TIMEOUT_MS;

  // Our own passkey back, with a fresh salt (spec step 14).
  raw[0] = MSG_PROVIDER_PASSKEY;
  raw[1] = (uint8_t)(c.stack_passkey >> 16);
  raw[2] = (uint8_t)(c.stack_passkey >> 8);
  raw[3] = (uint8_t)c.stack_passkey;
  _p.randomBytes(&raw[4], FP_BLOCK - 4);
  aes128EcbEncrypt(c.k, raw, rsp, FP_BLOCK);
  memset(raw, 0, sizeof(raw));
  *rsp_len = FP_BLOCK;
  return _last_result = FP_OK;
}

void FastPairProvider::onPairingComplete(uint8_t conn, bool success) {
  if (conn >= FP_MAX_CONN) return;
  Conn& c = _conns[conn];
  if (c.state == KEY_NONE) return;
  if (success && c.cmp_decided && c.cmp_ok) {
    c.await_account_key = true;
    c.deadline = _p.millis() + KEY_TIMEOUT_MS;
  } else {
    dropKey(c);
  }
}

bool FastPairProvider::storeAccountKey(const uint8_t ak[AK_LEN]) {
  for (size_t i = 0; i < _keys.count; i++) {
    if (equalCT(_keys.keys[i], ak, AK_LEN)) {   // already known: just most recent now
      touchKey(i);
      return true;
    }
  }
  AccountKeyData next = _keys;
  if (next.count == MAX_ACCOUNT_KEYS) {
    // Evict the least recently used key that is not the owner's (FHN spec).
    size_t victim = MAX_ACCOUNT_KEYS - 1;
    if (next.owner == victim) victim--;
    memmove(next.keys[victim], next.keys[victim + 1], (MAX_ACCOUNT_KEYS - 1 - victim) * AK_LEN);
    if (next.owner != 0xFF && next.owner > victim) next.owner--;
    next.count--;
  }
  memmove(next.keys[1], next.keys[0], next.count * AK_LEN);
  memcpy(next.keys[0], ak, AK_LEN);
  next.count++;
  if (next.owner == 0xFF) next.owner = 0;    // the first account key ever is the owner's
  else next.owner++;
  if (!_p.saveAccountKeys(&next)) {
    memset(&next, 0, sizeof(next));
    return false;
  }
  _keys = next;
  memset(&next, 0, sizeof(next));
  return true;
}

uint8_t FastPairProvider::onAccountKey(uint8_t conn, const uint8_t* buf, size_t len, bool link_encrypted) {
  if (conn >= FP_MAX_CONN) return _last_result = FP_ERR_UNLIKELY;
  Conn& c = _conns[conn];
  if (len != AK_LEN) return _last_result = FP_ERR_INVALID_LEN;
  // Bonding flow: only after the passkey-confirmed pairing. No-bonding flow: on
  // the unencrypted link of a fresh Key-based Pairing.
  bool allowed = c.state != KEY_NONE && (link_encrypted ? c.await_account_key : true);
  if (!allowed) {
    dropKey(c);
    return _last_result = FP_ERR_UNLIKELY;
  }
  uint8_t ak[AK_LEN];
  aes128EcbDecrypt(c.k, buf, ak, AK_LEN);
  dropKey(c);                                // K is single-use (spec step 16.1)
  uint8_t status = FP_OK;
  if (ak[0] != ACCOUNT_KEY_PREFIX) status = FP_ERR_UNLIKELY;   // 0xFF temporary sessions unsupported
  else if (!storeAccountKey(ak)) status = FP_ERR_UNLIKELY;
  else _ak_written = true;
  memset(ak, 0, sizeof(ak));
  return _last_result = status;
}

size_t FastPairProvider::discoverableAdvert(uint8_t out[FP_ADV_MAX]) const {
  size_t i = 0;
  memcpy(&out[i], AD_FLAGS, sizeof(AD_FLAGS)); i += sizeof(AD_FLAGS);
  out[i++] = 0x06; out[i++] = 0x16; out[i++] = 0x2C; out[i++] = 0xFE;   // service data, UUID 0xFE2C
  memcpy(&out[i], _cfg.model_id, MODEL_ID_LEN); i += MODEL_ID_LEN;
  out[i++] = 0x02; out[i++] = 0x0A; out[i++] = (uint8_t)_p.calibratedPower();  // Tx Power Level
  return i;
}

size_t FastPairProvider::notDiscoverableAdvert(const uint8_t salt[2], uint8_t out[FP_ADV_MAX]) const {
  if (_keys.count == 0) return 0;     // spec: account data only with one or more keys
  uint8_t filter[MAX_FILTER_LEN];
  size_t s = accountKeyFilter(_keys.keys, _keys.count, salt, NULL, 0, filter);
  if (s == 0) return 0;
  size_t i = 0;
  memcpy(&out[i], AD_FLAGS, sizeof(AD_FLAGS)); i += sizeof(AD_FLAGS);
  size_t svc_len = 2 + 1 + 1 + s + 1 + 2;      // UUID, version, filter header, filter, salt header, salt
  out[i++] = (uint8_t)(1 + svc_len); out[i++] = 0x16; out[i++] = 0x2C; out[i++] = 0xFE;
  out[i++] = 0x00;                                         // version and flags
  out[i++] = (uint8_t)((s << 4) | FIELD_FILTER_HIDE_UI);
  memcpy(&out[i], filter, s); i += s;
  out[i++] = (uint8_t)((2 << 4) | FIELD_SALT);
  out[i++] = salt[0]; out[i++] = salt[1];
  out[i++] = 0x02; out[i++] = 0x0A; out[i++] = (uint8_t)_p.calibratedPower();
  return i;
}

}  // namespace findhub

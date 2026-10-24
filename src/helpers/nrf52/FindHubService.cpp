#include "FindHubService.h"

#include <InternalFileSystem.h>
#include "SerialBLEInterface.h"   // BLE_TX_POWER

using namespace Adafruit_LittleFS_Namespace;
using namespace findhub;

FindHubService* findhub_service = nullptr;
static uint32_t* sd_err_sink = nullptr;

// FE2C12xx-8366-4814-8EB0-01DE32100BEA (little-endian for Bluefruit). Static:
// BLEUuid keeps a pointer to the array, not a copy.
#define FP_UUID(xx) { 0xEA, 0x0B, 0x10, 0x32, 0xDE, 0x01, 0xB0, 0x8E, 0x14, 0x48, 0x66, 0x83, xx, 0x12, 0x2C, 0xFE }
static const uint8_t UUID_MODEL_ID[16] = FP_UUID(0x33);
static const uint8_t UUID_KBP[16] = FP_UUID(0x34);
static const uint8_t UUID_PASSKEY[16] = FP_UUID(0x35);
static const uint8_t UUID_ACCOUNT_KEY[16] = FP_UUID(0x36);
static const uint8_t UUID_BEACON_ACTIONS[16] = FP_UUID(0x38);
static const uint16_t FAST_PAIR_SERVICE_UUID = 0xFE2C;
static const uint16_t DIS_UUID = 0x180A;
static const uint16_t FW_REV_UUID = 0x2A26;

#define AK_FILE        "/fh_ak"
#define EIK_FILE       "/fh_eik"
#define CLOCK_FILE     "/fh_clk"
#define BOOT_FILE      "/fh_boot"       // exists once Find Hub ran on this device
#define AK_MAGIC       0x324B4146UL     // "FAK2"
#define EIK_MAGIC      0x324B4945UL     // "EIK2"
#define CLOCK_SAVE_SECS 3600            // spec: persist the clock at least daily

struct AkRecord { uint32_t magic; AccountKeyData d; };
struct EikRecord { uint32_t magic; uint8_t eik[EIK_LEN]; };

static bool hexToBytes(const char* hex, uint8_t* out, size_t len) {
  if (strlen(hex) != len * 2) return false;
  for (size_t i = 0; i < len; i++) {
    unsigned v;
    if (sscanf(&hex[i * 2], "%2x", &v) != 1) return false;
    out[i] = (uint8_t)v;
  }
  return true;
}

static FastPairConfig makeConfig() {
  FastPairConfig c;
  uint32_t id = FINDHUB_MODEL_ID;
  c.model_id[0] = (uint8_t)(id >> 16);
  c.model_id[1] = (uint8_t)(id >> 8);
  c.model_id[2] = (uint8_t)id;
  if (!hexToBytes(FINDHUB_ANTISPOOF_KEY_HEX, c.antispoof_priv, sizeof(c.antispoof_priv))) {
    memset(c.antispoof_priv, 0, sizeof(c.antispoof_priv));   // ECDH then fails: no initial pairing
  }
  return c;
}

FindHubService::FindHubService()
  : _svc(FAST_PAIR_SERVICE_UUID), _model_id(UUID_MODEL_ID), _kbp(UUID_KBP), _passkey(UUID_PASSKEY),
    _account_key(UUID_ACCOUNT_KEY), _beacon_chr(UUID_BEACON_ACTIONS), _dis(DIS_UUID), _fw_rev(FW_REV_UUID),
    _fw_version("unknown"), _cfg(makeConfig()), _hub(*this, _cfg), _board(nullptr), _ring_cb(nullptr),
    _q_head(0), _q_tail(0), _started(false), _clock_s(0), _clock_ms_acc(0), _clock_last_ms(0), _clock_saved(0) {
  memset(&_stats, 0, sizeof(_stats));
  memset(_adv_addr, 0, sizeof(_adv_addr));
  findhub_service = this;
}

// Known-answer test of the elliptic-curve backend (the CryptoCell's domain IDs
// are only trusted once they reproduce these): Fast Pair's ECDH test case and the
// FHN EID of EIK 00..1f at clock 0 (test/test_findhub).
static bool selfTest() {
  static const uint8_t bob[32] = {
    0x02, 0xB4, 0x37, 0xB0, 0xED, 0xD6, 0xBB, 0xD4, 0x29, 0x06, 0x4A, 0x4E, 0x52, 0x9F, 0xCB, 0xF1,
    0xC4, 0x8D, 0x0D, 0x62, 0x49, 0x24, 0xD5, 0x92, 0x27, 0x4B, 0x7E, 0xD8, 0x11, 0x93, 0xD7, 0x63};
  static const uint8_t alice_pub[64] = {
    0x36, 0xAC, 0x68, 0x2C, 0x50, 0x82, 0x15, 0x66, 0x8F, 0xBE, 0xFE, 0x24, 0x7D, 0x01, 0xD5, 0xEB,
    0x96, 0xE6, 0x31, 0x8E, 0x85, 0x5B, 0x2D, 0x64, 0xB5, 0x19, 0x5D, 0x38, 0xEE, 0x7E, 0x37, 0xBE,
    0x18, 0x38, 0xC0, 0xB9, 0x48, 0xC3, 0xF7, 0x55, 0x20, 0xE0, 0x7E, 0x70, 0xF0, 0x72, 0x91, 0x41,
    0x9A, 0xCE, 0x2D, 0x28, 0x14, 0x3C, 0x5A, 0xDB, 0x2D, 0xBD, 0x98, 0xEE, 0x3C, 0x8E, 0x4F, 0xBF};
  static const uint8_t shared_head[4] = { 0x9D, 0xAD, 0xE4, 0xF8 };
  static const uint8_t eid_head[4] = { 0xe6, 0xce, 0xc9, 0xca };
  uint8_t s[32], eik[32], eid[20];
  bool ok = ecdhP256(bob, alice_pub, s) && memcmp(s, shared_head, 4) == 0;
  for (int i = 0; i < 32; i++) eik[i] = (uint8_t)i;
  ok = computeEid(eik, 0, eid, NULL) && memcmp(eid, eid_head, 4) == 0 && ok;
  return ok;
}

void FindHubService::begin(mesh::MainBoard* board, const char* fw_version) {
  _board = board;
  if (fw_version) _fw_version = fw_version;
#ifdef FINDHUB_DEBUG
  for (unsigned long t = ::millis(); !Serial && ::millis() - t < 15000; ) delay(10);
  Serial.println("findhub: begin");
#endif
  _selftest_ok = selfTest();
  Serial.printf("findhub: ec self-test %s\n", _selftest_ok ? "ok" : "FAILED");
  loadState();
#ifdef FINDHUB_DEBUG
  Serial.printf("findhub: state=%d keys=%u clock=%lu\n", _hub.state(), (unsigned)_hub.fastPair().keyCount(), (unsigned long)_clock_s);
#endif
}

void FindHubService::loadState() {
  // Files of the earlier companion-provisioned beacon: incompatible, drop them.
  InternalFS.remove("/findhub");
  InternalFS.remove("/findhub_clk");

  bool first_boot = !InternalFS.exists(BOOT_FILE);
  if (first_boot) {
    File f = InternalFS.open(BOOT_FILE, FILE_O_WRITE);
    if (f) f.close();
  }

  AkRecord ak;
  bool have_ak = false;
  File f = InternalFS.open(AK_FILE, FILE_O_READ);
  if (f) {
    have_ak = f.read((uint8_t*)&ak, sizeof(ak)) == sizeof(ak) && ak.magic == AK_MAGIC && ak.d.count <= MAX_ACCOUNT_KEYS;
    f.close();
  }
  EikRecord eik;
  bool have_eik = false;
  f = InternalFS.open(EIK_FILE, FILE_O_READ);
  if (f) {
    have_eik = f.read((uint8_t*)&eik, sizeof(eik)) == sizeof(eik) && eik.magic == EIK_MAGIC;
    f.close();
  }

  // The beacon clock resumes from the last saved value (spec "Recovery from
  // power loss"); time spent powered off is lost, and the owner's phone
  // re-synchronises from the not-discoverable frames sent after boot.
  f = InternalFS.open(CLOCK_FILE, FILE_O_READ);
  if (f) {
    uint32_t saved = 0;
    if (f.read((uint8_t*)&saved, sizeof(saved)) == sizeof(saved)) _clock_s = saved;
    f.close();
  }
  _clock_saved = _clock_s;
  _clock_last_ms = ::millis();

  _hub.begin(have_ak ? &ak.d : NULL, have_eik ? eik.eik : NULL, first_boot);
  memset(&ak, 0, sizeof(ak));
  memset(&eik, 0, sizeof(eik));
  _started = true;
}

uint32_t FindHubService::beaconClock() {
  uint32_t now = ::millis();
  _clock_ms_acc += now - _clock_last_ms;     // wrap-safe
  _clock_last_ms = now;
  if (_clock_ms_acc >= 1000) {
    _clock_s += _clock_ms_acc / 1000;
    _clock_ms_acc %= 1000;
  }
  return _clock_s;
}

void FindHubService::persistClock(bool force) {
  // Only a device that is (being) paired needs its clock; spare the flash otherwise.
  if (_hub.fastPair().keyCount() == 0 && !_hub.beacon().isProvisioned()) return;
  uint32_t now = beaconClock();
  if (!force && now < _clock_saved + CLOCK_SAVE_SECS) return;
  InternalFS.remove(CLOCK_FILE);
  File f = InternalFS.open(CLOCK_FILE, FILE_O_WRITE);
  if (f) {
    f.write((const uint8_t*)&now, sizeof(now));
    f.close();
  }
  _clock_saved = now;
}

static bool writeFile(const char* path, const void* data, size_t len) {
  InternalFS.remove(path);
  if (!data) return !InternalFS.exists(path);
  File f = InternalFS.open(path, FILE_O_WRITE);
  if (!f) return false;
  bool ok = f.write((const uint8_t*)data, len) == len;
  f.close();
  return ok;
}

bool FindHubService::saveAccountKeys(const AccountKeyData* d) {
  if (!d) return writeFile(AK_FILE, NULL, 0);
  AkRecord rec;
  rec.magic = AK_MAGIC;
  rec.d = *d;
  bool ok = writeFile(AK_FILE, &rec, sizeof(rec));
  memset(&rec, 0, sizeof(rec));
  return ok;
}

bool FindHubService::saveEik(const uint8_t* eik) {
  if (!eik) return writeFile(EIK_FILE, NULL, 0);
  EikRecord rec;
  rec.magic = EIK_MAGIC;
  memcpy(rec.eik, eik, EIK_LEN);
  bool ok = writeFile(EIK_FILE, &rec, sizeof(rec));
  memset(&rec, 0, sizeof(rec));
  if (ok) persistClock(true);         // the Seeker just took our clock as its reference
  return ok;
}

#ifdef FINDHUB_DEBUG
  #define GATT_STEP(x) do { err_t e = (x); Serial.printf("findhub: gatt %s -> %d\n", #x, (int)e); } while (0)
#else
  #define GATT_STEP(x) (x)
#endif

void FindHubService::beginGatt() {
  sd_err_sink = &_stats.last_sd_err;
  GATT_STEP(_svc.begin());

  _model_id.setProperties(CHR_PROPS_READ);
  _model_id.setPermission(SECMODE_OPEN, SECMODE_NO_ACCESS);
  _model_id.setFixedLen(MODEL_ID_LEN);
  GATT_STEP(_model_id.begin());
  _model_id.write(_cfg.model_id, MODEL_ID_LEN);

  // Spec: none of these is encrypted. Writes are authorised so the answer (and
  // the notification before it) comes from the main loop.
  BLECharacteristic* writable[] = { &_kbp, &_passkey, &_account_key, &_beacon_chr };
  for (BLECharacteristic* c : writable) {
    bool notify = c != &_account_key;
    bool read = c == &_beacon_chr;
    c->setProperties(CHR_PROPS_WRITE | (notify ? CHR_PROPS_NOTIFY : 0) | (read ? CHR_PROPS_READ : 0));
    // Read permission open even without the READ property: Bluefruit gives the
    // CCCD the value's read permission, and a no-access CCCD is rejected
    // (NRF_ERROR_INVALID_PARAM). Without the property the value stays unreadable.
    c->setPermission(SECMODE_OPEN, SECMODE_OPEN);
    c->setMaxLen(c == &_kbp ? FP_BLOCK + P256_PUB_LEN : 64);
    c->setWriteAuthorizeCallback(onWriteAuth, false);    // run on the BLE task, just queue
    c->setWriteCallback(onLongWrite, false);
    if (read) c->setReadAuthorizeCallback(onReadAuth, false);
    GATT_STEP(c->begin());
  }

  // Firmware Revision (Seekers read it during pairing and once a day after).
  // Spec: readable while discoverable or after an authenticated Beacon Actions op.
  GATT_STEP(_dis.begin());
  _fw_rev.setProperties(CHR_PROPS_READ);
  _fw_rev.setPermission(SECMODE_OPEN, SECMODE_NO_ACCESS);
  _fw_rev.setMaxLen(32);
  _fw_rev.setReadAuthorizeCallback(onReadAuth, false);
  GATT_STEP(_fw_rev.begin());
}

FindHubService::Chr FindHubService::chrOf(BLECharacteristic* c) const {
  if (c == &_beacon_chr) return CHR_BEACON;
  if (c == &_kbp) return CHR_KBP;
  if (c == &_passkey) return CHR_PASSKEY;
  if (c == &_account_key) return CHR_ACCOUNT_KEY;
  if (c == &_fw_rev) return CHR_FW_REV;
  return CHR_NONE;
}

bool FindHubService::push(ReqType type, Chr chr, uint16_t conn, const uint8_t* data, size_t len) {
  uint8_t next = (_q_head + 1) % QUEUE_LEN;
  if (next == _q_tail) { _stats.queue_full++; return false; }
  Req& r = _queue[_q_head];
  r.type = type;
  r.chr = chr;
  r.conn = conn;
  r.len = len > sizeof(r.data) ? sizeof(r.data) : len;
  if (data && r.len) memcpy(r.data, data, r.len);
  __DMB();
  _q_head = next;
  return true;
}

static void noteSd(uint32_t err) {
  if (err != NRF_SUCCESS && sd_err_sink) *sd_err_sink = err;
}

static void replyRead(uint16_t conn, uint16_t status, const uint8_t* data, uint16_t len) {
  ble_gatts_rw_authorize_reply_params_t reply = { .type = BLE_GATTS_AUTHORIZE_TYPE_READ };
  reply.params.read.gatt_status = status;
  reply.params.read.update = data ? 1 : 0;
  reply.params.read.offset = 0;
  reply.params.read.len = len;
  reply.params.read.p_data = data;
  noteSd(sd_ble_gatts_rw_authorize_reply(conn, &reply));
}

static void replyWrite(uint16_t conn, uint16_t status, const uint8_t* data, uint16_t len) {
  ble_gatts_rw_authorize_reply_params_t reply = { .type = BLE_GATTS_AUTHORIZE_TYPE_WRITE };
  reply.params.write.gatt_status = status;
  // The SoftDevice rejects (NRF_ERROR_INVALID_PARAM) a successful Write Request
  // reply without update=1 and the written value; errors carry no value.
  bool ok = status == BLE_GATT_STATUS_SUCCESS;
  reply.params.write.update = ok ? 1 : 0;
  reply.params.write.offset = 0;
  reply.params.write.len = ok ? len : 0;
  reply.params.write.p_data = ok ? data : NULL;
  noteSd(sd_ble_gatts_rw_authorize_reply(conn, &reply));
}

void FindHubService::onReadAuth(uint16_t conn_hdl, BLECharacteristic* chr, ble_gatts_evt_read_t* req) {
  FindHubService* s = findhub_service;
  if (s && req->offset == 0) s->_stats.reads++;
  if (!s || req->offset != 0 || !s->push(REQ_READ, s->chrOf(chr), conn_hdl, NULL, 0)) {
    if (s) s->_stats.rejected++;
    replyRead(conn_hdl, BLE_GATT_STATUS_ATTERR_UNLIKELY_ERROR, NULL, 0);
  }
}

void FindHubService::onWriteAuth(uint16_t conn_hdl, BLECharacteristic* chr, ble_gatts_evt_write_t* req) {
  FindHubService* s = findhub_service;
  if (s) s->_stats.writes++;
  if (!s || req->offset != 0 || req->len > sizeof(Req::data) ||
      !s->push(REQ_WRITE, s->chrOf(chr), conn_hdl, req->data, req->len)) {
    if (s) s->_stats.rejected++;
    replyWrite(conn_hdl, BLE_GATT_STATUS_ATTERR_UNLIKELY_ERROR, NULL, 0);
  }
}

// A prepared (long) write is already acknowledged by Bluefruit, so only the
// notification can carry the outcome.
void FindHubService::onLongWrite(uint16_t conn_hdl, BLECharacteristic* chr, uint8_t* data, uint16_t len) {
  FindHubService* s = findhub_service;
  if (s) s->_stats.long_writes++;
  if (s && len <= sizeof(Req::data)) s->push(REQ_LONG_WRITE, s->chrOf(chr), conn_hdl, data, len);
}

void FindHubService::noteAdvAddress(const uint8_t addr[ADDR_LEN]) {
  if (memcmp(_adv_addr[0], addr, ADDR_LEN) == 0) return;
  memcpy(_adv_addr[1], _adv_addr[0], ADDR_LEN);
  memcpy(_adv_addr[0], addr, ADDR_LEN);
}

void FindHubService::onConnect(uint16_t conn_hdl) {
  // Snapshot the addresses now: the scheduler may move on before loop() runs.
  push(REQ_CONNECT, CHR_NONE, conn_hdl, &_adv_addr[0][0], sizeof(_adv_addr));
}

void FindHubService::onDisconnect(uint16_t conn_hdl) {
  push(REQ_DISCONNECT, CHR_NONE, conn_hdl, NULL, 0);
}

void FindHubService::handle(const Req& r) {
  uint8_t conn = r.conn < MAX_CONN ? (uint8_t)r.conn : 0xFF;
  switch (r.type) {
    case REQ_READ:
      if (r.chr == CHR_BEACON) {
        uint8_t out[1 + NONCE_LEN];
        size_t n = beacon().onRead(conn, out);
        replyRead(r.conn, n ? BLE_GATT_STATUS_SUCCESS : BLE_GATT_STATUS_ATTERR_UNLIKELY_ERROR, n ? out : NULL, n);
      } else if (r.chr == CHR_FW_REV) {
        bool allowed = _hub.pairingMode() || beacon().authenticated(conn);
        if (allowed) replyRead(r.conn, BLE_GATT_STATUS_SUCCESS, (const uint8_t*)_fw_version, strlen(_fw_version));
        else replyRead(r.conn, BLE_GATT_STATUS_ATTERR_INSUF_AUTHORIZATION, NULL, 0);
      } else {
        replyRead(r.conn, BLE_GATT_STATUS_ATTERR_UNLIKELY_ERROR, NULL, 0);
      }
      break;
    case REQ_WRITE:
    case REQ_LONG_WRITE:
      handleWrite(r);
      break;
    case REQ_CONNECT: {
      // The addresses advertised around the connection, plus the tag's own.
      uint8_t addrs[MAX_LINK_ADDRS][ADDR_LEN];
      memcpy(addrs, r.data, 2 * ADDR_LEN);
      size_t n = 2;
      uint8_t tag[MAX_LINK_ADDRS][ADDR_LEN];
      size_t nt = _hub.tagAddresses(tag, MAX_LINK_ADDRS);
      for (size_t i = 0; i < nt && n < MAX_LINK_ADDRS; i++) {
        if (memcmp(tag[i], addrs[0], ADDR_LEN) && memcmp(tag[i], addrs[1], ADDR_LEN)) memcpy(addrs[n++], tag[i], ADDR_LEN);
      }
      _hub.fastPair().onConnect(conn, addrs, n);
      break;
    }
    case REQ_DISCONNECT:
      _hub.fastPair().onDisconnect(conn);
      beacon().onDisconnect(conn);
      break;
  }
}

void FindHubService::handleWrite(const Req& r) {
  uint8_t conn = r.conn < MAX_CONN ? (uint8_t)r.conn : 0xFF;
  uint8_t status = 0x0E;      // unlikely error
  uint8_t rsp[MAX_NOTIFY_LEN];
  size_t rsp_len = 0;
  BLECharacteristic* notify_chr = NULL;
  switch (r.chr) {
    case CHR_BEACON:
      status = beacon().onWrite(conn, r.data, r.len, rsp, &rsp_len);
      notify_chr = &_beacon_chr;
      break;
    case CHR_KBP:
      status = _hub.fastPair().onKeyBasedPairing(conn, r.data, r.len, rsp, &rsp_len);
      if (status == FP_OK) _stats.kbp_ok++; else _stats.kbp_fail++;
      notify_chr = &_kbp;
      break;
    case CHR_PASSKEY:
      // Bluefruit answers numeric comparison inside its own event handler, so the
      // bonding flow cannot wait for this write: it only works without bonding.
      status = _hub.fastPair().onPasskey(conn, r.data, r.len, rsp, &rsp_len);
      notify_chr = &_passkey;
      break;
    case CHR_ACCOUNT_KEY: {
      BLEConnection* c = Bluefruit.Connection(r.conn);
      status = _hub.fastPair().onAccountKey(conn, r.data, r.len, c && c->secured());
      if (status == FP_OK) _stats.ak_ok++; else _stats.ak_fail++;
      break;
    }
    default:
      break;
  }
  if (status == 0 && rsp_len && notify_chr) {     // before the write response (spec)
    _stats.notifies++;
    if (!notify_chr->notify(r.conn, rsp, rsp_len)) _stats.notify_fail++;
  }
  if (r.type == REQ_WRITE) {
    replyWrite(r.conn, status == 0 ? BLE_GATT_STATUS_SUCCESS : (uint16_t)(0x0100 | status), r.data, r.len);
  }
}

void FindHubService::loop() {
  if (!_started) return;
  while (_q_tail != _q_head) {
    __DMB();
    handle(_queue[_q_tail]);
    _q_tail = (_q_tail + 1) % QUEUE_LEN;
  }
  _hub.loop();
  persistClock(false);
#ifdef FINDHUB_DEBUG
  static unsigned long last = 0;
  if (::millis() - last > 5000) {
    last = ::millis();
    Serial.printf("findhub: selftest=%d state=%d keys=%u clock=%lu kbp=%u/%u ak=%u/%u sd_err=%lx q=%u\n", _selftest_ok,
                  _hub.state(), (unsigned)_hub.fastPair().keyCount(), (unsigned long)beaconClock(), _stats.kbp_ok,
                  _stats.kbp_fail, _stats.ak_ok, _stats.ak_fail, (unsigned long)_stats.last_sd_err, _stats.queue_full);
  }
#endif
}

void FindHubService::randomBytes(uint8_t* dest, size_t len) {
  uint8_t sd_on = 0;
  sd_softdevice_is_enabled(&sd_on);
  if (!sd_on) {
    // begin() runs before Bluefruit.begin(): the RNG peripheral is still ours.
    NRF_RNG->CONFIG = RNG_CONFIG_DERCEN_Msk;       // bias correction
    NRF_RNG->TASKS_START = 1;
    for (size_t i = 0; i < len; i++) {
      NRF_RNG->EVENTS_VALRDY = 0;
      while (!NRF_RNG->EVENTS_VALRDY) {}
      dest[i] = (uint8_t)NRF_RNG->VALUE;
    }
    NRF_RNG->TASKS_STOP = 1;
    return;
  }
  // SoftDevice TRNG pool; wait for it to refill when empty.
  while (len > 0) {
    uint8_t avail = 0;
    sd_rand_application_bytes_available_get(&avail);
    if (avail == 0) { delay(1); continue; }
    uint8_t n = len < avail ? len : avail;
    if (sd_rand_application_vector_get(dest, n) == NRF_SUCCESS) {
      dest += n;
      len -= n;
    }
  }
}

int8_t FindHubService::calibratedPower() {
  // RSSI at 0 m: TX power minus a typical ~10 dB of antenna/near-field loss for
  // a small PCB antenna. Seekers use it for distance hints only.
  return (int8_t)(BLE_TX_POWER - 10);
}

BatteryLevel FindHubService::batteryLevel() {
  uint16_t mv = _board ? _board->getBattMilliVolts() : 0;
  if (mv == 0) return BATTERY_UNSUPPORTED;
  if (mv >= 3600) return BATTERY_NORMAL;
  if (mv >= 3450) return BATTERY_LOW;
  return BATTERY_CRITICAL;
}

void FindHubService::notify(uint8_t conn, const uint8_t* data, size_t len) {
  if (conn >= MAX_CONN) return;
  _stats.notifies++;
  if (!_beacon_chr.notify(conn, data, len)) _stats.notify_fail++;
}

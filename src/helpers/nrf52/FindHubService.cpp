#include "FindHubService.h"

#include <InternalFileSystem.h>
#include "SerialBLEInterface.h"   // BLE_TX_POWER

using namespace Adafruit_LittleFS_Namespace;
using namespace findhub;

FindHubService* findhub_service = nullptr;
static uint32_t* sd_err_sink = nullptr;

// Beacon Actions: FE2C1238-8366-4814-8EB0-01DE32100BEA (little-endian for Bluefruit).
static const uint8_t BEACON_ACTIONS_UUID[16] = {
  0xEA, 0x0B, 0x10, 0x32, 0xDE, 0x01, 0xB0, 0x8E, 0x14, 0x48, 0x66, 0x83, 0x38, 0x12, 0x2C, 0xFE,
};
static const uint16_t FAST_PAIR_SERVICE_UUID = 0xFE2C;

#define PROV_FILE      "/findhub"
#define CLOCK_FILE     "/findhub_clk"
#define PROV_MAGIC     0x314E4846UL     // "FHN1"
#define CLOCK_SAVE_SECS 3600            // spec: persist the clock at least daily
#define GPS_RESYNC_MS   (24UL * 3600 * 1000)   // daily: the nRF52 RC/crystal drift stays well inside a window
#define GPS_TIMEOUT_MS  (10UL * 60 * 1000)     // cold start indoors may never fix; give up and retry
#define GPS_RETRY_MS    (60UL * 60 * 1000)

struct ProvRecord {
  uint32_t magic;
  Provisioning prov;
};

FindHubService::FindHubService()
  : _svc(FAST_PAIR_SERVICE_UUID), _chr(BEACON_ACTIONS_UUID), _beacon(*this),
    _clock(nullptr), _board(nullptr), _ring_cb(nullptr), _q_head(0), _q_tail(0), _last_clock_save(0) {
  memset(&_stats, 0, sizeof(_stats));
  findhub_service = this;
}

void FindHubService::begin(mesh::RTCClock* clock, mesh::MainBoard* board) {
  _clock = clock;
  _board = board;
  loadState();
}

void FindHubService::loadState() {
  File f = InternalFS.open(PROV_FILE, FILE_O_READ);
  if (f) {
    ProvRecord rec;
    if (f.read((uint8_t*)&rec, sizeof(rec)) == sizeof(rec) && rec.magic == PROV_MAGIC) {
      _beacon.load(&rec.prov);
    }
    memset(&rec, 0, sizeof(rec));
    f.close();
  }

  // No RTC on this board: after a reset the clock restarts in 2024. Resume from the
  // last saved value so the EIDs are at most CLOCK_SAVE_SECS (+ the time off) behind
  // until GPS, the companion app or the gateway sets the real time.
  f = InternalFS.open(CLOCK_FILE, FILE_O_READ);
  if (f) {
    uint32_t saved = 0;
    if (f.read((uint8_t*)&saved, sizeof(saved)) == sizeof(saved) && _clock && saved > _clock->getCurrentTime()) {
      _clock->setCurrentTime(saved);
    }
    _last_clock_save = saved;
    f.close();
  }
}

void FindHubService::persistClock() {
  if (!_beacon.isProvisioned() || !_beacon.clockValid()) return;
  uint32_t now = unixTime();
  if (now < _last_clock_save + CLOCK_SAVE_SECS) return;
  InternalFS.remove(CLOCK_FILE);
  File f = InternalFS.open(CLOCK_FILE, FILE_O_WRITE);
  if (f) {
    f.write((const uint8_t*)&now, sizeof(now));
    f.close();
  }
  _last_clock_save = now;
}

bool FindHubService::saveProvisioning(const Provisioning* p) {
  InternalFS.remove(PROV_FILE);
  if (!p) return !InternalFS.exists(PROV_FILE);
  File f = InternalFS.open(PROV_FILE, FILE_O_WRITE);
  if (!f) return false;
  ProvRecord rec;
  rec.magic = PROV_MAGIC;
  rec.prov = *p;
  bool ok = f.write((const uint8_t*)&rec, sizeof(rec)) == sizeof(rec);
  memset(&rec, 0, sizeof(rec));
  f.close();
  return ok;
}

void FindHubService::beginGatt() {
  sd_err_sink = &_stats.last_sd_err;
  _svc.begin();
  _chr.setProperties(CHR_PROPS_READ | CHR_PROPS_WRITE | CHR_PROPS_NOTIFY);
  _chr.setPermission(SECMODE_OPEN, SECMODE_OPEN);     // spec: not encrypted
  _chr.setMaxLen(64);
  _chr.setReadAuthorizeCallback(onReadAuth, false);    // run on the BLE task, just queue
  _chr.setWriteAuthorizeCallback(onWriteAuth, false);
  _chr.setWriteCallback(onLongWrite, false);
  _chr.begin();
}

bool FindHubService::push(ReqType type, uint16_t conn, const uint8_t* data, size_t len) {
  uint8_t next = (_q_head + 1) % QUEUE_LEN;
  if (next == _q_tail) { _stats.queue_full++; return false; }
  Req& r = _queue[_q_head];
  r.type = type;
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
  if (findhub_service && req->offset == 0) findhub_service->_stats.reads++;
  if (!findhub_service || req->offset != 0 || !findhub_service->push(REQ_READ, conn_hdl, NULL, 0)) {
    if (findhub_service) findhub_service->_stats.rejected++;
    replyRead(conn_hdl, BLE_GATT_STATUS_ATTERR_UNLIKELY_ERROR, NULL, 0);
  }
}

void FindHubService::onWriteAuth(uint16_t conn_hdl, BLECharacteristic* chr, ble_gatts_evt_write_t* req) {
  if (findhub_service) findhub_service->_stats.writes++;
  if (!findhub_service || req->offset != 0 || req->len > 64 ||
      !findhub_service->push(REQ_WRITE, conn_hdl, req->data, req->len)) {
    if (findhub_service) findhub_service->_stats.rejected++;
    replyWrite(conn_hdl, BLE_GATT_STATUS_ATTERR_UNLIKELY_ERROR, NULL, 0);
  }
}

// A prepared (long) write is already acknowledged by Bluefruit, so only the
// notification can carry the outcome.
void FindHubService::onLongWrite(uint16_t conn_hdl, BLECharacteristic* chr, uint8_t* data, uint16_t len) {
  if (findhub_service) findhub_service->_stats.long_writes++;
  if (findhub_service && len <= 64) findhub_service->push(REQ_LONG_WRITE, conn_hdl, data, len);
}

void FindHubService::onDisconnect(uint16_t conn_hdl) {
  push(REQ_DISCONNECT, conn_hdl, NULL, 0);
}

void FindHubService::handle(const Req& r) {
  uint8_t conn = r.conn < MAX_CONN ? (uint8_t)r.conn : 0xFF;
  switch (r.type) {
    case REQ_READ: {
      uint8_t out[1 + NONCE_LEN];
      size_t n = _beacon.onRead(conn, out);
      replyRead(r.conn, n ? BLE_GATT_STATUS_SUCCESS : BLE_GATT_STATUS_ATTERR_UNLIKELY_ERROR, n ? out : NULL, n);
      break;
    }
    case REQ_WRITE:
    case REQ_LONG_WRITE: {
      uint8_t rsp[MAX_NOTIFY_LEN];
      size_t rsp_len = 0;
      uint8_t status = _beacon.onWrite(conn, r.data, r.len, rsp, &rsp_len);
      if (status == ATT_OK && rsp_len) notify(conn, rsp, rsp_len);   // before the write response (spec)
      if (r.type == REQ_WRITE) {
        replyWrite(r.conn, status == ATT_OK ? BLE_GATT_STATUS_SUCCESS : (uint16_t)(0x0100 | status), r.data, r.len);
      }
      break;
    }
    case REQ_DISCONNECT:
      _beacon.onDisconnect(conn);
      break;
  }
}

void FindHubService::loop() {
  while (_q_tail != _q_head) {
    __DMB();
    handle(_queue[_q_tail]);
    _q_tail = (_q_tail + 1) % QUEUE_LEN;
  }
  _beacon.loop();
  gpsLoop();
  persistClock();
}

void FindHubService::gpsLoop() {
  if (!_sensors || !_beacon.isProvisioned()) return;
  LocationProvider* loc = _sensors->getLocationProvider();
  if (!loc) { _gps_state = GPS_NO_GPS; return; }
  uint32_t now = ::millis();
  bool user_on = _user_gps && *_user_gps;

  if (_gps_state == GPS_IDLE) {
    if ((int32_t)(now - _gps_next_try_ms) < 0) return;
    loc->syncTime();                         // set the RTC from the next good fix
    if (!user_on) {                          // the user's GPS is already running otherwise
      if (!_sensors->setSettingValue("gps", "1")) { _gps_state = GPS_NO_GPS; return; }
      _gps_we_powered = true;
    }
    _gps_started_ms = now;
    _gps_state = GPS_SYNCING;
    return;
  }

  if (_gps_state != GPS_SYNCING) return;
  bool done = !loc->waitingTimeSync();
  bool timed_out = now - _gps_started_ms > GPS_TIMEOUT_MS;
  if (!done && !timed_out) return;

  if (done) {
    _gps_last_ok = true;
    _gps_last_ok_ms = now;
  }
  _gps_next_try_ms = now + (done ? GPS_RESYNC_MS : GPS_RETRY_MS);
  // Power down only what we powered up, and not if the user switched GPS on meanwhile.
  if (_gps_we_powered && !(_user_gps && *_user_gps)) _sensors->setSettingValue("gps", "0");
  _gps_we_powered = false;
  _gps_state = GPS_IDLE;
}

void FindHubService::randomBytes(uint8_t* dest, size_t len) {
  // SoftDevice TRNG pool; fall back to waiting for it to refill.
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

uint32_t FindHubService::unixTime() {
  return _clock ? _clock->getCurrentTime() : 0;
}

int8_t FindHubService::calibratedPower() {
  // RSSI at 0 m: TX power minus a typical ~10 dB of antenna/near-field loss for
  // a small PCB antenna. Only used by seekers for distance hints.
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
  if (!_chr.notify(conn, data, len)) _stats.notify_fail++;
}

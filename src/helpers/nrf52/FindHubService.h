#pragma once

// nRF52 / Bluefruit glue for the Find Hub Network beacon (helpers/findhub):
// the Fast Pair service (0xFE2C) with the Beacon Actions characteristic, the
// beacon's advertising payload, persistence on InternalFS and the clock.
//
// GATT requests arrive on Bluefruit's BLE task; they are queued and answered from
// loop(), so every FindHubBeacon call runs on the main loop (one thread).

#include <Arduino.h>
#include <bluefruit.h>
#include <MeshCore.h>
#include <helpers/findhub/FindHubBeacon.h>
#include <helpers/SensorManager.h>

class FindHubService : public findhub::FindHubPlatform {
public:
  typedef void (*RingCallback)(bool on);

  FindHubService();

  // Call after the filesystem is up and before Bluefruit.begin().
  void begin(mesh::RTCClock* clock, mesh::MainBoard* board);
  // Call after Bluefruit.begin(), before advertising starts: registers the GATT service.
  void beginGatt();
  void loop();

  void setRingCallback(RingCallback cb) { _ring_cb = cb; }

  // GPS time sync: while provisioned, power the GPS up at boot and once a day
  // just long enough for a time fix (the location provider sets the RTC), then
  // power it down again. Left alone when the user has GPS on (*user_gps != 0):
  // the provider already re-syncs the clock every 30 min then.
  void setGps(SensorManager* sensors, const uint8_t* user_gps) { _sensors = sensors; _user_gps = user_gps; }
  enum GpsSync : uint8_t { GPS_IDLE = 0, GPS_SYNCING = 1, GPS_NO_GPS = 2 };
  GpsSync gpsState() const { return _gps_state; }
  uint32_t gpsLastSyncAgeS() const { return _gps_last_ok ? (::millis() - _gps_last_ok_ms) / 1000 : 0xFFFFFFFF; }
  void onDisconnect(uint16_t conn_hdl);

  findhub::FindHubBeacon& beacon() { return _beacon; }

  struct Stats {
    uint16_t reads, writes, long_writes, queue_full, rejected;   // rejected: offset/len/no service
    uint32_t last_sd_err;      // last non-success return from a SoftDevice reply/notify
    uint16_t notifies, notify_fail;
  };
  const Stats& stats() const { return _stats; }
  bool wantsAdvertising() { return _beacon.isProvisioned(); }
  size_t advertisement(uint8_t out[findhub::ADV_FRAME_LEN]) { return _beacon.buildAdvert(out); }

  // FindHubPlatform
  void randomBytes(uint8_t* dest, size_t len) override;
  uint32_t unixTime() override;
  uint32_t millis() override { return ::millis(); }
  int8_t calibratedPower() override;
  findhub::BatteryLevel batteryLevel() override;
  bool saveProvisioning(const findhub::Provisioning* p) override;
  void ringStart() override { if (_ring_cb) _ring_cb(true); }
  void ringStop() override { if (_ring_cb) _ring_cb(false); }
  void notify(uint8_t conn, const uint8_t* data, size_t len) override;

private:
  enum ReqType : uint8_t { REQ_READ, REQ_WRITE, REQ_LONG_WRITE, REQ_DISCONNECT };
  struct Req {
    ReqType type;
    uint16_t conn;
    uint8_t len;
    uint8_t data[64];
  };
  static const uint8_t QUEUE_LEN = 8;

  BLEService _svc;
  BLECharacteristic _chr;
  findhub::FindHubBeacon _beacon;
  mesh::RTCClock* _clock;
  mesh::MainBoard* _board;
  RingCallback _ring_cb;

  Req _queue[QUEUE_LEN];
  volatile uint8_t _q_head;    // written by the BLE task
  volatile uint8_t _q_tail;    // written by loop()

  uint32_t _last_clock_save;
  Stats _stats;

  SensorManager* _sensors = nullptr;
  const uint8_t* _user_gps = nullptr;
  GpsSync _gps_state = GPS_IDLE;
  bool _gps_last_ok = false;
  bool _gps_we_powered = false;
  uint32_t _gps_started_ms = 0;
  uint32_t _gps_last_ok_ms = 0;
  uint32_t _gps_next_try_ms = 0;     // 0 = as soon as provisioned (boot)
  void gpsLoop();

  bool push(ReqType type, uint16_t conn, const uint8_t* data, size_t len);
  void handle(const Req& r);
  void loadState();
  void persistClock();

  static void onReadAuth(uint16_t conn_hdl, BLECharacteristic* chr, ble_gatts_evt_read_t* req);
  static void onWriteAuth(uint16_t conn_hdl, BLECharacteristic* chr, ble_gatts_evt_write_t* req);
  static void onLongWrite(uint16_t conn_hdl, BLECharacteristic* chr, uint8_t* data, uint16_t len);
};

extern FindHubService* findhub_service;

#pragma once

// nRF52 / Bluefruit glue for the Find Hub accessory (helpers/findhub): the Fast
// Pair service (0xFE2C: Model ID, Key-based Pairing, Passkey, Account Key, Beacon
// Actions), the Device Information Firmware Revision, persistence on InternalFS
// and the FHN beacon clock.
//
// GATT requests arrive on Bluefruit's BLE task; they are queued and answered from
// loop(), so every findhub call runs on the main loop (one thread), and the
// CryptoCell is only ever used from there.

#include <Arduino.h>
#include <bluefruit.h>
#include <MeshCore.h>
#include <helpers/findhub/FindHub.h>

// Fast Pair model. Default: Nordic's debug "NCS locator tag" model (Model ID
// 0x4A436B), which Android only shows with "Include debug results" on, and whose
// FHN provisioning only works for Google accounts on Google's allowlist. A
// registered model swaps in with these two build flags.
#ifndef FINDHUB_MODEL_ID
  #define FINDHUB_MODEL_ID 0x4A436B
#endif
#ifndef FINDHUB_ANTISPOOF_KEY_HEX       // 32-byte secp256r1 private key, hex
  #define FINDHUB_ANTISPOOF_KEY_HEX "ae27b5d00ece36ac1defb5669311ac6e53d46ccb77f38aa30e070427f72d4fd6"
#endif

class FindHubService : public findhub::FindHubPlatform {
public:
  typedef void (*RingCallback)(bool on);

  FindHubService();

  // Call after the filesystem is up and before Bluefruit.begin().
  void begin(mesh::MainBoard* board, const char* fw_version);
  // Call after Bluefruit.begin(), before advertising starts: registers the GATT services.
  void beginGatt();
  void loop();

  void setRingCallback(RingCallback cb) { _ring_cb = cb; }

  findhub::FindHub& hub() { return _hub; }
  findhub::FindHubBeacon& beacon() { return _hub.beacon(); }

  // User actions (UI, companion command).
  void requestPairing() { _hub.requestPairing(); }
  bool clearDevice() { return _hub.beacon().factoryReset(); }

  // BLE glue. onConnect/onDisconnect run on the BLE task (they only queue).
  void onConnect(uint16_t conn_hdl);
  void onDisconnect(uint16_t conn_hdl);
  // The scheduler reports each address it starts advertising on, so a new link
  // can be matched to the address the Seeker saw.
  void noteAdvAddress(const uint8_t addr[findhub::ADDR_LEN]);

  struct Stats {
    uint16_t reads, writes, long_writes, queue_full, rejected;   // rejected: offset/len/no service
    uint32_t last_sd_err;      // last non-success return from a SoftDevice reply/notify
    uint16_t notifies, notify_fail;
    uint16_t kbp_ok, kbp_fail, ak_ok, ak_fail;
  };
  const Stats& stats() const { return _stats; }
  bool selfTestOk() const { return _selftest_ok; }

  // FindHubPlatform
  void randomBytes(uint8_t* dest, size_t len) override;
  uint32_t millis() override { return ::millis(); }
  uint32_t beaconClock() override;
  int8_t calibratedPower() override;
  findhub::BatteryLevel batteryLevel() override;
  bool saveAccountKeys(const findhub::AccountKeyData* d) override;
  bool saveEik(const uint8_t* eik) override;
  void ringStart() override { if (_ring_cb) _ring_cb(true); }
  void ringStop() override { if (_ring_cb) _ring_cb(false); }
  void notify(uint8_t conn, const uint8_t* data, size_t len) override;

private:
  enum ReqType : uint8_t { REQ_READ, REQ_WRITE, REQ_LONG_WRITE, REQ_CONNECT, REQ_DISCONNECT };
  enum Chr : uint8_t { CHR_BEACON, CHR_KBP, CHR_PASSKEY, CHR_ACCOUNT_KEY, CHR_FW_REV, CHR_NONE };
  struct Req {
    ReqType type;
    Chr chr;
    uint16_t conn;
    uint8_t len;
    uint8_t data[80];          // Key-based Pairing with the Seeker's public key
  };
  static const uint8_t QUEUE_LEN = 8;

  BLEService _svc;
  BLECharacteristic _model_id;
  BLECharacteristic _kbp;
  BLECharacteristic _passkey;
  BLECharacteristic _account_key;
  BLECharacteristic _beacon_chr;
  BLEService _dis;
  BLECharacteristic _fw_rev;
  const char* _fw_version;

  findhub::FastPairConfig _cfg;
  findhub::FindHub _hub;
  mesh::MainBoard* _board;
  RingCallback _ring_cb;

  Req _queue[QUEUE_LEN];
  volatile uint8_t _q_head;    // written by the BLE task
  volatile uint8_t _q_tail;    // written by loop()

  uint8_t _adv_addr[2][findhub::ADDR_LEN];   // [0] = current, [1] = previous
  bool _started;
  bool _selftest_ok = false;

  // beacon clock: seconds, persisted, counts from the first boot
  uint32_t _clock_s;
  uint32_t _clock_ms_acc;
  uint32_t _clock_last_ms;
  uint32_t _clock_saved;

  Stats _stats;

  bool push(ReqType type, Chr chr, uint16_t conn, const uint8_t* data, size_t len);
  void handle(const Req& r);
  void handleWrite(const Req& r);
  void loadState();
  void persistClock(bool force);
  Chr chrOf(BLECharacteristic* c) const;

  static void onReadAuth(uint16_t conn_hdl, BLECharacteristic* chr, ble_gatts_evt_read_t* req);
  static void onWriteAuth(uint16_t conn_hdl, BLECharacteristic* chr, ble_gatts_evt_write_t* req);
  static void onLongWrite(uint16_t conn_hdl, BLECharacteristic* chr, uint8_t* data, uint16_t len);
};

extern FindHubService* findhub_service;

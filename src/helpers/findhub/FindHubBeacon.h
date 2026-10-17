#pragma once

// Find Hub Network beacon: provisioning state, rotating EID advertisement and the
// Fast Pair "Beacon Actions" GATT protocol (ring, ringing state, beacon
// parameters/clock, provisioning state, unwanted tracking protection).
//
// Portable: the BLE stack, clock, RNG, storage and buzzer come in through
// FindHubPlatform, so the whole protocol runs under the native test env.
//
// Not implemented on purpose: Fast Pair pairing (key-based pairing needs a
// Google-issued model anti-spoofing key; we are provisioned over the bonded
// companion link instead), EIK recovery with user consent (0x04: always "no user
// consent"), precision finding, and the DULT non-owner service.

#include "FindHubCrypto.h"

namespace findhub {

constexpr size_t MAX_CONN = 8;            // Bluefruit connection handles are < 8 here
constexpr size_t ADV_FRAME_LEN = 29;      // flags(3) + service data(26)
constexpr size_t MAX_NOTIFY_LEN = 2 + AUTH_LEN + EID_LEN + 1;   // largest: provisioning state
constexpr uint16_t RING_MAX_DS = 6000;    // 10 minutes in deciseconds

// ATT application error codes from the spec (table 7).
enum AttStatus : uint8_t {
  ATT_OK = 0x00,
  ATT_UNAUTHENTICATED = 0x80,
  ATT_INVALID_VALUE = 0x81,
  ATT_NO_USER_CONSENT = 0x82,
};

enum BatteryLevel : uint8_t {
  BATTERY_UNSUPPORTED = 0,
  BATTERY_NORMAL = 1,
  BATTERY_LOW = 2,
  BATTERY_CRITICAL = 3,
};

// What is persisted. pair_date = Unix time at provisioning; the beacon clock is
// unix_now - pair_date, the convention Google's backend and owner phones use
// when they precompute EIDs from the registration's pairDate.
struct Provisioning {
  uint8_t eik[EIK_LEN];
  uint8_t ak[AK_LEN];        // owner account key
  uint32_t pair_date;
};

class FindHubPlatform {
public:
  virtual ~FindHubPlatform() {}
  virtual void randomBytes(uint8_t* dest, size_t len) = 0;
  virtual uint32_t unixTime() = 0;           // 0 or a pre-provisioning value = unknown
  virtual uint32_t millis() = 0;
  virtual int8_t calibratedPower() = 0;      // dBm at 0 m
  virtual BatteryLevel batteryLevel() = 0;
  virtual bool saveProvisioning(const Provisioning* p) = 0;   // NULL = erase
  virtual void ringStart() = 0;              // start (or keep) sounding
  virtual void ringStop() = 0;
  virtual void notify(uint8_t conn, const uint8_t* data, size_t len) = 0;  // async notifications
};

enum RingTrigger : uint8_t {
  RING_STARTED = 0x00,
  RING_FAILED = 0x01,
  RING_STOPPED_TIMEOUT = 0x02,
  RING_STOPPED_BUTTON = 0x03,
  RING_STOPPED_GATT = 0x04,
};

class FindHubBeacon {
public:
  explicit FindHubBeacon(FindHubPlatform& platform);

  // Provisioning (from the bonded companion link, or GATT 0x02/0x03).
  void load(const Provisioning* p);          // boot: restore without persisting
  bool provision(const Provisioning& p);     // persist + take effect
  bool clear();
  bool isProvisioned() const { return _provisioned; }
  uint32_t pairDate() const { return _prov.pair_date; }

  // Clock. Valid once the wall clock is at or after pair_date.
  bool clockValid();
  uint32_t counter();

  // Full advertising payload (flags + FHN service data). Returns 0 when the beacon
  // must not advertise (unprovisioned or clock unknown). Recomputes the EID when
  // its rotation window changes (one secp160r1 multiplication per ~1024 s).
  size_t buildAdvert(uint8_t out[ADV_FRAME_LEN]);
  // The EID currently advertised (valid after buildAdvert returned > 0).
  const uint8_t* currentEid() const { return _eid; }

  // GATT Beacon Actions characteristic.
  size_t onRead(uint8_t conn, uint8_t out[1 + NONCE_LEN]);
  // Returns an ATT status. On ATT_OK, `rsp` holds the notification to send BEFORE
  // the write response (spec: table 6 note), rsp_len its length (0 = none).
  uint8_t onWrite(uint8_t conn, const uint8_t* buf, size_t len, uint8_t rsp[MAX_NOTIFY_LEN], size_t* rsp_len);
  uint8_t dispatch(uint8_t conn, const uint8_t* buf, size_t len, uint8_t* rsp, size_t* rsp_len);
  void onDisconnect(uint8_t conn);

  // Ringing.
  void loop();                               // timeout handling
  bool isRinging() const { return _ring_comp != 0; }
  void buttonPressed();                      // stops ringing (spec: physical button)
  void ringLocal(uint16_t deciseconds);      // companion-initiated test ring
  uint16_t ringRemainingDs();

  bool utpMode() const { return _utp; }

  // Diagnostics (companion status): last Beacon Actions write and its outcome.
  uint8_t lastOp() const { return _last_op; }
  uint8_t lastStatus() const { return _last_status; }

private:
  struct Conn {
    uint8_t nonce[NONCE_LEN];
    bool nonce_valid;
  };

  FindHubPlatform& _p;
  bool _provisioned;
  Provisioning _prov;
  Conn _conns[MAX_CONN];

  // advertisement cache
  bool _eid_valid;
  uint32_t _eid_window;          // counter >> ROTATION_EXP of the cached EID
  uint8_t _eid[EID_LEN];
  uint8_t _hash_xor;
  uint32_t _rot_delay;           // spec: rotate 1..204 s after the window boundary
  uint32_t _rot_delay_window;

  // ringing
  uint8_t _ring_comp;            // active component bitmask, 0 = silent
  uint32_t _ring_until;          // millis
  bool _ring_has_conn;
  uint8_t _ring_conn;
  uint8_t _ring_nonce[NONCE_LEN];

  uint8_t _last_op;
  uint8_t _last_status;

  // unwanted tracking protection
  bool _utp;
  bool _utp_skip_ring_auth;

  void invalidateEid() { _eid_valid = false; }
  bool ensureEid(uint32_t adv_counter);
  uint8_t hashedFlags();
  void startRing(uint16_t ds);
  void stopRing(RingTrigger why);
  void notifyRingState(RingTrigger why);
  size_t buildResponse(uint8_t* rsp, uint8_t data_id, const uint8_t* key, size_t key_len,
                       const uint8_t nonce[NONCE_LEN], const uint8_t* add, size_t add_len);

  uint8_t opBeaconParams(uint8_t conn, const uint8_t* p, size_t n, uint8_t* rsp, size_t* rsp_len);
  uint8_t opProvisioningState(uint8_t conn, const uint8_t* p, size_t n, uint8_t* rsp, size_t* rsp_len);
  uint8_t opSetEik(uint8_t conn, const uint8_t* p, size_t n, uint8_t* rsp, size_t* rsp_len);
  uint8_t opClearEik(uint8_t conn, const uint8_t* p, size_t n, uint8_t* rsp, size_t* rsp_len);
  uint8_t opRing(uint8_t conn, const uint8_t* p, size_t n, uint8_t* rsp, size_t* rsp_len);
  uint8_t opRingState(uint8_t conn, const uint8_t* p, size_t n, uint8_t* rsp, size_t* rsp_len);
  uint8_t opUtp(uint8_t conn, uint8_t id, const uint8_t* p, size_t n, uint8_t* rsp, size_t* rsp_len);
};

}  // namespace findhub

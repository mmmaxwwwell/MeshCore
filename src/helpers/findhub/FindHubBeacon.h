#pragma once

// Find Hub Network beacon: the ephemeral identity key, the rotating EID
// advertisement and the Fast Pair "Beacon Actions" GATT protocol (beacon
// parameters/clock, provisioning state, set/clear/recover the EIK, ring, ringing
// state, unwanted tracking protection).
// Spec: https://developers.google.com/nearby/fast-pair/specifications/extensions/fmdn
//
// Account keys (and which one is the owner's) come from the FastPairProvider:
// the Seeker provisions the EIK over Beacon Actions right after Fast Pair wrote
// its account key. Portable: board services come in through FindHubPlatform.
//
// Not implemented: precision finding (data IDs 0x0A-0x0D) and the DULT
// accessory non-owner service.

#include "FastPair.h"

namespace findhub {

constexpr size_t MAX_CONN = FP_MAX_CONN;
constexpr size_t ADV_FRAME_LEN = 29;      // flags(3) + service data(26)
constexpr size_t MAX_NOTIFY_LEN = 2 + AUTH_LEN + 2 * AK_LEN;   // largest: read EIK (32 bytes)
constexpr uint16_t RING_MAX_DS = 6000;    // 10 minutes in deciseconds

// ATT application error codes from the spec (table 7).
enum AttStatus : uint8_t {
  ATT_OK = 0x00,
  ATT_UNAUTHENTICATED = 0x80,
  ATT_INVALID_VALUE = 0x81,
  ATT_NO_USER_CONSENT = 0x82,
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
  FindHubBeacon(FindHubPlatform& platform, FastPairProvider& fp);

  // EIK (Beacon Actions 0x02/0x03, or restored at boot).
  void load(const uint8_t* eik);             // boot: restore without persisting (NULL = none)
  bool isProvisioned() const { return _provisioned; }
  // Forget the EIK and every account key (spec: clearing the EIK is a factory reset).
  bool factoryReset();

  uint32_t clock() { return _p.beaconClock(); }

  // Full advertising payload (flags + FHN service data). 0 when unprovisioned.
  // Recomputes the EID when its rotation window changes (one secp160r1
  // multiplication per ~1024 s).
  size_t buildAdvert(uint8_t out[ADV_FRAME_LEN]);
  const uint8_t* currentEid() const { return _eid; }
  // Changes exactly when the advertised EID does (after the random delay): the
  // FHN address rotates with it.
  uint32_t advertWindow() const { return _eid_window; }

  // GATT Beacon Actions characteristic.
  size_t onRead(uint8_t conn, uint8_t out[1 + NONCE_LEN]);
  // Returns an ATT status. On ATT_OK, `rsp` holds the notification to send BEFORE
  // the write response (spec: table 6 note), rsp_len its length (0 = none).
  uint8_t onWrite(uint8_t conn, const uint8_t* buf, size_t len, uint8_t rsp[MAX_NOTIFY_LEN], size_t* rsp_len);
  void onDisconnect(uint8_t conn);
  // True on a link that passed Beacon Actions authentication (Firmware Revision
  // reads are allowed there, spec "Firmware updates").
  bool authenticated(uint8_t conn) const { return conn < MAX_CONN && _conns[conn].authed; }

  // User consent for "read EIK" (0x04): pairing mode or a recent button press.
  void setUserConsent(bool on) { _consent = on; }

  // True once after an authenticated read of the beacon parameters (the Seeker
  // synchronised its copy of our clock).
  bool takeClockRead() { bool r = _clock_read; _clock_read = false; return r; }
  // True once after the EIK was set or cleared over GATT.
  bool takeProvisioningChanged() { bool r = _prov_changed; _prov_changed = false; return r; }

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
    bool authed;
  };

  FindHubPlatform& _p;
  FastPairProvider& _fp;
  bool _provisioned;
  uint8_t _eik[EIK_LEN];
  Conn _conns[MAX_CONN];
  bool _consent;
  bool _clock_read;
  bool _prov_changed;

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
  bool setEik(const uint8_t* eik);
  const uint8_t* matchAccountKey(const uint8_t nonce[NONCE_LEN], uint8_t id, const uint8_t* p, size_t n, bool hash_add);
  void startRing(uint16_t ds);
  void stopRing(RingTrigger why);
  void notifyRingState(RingTrigger why);
  size_t buildResponse(uint8_t* rsp, uint8_t data_id, const uint8_t* key, size_t key_len,
                       const uint8_t nonce[NONCE_LEN], const uint8_t* add, size_t add_len);

  uint8_t dispatch(uint8_t conn, const uint8_t* buf, size_t len, uint8_t* rsp, size_t* rsp_len);
  uint8_t opBeaconParams(uint8_t conn, const uint8_t* p, size_t n, uint8_t* rsp, size_t* rsp_len);
  uint8_t opProvisioningState(uint8_t conn, const uint8_t* p, size_t n, uint8_t* rsp, size_t* rsp_len);
  uint8_t opSetEik(uint8_t conn, const uint8_t* p, size_t n, uint8_t* rsp, size_t* rsp_len);
  uint8_t opClearEik(uint8_t conn, const uint8_t* p, size_t n, uint8_t* rsp, size_t* rsp_len);
  uint8_t opReadEik(uint8_t conn, const uint8_t* p, size_t n, uint8_t* rsp, size_t* rsp_len);
  uint8_t opRing(uint8_t conn, const uint8_t* p, size_t n, uint8_t* rsp, size_t* rsp_len);
  uint8_t opRingState(uint8_t conn, const uint8_t* p, size_t n, uint8_t* rsp, size_t* rsp_len);
  uint8_t opUtp(uint8_t conn, uint8_t id, const uint8_t* p, size_t n, uint8_t* rsp, size_t* rsp_len);
};

}  // namespace findhub

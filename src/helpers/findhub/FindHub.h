#pragma once

// Find Hub accessory: Fast Pair Provider + FHN beacon, and the policy around
// them (locator-tag guidelines of the FHN spec, NCS locator_tag behaviour):
//  - pairing mode (discoverable Fast Pair frames) on request or on the very
//    first boot, for 10 minutes, never while provisioned;
//  - an account key that is not followed by an EIK within 5 minutes is wiped;
//  - after a reboot a provisioned tag sends not-discoverable Fast Pair frames
//    until the owner's phone reads the beacon parameters (clock sync);
//  - addresses: one rotating random address for the Fast Pair and FHN frames,
//    switched together with the EID; frozen while discoverable and between the
//    account key write and the EIK; the FHN address held for 24 h in unwanted
//    tracking protection mode.
// What goes on air and when is the board's scheduler's job; this class only says
// which frames are wanted, with which address.

#include "FindHubBeacon.h"

namespace findhub {

constexpr uint32_t PAIRING_MODE_MS = 10UL * 60 * 1000;
constexpr uint32_t CONSENT_MS = 60UL * 1000;           // EIK recovery window (NCS default 1 min)
constexpr uint32_t PROVISION_TIMEOUT_MS = 5UL * 60 * 1000;
constexpr uint32_t UTP_ADDR_HOLD_S = 24UL * 3600;

struct AdvFrame {
  uint8_t data[FP_ADV_MAX];
  uint8_t len;
  uint8_t addr[ADDR_LEN];        // random static, SoftDevice byte order (LSB first)
  bool connectable;
  uint16_t interval;             // 0.625 ms units
};

class FindHub {
public:
  FindHub(FindHubPlatform& platform, const FastPairConfig& cfg);

  FastPairProvider& fastPair() { return _fp; }
  FindHubBeacon& beacon() { return _beacon; }

  // Boot. first_boot: no Find Hub state was ever stored on this device.
  void begin(const AccountKeyData* keys, const uint8_t* eik, bool first_boot);
  void loop();

  // User actions. requestPairing(): pairing mode when unprovisioned; when
  // provisioned it opens the EIK recovery consent window instead (the spec
  // forbids discoverable frames on a provisioned tag).
  void requestPairing();
  void stopPairing();
  bool pairingMode() const { return _fp.pairingMode(); }
  bool consentOpen() const;
  bool clockSyncPending() const { return _clock_sync_pending; }
  void buttonPressed();

  // Wanted frames. `links` = peripheral links up now. FHN frames go
  // non-connectable while any link is up (the companion link included).
  bool fastPairFrame(AdvFrame& out);
  bool fhnFrame(AdvFrame& out, uint8_t links);

  // The local address a new link may have used (current FP/FHN addresses).
  size_t tagAddresses(uint8_t (*out)[ADDR_LEN], size_t max) const;

  enum State : uint8_t { ST_IDLE, ST_PAIRING, ST_AWAIT_EIK, ST_PROVISIONED };
  State state() const;

private:
  FindHubPlatform& _p;
  FastPairProvider _fp;
  FindHubBeacon _beacon;

  uint32_t _pairing_until;
  bool _consent;
  uint32_t _consent_until;
  bool _await_eik;
  uint32_t _await_eik_until;
  bool _clock_sync_pending;

  uint8_t _addr[ADDR_LEN];       // Fast Pair (and FHN unless UTP holds it)
  uint8_t _prev_addr[ADDR_LEN];  // a link made just before a rotation still names it
  uint8_t _fhn_utp_addr[ADDR_LEN];
  bool _utp_addr_valid;
  uint32_t _utp_addr_since;      // beacon clock
  uint32_t _addr_window;         // advertWindow() the address belongs to
  uint32_t _unprov_rotate_at;    // millis, rotation while not provisioned
  uint8_t _salt[2];

  void newAddress(uint8_t out[ADDR_LEN]);
  void rotate();
  bool addressFrozen() const;
};

}  // namespace findhub

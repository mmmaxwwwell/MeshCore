#include "FindHub.h"

#include <string.h>

namespace findhub {

static const uint16_t INTERVAL_FP_DISCOVERABLE = 160;      // 100 ms (spec: <= 100 ms)
static const uint16_t INTERVAL_FP_NOT_DISCOVERABLE = 400;  // 250 ms (spec: <= 250 ms)
static const uint16_t INTERVAL_FHN = 320;                  // 200 ms (spec: a frame at least every 2 s)
static const uint32_t UNPROV_ROTATE_MS = 1024UL * 1000;

FindHub::FindHub(FindHubPlatform& platform, const FastPairConfig& cfg)
  : _p(platform), _fp(platform, cfg), _beacon(platform, _fp) {
  _pairing_until = 0;
  _consent = false;
  _consent_until = 0;
  _await_eik = false;
  _await_eik_until = 0;
  _clock_sync_pending = false;
  memset(_addr, 0, sizeof(_addr));
  memset(_prev_addr, 0, sizeof(_prev_addr));
  memset(_fhn_utp_addr, 0, sizeof(_fhn_utp_addr));
  _utp_addr_valid = false;
  _utp_addr_since = 0;
  _addr_window = 0xFFFFFFFF;
  _unprov_rotate_at = 0;
  memset(_salt, 0, sizeof(_salt));
}

void FindHub::begin(const AccountKeyData* keys, const uint8_t* eik, bool first_boot) {
  _fp.load(keys);
  _beacon.load(eik);
  newAddress(_addr);
  memcpy(_prev_addr, _addr, ADDR_LEN);
  _p.randomBytes(_salt, sizeof(_salt));
  _unprov_rotate_at = _p.millis() + UNPROV_ROTATE_MS;

  if (!eik && _fp.keyCount() > 0) {
    // Paired but never provisioned (or reset mid-way): back to factory state (spec).
    _fp.factoryReset();
  }
  // After a power loss the owner's phone re-reads our clock; tell it we are here.
  _clock_sync_pending = eik != NULL && _fp.keyCount() > 0;
  if (first_boot && !eik) requestPairing();
}

void FindHub::newAddress(uint8_t out[ADDR_LEN]) {
  // Random static address: the two most significant bits set, the rest neither
  // all zeros nor all ones.
  do {
    _p.randomBytes(out, ADDR_LEN);
    out[ADDR_LEN - 1] |= 0xC0;
  } while ((out[0] == 0xFF && out[1] == 0xFF && out[2] == 0xFF && out[3] == 0xFF && out[4] == 0xFF && out[5] == 0xFF) ||
           (out[0] == 0x00 && out[1] == 0x00 && out[2] == 0x00 && out[3] == 0x00 && out[4] == 0x00 && out[5] == 0xC0));
}

void FindHub::rotate() {
  memcpy(_prev_addr, _addr, ADDR_LEN);
  newAddress(_addr);
  _p.randomBytes(_salt, sizeof(_salt));     // spec: a new salt with every address
}

bool FindHub::addressFrozen() const {
  // Discoverable: the address must not rotate. Paired: not until the EIK (or 5 min).
  return _fp.pairingMode() || _await_eik;
}

bool FindHub::consentOpen() const {
  return _fp.pairingMode() || _consent;
}

void FindHub::requestPairing() {
  uint32_t now = _p.millis();
  _consent = true;
  _consent_until = now + CONSENT_MS;
  if (_beacon.isProvisioned()) return;
  _fp.setPairingMode(true);
  _pairing_until = now + PAIRING_MODE_MS;
}

void FindHub::stopPairing() {
  _fp.setPairingMode(false);
}

void FindHub::buttonPressed() {
  _beacon.buttonPressed();
}

FindHub::State FindHub::state() const {
  if (_beacon.isProvisioned()) return ST_PROVISIONED;
  if (_await_eik) return ST_AWAIT_EIK;
  if (_fp.pairingMode()) return ST_PAIRING;
  return ST_IDLE;
}

void FindHub::loop() {
  _fp.loop();
  _beacon.loop();
  uint32_t now = _p.millis();

  if (_fp.pairingMode() && (int32_t)(now - _pairing_until) >= 0) stopPairing();
  if (_consent && (int32_t)(now - _consent_until) >= 0) _consent = false;

  if (_fp.takeAccountKeyWritten() && !_beacon.isProvisioned()) {
    // The Seeker goes on to FHN provisioning; it no longer needs us discoverable.
    stopPairing();
    _await_eik = true;
    _await_eik_until = now + PROVISION_TIMEOUT_MS;
  }
  if (_beacon.takeProvisioningChanged()) {
    _await_eik = false;
    _clock_sync_pending = false;   // provisioning reads the clock, and a cleared tag has none
    stopPairing();
  }
  if (_await_eik && (int32_t)(now - _await_eik_until) >= 0) {
    _await_eik = false;
    _beacon.factoryReset();
  }
  if (_beacon.takeClockRead()) _clock_sync_pending = false;
  _beacon.setUserConsent(consentOpen());

  if (!_beacon.isProvisioned() && !addressFrozen() && (int32_t)(now - _unprov_rotate_at) >= 0) {
    rotate();
    _unprov_rotate_at = now + UNPROV_ROTATE_MS;
  }
}

bool FindHub::fastPairFrame(AdvFrame& out) {
  bool provisioned = _beacon.isProvisioned();
  size_t len = 0;
  if (_fp.pairingMode() && !provisioned) {
    len = _fp.discoverableAdvert(out.data);
    out.interval = INTERVAL_FP_DISCOVERABLE;
  } else if (_fp.keyCount() > 0 && (_await_eik || (provisioned && _clock_sync_pending))) {
    len = _fp.notDiscoverableAdvert(_salt, out.data);
    out.interval = INTERVAL_FP_NOT_DISCOVERABLE;
  }
  if (len == 0) return false;
  out.len = (uint8_t)len;
  memcpy(out.addr, _addr, ADDR_LEN);
  out.connectable = true;
  return true;
}

bool FindHub::fhnFrame(AdvFrame& out, uint8_t links) {
  size_t len = _beacon.buildAdvert(out.data);
  if (len == 0) {
    _utp_addr_valid = false;
    return false;
  }
  // The address follows the EID (same window, same random delay).
  uint32_t w = _beacon.advertWindow();
  if (w != _addr_window) {
    if (_addr_window != 0xFFFFFFFF && !addressFrozen()) rotate();
    _addr_window = w;
  }
  if (_beacon.utpMode()) {
    uint32_t clk = _beacon.clock();
    if (!_utp_addr_valid || clk - _utp_addr_since >= UTP_ADDR_HOLD_S) {
      // Entering UTP: keep the address the frame already has; then one per 24 h.
      if (_utp_addr_valid) newAddress(_fhn_utp_addr);
      else memcpy(_fhn_utp_addr, _addr, ADDR_LEN);
      _utp_addr_valid = true;
      _utp_addr_since = clk;
    }
  } else {
    _utp_addr_valid = false;
  }
  out.len = (uint8_t)len;
  memcpy(out.addr, _utp_addr_valid ? _fhn_utp_addr : _addr, ADDR_LEN);
  out.connectable = links == 0;
  out.interval = INTERVAL_FHN;
  return true;
}

size_t FindHub::tagAddresses(uint8_t (*out)[ADDR_LEN], size_t max) const {
  size_t n = 0;
  if (n < max) memcpy(out[n++], _addr, ADDR_LEN);
  if (_utp_addr_valid && n < max) memcpy(out[n++], _fhn_utp_addr, ADDR_LEN);
  if (n < max && memcmp(_prev_addr, _addr, ADDR_LEN) != 0) memcpy(out[n++], _prev_addr, ADDR_LEN);
  return n;
}

}  // namespace findhub

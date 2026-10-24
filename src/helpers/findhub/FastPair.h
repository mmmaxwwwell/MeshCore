#pragma once

// Fast Pair Provider: Key-based Pairing, Passkey and Account Key characteristics,
// the account key list and the advertising payloads.
// Spec: https://developers.google.com/nearby/fast-pair/specifications/service/gatt
//       https://developers.google.com/nearby/fast-pair/specifications/characteristics
//       https://developers.google.com/nearby/fast-pair/specifications/service/provider
// Reference state machine: nRF Connect SDK subsys/bluetooth/fast_pair/fp_keys.c.
//
// Two ways to finish a pairing, as in the spec:
//  - without BLE bonding (locator tags; Nordic's locator_tag builds this way):
//    Key-based Pairing, then the Account Key write on the same, unencrypted link;
//  - with bonding: Key-based Pairing, numeric-comparison pairing confirmed through
//    the Passkey characteristic, then the Account Key write on the encrypted link.
//
// Every call runs on one thread (FindHubService's main-loop queue).

#include "FindHubPlatform.h"

namespace findhub {

constexpr size_t FP_MAX_CONN = 8;          // Bluefruit connection handles are < 8 here
constexpr size_t ADDR_LEN = 6;
constexpr size_t MODEL_ID_LEN = 3;
constexpr size_t FP_BLOCK = 16;
constexpr size_t FP_ADV_MAX = 31;
constexpr size_t MAX_LINK_ADDRS = 3;

// GATT status codes (ATT errors) Fast Pair writes answer with.
enum FpStatus : uint8_t {
  FP_OK = 0x00,
  FP_ERR_INVALID_OFFSET = 0x07,
  FP_ERR_INVALID_LEN = 0x0D,
  FP_ERR_UNLIKELY = 0x0E,
};

struct FastPairConfig {
  uint8_t model_id[MODEL_ID_LEN];
  uint8_t antispoof_priv[P256_PRIV_LEN];
};

class FastPairProvider {
public:
  FastPairProvider(FindHubPlatform& platform, const FastPairConfig& cfg);

  // Account keys.
  void load(const AccountKeyData* d);                // boot: restore without persisting
  bool factoryReset();                               // erase every account key
  size_t keyCount() const { return _keys.count; }
  const uint8_t* key(size_t i) const { return i < _keys.count ? _keys.keys[i] : NULL; }
  const uint8_t* ownerKey() const { return _keys.owner < _keys.count ? _keys.keys[_keys.owner] : NULL; }
  bool isOwnerKey(const uint8_t* k) const;

  // Pairing mode: discoverable advertising, and the only time a Seeker's public
  // key (initial pairing) is accepted.
  void setPairingMode(bool on) { _pairing_mode = on; }
  bool pairingMode() const { return _pairing_mode; }
  const uint8_t* modelId() const { return _cfg.model_id; }

  // Connections. `addrs` are the local addresses this link may have been made on
  // (SoftDevice byte order, LSB first): the ones advertised around the time it
  // connected, as the address can change between the radio event and the
  // callback. Key-based Pairing requests must name one of them.
  void onConnect(uint8_t conn, const uint8_t (*addrs)[ADDR_LEN], size_t n);
  void onDisconnect(uint8_t conn);
  void loop();                                       // 10 s key and 5 min lockout timers

  // GATT writes. Each returns an FpStatus; on FP_OK, *rsp_len bytes of `rsp`
  // go out as a notification on that characteristic BEFORE the write response.
  uint8_t onKeyBasedPairing(uint8_t conn, const uint8_t* buf, size_t len, uint8_t rsp[FP_BLOCK], size_t* rsp_len);
  uint8_t onPasskey(uint8_t conn, const uint8_t* buf, size_t len, uint8_t rsp[FP_BLOCK], size_t* rsp_len);
  uint8_t onAccountKey(uint8_t conn, const uint8_t* buf, size_t len, bool link_encrypted);

  // BLE pairing hooks (bonding flow). The stack shows the numeric-comparison
  // passkey; the Passkey write decides whether it matches. Returns true when the
  // passkey characteristic has already confirmed it (*ok holds the answer).
  void onNumericComparison(uint8_t conn, uint32_t passkey);
  bool comparisonResult(uint8_t conn, bool* ok) const;
  void onPairingComplete(uint8_t conn, bool success);

  // True once after each stored account key (FindHub starts its 5 min timer).
  bool takeAccountKeyWritten() { bool w = _ak_written; _ak_written = false; return w; }

  // Advertising payloads (full AD structures, flags included).
  size_t discoverableAdvert(uint8_t out[FP_ADV_MAX]) const;
  // Not discoverable: Account Key Filter + salt, UI indication hidden. 0 when no keys.
  size_t notDiscoverableAdvert(const uint8_t salt[2], uint8_t out[FP_ADV_MAX]) const;

  // Diagnostics.
  uint8_t failures() const { return _failures; }
  uint8_t lastResult() const { return _last_result; }

private:
  enum KeyState : uint8_t { KEY_NONE, KEY_ANTISPOOF, KEY_ACCOUNT };
  struct Conn {
    uint8_t addrs[MAX_LINK_ADDRS][ADDR_LEN];
    uint8_t n_addrs;
    uint8_t addr_used;            // which one the Key-based Pairing request named
    bool pairing_mode;            // pairing mode when this link came up
    KeyState state;
    uint8_t k[AK_LEN];            // K: shared secret of this procedure
    uint32_t deadline;            // millis; K is discarded after it
    bool await_account_key;       // bonding flow: pairing succeeded
    bool cmp_pending;             // stack is waiting for the numeric comparison
    bool cmp_decided;
    bool cmp_ok;
    uint32_t stack_passkey;
  };

  FindHubPlatform& _p;
  FastPairConfig _cfg;
  AccountKeyData _keys;
  bool _pairing_mode;
  Conn _conns[FP_MAX_CONN];
  uint8_t _failures;
  uint32_t _lockout_until;
  bool _ak_written;
  uint8_t _last_result;

  // Replay protection (spec step 2.3): the last decrypted requests.
  static const uint8_t SEEN = 8;
  uint8_t _seen[SEEN][8];
  uint8_t _seen_next;

  void dropKey(Conn& c);
  bool validRequest(Conn& c, const uint8_t req[FP_BLOCK]);
  bool tryKey(Conn& c, const uint8_t key[AK_LEN], const uint8_t enc[FP_BLOCK], uint8_t req[FP_BLOCK]);
  void fail();
  bool storeAccountKey(const uint8_t ak[AK_LEN]);
  void touchKey(size_t i);
};

}  // namespace findhub

#pragma once

// Find Hub Network (FHN, formerly Find My Device Network) accessory crypto.
// Spec: https://developers.google.com/nearby/fast-pair/specifications/extensions/fmdn
//
// Pure functions, no Arduino/BLE dependencies, so the native test env can check
// them against the Python reference (GoogleFindMyTools' eid_generator.py).

#include <stdint.h>
#include <stddef.h>

namespace findhub {

constexpr size_t EIK_LEN = 32;     // ephemeral identity key
constexpr size_t AK_LEN = 16;      // Fast Pair account key
constexpr size_t EID_LEN = 20;     // secp160r1 x coordinate
constexpr size_t NONCE_LEN = 8;
constexpr size_t AUTH_LEN = 8;     // one-time authentication segment
constexpr size_t DERIVED_KEY_LEN = 8;
constexpr uint8_t ROTATION_EXP = 10;           // K: 2^10 = 1024 s, fixed by the spec
constexpr uint8_t PROTOCOL_MAJOR = 0x01;

enum DerivedKey : uint8_t {
  KEY_RECOVERY = 0x01,
  KEY_RING = 0x02,
  KEY_UTP = 0x03,     // unwanted tracking protection
};

// EID for beacon clock value `counter` (seconds since provisioning). The K lowest
// bits are cleared internally. `hash_xor` (optional) receives the low byte of
// SHA256(r), the XOR operand of the hashed-flags byte. Returns false only if the
// curve multiplication failed (r == 0, astronomically unlikely).
bool computeEid(const uint8_t eik[EIK_LEN], uint32_t counter, uint8_t eid[EID_LEN], uint8_t* hash_xor);

// SHA256(eik || which), truncated to 8 bytes.
void deriveKey(const uint8_t eik[EIK_LEN], DerivedKey which, uint8_t out[DERIVED_KEY_LEN]);

// First 8 bytes of HMAC-SHA256(key, PROTOCOL_MAJOR || nonce || data_id || data_len
// || add || [0x01 if response]). data_len is the frame's Data length field (it
// counts the 8-byte auth segment), add_len the bytes of additional data hashed.
void authSegment(const uint8_t* key, size_t key_len, const uint8_t nonce[NONCE_LEN],
                 uint8_t data_id, uint8_t data_len, const uint8_t* add, size_t add_len,
                 bool response, uint8_t out[AUTH_LEN]);

// Constant-time compare.
bool equalCT(const uint8_t* a, const uint8_t* b, size_t len);

void aes128EcbEncrypt(const uint8_t key[AK_LEN], const uint8_t* in, uint8_t* out, size_t len);  // len % 16 == 0
void aes128EcbDecrypt(const uint8_t key[AK_LEN], const uint8_t* in, uint8_t* out, size_t len);

// First 8 bytes of SHA256(a || b).
void sha256Trunc8(const uint8_t* a, size_t a_len, const uint8_t* b, size_t b_len, uint8_t out[8]);

}  // namespace findhub

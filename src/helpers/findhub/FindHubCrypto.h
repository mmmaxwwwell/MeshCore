#pragma once

// Fast Pair + Find Hub Network (FHN, formerly Find My Device Network) accessory crypto.
// Specs: https://developers.google.com/nearby/fast-pair/specifications/introduction
//        https://developers.google.com/nearby/fast-pair/specifications/extensions/fmdn
//
// Pure functions, no Arduino/BLE dependencies, so the native test env checks them
// against the spec's "Cryptographic Test Cases" and a Python reference.

#include <stdint.h>
#include <stddef.h>

namespace findhub {

constexpr size_t EIK_LEN = 32;     // ephemeral identity key
constexpr size_t AK_LEN = 16;      // Fast Pair account key (also the AES-128 key size)
constexpr size_t EID_LEN = 20;     // secp160r1 x coordinate
constexpr size_t NONCE_LEN = 8;
constexpr size_t AUTH_LEN = 8;     // one-time authentication segment
constexpr size_t DERIVED_KEY_LEN = 8;
constexpr size_t P256_PRIV_LEN = 32;
constexpr size_t P256_PUB_LEN = 64;   // X || Y, big-endian, no point-format byte
constexpr size_t SECP160R1_PRIV_LEN = 21;   // n is 161 bits
constexpr uint8_t ROTATION_EXP = 10;           // K: 2^10 = 1024 s, fixed by the spec
constexpr uint8_t PROTOCOL_MAJOR = 0x01;

enum DerivedKey : uint8_t {
  KEY_RECOVERY = 0x01,
  KEY_RING = 0x02,
  KEY_UTP = 0x03,     // unwanted tracking protection
};

// ---------------------------------------------------------------- elliptic curves
// Implemented by FindHubEcSw.cpp (micro-ecc) or, on the nRF52840,
// nrf52/FindHubEcCC310.cpp (CryptoCell). Both return false on any failure.

// x coordinate of k*G on secp160r1, k big-endian (21 bytes, 0 < k < n).
bool ecSecp160r1MulG(const uint8_t k[SECP160R1_PRIV_LEN], uint8_t x[EID_LEN]);
// ECDH on secp256r1: x coordinate of priv*pub. Rejects a point not on the curve.
bool ecdhP256(const uint8_t priv[P256_PRIV_LEN], const uint8_t pub[P256_PUB_LEN], uint8_t secret[32]);

// ---------------------------------------------------------------- FHN

// EID for beacon clock value `counter` (seconds). The K lowest bits are cleared
// internally. `hash_xor` (optional) receives the low byte of SHA256(r), the XOR
// operand of the hashed-flags byte. Returns false only if the curve
// multiplication failed (r == 0, astronomically unlikely).
bool computeEid(const uint8_t eik[EIK_LEN], uint32_t counter, uint8_t eid[EID_LEN], uint8_t* hash_xor);

// SHA256(eik || which), truncated to 8 bytes.
void deriveKey(const uint8_t eik[EIK_LEN], DerivedKey which, uint8_t out[DERIVED_KEY_LEN]);

// First 8 bytes of HMAC-SHA256(key, PROTOCOL_MAJOR || nonce || data_id || data_len
// || add || [0x01 if response]). data_len is the frame's Data length field (it
// counts the 8-byte auth segment), add_len the bytes of additional data hashed.
void authSegment(const uint8_t* key, size_t key_len, const uint8_t nonce[NONCE_LEN],
                 uint8_t data_id, uint8_t data_len, const uint8_t* add, size_t add_len,
                 bool response, uint8_t out[AUTH_LEN]);

// ---------------------------------------------------------------- Fast Pair

// Anti-Spoofing AES key: SHA256(ECDH shared secret), first 16 bytes.
void aesKeyFromSecret(const uint8_t secret[32], uint8_t key[AK_LEN]);

// Account Key Filter (Bloom filter, provider spec "Account Key Filter"): V =
// key || salt || extra for each key. Returns the filter length s = floor(1.2 n) + 3.
constexpr size_t MAX_FILTER_LEN = 3 + (12 * 8) / 10;   // room for 8 keys
size_t accountKeyFilter(const uint8_t (*keys)[AK_LEN], size_t n, const uint8_t salt[2],
                        const uint8_t* extra, size_t extra_len, uint8_t out[MAX_FILTER_LEN]);

// Additional Data packet (characteristic FE2C1237): HMAC(8) || nonce(8) || AES-CTR(data).
constexpr size_t ADDITIONAL_DATA_HDR = 16;
void additionalDataEncode(const uint8_t key[AK_LEN], const uint8_t nonce[8], const uint8_t* data, size_t len,
                          uint8_t* out /* ADDITIONAL_DATA_HDR + len */);
// Returns false when the HMAC does not match (out untouched).
bool additionalDataDecode(const uint8_t key[AK_LEN], const uint8_t* packet, size_t packet_len,
                          uint8_t* out /* packet_len - ADDITIONAL_DATA_HDR */);

// ---------------------------------------------------------------- primitives

void sha256(const uint8_t* a, size_t a_len, const uint8_t* b, size_t b_len, uint8_t out[32]);
// First 8 bytes of SHA256(a || b).
void sha256Trunc8(const uint8_t* a, size_t a_len, const uint8_t* b, size_t b_len, uint8_t out[8]);
void hmacSha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t out[32]);

// Constant-time compare.
bool equalCT(const uint8_t* a, const uint8_t* b, size_t len);

void aes128EcbEncrypt(const uint8_t key[AK_LEN], const uint8_t* in, uint8_t* out, size_t len);  // len % 16 == 0
void aes128EcbDecrypt(const uint8_t key[AK_LEN], const uint8_t* in, uint8_t* out, size_t len);

}  // namespace findhub

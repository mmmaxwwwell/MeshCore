#include "FindHubCrypto.h"

#include <string.h>
#include <AES.h>
#include <SHA256.h>
#include <uECC.h>

namespace findhub {

// secp160r1 group order n (161 bits), big-endian, 21 bytes.
static const uint8_t SECP160R1_N[21] = {
  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
  0xF4, 0xC8, 0xF9, 0x27, 0xAE, 0xD3, 0xCA, 0x75, 0x22, 0x57,
};

// 6 little-endian 32-bit limbs hold anything below 2^192 (> 2n).
struct U192 { uint32_t w[6]; };

static void u192FromBE(U192& r, const uint8_t* be, size_t len) {
  memset(&r, 0, sizeof(r));
  for (size_t i = 0; i < len; i++) {
    size_t bit = (len - 1 - i) * 8;
    r.w[bit / 32] |= (uint32_t)be[i] << (bit % 32);
  }
}

static void u192ToBE(const U192& r, uint8_t* be, size_t len) {
  for (size_t i = 0; i < len; i++) {
    size_t bit = (len - 1 - i) * 8;
    be[i] = (uint8_t)(r.w[bit / 32] >> (bit % 32));
  }
}

static bool u192Gte(const U192& a, const U192& b) {
  for (int i = 5; i >= 0; i--) {
    if (a.w[i] != b.w[i]) return a.w[i] > b.w[i];
  }
  return true;
}

static void u192Sub(U192& a, const U192& b) {
  uint64_t borrow = 0;
  for (int i = 0; i < 6; i++) {
    uint64_t d = (uint64_t)a.w[i] - b.w[i] - borrow;
    a.w[i] = (uint32_t)d;
    borrow = (d >> 63) & 1;
  }
}

// r = x mod n, x a 256-bit big-endian value. Bit-serial shift-and-subtract:
// 256 iterations, runs once per 1024 s rotation.
static void modN(const uint8_t x[32], U192& r) {
  U192 n;
  u192FromBE(n, SECP160R1_N, sizeof(SECP160R1_N));
  memset(&r, 0, sizeof(r));
  for (int i = 0; i < 256; i++) {
    uint32_t bit = (x[i / 8] >> (7 - (i % 8))) & 1;
    for (int j = 5; j > 0; j--) r.w[j] = (r.w[j] << 1) | (r.w[j - 1] >> 31);
    r.w[0] = (r.w[0] << 1) | bit;
    if (u192Gte(r, n)) u192Sub(r, n);
  }
}

bool computeEid(const uint8_t eik[EIK_LEN], uint32_t counter, uint8_t eid[EID_LEN], uint8_t* hash_xor) {
  uint32_t ts = counter & ~((1UL << ROTATION_EXP) - 1);
  uint8_t seed[32];
  memset(seed, 0xFF, 11);
  seed[11] = ROTATION_EXP;
  seed[12] = (uint8_t)(ts >> 24); seed[13] = (uint8_t)(ts >> 16);
  seed[14] = (uint8_t)(ts >> 8);  seed[15] = (uint8_t)ts;
  memset(&seed[16], 0x00, 11);
  seed[27] = ROTATION_EXP;
  memcpy(&seed[28], &seed[12], 4);

  // AES-ECB-256 of the 32-byte seed = two independent blocks.
  uint8_t r_dash[32];
  AES256 aes;
  aes.setKey(eik, EIK_LEN);
  aes.encryptBlock(&r_dash[0], &seed[0]);
  aes.encryptBlock(&r_dash[16], &seed[16]);
  aes.clear();

  U192 r;
  modN(r_dash, r);
  uint8_t priv[21];
  u192ToBE(r, priv, sizeof(priv));

  uint8_t pub[40];
  bool ok = uECC_compute_public_key(priv, pub, uECC_secp160r1()) == 1;
  if (ok) memcpy(eid, pub, EID_LEN);

  if (hash_xor) {
    // r aligned to the curve size: its low 160 bits, big-endian.
    uint8_t digest[32];
    SHA256 sha;
    sha.update(&priv[1], 20);
    sha.finalize(digest, sizeof(digest));
    *hash_xor = digest[31];
  }
  memset(priv, 0, sizeof(priv));
  memset(r_dash, 0, sizeof(r_dash));
  return ok;
}

void deriveKey(const uint8_t eik[EIK_LEN], DerivedKey which, uint8_t out[DERIVED_KEY_LEN]) {
  uint8_t w = which;
  sha256Trunc8(eik, EIK_LEN, &w, 1, out);
}

void sha256Trunc8(const uint8_t* a, size_t a_len, const uint8_t* b, size_t b_len, uint8_t out[8]) {
  uint8_t digest[32];
  SHA256 sha;
  sha.update(a, a_len);
  sha.update(b, b_len);
  sha.finalize(digest, sizeof(digest));
  memcpy(out, digest, 8);
}

void authSegment(const uint8_t* key, size_t key_len, const uint8_t nonce[NONCE_LEN],
                 uint8_t data_id, uint8_t data_len, const uint8_t* add, size_t add_len,
                 bool response, uint8_t out[AUTH_LEN]) {
  uint8_t hdr[1 + NONCE_LEN + 2];
  hdr[0] = PROTOCOL_MAJOR;
  memcpy(&hdr[1], nonce, NONCE_LEN);
  hdr[1 + NONCE_LEN] = data_id;
  hdr[2 + NONCE_LEN] = data_len;

  SHA256 sha;
  sha.resetHMAC(key, key_len);
  sha.update(hdr, sizeof(hdr));
  if (add_len) sha.update(add, add_len);
  if (response) {
    uint8_t one = 0x01;
    sha.update(&one, 1);
  }
  uint8_t mac[32];
  sha.finalizeHMAC(key, key_len, mac, sizeof(mac));
  memcpy(out, mac, AUTH_LEN);
}

bool equalCT(const uint8_t* a, const uint8_t* b, size_t len) {
  uint8_t diff = 0;
  for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
  return diff == 0;
}

void aes128EcbEncrypt(const uint8_t key[AK_LEN], const uint8_t* in, uint8_t* out, size_t len) {
  AES128 aes;
  aes.setKey(key, AK_LEN);
  for (size_t i = 0; i + 16 <= len; i += 16) aes.encryptBlock(&out[i], &in[i]);
  aes.clear();
}

void aes128EcbDecrypt(const uint8_t key[AK_LEN], const uint8_t* in, uint8_t* out, size_t len) {
  AES128 aes;
  aes.setKey(key, AK_LEN);
  for (size_t i = 0; i + 16 <= len; i += 16) aes.decryptBlock(&out[i], &in[i]);
  aes.clear();
}

}  // namespace findhub

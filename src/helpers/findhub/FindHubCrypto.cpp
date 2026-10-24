#include "FindHubCrypto.h"

#include <string.h>
#include <AES.h>
#include <SHA256.h>

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
  uint8_t priv[SECP160R1_PRIV_LEN];
  u192ToBE(r, priv, sizeof(priv));

  bool ok = ecSecp160r1MulG(priv, eid);

  if (hash_xor) {
    // r aligned to the curve size: its low 160 bits, big-endian.
    uint8_t digest[32];
    sha256(&priv[1], 20, NULL, 0, digest);
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

void sha256(const uint8_t* a, size_t a_len, const uint8_t* b, size_t b_len, uint8_t out[32]) {
  SHA256 sha;
  if (a_len) sha.update(a, a_len);
  if (b_len) sha.update(b, b_len);
  sha.finalize(out, 32);
}

void sha256Trunc8(const uint8_t* a, size_t a_len, const uint8_t* b, size_t b_len, uint8_t out[8]) {
  uint8_t digest[32];
  sha256(a, a_len, b, b_len, digest);
  memcpy(out, digest, 8);
}

void hmacSha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t out[32]) {
  SHA256 sha;
  sha.resetHMAC(key, key_len);
  if (len) sha.update(data, len);
  sha.finalizeHMAC(key, key_len, out, 32);
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

void aesKeyFromSecret(const uint8_t secret[32], uint8_t key[AK_LEN]) {
  uint8_t digest[32];
  sha256(secret, 32, NULL, 0, digest);
  memcpy(key, digest, AK_LEN);
  memset(digest, 0, sizeof(digest));
}

size_t accountKeyFilter(const uint8_t (*keys)[AK_LEN], size_t n, const uint8_t salt[2],
                        const uint8_t* extra, size_t extra_len, uint8_t out[MAX_FILTER_LEN]) {
  size_t s = (12 * n) / 10 + 3;     // (uint8_t)(1.2f * n) + 3, without floats
  if (s > MAX_FILTER_LEN) return 0;
  memset(out, 0, s);
  for (size_t k = 0; k < n; k++) {
    SHA256 sha;
    uint8_t h[32];
    sha.update(keys[k], AK_LEN);
    sha.update(salt, 2);
    if (extra_len) sha.update(extra, extra_len);
    sha.finalize(h, sizeof(h));
    for (int i = 0; i < 8; i++) {
      uint32_t x = ((uint32_t)h[i * 4] << 24) | ((uint32_t)h[i * 4 + 1] << 16) |
                   ((uint32_t)h[i * 4 + 2] << 8) | h[i * 4 + 3];
      uint32_t m = x % (uint32_t)(s * 8);
      out[m / 8] |= (uint8_t)(1 << (m % 8));
    }
  }
  return s;
}

// encryptedBlock[i] = clearBlock[i] ^ AES(key, (uint8)i || 0x00 * 7 || nonce)
static void aesCtr(const uint8_t key[AK_LEN], const uint8_t nonce[8], const uint8_t* in, size_t len, uint8_t* out) {
  AES128 aes;
  aes.setKey(key, AK_LEN);
  uint8_t ctr[16], ks[16];
  for (size_t off = 0, i = 0; off < len; off += 16, i++) {
    memset(ctr, 0, sizeof(ctr));
    ctr[0] = (uint8_t)i;
    memcpy(&ctr[8], nonce, 8);
    aes.encryptBlock(ks, ctr);
    size_t n = len - off < 16 ? len - off : 16;
    for (size_t j = 0; j < n; j++) out[off + j] = in[off + j] ^ ks[j];
  }
  aes.clear();
  memset(ks, 0, sizeof(ks));
}

// HMAC-SHA256 with K = key || 48 zero bytes, which is what HMAC pads a 16-byte key to.
void additionalDataEncode(const uint8_t key[AK_LEN], const uint8_t nonce[8], const uint8_t* data, size_t len,
                          uint8_t* out) {
  memcpy(&out[8], nonce, 8);
  aesCtr(key, nonce, data, len, &out[ADDITIONAL_DATA_HDR]);
  uint8_t mac[32];
  hmacSha256(key, AK_LEN, &out[8], 8 + len, mac);
  memcpy(out, mac, 8);
}

bool additionalDataDecode(const uint8_t key[AK_LEN], const uint8_t* packet, size_t packet_len, uint8_t* out) {
  if (packet_len < ADDITIONAL_DATA_HDR) return false;
  uint8_t mac[32];
  hmacSha256(key, AK_LEN, &packet[8], packet_len - 8, mac);
  if (!equalCT(mac, packet, 8)) return false;
  aesCtr(key, &packet[8], &packet[ADDITIONAL_DATA_HDR], packet_len - ADDITIONAL_DATA_HDR, out);
  return true;
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

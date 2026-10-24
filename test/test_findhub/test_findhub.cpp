#include <gtest/gtest.h>
#include <string.h>
#include <vector>
#include <uECC.h>

#include "helpers/findhub/FindHub.h"

using namespace findhub;

static std::vector<uint8_t> V(std::initializer_list<uint8_t> l) { return std::vector<uint8_t>(l); }

// ================================================================ spec vectors
// https://developers.google.com/nearby/fast-pair/specifications/appendix/cryptotestcases

static const uint8_t BOB_PRIV[32] = {
  0x02, 0xB4, 0x37, 0xB0, 0xED, 0xD6, 0xBB, 0xD4, 0x29, 0x06, 0x4A, 0x4E, 0x52, 0x9F, 0xCB, 0xF1,
  0xC4, 0x8D, 0x0D, 0x62, 0x49, 0x24, 0xD5, 0x92, 0x27, 0x4B, 0x7E, 0xD8, 0x11, 0x93, 0xD7, 0x63};
static const uint8_t BOB_PUB[64] = {
  0xF7, 0xD4, 0x96, 0xA6, 0x2E, 0xCA, 0x41, 0x63, 0x51, 0x54, 0x0A, 0xA3, 0x43, 0xBC, 0x69, 0x0A,
  0x61, 0x09, 0xF5, 0x51, 0x50, 0x06, 0x66, 0xB8, 0x3B, 0x12, 0x51, 0xFB, 0x84, 0xFA, 0x28, 0x60,
  0x79, 0x5E, 0xBD, 0x63, 0xD3, 0xB8, 0x83, 0x6F, 0x44, 0xA9, 0xA3, 0xE2, 0x8B, 0xB3, 0x40, 0x17,
  0xE0, 0x15, 0xF5, 0x97, 0x93, 0x05, 0xD8, 0x49, 0xFD, 0xF8, 0xDE, 0x10, 0x12, 0x3B, 0x61, 0xD2};
static const uint8_t ALICE_PRIV[32] = {
  0xD7, 0x5E, 0x54, 0xC7, 0x7D, 0x76, 0x24, 0x89, 0xE5, 0x7C, 0xFA, 0x92, 0x37, 0x43, 0xF1, 0x67,
  0x77, 0xA4, 0x28, 0x3D, 0x99, 0x80, 0x0B, 0xAC, 0x55, 0x58, 0x48, 0x38, 0x93, 0xE5, 0xB0, 0x6D};
static const uint8_t ALICE_PUB[64] = {
  0x36, 0xAC, 0x68, 0x2C, 0x50, 0x82, 0x15, 0x66, 0x8F, 0xBE, 0xFE, 0x24, 0x7D, 0x01, 0xD5, 0xEB,
  0x96, 0xE6, 0x31, 0x8E, 0x85, 0x5B, 0x2D, 0x64, 0xB5, 0x19, 0x5D, 0x38, 0xEE, 0x7E, 0x37, 0xBE,
  0x18, 0x38, 0xC0, 0xB9, 0x48, 0xC3, 0xF7, 0x55, 0x20, 0xE0, 0x7E, 0x70, 0xF0, 0x72, 0x91, 0x41,
  0x9A, 0xCE, 0x2D, 0x28, 0x14, 0x3C, 0x5A, 0xDB, 0x2D, 0xBD, 0x98, 0xEE, 0x3C, 0x8E, 0x4F, 0xBF};
static const uint8_t SHARED[32] = {
  0x9D, 0xAD, 0xE4, 0xF8, 0x6A, 0xC3, 0x48, 0x8B, 0xBA, 0xC2, 0xAC, 0x34, 0xB5, 0xFE, 0x68, 0xA0,
  0xEE, 0x5A, 0x67, 0x06, 0xF5, 0x43, 0xD9, 0x06, 0x1A, 0xD5, 0x78, 0x89, 0x49, 0x8A, 0xE6, 0xBA};
static const uint8_t SHARED_AES[16] = {
  0xB0, 0x7F, 0x1F, 0x17, 0xC2, 0x36, 0xCB, 0xD3, 0x35, 0x23, 0xC5, 0x15, 0xF3, 0x50, 0xAE, 0x57};

TEST(SpecVectors, Sha256) {
  const uint8_t in[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  const uint8_t expect[32] = {
    0xBB, 0x00, 0x0D, 0xDD, 0x92, 0xA0, 0xA2, 0xA3, 0x46, 0xF0, 0xB5, 0x31, 0xF2, 0x78, 0xAF, 0x06,
    0xE3, 0x70, 0xF8, 0x69, 0x32, 0xCC, 0xAF, 0xCC, 0xC8, 0x92, 0xD6, 0x8D, 0x35, 0x0F, 0x80, 0xF8};
  uint8_t out[32];
  sha256(in, sizeof(in), NULL, 0, out);
  EXPECT_EQ(0, memcmp(out, expect, 32));
}

TEST(SpecVectors, AesEcb) {
  const uint8_t in[16] = {0xF3, 0x0F, 0x4E, 0x78, 0x6C, 0x59, 0xA7, 0xBB, 0xF3, 0x87, 0x3B, 0x5A, 0x49, 0xBA, 0x97, 0xEA};
  const uint8_t key[16] = {0xA0, 0xBA, 0xF0, 0xBB, 0x95, 0x1F, 0xF7, 0xB6, 0xCF, 0x5E, 0x3F, 0x45, 0x61, 0xC3, 0x32, 0x1D};
  const uint8_t expect[16] = {0xAC, 0x9A, 0x16, 0xF0, 0x95, 0x3A, 0x3F, 0x22, 0x3D, 0xD1, 0x0C, 0xF5, 0x36, 0xE0, 0x9E, 0x9C};
  uint8_t out[16], back[16];
  aes128EcbEncrypt(key, in, out, 16);
  EXPECT_EQ(0, memcmp(out, expect, 16));
  aes128EcbDecrypt(key, out, back, 16);
  EXPECT_EQ(0, memcmp(back, in, 16));
}

TEST(SpecVectors, Ecdh) {
  uint8_t s[32];
  ASSERT_TRUE(ecdhP256(BOB_PRIV, ALICE_PUB, s));
  EXPECT_EQ(0, memcmp(s, SHARED, 32));
  ASSERT_TRUE(ecdhP256(ALICE_PRIV, BOB_PUB, s));
  EXPECT_EQ(0, memcmp(s, SHARED, 32));
  uint8_t off_curve[64];
  memcpy(off_curve, ALICE_PUB, 64);
  off_curve[63] ^= 1;
  EXPECT_FALSE(ecdhP256(BOB_PRIV, off_curve, s));
}

TEST(SpecVectors, AesKeyFromEcdh) {
  uint8_t k[16];
  aesKeyFromSecret(SHARED, k);
  EXPECT_EQ(0, memcmp(k, SHARED_AES, 16));
}

TEST(SpecVectors, BloomFilter) {
  const uint8_t salt[2] = {0xC7, 0xC8};
  const uint8_t keys[2][16] = {
    {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
    {0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88}};
  const uint8_t battery[4] = {0x33, 0x40, 0x40, 0x40};
  uint8_t f[MAX_FILTER_LEN];

  ASSERT_EQ(4u, accountKeyFilter(keys, 1, salt, NULL, 0, f));
  EXPECT_EQ(V({0x02, 0x0C, 0x80, 0x2A}), std::vector<uint8_t>(f, f + 4));
  ASSERT_EQ(4u, accountKeyFilter(keys, 1, salt, battery, 4, f));
  EXPECT_EQ(V({0x01, 0x01, 0x46, 0x0A}), std::vector<uint8_t>(f, f + 4));
  ASSERT_EQ(5u, accountKeyFilter(keys, 2, salt, NULL, 0, f));
  EXPECT_EQ(V({0x84, 0x4A, 0x62, 0x20, 0x8B}), std::vector<uint8_t>(f, f + 5));
  ASSERT_EQ(5u, accountKeyFilter(keys, 2, salt, battery, 4, f));
  EXPECT_EQ(V({0x46, 0x15, 0x24, 0xD0, 0x08}), std::vector<uint8_t>(f, f + 5));
}

static const uint8_t NAME[26] = {
  0x53, 0x6F, 0x6D, 0x65, 0x6F, 0x6E, 0x65, 0x27, 0x73, 0x20, 0x47, 0x6F, 0x6F,
  0x67, 0x6C, 0x65, 0x20, 0x48, 0x65, 0x61, 0x64, 0x70, 0x68, 0x6F, 0x6E, 0x65};   // "Someone's Google Headphone"
static const uint8_t CTR_KEY[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
static const uint8_t CTR_NONCE[8] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
static const uint8_t PACKET[42] = {
  0x55, 0xEC, 0x5E, 0x60, 0x55, 0xAF, 0x6E, 0x92, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0xEE, 0x4A, 0x24, 0x83, 0x73, 0x80, 0x52, 0xE4, 0x4E, 0x9B, 0x2A, 0x14, 0x5E, 0x5D, 0xDF, 0xAA,
  0x44, 0xB9, 0xE5, 0x53, 0x6A, 0xF4, 0x38, 0xE1, 0xE5, 0xC6};

TEST(SpecVectors, HmacSha256) {
  const uint8_t expect[32] = {
    0x55, 0xEC, 0x5E, 0x60, 0x55, 0xAF, 0x6E, 0x92, 0x61, 0x8B, 0x7D, 0x87, 0x10, 0xD4, 0x41, 0x37,
    0x09, 0xAB, 0x5D, 0xA2, 0x7C, 0xA2, 0x6A, 0x66, 0xF5, 0x2E, 0x5A, 0xD4, 0xE8, 0x20, 0x90, 0x52};
  uint8_t out[32];
  hmacSha256(CTR_KEY, 16, &PACKET[8], 34, out);     // nonce || encrypted data
  EXPECT_EQ(0, memcmp(out, expect, 32));
}

TEST(SpecVectors, AdditionalDataEncodeDecode) {
  uint8_t pkt[42], name[26];
  additionalDataEncode(CTR_KEY, CTR_NONCE, NAME, sizeof(NAME), pkt);
  EXPECT_EQ(0, memcmp(pkt, PACKET, 42));        // covers the AES-CTR vector too
  ASSERT_TRUE(additionalDataDecode(CTR_KEY, PACKET, 42, name));
  EXPECT_EQ(0, memcmp(name, NAME, 26));
  uint8_t bad[42];
  memcpy(bad, PACKET, 42);
  bad[41] ^= 1;
  EXPECT_FALSE(additionalDataDecode(CTR_KEY, bad, 42, name));
}

// ================================================================ FHN EID vectors
// From gen_vectors.py (independent Python secp160r1 + cryptography; the EID math
// is GoogleFindMyTools' eid_generator.py, which decrypts real trackers' reports).

static const uint8_t EIK_A[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
static const uint8_t EIK_B[32] = {0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
                                  0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c};

struct EidVector {
  const uint8_t* eik;
  uint32_t counter;
  uint8_t eid[20];
  uint8_t hash_xor;
};

static const EidVector EID_VECTORS[] = {
  {EIK_A, 0u, {0xe6, 0xce, 0xc9, 0xca, 0x55, 0x05, 0xf8, 0x6e, 0x82, 0x78, 0x1b, 0xcb, 0xe7, 0x59, 0x84, 0xac, 0xb3, 0xce, 0x5e, 0x03}, 0x96},
  {EIK_A, 1023u, {0xe6, 0xce, 0xc9, 0xca, 0x55, 0x05, 0xf8, 0x6e, 0x82, 0x78, 0x1b, 0xcb, 0xe7, 0x59, 0x84, 0xac, 0xb3, 0xce, 0x5e, 0x03}, 0x96},
  {EIK_A, 1024u, {0x3a, 0x19, 0xac, 0x7d, 0xb9, 0xa3, 0xa9, 0x14, 0x0c, 0x0f, 0xac, 0xea, 0xe2, 0x10, 0xec, 0x57, 0xa1, 0x27, 0xfb, 0x31}, 0x70},
  {EIK_A, 10000000u, {0x7a, 0x3a, 0xeb, 0x38, 0x20, 0xe7, 0xfa, 0x04, 0x8d, 0xc4, 0xec, 0xb6, 0x31, 0x42, 0x9d, 0xa6, 0xde, 0xf4, 0x80, 0x60}, 0xe7},
  {EIK_A, 4294966272u, {0xd0, 0x87, 0x5f, 0xc3, 0x4c, 0xe1, 0xd9, 0x9b, 0xaf, 0x8e, 0x3d, 0x4a, 0xe5, 0x6c, 0x04, 0x36, 0x41, 0xa8, 0xc6, 0x67}, 0x42},
  {EIK_B, 0u, {0x4f, 0xe5, 0xbf, 0x5a, 0xe4, 0xa3, 0x43, 0x6e, 0xb8, 0x3d, 0xf0, 0x49, 0x5d, 0x66, 0x08, 0xd8, 0x20, 0x3e, 0x38, 0xd3}, 0x9a},
  {EIK_B, 1023u, {0x4f, 0xe5, 0xbf, 0x5a, 0xe4, 0xa3, 0x43, 0x6e, 0xb8, 0x3d, 0xf0, 0x49, 0x5d, 0x66, 0x08, 0xd8, 0x20, 0x3e, 0x38, 0xd3}, 0x9a},
  {EIK_B, 1024u, {0xcb, 0x08, 0xb0, 0x25, 0xee, 0xa9, 0x71, 0x59, 0x1a, 0xbf, 0x83, 0x64, 0xef, 0x87, 0x21, 0x09, 0x23, 0x9c, 0xd3, 0x57}, 0x6b},
  {EIK_B, 10000000u, {0x34, 0x8a, 0x1d, 0xd5, 0xe4, 0x33, 0x57, 0x43, 0x44, 0xf9, 0x2d, 0x5b, 0xc1, 0x23, 0x1f, 0x21, 0xb1, 0xff, 0x17, 0xb1}, 0xd3},
  {EIK_B, 4294966272u, {0x64, 0xae, 0x66, 0x93, 0xc8, 0x6f, 0x46, 0xc2, 0x2c, 0x9e, 0xbc, 0x30, 0x4f, 0x8c, 0x8b, 0x63, 0xca, 0x63, 0x6e, 0x9b}, 0x76},
};

TEST(FindHubCrypto, EidMatchesReference) {
  for (const auto& v : EID_VECTORS) {
    uint8_t eid[20], hx = 0;
    ASSERT_TRUE(computeEid(v.eik, v.counter, eid, &hx)) << v.counter;
    EXPECT_EQ(0, memcmp(eid, v.eid, 20)) << "counter " << v.counter;
    EXPECT_EQ(v.hash_xor, hx) << "counter " << v.counter;
  }
}

TEST(FindHubCrypto, DerivedKeys) {
  const uint8_t ring[8] = {0x57, 0x28, 0x70, 0x52, 0x14, 0x32, 0x61, 0x74};
  const uint8_t recovery[8] = {0x8b, 0x44, 0xd9, 0x6f, 0x21, 0x43, 0x04, 0xbc};
  const uint8_t utp[8] = {0x94, 0x4c, 0x53, 0x38, 0x76, 0xf9, 0xde, 0x37};
  uint8_t k[8];
  deriveKey(EIK_A, KEY_RING, k);     EXPECT_EQ(0, memcmp(k, ring, 8));
  deriveKey(EIK_A, KEY_RECOVERY, k); EXPECT_EQ(0, memcmp(k, recovery, 8));
  deriveKey(EIK_A, KEY_UTP, k);      EXPECT_EQ(0, memcmp(k, utp, 8));
}

TEST(FindHubCrypto, AuthSegment) {
  const uint8_t nonce[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  uint8_t rk[8];
  deriveKey(EIK_A, KEY_RING, rk);
  const uint8_t req_add[4] = {0xff, 0x00, 0x64, 0x00};
  const uint8_t req_expect[8] = {0xa3, 0x20, 0x22, 0xf3, 0x6f, 0x3b, 0x55, 0x68};
  uint8_t out[8];
  authSegment(rk, 8, nonce, 0x05, 12, req_add, 4, false, out);
  EXPECT_EQ(0, memcmp(out, req_expect, 8));

  const uint8_t rsp_add[4] = {0x00, 0xff, 0x00, 0x64};
  const uint8_t rsp_expect[8] = {0x39, 0xc4, 0x59, 0x9b, 0xcb, 0x2f, 0xbe, 0x11};
  authSegment(rk, 8, nonce, 0x05, 12, rsp_add, 4, true, out);
  EXPECT_EQ(0, memcmp(out, rsp_expect, 8));
}

// ================================================================ fakes

struct FakePlatform : public FindHubPlatform {
  uint32_t clock_s = 3000;
  uint32_t now_ms = 1000;
  uint8_t next_random = 0x10;
  int ak_saves = 0, eik_saves = 0;
  bool ak_erased = false, eik_erased = false;
  AccountKeyData saved_keys{};
  uint8_t saved_eik[32]{};
  int ring_starts = 0, ring_stops = 0;
  bool ringing = false;
  std::vector<std::vector<uint8_t>> notes;
  BatteryLevel batt = BATTERY_NORMAL;

  void randomBytes(uint8_t* d, size_t n) override { for (size_t i = 0; i < n; i++) d[i] = next_random++; }
  uint32_t millis() override { return now_ms; }
  uint32_t beaconClock() override { return clock_s; }
  int8_t calibratedPower() override { return -10; }
  BatteryLevel batteryLevel() override { return batt; }
  bool saveAccountKeys(const AccountKeyData* d) override {
    ak_saves++; ak_erased = d == NULL;
    if (d) saved_keys = *d; else memset(&saved_keys, 0, sizeof(saved_keys));
    return true;
  }
  bool saveEik(const uint8_t* eik) override {
    eik_saves++; eik_erased = eik == NULL;
    if (eik) memcpy(saved_eik, eik, 32);
    return true;
  }
  void ringStart() override { ring_starts++; ringing = true; }
  void ringStop() override { ring_stops++; ringing = false; }
  void notify(uint8_t conn, const uint8_t* d, size_t n) override { notes.emplace_back(d, d + n); }
};

// Provider uses the spec's "Bob" as its anti-spoofing key, so a Seeker using
// "Alice" lands exactly on the spec's shared AES key.
static FastPairConfig cfgBob() {
  FastPairConfig c;
  c.model_id[0] = 0x4A; c.model_id[1] = 0x43; c.model_id[2] = 0x6B;
  memcpy(c.antispoof_priv, BOB_PRIV, 32);
  return c;
}

static const uint8_t LINK_ADDR[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0xC6};   // SoftDevice order (LSB first)
static const uint8_t AK1[16] = {0x04, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF};

// What a Fast Pair Seeker (Android) sends.
struct FpSeeker {
  FastPairProvider& fp;
  uint8_t conn;
  uint8_t k[16];
  uint8_t salt = 0x50;

  void rawRequest(uint8_t raw[16], const uint8_t addr_lsb[6], uint8_t type = 0x00, uint8_t flags = 0x00) {
    raw[0] = type; raw[1] = flags;
    for (int i = 0; i < 6; i++) raw[2 + i] = addr_lsb[5 - i];       // MSB first on the wire
    for (int i = 8; i < 16; i++) raw[i] = salt++;
  }
  uint8_t initial(const uint8_t addr_lsb[6], uint8_t rsp[16], size_t* rsp_len, uint8_t type = 0x00, uint8_t flags = 0x00) {
    memcpy(k, SHARED_AES, 16);
    uint8_t raw[16], w[80];
    rawRequest(raw, addr_lsb, type, flags);
    aes128EcbEncrypt(k, raw, w, 16);
    memcpy(&w[16], ALICE_PUB, 64);
    return fp.onKeyBasedPairing(conn, w, 80, rsp, rsp_len);
  }
  uint8_t subsequent(const uint8_t ak[16], const uint8_t addr_lsb[6], uint8_t rsp[16], size_t* rsp_len) {
    memcpy(k, ak, 16);
    uint8_t raw[16], w[16];
    rawRequest(raw, addr_lsb);
    aes128EcbEncrypt(k, raw, w, 16);
    return fp.onKeyBasedPairing(conn, w, 16, rsp, rsp_len);
  }
  uint8_t writeAccountKey(const uint8_t ak[16], bool encrypted = false) {
    uint8_t w[16];
    aes128EcbEncrypt(k, ak, w, 16);
    return fp.onAccountKey(conn, w, 16, encrypted);
  }
};

struct FpFixture {
  FakePlatform pf;
  FastPairProvider fp{pf, cfgBob()};
  FpSeeker s{fp, 1};
  FpFixture() {
    const uint8_t a[1][6] = {{0x11, 0x22, 0x33, 0x44, 0x55, 0xC6}};
    fp.onConnect(1, a, 1);
  }
};

// ================================================================ Fast Pair

TEST(FastPair, InitialPairingThenAccountKey) {
  FpFixture f;
  f.fp.setPairingMode(true);
  const uint8_t a[1][6] = {{0x11, 0x22, 0x33, 0x44, 0x55, 0xC6}};
  f.fp.onConnect(1, a, 1);
  uint8_t rsp[16]; size_t rl;
  ASSERT_EQ(FP_OK, f.s.initial(LINK_ADDR, rsp, &rl));
  ASSERT_EQ(16u, rl);
  uint8_t raw[16];
  aes128EcbDecrypt(SHARED_AES, rsp, raw, 16);
  EXPECT_EQ(0x01, raw[0]);
  EXPECT_EQ(V({0xC6, 0x55, 0x44, 0x33, 0x22, 0x11}), std::vector<uint8_t>(&raw[1], &raw[7]));

  ASSERT_EQ(FP_OK, f.s.writeAccountKey(AK1));
  EXPECT_EQ(1u, f.fp.keyCount());
  EXPECT_TRUE(f.fp.isOwnerKey(AK1));
  EXPECT_EQ(0, memcmp(f.pf.saved_keys.keys[0], AK1, 16));
  EXPECT_TRUE(f.fp.takeAccountKeyWritten());
  EXPECT_FALSE(f.fp.takeAccountKeyWritten());
  // K is single-use.
  EXPECT_EQ(FP_ERR_UNLIKELY, f.s.writeAccountKey(AK1));
}

TEST(FastPair, PublicKeyOnlyInPairingMode) {
  FpFixture f;
  uint8_t rsp[16]; size_t rl;
  EXPECT_EQ(FP_ERR_UNLIKELY, f.s.initial(LINK_ADDR, rsp, &rl));
  EXPECT_EQ(0, f.fp.failures());            // ignored, not counted (spec step 1.1)
}

TEST(FastPair, WrongAddressFailsAndLocksOutAfterTen) {
  FpFixture f;
  f.fp.setPairingMode(true);
  uint8_t rsp[16]; size_t rl;
  const uint8_t other[6] = {1, 2, 3, 4, 5, 0xC0};
  for (int i = 0; i < 10; i++) EXPECT_EQ(FP_ERR_UNLIKELY, f.s.initial(other, rsp, &rl));
  EXPECT_EQ(10, f.fp.failures());
  EXPECT_EQ(FP_ERR_UNLIKELY, f.s.initial(LINK_ADDR, rsp, &rl));    // locked out
  f.pf.now_ms += 5 * 60 * 1000;
  f.fp.loop();
  EXPECT_EQ(FP_OK, f.s.initial(LINK_ADDR, rsp, &rl));
  EXPECT_EQ(0, f.fp.failures());
}

TEST(FastPair, ReplayedRequestRejected) {
  FpFixture f;
  f.fp.setPairingMode(true);
  uint8_t raw[16], w[80], rsp[16]; size_t rl;
  f.s.rawRequest(raw, LINK_ADDR);
  aes128EcbEncrypt(SHARED_AES, raw, w, 16);
  memcpy(&w[16], ALICE_PUB, 64);
  ASSERT_EQ(FP_OK, f.fp.onKeyBasedPairing(1, w, 80, rsp, &rl));
  f.fp.onDisconnect(1);
  const uint8_t a[1][6] = {{0x11, 0x22, 0x33, 0x44, 0x55, 0xC6}};
  f.fp.onConnect(1, a, 1);
  EXPECT_EQ(FP_ERR_UNLIKELY, f.fp.onKeyBasedPairing(1, w, 80, rsp, &rl));
}

TEST(FastPair, AccountKeyNeedsFreshKeyBasedPairing) {
  FpFixture f;
  f.fp.setPairingMode(true);
  uint8_t rsp[16]; size_t rl;
  memcpy(f.s.k, SHARED_AES, 16);
  EXPECT_EQ(FP_ERR_UNLIKELY, f.s.writeAccountKey(AK1));          // no KBP yet
  ASSERT_EQ(FP_OK, f.s.initial(LINK_ADDR, rsp, &rl));
  f.pf.now_ms += 10001;
  f.fp.loop();
  EXPECT_EQ(FP_ERR_UNLIKELY, f.s.writeAccountKey(AK1));          // K expired after 10 s
  ASSERT_EQ(FP_OK, f.s.initial(LINK_ADDR, rsp, &rl));
  EXPECT_EQ(FP_ERR_UNLIKELY, f.s.writeAccountKey(AK1, true));    // encrypted link: needs the passkey flow
  ASSERT_EQ(FP_OK, f.s.initial(LINK_ADDR, rsp, &rl));
  uint8_t not_ak[16];
  memcpy(not_ak, AK1, 16);
  not_ak[0] = 0x05;
  EXPECT_EQ(FP_ERR_UNLIKELY, f.s.writeAccountKey(not_ak));       // must start with 0x04
  EXPECT_EQ(0u, f.fp.keyCount());
}

TEST(FastPair, PasskeyFlowWithBonding) {
  FpFixture f;
  f.fp.setPairingMode(true);
  uint8_t rsp[16]; size_t rl;
  ASSERT_EQ(FP_OK, f.s.initial(LINK_ADDR, rsp, &rl));
  f.fp.onNumericComparison(1, 123456);
  uint8_t raw[16] = {0x02, 0x01, 0xE2, 0x40}, w[16];               // 123456 = 0x01E240
  for (int i = 4; i < 16; i++) raw[i] = (uint8_t)i;
  aes128EcbEncrypt(SHARED_AES, raw, w, 16);
  ASSERT_EQ(FP_OK, f.fp.onPasskey(1, w, 16, rsp, &rl));
  bool ok = false;
  ASSERT_TRUE(f.fp.comparisonResult(1, &ok));
  EXPECT_TRUE(ok);
  uint8_t back[16];
  aes128EcbDecrypt(SHARED_AES, rsp, back, 16);
  EXPECT_EQ(V({0x03, 0x01, 0xE2, 0x40}), std::vector<uint8_t>(back, back + 4));
  EXPECT_NE(0, memcmp(&back[4], &raw[4], 12));                       // fresh salt
  f.fp.onPairingComplete(1, true);
  EXPECT_EQ(FP_OK, f.s.writeAccountKey(AK1, true));
  EXPECT_EQ(1u, f.fp.keyCount());
}

TEST(FastPair, PasskeyMismatch) {
  FpFixture f;
  f.fp.setPairingMode(true);
  uint8_t rsp[16]; size_t rl;
  ASSERT_EQ(FP_OK, f.s.initial(LINK_ADDR, rsp, &rl));
  f.fp.onNumericComparison(1, 123456);
  uint8_t raw[16] = {0x02, 0x00, 0x00, 0x01}, w[16];
  aes128EcbEncrypt(SHARED_AES, raw, w, 16);
  ASSERT_EQ(FP_OK, f.fp.onPasskey(1, w, 16, rsp, &rl));
  bool ok = true;
  ASSERT_TRUE(f.fp.comparisonResult(1, &ok));
  EXPECT_FALSE(ok);
  f.fp.onPairingComplete(1, false);
  EXPECT_EQ(FP_ERR_UNLIKELY, f.s.writeAccountKey(AK1, true));
}

TEST(FastPair, SubsequentPairingAndLruKeepsOwner) {
  FpFixture f;
  AccountKeyData d{};
  d.count = 0; d.owner = 0xFF;
  f.fp.load(&d);
  f.fp.setPairingMode(true);
  uint8_t rsp[16]; size_t rl;
  // Six keys through the full initial flow: the owner (first) survives eviction.
  for (int i = 0; i < 6; i++) {
    uint8_t ak[16];
    memcpy(ak, AK1, 16);
    ak[15] = (uint8_t)i;
    ASSERT_EQ(FP_OK, f.s.initial(LINK_ADDR, rsp, &rl)) << i;
    ASSERT_EQ(FP_OK, f.s.writeAccountKey(ak)) << i;
  }
  EXPECT_EQ(5u, f.fp.keyCount());
  uint8_t owner[16];
  memcpy(owner, AK1, 16);
  owner[15] = 0;
  EXPECT_TRUE(f.fp.isOwnerKey(owner));
  bool found_owner = false, found_1 = false;
  for (size_t i = 0; i < f.fp.keyCount(); i++) {
    if (f.fp.key(i)[15] == 0) found_owner = true;
    if (f.fp.key(i)[15] == 1) found_1 = true;
  }
  EXPECT_TRUE(found_owner);
  EXPECT_FALSE(found_1);           // the least recently used non-owner key went

  // Subsequent pairing with the owner key (no public key, not in pairing mode).
  f.fp.setPairingMode(false);
  ASSERT_EQ(FP_OK, f.s.subsequent(owner, LINK_ADDR, rsp, &rl));
  EXPECT_EQ(0, memcmp(f.fp.key(0), owner, 16));      // now most recently used
  EXPECT_TRUE(f.fp.isOwnerKey(owner));
}

TEST(FastPair, Advertisements) {
  FpFixture f;
  uint8_t adv[FP_ADV_MAX];
  size_t n = f.fp.discoverableAdvert(adv);
  EXPECT_EQ(V({0x02, 0x01, 0x06, 0x06, 0x16, 0x2C, 0xFE, 0x4A, 0x43, 0x6B, 0x02, 0x0A, 0xF6}),
            std::vector<uint8_t>(adv, adv + n));

  const uint8_t salt[2] = {0xC7, 0xC8};
  EXPECT_EQ(0u, f.fp.notDiscoverableAdvert(salt, adv));     // no account keys yet
  AccountKeyData d{};
  d.count = 1; d.owner = 0;
  const uint8_t k[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
  memcpy(d.keys[0], k, 16);
  f.fp.load(&d);
  n = f.fp.notDiscoverableAdvert(salt, adv);
  EXPECT_EQ(V({0x02, 0x01, 0x06, 0x0C, 0x16, 0x2C, 0xFE, 0x00, 0x42, 0x02, 0x0C, 0x80, 0x2A, 0x21, 0xC7, 0xC8,
               0x02, 0x0A, 0xF6}),
            std::vector<uint8_t>(adv, adv + n));
}

// The Nordic debug "NCS locator tag" key really is a P-256 private key whose
// ECDH works both ways (what a Seeker holding its public key does).
TEST(FastPair, NordicDebugKeyRoundTrip) {
  const uint8_t ncs_priv[32] = {
    0xAE, 0x27, 0xB5, 0xD0, 0x0E, 0xCE, 0x36, 0xAC, 0x1D, 0xEF, 0xB5, 0x66, 0x93, 0x11, 0xAC, 0x6E,
    0x53, 0xD4, 0x6C, 0xCB, 0x77, 0xF3, 0x8A, 0xA3, 0x0E, 0x07, 0x04, 0x27, 0xF7, 0x2D, 0x4F, 0xD6};
  uint8_t ncs_pub[64], s1[32], s2[32];
  ASSERT_EQ(1, uECC_compute_public_key(ncs_priv, ncs_pub, uECC_secp256r1()));
  ASSERT_TRUE(ecdhP256(ncs_priv, ALICE_PUB, s1));
  ASSERT_TRUE(ecdhP256(ALICE_PRIV, ncs_pub, s2));
  EXPECT_EQ(0, memcmp(s1, s2, 32));
}

// ================================================================ Beacon Actions

// What a Seeker (owner's phone) does: read nonce, then write an authenticated op.
struct Seeker {
  FindHubBeacon& b;
  uint8_t conn;
  uint8_t nonce[8];
  uint8_t rsp[MAX_NOTIFY_LEN];
  size_t rsp_len = 0;

  void readNonce() {
    uint8_t out[9];
    ASSERT_EQ(9u, b.onRead(conn, out));
    ASSERT_EQ(0x01, out[0]);
    memcpy(nonce, &out[1], 8);
  }
  uint8_t write(uint8_t id, const uint8_t* key, size_t key_len, const uint8_t* add, size_t add_len, bool hash_add = true) {
    std::vector<uint8_t> f(2 + 8 + add_len);
    f[0] = id; f[1] = (uint8_t)(8 + add_len);
    authSegment(key, key_len, nonce, id, f[1], add, hash_add ? add_len : 0, false, &f[2]);
    if (add_len) memcpy(&f[10], add, add_len);
    return b.onWrite(conn, f.data(), f.size(), rsp, &rsp_len);
  }
};

static const uint8_t AK2[16] = {0x04, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF};

// AK1 = owner, AK2 = a second account; EIK_A provisioned.
struct BeaconFixture {
  FakePlatform pf;
  FastPairProvider fp{pf, cfgBob()};
  FindHubBeacon b{pf, fp};
  BeaconFixture(bool provisioned = true) {
    AccountKeyData d{};
    d.count = 2; d.owner = 1;
    memcpy(d.keys[0], AK2, 16);
    memcpy(d.keys[1], AK1, 16);
    fp.load(&d);
    b.load(provisioned ? EIK_A : NULL);
  }
};

TEST(FindHubBeacon, SilentUntilProvisioned) {
  BeaconFixture f(false);
  uint8_t adv[ADV_FRAME_LEN];
  EXPECT_EQ(0u, f.b.buildAdvert(adv));
  f.b.load(EIK_A);
  EXPECT_EQ(29u, f.b.buildAdvert(adv));
}

TEST(FindHubBeacon, AdvertFrameLayoutAndRotation) {
  BeaconFixture f;
  uint8_t adv[ADV_FRAME_LEN];

  // Middle of window 9765 (counter 10000000 lies in it): no rotation delay effect.
  f.pf.clock_s = 10000000u;
  ASSERT_EQ(29u, f.b.buildAdvert(adv));
  const uint8_t hdr[] = {0x02, 0x01, 0x06, 0x19, 0x16, 0xAA, 0xFE, 0x40};
  EXPECT_EQ(0, memcmp(adv, hdr, sizeof(hdr)));
  EXPECT_EQ(0, memcmp(&adv[8], EID_VECTORS[3].eid, 20));
  EXPECT_EQ((uint8_t)(0x02 ^ EID_VECTORS[3].hash_xor), adv[28]);   // battery normal = 01 in bits 1-2

  // Just past a window boundary, the previous EID is kept for 1..204 s.
  f.pf.clock_s = 1024;
  ASSERT_EQ(29u, f.b.buildAdvert(adv));
  EXPECT_EQ(0, memcmp(&adv[8], EID_VECTORS[0].eid, 20));
  uint32_t w0 = f.b.advertWindow();
  f.pf.clock_s = 1024 + 205;
  ASSERT_EQ(29u, f.b.buildAdvert(adv));
  EXPECT_EQ(0, memcmp(&adv[8], EID_VECTORS[2].eid, 20));
  EXPECT_NE(w0, f.b.advertWindow());
}

TEST(FindHubBeacon, BeaconParamsAnyAccountKey) {
  BeaconFixture f;
  f.pf.clock_s = 0x01020304;
  Seeker s{f.b, 0};
  for (const uint8_t* ak : {AK1, AK2}) {
    s.readNonce();
    ASSERT_EQ(ATT_OK, s.write(0x00, ak, 16, NULL, 0));
    ASSERT_EQ(26u, s.rsp_len);
    uint8_t plain[16];
    aes128EcbDecrypt(ak, &s.rsp[10], plain, 16);        // encrypted with the key that authenticated
    EXPECT_EQ((uint8_t)-10, plain[0]);
    EXPECT_EQ(V({0x01, 0x02, 0x03, 0x04}), std::vector<uint8_t>(&plain[1], &plain[5]));
    EXPECT_EQ(0x00, plain[5]);   // secp160r1
    EXPECT_EQ(0x01, plain[6]);   // one ringing component
    uint8_t expect[8];
    authSegment(ak, 16, s.nonce, 0x00, 24, &s.rsp[10], 16, true, expect);
    EXPECT_EQ(0, memcmp(&s.rsp[2], expect, 8));
    EXPECT_TRUE(f.b.takeClockRead());
    EXPECT_TRUE(f.b.authenticated(0));
  }
  s.readNonce();
  uint8_t bad[16] = {0};
  EXPECT_EQ(ATT_UNAUTHENTICATED, s.write(0x00, bad, 16, NULL, 0));
}

TEST(FindHubBeacon, ProvisioningStateOwnerFlag) {
  BeaconFixture f;
  f.pf.clock_s = 5000;
  Seeker s{f.b, 0};
  s.readNonce();
  ASSERT_EQ(ATT_OK, s.write(0x01, AK1, 16, NULL, 0));
  ASSERT_EQ(31u, s.rsp_len);
  EXPECT_EQ(0x03, s.rsp[10]);          // EIK set + owner
  uint8_t eid[20];
  computeEid(EIK_A, 5000, eid, NULL);
  EXPECT_EQ(0, memcmp(&s.rsp[11], eid, 20));
  s.readNonce();
  ASSERT_EQ(ATT_OK, s.write(0x01, AK2, 16, NULL, 0));
  EXPECT_EQ(0x01, s.rsp[10]);          // not the owner

  BeaconFixture u(false);
  Seeker su{u.b, 0};
  su.readNonce();
  ASSERT_EQ(ATT_OK, su.write(0x01, AK1, 16, NULL, 0));
  ASSERT_EQ(11u, su.rsp_len);
  EXPECT_EQ(0x02, su.rsp[10]);         // owner, no EIK
}

TEST(FindHubBeacon, FirstProvisioningOwnerOnly) {
  BeaconFixture f(false);
  Seeker s{f.b, 0};
  uint8_t enc[32];

  s.readNonce();
  aes128EcbEncrypt(AK2, EIK_B, enc, 32);
  EXPECT_EQ(ATT_UNAUTHENTICATED, s.write(0x02, AK2, 16, enc, 32));     // not the owner
  EXPECT_FALSE(f.b.isProvisioned());

  s.readNonce();
  aes128EcbEncrypt(AK1, EIK_B, enc, 32);
  ASSERT_EQ(ATT_OK, s.write(0x02, AK1, 16, enc, 32));
  EXPECT_TRUE(f.b.isProvisioned());
  EXPECT_EQ(0, memcmp(f.pf.saved_eik, EIK_B, 32));
  EXPECT_TRUE(f.b.takeProvisioningChanged());
  uint8_t expect[8];
  authSegment(AK1, 16, s.nonce, 0x02, 8, NULL, 0, true, expect);
  ASSERT_EQ(10u, s.rsp_len);
  EXPECT_EQ(0, memcmp(&s.rsp[2], expect, 8));

  s.readNonce();
  EXPECT_EQ(ATT_UNAUTHENTICATED, s.write(0x02, AK1, 16, enc, 32));     // provisioned: needs the hash
}

TEST(FindHubBeacon, RekeyAndClearIsFactoryReset) {
  BeaconFixture f;
  Seeker s{f.b, 0};

  s.readNonce();
  uint8_t add[40];
  aes128EcbEncrypt(AK1, EIK_B, add, 32);
  sha256Trunc8(EIK_A, 32, s.nonce, 8, &add[32]);
  ASSERT_EQ(ATT_OK, s.write(0x02, AK1, 16, add, 40));
  EXPECT_EQ(0, memcmp(f.pf.saved_eik, EIK_B, 32));

  s.readNonce();
  uint8_t h[8];
  sha256Trunc8(EIK_A, 32, s.nonce, 8, h);              // old EIK no longer accepted
  EXPECT_EQ(ATT_UNAUTHENTICATED, s.write(0x03, AK1, 16, h, 8));
  s.readNonce();
  sha256Trunc8(EIK_B, 32, s.nonce, 8, h);
  EXPECT_EQ(ATT_UNAUTHENTICATED, s.write(0x03, AK2, 16, h, 8));   // owner only
  s.readNonce();
  sha256Trunc8(EIK_B, 32, s.nonce, 8, h);
  ASSERT_EQ(ATT_OK, s.write(0x03, AK1, 16, h, 8));
  uint8_t expect[8];
  authSegment(AK1, 16, s.nonce, 0x03, 8, NULL, 0, true, expect);
  EXPECT_EQ(0, memcmp(&s.rsp[2], expect, 8));
  EXPECT_TRUE(f.pf.eik_erased);
  EXPECT_TRUE(f.pf.ak_erased);
  EXPECT_FALSE(f.b.isProvisioned());
  EXPECT_EQ(0u, f.fp.keyCount());
}

TEST(FindHubBeacon, ReadEikNeedsRecoveryKeyAndConsent) {
  BeaconFixture f;
  Seeker s{f.b, 0};
  uint8_t rk[8], ring[8];
  deriveKey(EIK_A, KEY_RECOVERY, rk);
  deriveKey(EIK_A, KEY_RING, ring);

  s.readNonce();
  EXPECT_EQ(ATT_NO_USER_CONSENT, s.write(0x04, rk, 8, NULL, 0));
  s.readNonce();
  f.b.setUserConsent(true);
  EXPECT_EQ(ATT_UNAUTHENTICATED, s.write(0x04, ring, 8, NULL, 0));   // auth first, consent second
  s.readNonce();
  ASSERT_EQ(ATT_OK, s.write(0x04, rk, 8, NULL, 0));
  ASSERT_EQ(42u, s.rsp_len);
  EXPECT_EQ(0x04, s.rsp[0]);
  EXPECT_EQ(40, s.rsp[1]);
  uint8_t eik[32];
  aes128EcbDecrypt(AK1, &s.rsp[10], eik, 32);               // with the owner key
  EXPECT_EQ(0, memcmp(eik, EIK_A, 32));
  uint8_t expect[8];
  authSegment(rk, 8, s.nonce, 0x04, 40, &s.rsp[10], 32, true, expect);
  EXPECT_EQ(0, memcmp(&s.rsp[2], expect, 8));
}

TEST(FindHubBeacon, RingFlowLikeAPhone) {
  BeaconFixture f;
  uint8_t rk[8];
  deriveKey(EIK_A, KEY_RING, rk);

  Seeker s{f.b, 2};
  s.readNonce();
  const uint8_t ring[4] = {0xFF, 0x00, 120, 0x03};    // all, 12.0 s, high
  ASSERT_EQ(ATT_OK, s.write(0x05, rk, 8, ring, 4));
  EXPECT_TRUE(f.pf.ringing);
  ASSERT_EQ(1u, f.pf.notes.size());

  // Notification: 05 | 0C | auth(ring key, request nonce, ..., 0x01) | started, ff, 120 ds
  const auto& n = f.pf.notes[0];
  ASSERT_EQ(14u, n.size());
  EXPECT_EQ(0x05, n[0]);
  EXPECT_EQ(12, n[1]);
  const uint8_t add[4] = {0x00, 0xFF, 0x00, 120};
  EXPECT_EQ(0, memcmp(&n[10], add, 4));
  uint8_t expect[8];
  authSegment(rk, 8, s.nonce, 0x05, 12, add, 4, true, expect);
  EXPECT_EQ(0, memcmp(&n[2], expect, 8));

  f.pf.now_ms += 2000;
  s.readNonce();
  ASSERT_EQ(ATT_OK, s.write(0x06, rk, 8, NULL, 0));
  ASSERT_EQ(13u, s.rsp_len);
  EXPECT_EQ(0xFF, s.rsp[10]);
  EXPECT_EQ(100, (s.rsp[11] << 8) | s.rsp[12]);       // 10.0 s left

  f.pf.now_ms += 10001;
  f.b.loop();
  EXPECT_FALSE(f.pf.ringing);
  ASSERT_EQ(2u, f.pf.notes.size());
  EXPECT_EQ(RING_STOPPED_TIMEOUT, f.pf.notes[1][10]);
}

TEST(FindHubBeacon, NonceIsSingleUseAndAuthEnforced) {
  BeaconFixture f;
  uint8_t rk[8], wrong[8] = {0};
  deriveKey(EIK_A, KEY_RING, rk);
  const uint8_t ring[4] = {0xFF, 0x00, 50, 0x00};

  Seeker s{f.b, 1};
  EXPECT_EQ(ATT_UNAUTHENTICATED, s.write(0x05, rk, 8, ring, 4));   // never read a nonce
  s.readNonce();
  EXPECT_EQ(ATT_UNAUTHENTICATED, s.write(0x05, wrong, 8, ring, 4));
  EXPECT_EQ(ATT_UNAUTHENTICATED, s.write(0x05, rk, 8, ring, 4));    // nonce burnt by the failure
  s.readNonce();
  EXPECT_EQ(ATT_OK, s.write(0x05, rk, 8, ring, 4));
  EXPECT_EQ(ATT_UNAUTHENTICATED, s.write(0x05, rk, 8, ring, 4));    // replay

  Seeker other{f.b, 3};
  other.readNonce();
  memcpy(s.nonce, other.nonce, 8);
  EXPECT_EQ(ATT_UNAUTHENTICATED, s.write(0x05, rk, 8, ring, 4));

  s.readNonce();
  const uint8_t too_long[4] = {0xFF, 0x17, 0x71, 0x00};             // 6001 ds > 10 min
  EXPECT_EQ(ATT_INVALID_VALUE, s.write(0x05, rk, 8, too_long, 4));
  s.readNonce();
  const uint8_t two_comps[4] = {0x03, 0x00, 10, 0x00};               // left + right on a 1-component device
  EXPECT_EQ(ATT_UNAUTHENTICATED, s.write(0x05, rk, 8, two_comps, 4));
}

TEST(FindHubBeacon, StopAndButton) {
  BeaconFixture f;
  uint8_t rk[8];
  deriveKey(EIK_A, KEY_RING, rk);
  Seeker s{f.b, 0};

  s.readNonce();
  const uint8_t ring[4] = {0x01, 0x00, 100, 0x00};    // "right" = our one component
  ASSERT_EQ(ATT_OK, s.write(0x05, rk, 8, ring, 4));
  f.b.buttonPressed();
  EXPECT_FALSE(f.pf.ringing);
  EXPECT_EQ(RING_STOPPED_BUTTON, f.pf.notes.back()[10]);

  s.readNonce();
  const uint8_t stop[4] = {0x00, 0x00, 0x00, 0x00};
  ASSERT_EQ(ATT_OK, s.write(0x05, rk, 8, stop, 4));   // already silent: still answers "stopped (GATT)"
  EXPECT_EQ(RING_STOPPED_GATT, f.pf.notes.back()[10]);

  s.readNonce();
  ASSERT_EQ(ATT_OK, s.write(0x05, rk, 8, ring, 4));
  size_t notes = f.pf.notes.size();
  f.b.onDisconnect(0);                                 // keeps ringing (spec), nobody to notify
  f.pf.now_ms += 20000;
  f.b.loop();
  EXPECT_FALSE(f.pf.ringing);
  EXPECT_EQ(notes, f.pf.notes.size());
}

TEST(FindHubBeacon, UtpModeSkipsRingAuthOnlyWhenAsked) {
  BeaconFixture f;
  uint8_t uk[8], junk[8] = {9, 9, 9, 9, 9, 9, 9, 9};
  deriveKey(EIK_A, KEY_UTP, uk);
  Seeker s{f.b, 0};

  s.readNonce();
  const uint8_t flags = 0x01;
  ASSERT_EQ(ATT_OK, s.write(0x07, uk, 8, &flags, 1));
  EXPECT_TRUE(f.b.utpMode());
  uint8_t adv[ADV_FRAME_LEN];
  ASSERT_EQ(29u, f.b.buildAdvert(adv));
  EXPECT_EQ(0x41, adv[7]);

  s.readNonce();
  const uint8_t ring[4] = {0xFF, 0x00, 10, 0x00};
  EXPECT_EQ(ATT_OK, s.write(0x05, junk, 8, ring, 4));   // unauthenticated ring allowed in UTP+skip

  s.readNonce();
  uint8_t eik_hash[8];
  sha256Trunc8(EIK_A, 32, s.nonce, 8, eik_hash);
  ASSERT_EQ(ATT_OK, s.write(0x08, uk, 8, eik_hash, 8));
  EXPECT_FALSE(f.b.utpMode());
  s.readNonce();
  EXPECT_EQ(ATT_UNAUTHENTICATED, s.write(0x05, junk, 8, ring, 4));
}

TEST(FindHubBeacon, MalformedFrames) {
  BeaconFixture f;
  uint8_t rsp[MAX_NOTIFY_LEN];
  size_t rsp_len;
  uint8_t out[9];
  f.b.onRead(0, out);
  const uint8_t short_frame[1] = {0x05};
  EXPECT_EQ(ATT_INVALID_VALUE, f.b.onWrite(0, short_frame, 1, rsp, &rsp_len));
  f.b.onRead(0, out);
  const uint8_t len_mismatch[5] = {0x05, 12, 0, 0, 0};
  EXPECT_EQ(ATT_INVALID_VALUE, f.b.onWrite(0, len_mismatch, 5, rsp, &rsp_len));
  f.b.onRead(0, out);
  uint8_t unknown[10] = {0x42, 8};
  EXPECT_EQ(ATT_INVALID_VALUE, f.b.onWrite(0, unknown, 10, rsp, &rsp_len));
  EXPECT_EQ(ATT_INVALID_VALUE, f.b.onWrite(MAX_CONN, unknown, 10, rsp, &rsp_len));
  EXPECT_FALSE(f.b.authenticated(0));
}

// ================================================================ FindHub policy

struct HubFixture {
  FakePlatform pf;
  FindHub hub{pf, cfgBob()};
  FpSeeker fs{hub.fastPair(), 0};
  Seeker bs{hub.beacon(), 0};

  void connectOnTagAddress() {
    uint8_t a[MAX_LINK_ADDRS][ADDR_LEN];
    size_t n = hub.tagAddresses(a, MAX_LINK_ADDRS);
    hub.fastPair().onConnect(0, a, n);
  }
  // What Android does: Fast Pair, then FHN provisioning over Beacon Actions.
  void pairAndProvision(const uint8_t* eik) {
    AdvFrame f;
    ASSERT_TRUE(hub.fastPairFrame(f));
    connectOnTagAddress();
    uint8_t rsp[16]; size_t rl;
    ASSERT_EQ(FP_OK, fs.initial(f.addr, rsp, &rl));
    ASSERT_EQ(FP_OK, fs.writeAccountKey(AK1));
    hub.loop();
    bs.readNonce();
    ASSERT_EQ(ATT_OK, bs.write(0x00, AK1, 16, NULL, 0));       // beacon parameters (clock)
    bs.readNonce();
    ASSERT_EQ(ATT_OK, bs.write(0x01, AK1, 16, NULL, 0));       // provisioning state
    bs.readNonce();
    uint8_t enc[32];
    aes128EcbEncrypt(AK1, eik, enc, 32);
    ASSERT_EQ(ATT_OK, bs.write(0x02, AK1, 16, enc, 32));
    hub.loop();
  }
};

TEST(FindHubPolicy, FirstBootPairsAndProvisions) {
  HubFixture h;
  h.hub.begin(NULL, NULL, true);
  EXPECT_EQ(FindHub::ST_PAIRING, h.hub.state());
  AdvFrame f;
  ASSERT_TRUE(h.hub.fastPairFrame(f));
  EXPECT_EQ(0x4A, f.data[7]);                        // discoverable: model ID
  EXPECT_EQ(160, f.interval);
  EXPECT_TRUE(f.connectable);
  EXPECT_EQ(0xC0, f.addr[5] & 0xC0);                 // random static
  AdvFrame fhn;
  EXPECT_FALSE(h.hub.fhnFrame(fhn, 0));

  // Account key written: not discoverable any more, waiting for the EIK, same address.
  h.connectOnTagAddress();
  uint8_t rsp[16]; size_t rl;
  ASSERT_EQ(FP_OK, h.fs.initial(f.addr, rsp, &rl));
  ASSERT_EQ(FP_OK, h.fs.writeAccountKey(AK1));
  h.hub.loop();
  EXPECT_EQ(FindHub::ST_AWAIT_EIK, h.hub.state());
  AdvFrame nd;
  ASSERT_TRUE(h.hub.fastPairFrame(nd));
  EXPECT_EQ(0x00, nd.data[7]);                       // account data, version 0
  EXPECT_EQ(400, nd.interval);
  EXPECT_EQ(0, memcmp(nd.addr, f.addr, 6));

  h.bs.readNonce();
  uint8_t enc[32];
  aes128EcbEncrypt(AK1, EIK_A, enc, 32);
  ASSERT_EQ(ATT_OK, h.bs.write(0x02, AK1, 16, enc, 32));
  h.hub.loop();
  EXPECT_EQ(FindHub::ST_PROVISIONED, h.hub.state());
  EXPECT_FALSE(h.hub.fastPairFrame(f));              // no Fast Pair frames once provisioned
  ASSERT_TRUE(h.hub.fhnFrame(fhn, 0));
  EXPECT_TRUE(fhn.connectable);
  ASSERT_TRUE(h.hub.fhnFrame(fhn, 1));
  EXPECT_FALSE(fhn.connectable);                     // a link is up
}

TEST(FindHubPolicy, NoEikWithinFiveMinutesWipesKeys) {
  HubFixture h;
  h.hub.begin(NULL, NULL, true);
  AdvFrame f;
  ASSERT_TRUE(h.hub.fastPairFrame(f));
  h.connectOnTagAddress();
  uint8_t rsp[16]; size_t rl;
  ASSERT_EQ(FP_OK, h.fs.initial(f.addr, rsp, &rl));
  ASSERT_EQ(FP_OK, h.fs.writeAccountKey(AK1));
  h.hub.loop();
  h.pf.now_ms += 5 * 60 * 1000;
  h.hub.loop();
  EXPECT_EQ(0u, h.hub.fastPair().keyCount());
  EXPECT_TRUE(h.pf.ak_erased);
  EXPECT_EQ(FindHub::ST_IDLE, h.hub.state());
}

TEST(FindHubPolicy, NotFirstBootStaysQuietUntilAsked) {
  HubFixture h;
  h.hub.begin(NULL, NULL, false);
  AdvFrame f;
  EXPECT_FALSE(h.hub.fastPairFrame(f));
  h.hub.requestPairing();
  EXPECT_TRUE(h.hub.fastPairFrame(f));
  h.pf.now_ms += PAIRING_MODE_MS;
  h.hub.loop();
  EXPECT_FALSE(h.hub.fastPairFrame(f));
}

TEST(FindHubPolicy, PairedButUnprovisionedAtBootIsReset) {
  HubFixture h;
  AccountKeyData d{};
  d.count = 1; d.owner = 0;
  memcpy(d.keys[0], AK1, 16);
  h.hub.begin(&d, NULL, false);
  EXPECT_EQ(0u, h.hub.fastPair().keyCount());
  EXPECT_TRUE(h.pf.ak_erased);
}

TEST(FindHubPolicy, RebootAdvertisesForClockSync) {
  HubFixture h;
  AccountKeyData d{};
  d.count = 1; d.owner = 0;
  memcpy(d.keys[0], AK1, 16);
  h.hub.begin(&d, EIK_A, false);
  EXPECT_TRUE(h.hub.clockSyncPending());
  AdvFrame f;
  ASSERT_TRUE(h.hub.fastPairFrame(f));
  EXPECT_EQ(0x00, f.data[7]);                        // not discoverable
  h.connectOnTagAddress();
  h.bs.readNonce();
  ASSERT_EQ(ATT_OK, h.bs.write(0x00, AK1, 16, NULL, 0));
  h.hub.loop();
  EXPECT_FALSE(h.hub.clockSyncPending());
  EXPECT_FALSE(h.hub.fastPairFrame(f));
}

TEST(FindHubPolicy, ProvisionedPairingRequestOnlyOpensConsent) {
  HubFixture h;
  AccountKeyData d{};
  d.count = 1; d.owner = 0;
  memcpy(d.keys[0], AK1, 16);
  h.hub.begin(&d, EIK_A, false);
  h.hub.requestPairing();
  h.hub.loop();
  EXPECT_FALSE(h.hub.pairingMode());
  EXPECT_TRUE(h.hub.consentOpen());
  uint8_t rk[8];
  deriveKey(EIK_A, KEY_RECOVERY, rk);
  h.bs.readNonce();
  EXPECT_EQ(ATT_OK, h.bs.write(0x04, rk, 8, NULL, 0));
  h.pf.now_ms += CONSENT_MS;
  h.hub.loop();
  h.bs.readNonce();
  EXPECT_EQ(ATT_NO_USER_CONSENT, h.bs.write(0x04, rk, 8, NULL, 0));
}

TEST(FindHubPolicy, AddressRotatesWithEidAndHoldsInUtp) {
  HubFixture h;
  h.hub.begin(NULL, NULL, true);
  h.pairAndProvision(EIK_A);
  ASSERT_EQ(FindHub::ST_PROVISIONED, h.hub.state());

  AdvFrame a, b;
  h.pf.clock_s = 4096 + 300;                         // well past the random delay
  ASSERT_TRUE(h.hub.fhnFrame(a, 0));
  h.pf.clock_s = 4096 + 400;
  ASSERT_TRUE(h.hub.fhnFrame(b, 0));
  EXPECT_EQ(0, memcmp(a.addr, b.addr, 6));           // same window, same address
  EXPECT_EQ(0, memcmp(&a.data[8], &b.data[8], 20));
  h.pf.clock_s = 5120 + 300;
  ASSERT_TRUE(h.hub.fhnFrame(b, 0));
  EXPECT_NE(0, memcmp(a.addr, b.addr, 6));           // new window: new EID and new address
  EXPECT_NE(0, memcmp(&a.data[8], &b.data[8], 20));

  // UTP on: the FHN address is held while the EID keeps rotating.
  uint8_t uk[8];
  deriveKey(EIK_A, KEY_UTP, uk);
  h.bs.readNonce();
  ASSERT_EQ(ATT_OK, h.bs.write(0x07, uk, 8, NULL, 0));
  AdvFrame u1, u2;
  ASSERT_TRUE(h.hub.fhnFrame(u1, 0));
  EXPECT_EQ(0x41, u1.data[7]);
  h.pf.clock_s = 6144 + 300;
  ASSERT_TRUE(h.hub.fhnFrame(u2, 0));
  EXPECT_EQ(0, memcmp(u1.addr, u2.addr, 6));
  EXPECT_NE(0, memcmp(&u1.data[8], &u2.data[8], 20));
  h.pf.clock_s = 6144 + 300 + UTP_ADDR_HOLD_S;
  ASSERT_TRUE(h.hub.fhnFrame(u2, 0));
  EXPECT_NE(0, memcmp(u1.addr, u2.addr, 6));         // once a day
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

#include <gtest/gtest.h>
#include <string.h>
#include <vector>

#include "helpers/findhub/FindHubBeacon.h"

using namespace findhub;

// Vectors from gen_vectors.py (independent Python secp160r1 + cryptography).
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

// ---------------------------------------------------------------- beacon

struct FakePlatform : public FindHubPlatform {
  uint32_t now_unix = 0;
  uint32_t now_ms = 1000;
  uint8_t next_random = 0x10;
  bool saved = false;
  bool saved_null = false;
  Provisioning saved_p{};
  int ring_starts = 0, ring_stops = 0;
  bool ringing = false;
  std::vector<std::vector<uint8_t>> notes;
  BatteryLevel batt = BATTERY_NORMAL;

  void randomBytes(uint8_t* d, size_t n) override { for (size_t i = 0; i < n; i++) d[i] = next_random++; }
  uint32_t unixTime() override { return now_unix; }
  uint32_t millis() override { return now_ms; }
  int8_t calibratedPower() override { return -10; }
  BatteryLevel batteryLevel() override { return batt; }
  bool saveProvisioning(const Provisioning* p) override {
    saved = true; saved_null = (p == NULL);
    if (p) saved_p = *p;
    return true;
  }
  void ringStart() override { ring_starts++; ringing = true; }
  void ringStop() override { ring_stops++; ringing = false; }
  void notify(uint8_t conn, const uint8_t* d, size_t n) override { notes.emplace_back(d, d + n); }
};

static const uint32_t PAIR_DATE = 1760000000u;   // 2025-10-09

static Provisioning provA() {
  Provisioning p;
  memcpy(p.eik, EIK_A, 32);
  for (int i = 0; i < 16; i++) p.ak[i] = 0xA0 + i;
  p.pair_date = PAIR_DATE;
  return p;
}

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

TEST(FindHubBeacon, SilentUntilProvisionedAndClockKnown) {
  FakePlatform pf;
  FindHubBeacon b(pf);
  uint8_t adv[ADV_FRAME_LEN];
  pf.now_unix = PAIR_DATE + 5000;
  EXPECT_EQ(0u, b.buildAdvert(adv));                  // unprovisioned

  Provisioning p = provA();
  ASSERT_TRUE(b.provision(p));
  EXPECT_TRUE(pf.saved);

  pf.now_unix = 1715770351;                           // VolatileRTCClock boot default (2024)
  EXPECT_EQ(0u, b.buildAdvert(adv));
  pf.now_unix = PAIR_DATE - 1;                        // before provisioning
  EXPECT_EQ(0u, b.buildAdvert(adv));
}

TEST(FindHubBeacon, AdvertFrameLayoutAndRotation) {
  FakePlatform pf;
  FindHubBeacon b(pf);
  b.load(&(const Provisioning&)provA());
  uint8_t adv[ADV_FRAME_LEN];

  // Middle of window 9765 (counter 10000000 lies in it): no rotation delay effect.
  pf.now_unix = PAIR_DATE + 10000000u;
  ASSERT_EQ(29u, b.buildAdvert(adv));
  const uint8_t hdr[] = {0x02, 0x01, 0x06, 0x19, 0x16, 0xAA, 0xFE, 0x40};
  EXPECT_EQ(0, memcmp(adv, hdr, sizeof(hdr)));
  EXPECT_EQ(0, memcmp(&adv[8], EID_VECTORS[3].eid, 20));
  EXPECT_EQ((uint8_t)(0x02 ^ EID_VECTORS[3].hash_xor), adv[28]);   // battery normal = 01 in bits 1-2

  // Just past a window boundary, the previous EID is kept for 1..204 s.
  pf.now_unix = PAIR_DATE + 1024;
  ASSERT_EQ(29u, b.buildAdvert(adv));
  EXPECT_EQ(0, memcmp(&adv[8], EID_VECTORS[0].eid, 20));
  pf.now_unix = PAIR_DATE + 1024 + 205;
  ASSERT_EQ(29u, b.buildAdvert(adv));
  EXPECT_EQ(0, memcmp(&adv[8], EID_VECTORS[2].eid, 20));
}

TEST(FindHubBeacon, RingFlowLikeAPhone) {
  FakePlatform pf;
  FindHubBeacon b(pf);
  b.load(&(const Provisioning&)provA());
  pf.now_unix = PAIR_DATE + 3000;
  uint8_t rk[8];
  deriveKey(EIK_A, KEY_RING, rk);

  Seeker s{b, 2};
  s.readNonce();
  const uint8_t ring[4] = {0xFF, 0x00, 120, 0x03};    // all, 12.0 s, high
  ASSERT_EQ(ATT_OK, s.write(0x05, rk, 8, ring, 4));
  EXPECT_TRUE(pf.ringing);
  ASSERT_EQ(1u, pf.notes.size());

  // Notification: 05 | 0C | auth(ring key, request nonce, ..., 0x01) | started, ff, 120 ds
  const auto& n = pf.notes[0];
  ASSERT_EQ(14u, n.size());
  EXPECT_EQ(0x05, n[0]);
  EXPECT_EQ(12, n[1]);
  const uint8_t add[4] = {0x00, 0xFF, 0x00, 120};
  EXPECT_EQ(0, memcmp(&n[10], add, 4));
  uint8_t expect[8];
  authSegment(rk, 8, s.nonce, 0x05, 12, add, 4, true, expect);
  EXPECT_EQ(0, memcmp(&n[2], expect, 8));

  // Ringing state read.
  pf.now_ms += 2000;
  s.readNonce();
  ASSERT_EQ(ATT_OK, s.write(0x06, rk, 8, NULL, 0));
  ASSERT_EQ(13u, s.rsp_len);
  EXPECT_EQ(0xFF, s.rsp[10]);
  EXPECT_EQ(100, (s.rsp[11] << 8) | s.rsp[12]);       // 10.0 s left

  // Times out and notifies "stopped (timeout)".
  pf.now_ms += 10001;
  b.loop();
  EXPECT_FALSE(pf.ringing);
  ASSERT_EQ(2u, pf.notes.size());
  EXPECT_EQ(RING_STOPPED_TIMEOUT, pf.notes[1][10]);
}

TEST(FindHubBeacon, NonceIsSingleUseAndAuthEnforced) {
  FakePlatform pf;
  FindHubBeacon b(pf);
  b.load(&(const Provisioning&)provA());
  pf.now_unix = PAIR_DATE + 3000;
  uint8_t rk[8], wrong[8] = {0};
  deriveKey(EIK_A, KEY_RING, rk);
  const uint8_t ring[4] = {0xFF, 0x00, 50, 0x00};

  Seeker s{b, 1};
  EXPECT_EQ(ATT_UNAUTHENTICATED, s.write(0x05, rk, 8, ring, 4));   // never read a nonce
  s.readNonce();
  EXPECT_EQ(ATT_UNAUTHENTICATED, s.write(0x05, wrong, 8, ring, 4));
  EXPECT_EQ(ATT_UNAUTHENTICATED, s.write(0x05, rk, 8, ring, 4));    // nonce burnt by the failure
  s.readNonce();
  EXPECT_EQ(ATT_OK, s.write(0x05, rk, 8, ring, 4));
  EXPECT_EQ(ATT_UNAUTHENTICATED, s.write(0x05, rk, 8, ring, 4));    // replay

  // Another connection's nonce does not authorise this one.
  Seeker other{b, 3};
  other.readNonce();
  memcpy(s.nonce, other.nonce, 8);
  EXPECT_EQ(ATT_UNAUTHENTICATED, s.write(0x05, rk, 8, ring, 4));

  // Bad length / timeout.
  s.readNonce();
  const uint8_t too_long[4] = {0xFF, 0x17, 0x71, 0x00};             // 6001 ds > 10 min
  EXPECT_EQ(ATT_INVALID_VALUE, s.write(0x05, rk, 8, too_long, 4));
  s.readNonce();
  const uint8_t two_comps[4] = {0x03, 0x00, 10, 0x00};               // left + right on a 1-component device
  EXPECT_EQ(ATT_UNAUTHENTICATED, s.write(0x05, rk, 8, two_comps, 4));
}

TEST(FindHubBeacon, StopAndButton) {
  FakePlatform pf;
  FindHubBeacon b(pf);
  b.load(&(const Provisioning&)provA());
  pf.now_unix = PAIR_DATE + 3000;
  uint8_t rk[8];
  deriveKey(EIK_A, KEY_RING, rk);
  Seeker s{b, 0};

  s.readNonce();
  const uint8_t ring[4] = {0x01, 0x00, 100, 0x00};    // "right" = our one component
  ASSERT_EQ(ATT_OK, s.write(0x05, rk, 8, ring, 4));
  b.buttonPressed();
  EXPECT_FALSE(pf.ringing);
  EXPECT_EQ(RING_STOPPED_BUTTON, pf.notes.back()[10]);

  s.readNonce();
  const uint8_t stop[4] = {0x00, 0x00, 0x00, 0x00};
  ASSERT_EQ(ATT_OK, s.write(0x05, rk, 8, stop, 4));   // already silent: still answers "stopped (GATT)"
  EXPECT_EQ(RING_STOPPED_GATT, pf.notes.back()[10]);

  // Disconnect keeps ringing (spec), but nothing to notify any more.
  s.readNonce();
  ASSERT_EQ(ATT_OK, s.write(0x05, rk, 8, ring, 4));
  size_t notes = pf.notes.size();
  b.onDisconnect(0);
  pf.now_ms += 20000;
  b.loop();
  EXPECT_FALSE(pf.ringing);
  EXPECT_EQ(notes, pf.notes.size());
}

TEST(FindHubBeacon, BeaconParamsAndProvisioningState) {
  FakePlatform pf;
  FindHubBeacon b(pf);
  Provisioning p = provA();
  b.load(&p);
  pf.now_unix = PAIR_DATE + 0x01020304;
  Seeker s{b, 0};

  s.readNonce();
  ASSERT_EQ(ATT_OK, s.write(0x00, p.ak, 16, NULL, 0));
  ASSERT_EQ(26u, s.rsp_len);
  uint8_t plain[16];
  aes128EcbDecrypt(p.ak, &s.rsp[10], plain, 16);
  EXPECT_EQ((uint8_t)-10, plain[0]);
  EXPECT_EQ(0x01, plain[1]); EXPECT_EQ(0x02, plain[2]); EXPECT_EQ(0x03, plain[3]); EXPECT_EQ(0x04, plain[4]);
  EXPECT_EQ(0x00, plain[5]);   // secp160r1
  EXPECT_EQ(0x01, plain[6]);   // one ringing component
  uint8_t expect[8];
  authSegment(p.ak, 16, s.nonce, 0x00, 24, &s.rsp[10], 16, true, expect);
  EXPECT_EQ(0, memcmp(&s.rsp[2], expect, 8));

  s.readNonce();
  ASSERT_EQ(ATT_OK, s.write(0x01, p.ak, 16, NULL, 0));
  ASSERT_EQ(31u, s.rsp_len);
  EXPECT_EQ(0x03, s.rsp[10]);  // EIK set + owner
  uint8_t eid[20];
  computeEid(EIK_A, 0x01020304, eid, NULL);
  EXPECT_EQ(0, memcmp(&s.rsp[11], eid, 20));

  s.readNonce();
  uint8_t bad_ak[16] = {0};
  EXPECT_EQ(ATT_UNAUTHENTICATED, s.write(0x00, bad_ak, 16, NULL, 0));
}

TEST(FindHubBeacon, UtpModeSkipsRingAuthOnlyWhenAsked) {
  FakePlatform pf;
  FindHubBeacon b(pf);
  b.load(&(const Provisioning&)provA());
  pf.now_unix = PAIR_DATE + 3000;
  uint8_t uk[8], junk[8] = {9, 9, 9, 9, 9, 9, 9, 9};
  deriveKey(EIK_A, KEY_UTP, uk);
  Seeker s{b, 0};

  s.readNonce();
  const uint8_t flags = 0x01;
  ASSERT_EQ(ATT_OK, s.write(0x07, uk, 8, &flags, 1));
  EXPECT_TRUE(b.utpMode());
  uint8_t adv[ADV_FRAME_LEN];
  ASSERT_EQ(29u, b.buildAdvert(adv));
  EXPECT_EQ(0x41, adv[7]);

  s.readNonce();
  const uint8_t ring[4] = {0xFF, 0x00, 10, 0x00};
  EXPECT_EQ(ATT_OK, s.write(0x05, junk, 8, ring, 4));   // unauthenticated ring allowed in UTP+skip

  s.readNonce();
  uint8_t eik_hash[8];
  sha256Trunc8(EIK_A, 32, s.nonce, 8, eik_hash);
  ASSERT_EQ(ATT_OK, s.write(0x08, uk, 8, eik_hash, 8));
  EXPECT_FALSE(b.utpMode());
  s.readNonce();
  EXPECT_EQ(ATT_UNAUTHENTICATED, s.write(0x05, junk, 8, ring, 4));
}

TEST(FindHubBeacon, GattRekeyAndClear) {
  FakePlatform pf;
  FindHubBeacon b(pf);
  Provisioning p = provA();
  b.load(&p);
  pf.now_unix = PAIR_DATE + 3000;
  Seeker s{b, 0};

  s.readNonce();
  uint8_t add[40];
  aes128EcbEncrypt(p.ak, EIK_B, add, 32);
  sha256Trunc8(EIK_A, 32, s.nonce, 8, &add[32]);
  ASSERT_EQ(ATT_OK, s.write(0x02, p.ak, 16, add, 40));
  EXPECT_EQ(0, memcmp(pf.saved_p.eik, EIK_B, 32));
  EXPECT_EQ(PAIR_DATE, pf.saved_p.pair_date);

  s.readNonce();
  uint8_t h[8];
  sha256Trunc8(EIK_A, 32, s.nonce, 8, h);              // old EIK no longer accepted
  EXPECT_EQ(ATT_UNAUTHENTICATED, s.write(0x03, p.ak, 16, h, 8));
  s.readNonce();
  sha256Trunc8(EIK_B, 32, s.nonce, 8, h);
  ASSERT_EQ(ATT_OK, s.write(0x03, p.ak, 16, h, 8));
  EXPECT_TRUE(pf.saved_null);
  EXPECT_FALSE(b.isProvisioned());
}

TEST(FindHubBeacon, MalformedFrames) {
  FakePlatform pf;
  FindHubBeacon b(pf);
  b.load(&(const Provisioning&)provA());
  uint8_t rsp[MAX_NOTIFY_LEN];
  size_t rsp_len;
  uint8_t out[9];
  b.onRead(0, out);
  const uint8_t short_frame[1] = {0x05};
  EXPECT_EQ(ATT_INVALID_VALUE, b.onWrite(0, short_frame, 1, rsp, &rsp_len));
  b.onRead(0, out);
  const uint8_t len_mismatch[5] = {0x05, 12, 0, 0, 0};
  EXPECT_EQ(ATT_INVALID_VALUE, b.onWrite(0, len_mismatch, 5, rsp, &rsp_len));
  b.onRead(0, out);
  uint8_t unknown[10] = {0x42, 8};
  EXPECT_EQ(ATT_INVALID_VALUE, b.onWrite(0, unknown, 10, rsp, &rsp_len));
  b.onRead(0, out);
  uint8_t recover[10] = {0x04, 8};
  EXPECT_EQ(ATT_NO_USER_CONSENT, b.onWrite(0, recover, 10, rsp, &rsp_len));
  EXPECT_EQ(ATT_INVALID_VALUE, b.onWrite(MAX_CONN, recover, 10, rsp, &rsp_len));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

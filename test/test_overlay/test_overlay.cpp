// Overlay multi-hop simulator: the REAL MeshCore stack (Mesh, Dispatcher,
// BaseChatMesh, ed25519 + AES/SHA from rweather/Crypto) on N simulated
// companions sharing one "air", where each node hears only the nodes the
// topology says. Overlay decisions come from helpers/OverlayPolicy.h, the
// same header the companion firmware uses. No repeaters, no Rhea, no titan:
// companions with client repeat on are the only relays.
//
//   pio test -e native_overlay
#include <gtest/gtest.h>
#include <string.h>
#include <deque>
#include <random>
#include <string>
#include <vector>

#include <Mesh.h>
#include <helpers/BaseChatMesh.h>
#include <helpers/SimpleMeshTables.h>
#include <helpers/StaticPoolPacketManager.h>
#include <helpers/OverlayPolicy.h>
#include <SHA256.h>

static unsigned long g_now = 0;

struct SimClock : public mesh::MillisecondClock {
  unsigned long getMillis() override { return g_now; }
};

struct SimRTC : public mesh::RTCClock {
  uint32_t getCurrentTime() override { return 1792300000u + g_now / 1000; }
  void setCurrentTime(uint32_t) override {}
};

struct SimRNG : public mesh::RNG {
  std::mt19937 gen;
  explicit SimRNG(uint32_t seed) : gen(seed) {}
  void random(uint8_t* d, size_t n) override { for (size_t i = 0; i < n; i++) d[i] = (uint8_t)gen(); }
};

struct Air;

struct SimRadio : public mesh::Radio {
  Air* air = nullptr;
  int id = 0;
  std::deque<std::vector<uint8_t>> rx;
  int recvRaw(uint8_t* bytes, int sz) override {
    if (rx.empty()) return 0;
    auto f = rx.front(); rx.pop_front();
    int n = (int)f.size() < sz ? (int)f.size() : sz;
    memcpy(bytes, f.data(), n);
    return n;
  }
  uint32_t getEstAirtimeFor(int len) override { return 20 + len; }   // ms, order of SF7/62.5k
  float packetScore(float snr, int len) override { return 1.0f; }
  bool startSendRaw(const uint8_t* bytes, int len) override;
  bool isSendComplete() override { return true; }
  void onSendFinished() override {}
  bool isInRecvMode() const override { return true; }
  float getLastSNR() const override { return 8.0f; }
  float getLastRSSI() const override { return -80.0f; }
};

struct Air {
  std::vector<SimRadio*> radios;
  std::vector<std::vector<bool>> hears;   // hears[rx][tx]
  int transmissions = 0;
  void link(int a, int b) { hears[a][b] = hears[b][a] = true; }
};

bool SimRadio::startSendRaw(const uint8_t* bytes, int len) {
  air->transmissions++;
  for (size_t i = 0; i < air->radios.size(); i++) {
    if ((int)i != id && air->hears[i][id]) air->radios[i]->rx.emplace_back(bytes, bytes + len);
  }
  return true;
}

// Constructed BEFORE BaseChatMesh (base classes initialise in declaration
// order): the Dispatcher constructor already uses the radio and clock.
struct SimPlumbing {
  SimRadio radio;
  SimClock clock;
  SimRNG rng;
  SimRTC rtc;
  StaticPoolPacketManager mgr{32};
  SimpleMeshTables tables;
  explicit SimPlumbing(uint32_t seed) : rng(seed) {}
};

struct SimNode : public SimPlumbing, public BaseChatMesh {
  // overlay state (as MyMesh keeps it)
  bool overlay_on = false;
  bool repeat_on = false;
  TransportKey overlay_key{};
  // observations
  std::vector<std::string> dms, chans;
  std::vector<uint32_t> expected_acks, acked;

  explicit SimNode(uint32_t seed) : SimPlumbing(seed), BaseChatMesh(radio, clock, rng, rtc, mgr, tables) {
    self_id = mesh::LocalIdentity(&rng);
  }

  void setOverlay(const char* name, bool repeat) {
    overlay_on = name != nullptr;
    repeat_on = repeat;
    if (name) { SHA256 s; s.update(name, strlen(name)); s.finalize(overlay_key.key, sizeof(overlay_key.key)); }
  }

  // --- the overlay hooks, exactly as examples/companion_radio/MyMesh.cpp ---
  bool allowPacketForward(const mesh::Packet* p) override { return overlay::allowForward(repeat_on, overlay_on, overlay_key, p); }
  void sendFloodScoped(const ContactInfo& to, mesh::Packet* pkt, uint32_t delay) override {
    if (overlay::tagForContact(overlay_on, to.flags)) sendScoped(pkt, delay); else sendFlood(pkt, delay);
  }
  void sendFloodScoped(const mesh::GroupChannel& ch, mesh::Packet* pkt, uint32_t delay) override {
    int idx = findChannelIdx(ch);
    ChannelDetails d;
    if (overlay_on && idx >= 0 && getChannel(idx, d) && overlay::tagForChannel(true, d.name)) sendScoped(pkt, delay);
    else sendFlood(pkt, delay);
  }
  void sendScoped(mesh::Packet* pkt, uint32_t delay) {
    uint16_t codes[2] = { overlay_key.calcTransportCode(pkt), 0 };
    sendFlood(pkt, codes, delay);
  }

  // --- BaseChatMesh plumbing ---
  void onDiscoveredContact(ContactInfo&, bool, uint8_t, const uint8_t*) override {}
  ContactInfo* processAck(const uint8_t* data) override {
    uint32_t a; memcpy(&a, data, 4);
    for (auto e : expected_acks) if (e == a) { acked.push_back(a); return &self_contact; }
    return nullptr;
  }
  void onContactPathUpdated(const ContactInfo&) override {}
  void onMessageRecv(const ContactInfo& c, mesh::Packet*, uint32_t, const char* text) override { dms.push_back(text); }
  void onCommandDataRecv(const ContactInfo&, mesh::Packet*, uint32_t, const char*) override {}
  void onCLICommandRecv(const ContactInfo&, mesh::Packet*, uint32_t, const char*, char*) override {}
  void onSignedMessageRecv(const ContactInfo&, mesh::Packet*, uint32_t, const uint8_t*, const char*) override {}
  uint32_t calcFloodTimeoutMillisFor(uint32_t t) const override { return 500 + 16 * t; }
  uint32_t calcDirectTimeoutMillisFor(uint32_t t, uint8_t n) const override { return 500 + (t * 6 + 250) * (n + 1); }
  void onSendTimeout() override {}
  void onChannelMessageRecv(const mesh::GroupChannel&, mesh::Packet*, uint32_t, const char* text) override { chans.push_back(text); }
  uint8_t onContactRequest(const ContactInfo&, uint32_t, const uint8_t*, uint8_t, uint8_t*) override { return 0; }
  void onContactResponse(const ContactInfo&, const uint8_t*, uint8_t) override {}
  ContactInfo self_contact{};

  ContactInfo* know(SimNode& o, bool favourite, const char* name) {
    ContactInfo c{};
    c.id = o.self_id;
    strncpy(c.name, name, sizeof(c.name) - 1);
    c.type = ADV_TYPE_CHAT;
    c.flags = favourite ? 1 : 0;
    c.out_path_len = OUT_PATH_UNKNOWN;
    addContact(c);
    return lookupContactByPubKey(o.self_id.pub_key, PUB_KEY_SIZE);
  }
  bool dm(SimNode& to, const char* text) {
    ContactInfo* c = lookupContactByPubKey(to.self_id.pub_key, PUB_KEY_SIZE);
    uint32_t ack, est;
    int r = sendMessage(*c, rtc.getCurrentTimeUnique(), 0, text, ack, est);
    expected_acks.push_back(ack);
    return r != MSG_SEND_FAILED;
  }
  uint8_t pathLenTo(SimNode& to) { return lookupContactByPubKey(to.self_id.pub_key, PUB_KEY_SIZE)->out_path_len; }
};

static const char* REGION = "#hl-simulatedregion0001";
static const char* CREW_PSK = "q83vEjRWeJCrze8SNFZ4kA==";    // the group's private '~crew' channel
static const char* PUBLIC_PSK = "izOH6cXN6mrJ5e26oRXNcg==";   // MeshCore's public channel key

struct World {
  Air air;
  std::vector<SimNode*> n;
  explicit World(int count) {
    g_now = 1000;
    air.hears.assign(count, std::vector<bool>(count, false));
    for (int i = 0; i < count; i++) {
      auto* s = new SimNode(1000 + i);
      s->radio.air = &air; s->radio.id = i;
      air.radios.push_back(&s->radio);
      n.push_back(s);
    }
    for (auto* s : n) s->begin();
  }
  ~World() { for (auto* s : n) delete s; }
  void line() { for (size_t i = 0; i + 1 < n.size(); i++) air.link(i, i + 1); }   // each hears only its neighbours
  void allKnowAll(bool favourite) {
    for (auto* a : n) for (size_t j = 0; j < n.size(); j++) if (a != n[j]) a->know(*n[j], favourite, ("n" + std::to_string(j)).c_str());
  }
  void group(const char* name, const char* psk) { for (auto* s : n) s->addChannel(name, psk); }
  void run(unsigned long ms) {
    for (unsigned long t = 0; t < ms; t += 5) { g_now += 5; for (auto* s : n) s->loop(); }
  }
};

static int count(const std::vector<std::string>& v, const std::string& s) {
  int c = 0; for (auto& x : v) if (x == s) c++; return c;
}

// A - B - C: A and C cannot hear each other; B is a companion with repeat on.
TEST(Overlay, DmHopsTwoHopsAndAckComesBack) {
  World w(3); w.line(); w.allKnowAll(true);
  for (auto* s : w.n) s->setOverlay(REGION, true);
  ASSERT_TRUE(w.n[0]->dm(*w.n[2], "hello C"));
  w.run(8000);
  EXPECT_EQ(1, count(w.n[2]->dms, "hello C"));
  EXPECT_EQ(1u, w.n[0]->acked.size()) << "ACK did not come back over the overlay";
  // A stored path lists the RELAYS: A -> B -> C is one relay (B).
  EXPECT_EQ(1, w.n[0]->pathLenTo(*w.n[2]) & 63) << "A should have learned the path through B";
  // Second message goes DIRECT along the learned path and is still delivered.
  ASSERT_TRUE(w.n[0]->dm(*w.n[2], "again"));
  w.run(8000);
  EXPECT_EQ(1, count(w.n[2]->dms, "again"));
  EXPECT_EQ(2u, w.n[0]->acked.size());
}

// A - B - C - D: three hops.
TEST(Overlay, DmHopsThreeHops) {
  World w(4); w.line(); w.allKnowAll(true);
  for (auto* s : w.n) s->setOverlay(REGION, true);
  ASSERT_TRUE(w.n[0]->dm(*w.n[3], "far"));
  w.run(10000);
  EXPECT_EQ(1, count(w.n[3]->dms, "far"));
  EXPECT_EQ(1u, w.n[0]->acked.size());
  EXPECT_EQ(2, w.n[0]->pathLenTo(*w.n[3]) & 63) << "A should have learned the path through B and C";
}

TEST(Overlay, OverlayChannelHopsPublicChannelDoesNot) {
  World w(4); w.line(); w.allKnowAll(true);
  for (auto* s : w.n) s->setOverlay(REGION, true);
  w.group("~crew", CREW_PSK);
  w.group("Public", PUBLIC_PSK);
  ChannelDetails crew, pub;
  ASSERT_TRUE(w.n[0]->getChannel(0, crew));
  ASSERT_TRUE(w.n[0]->getChannel(1, pub));
  ASSERT_TRUE(w.n[0]->sendGroupMessage(w.n[0]->rtc.getCurrentTimeUnique(), crew.channel, "A", "meet at the creek", 17));
  w.run(8000);
  for (int i = 1; i < 4; i++) EXPECT_EQ(1, (int)w.n[i]->chans.size()) << "node " << i << " missed the ~crew message";
  // An untagged (non-'~') channel only reaches direct neighbours: nobody relays it.
  for (auto* s : w.n) s->chans.clear();
  ASSERT_TRUE(w.n[0]->sendGroupMessage(w.n[0]->rtc.getCurrentTimeUnique(), pub.channel, "A", "public hi", 9));
  w.run(8000);
  EXPECT_EQ(1u, w.n[1]->chans.size());
  EXPECT_EQ(0u, w.n[2]->chans.size());
  EXPECT_EQ(0u, w.n[3]->chans.size());
}

TEST(Overlay, NoRelayWithoutRepeatOrOverlayOrTag) {
  {  // B has overlay but repeat off
    World w(3); w.line(); w.allKnowAll(true);
    for (auto* s : w.n) s->setOverlay(REGION, true);
    w.n[1]->repeat_on = false;
    w.n[0]->dm(*w.n[2], "x"); w.run(8000);
    EXPECT_EQ(0u, w.n[2]->dms.size());
  }
  {  // B repeats but has a different overlay key (an outsider's companion)
    World w(3); w.line(); w.allKnowAll(true);
    for (auto* s : w.n) s->setOverlay(REGION, true);
    w.n[1]->setOverlay("#someone-elses-region", true);
    w.n[0]->dm(*w.n[2], "x"); w.run(8000);
    EXPECT_EQ(0u, w.n[2]->dms.size());
  }
  {  // C is not a favourite of A: the DM goes out untagged, B will not carry it
    World w(3); w.line(); w.allKnowAll(false);
    for (auto* s : w.n) s->setOverlay(REGION, true);
    w.n[0]->dm(*w.n[2], "x"); w.run(8000);
    EXPECT_EQ(0u, w.n[2]->dms.size());
  }
}

TEST(Overlay, FloodDoesNotLoopForever) {
  // A ring of 5 all repeating: one DM must not keep circulating.
  World w(5);
  for (int i = 0; i < 5; i++) w.air.link(i, (i + 1) % 5);
  w.allKnowAll(true);
  for (auto* s : w.n) s->setOverlay(REGION, true);
  w.n[0]->dm(*w.n[2], "ring"); w.run(5000);
  int tx = w.air.transmissions;
  w.run(10000);
  EXPECT_EQ(1, count(w.n[2]->dms, "ring"));
  EXPECT_EQ(tx, w.air.transmissions) << "traffic still flowing 10 s later";
  EXPECT_LT(tx, 30);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

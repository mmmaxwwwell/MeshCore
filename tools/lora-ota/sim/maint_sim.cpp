// Host simulator for maintenance over LoRa: the firmware's own
// lora_ota_maint::Maint over a fake companion (or repeater) behind a pipe.
// The node has two "filesystems" (path -> bytes), a contact table and its
// saved copy (/contacts3 on the secondary FS, as the companion keeps it),
// channels (/channels2), an identity and prefs on the primary FS that carry
// secret markers, and the counter record (/ota_maint, primary FS).
//
// stdin:  u16 len, request (type byte first)          -> u16 len, reply body (0 = nothing heard)
//         u16 0xFFFF, op u8, args                     -> u16 len, text (control, never "lost")
//           op 1 tick u32 ms | 2 dump (JSON) | 3 power cycle (RAM from flash) | 5 busy u8
//           op 6 the next counter save fails | 7 requester: 32 bytes (all 0 = none)
//           op 8 path u8 n, bytes: put a junk file on fs 1 (op 9: fs 0)
//
//   maint_sim --pubkey HEX --board TAG [--role companion|repeater] [--contacts N] [--max N]
//             [--self HEX32] [--drop PCT] [--seed N] [--no-fs2]
//
// Contact i (0-based) of the generated table: type 1 + i % 4 (chat, repeater,
// room, sensor), favourite when i % 10 == 0, key = sha-ish bytes of i.

#include "LoraOTAMaint.h"
#include <SHA256.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <map>
#include <string>
#include <vector>

using namespace lora_ota_maint;

static int hexval(char c) { return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10; }
static void fromHex(uint8_t* out, const char* hex, int n) {
  for (int i = 0; i < n; i++) out[i] = hexval(hex[2 * i]) << 4 | hexval(hex[2 * i + 1]);
}
static std::string hex(const uint8_t* p, int n) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (int i = 0; i < n; i++) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
  return s;
}

typedef std::map<std::string, std::vector<uint8_t>> Fs;
#define CREC 152   // the companion's /contacts3 record
#define CHREC 68   // /channels2

struct Channel { char name[32]; uint8_t secret[32]; };

static std::vector<uint8_t> bytes(const char* s) { return std::vector<uint8_t>(s, s + strlen(s)); }

class FakeNode : public Target {
public:
  bool companion = true, has_fs2 = true;
  uint8_t self[32];
  Fs fs[2];
  std::vector<ContactRec> contacts;   // RAM
  std::vector<Channel> channels;      // RAM
  int max_contacts = 350;
  int changed = 0, saves = 0, removes_this_poll = 0, max_removes_per_poll = 0, reboots = 0;
  bool fail_state_save = false, reboot_req = false;

  uint8_t identity[64];

  Role role() override { return companion ? COMPANION : REPEATER; }
  const char* fwVersion() override { return "v1.18.0-maint-sim"; }
  uint16_t battMilliVolts() override { return 4012; }
  const uint8_t* selfPubKey() override { return self; }
  void reboot() override { reboots++; reboot_req = true; }
  int loadState(uint8_t* buf, size_t max) override {
    auto it = fs[0].find("/ota_maint");
    if (it == fs[0].end()) return 0;
    size_t n = it->second.size() < max ? it->second.size() : max;
    memcpy(buf, it->second.data(), n);
    return n;
  }
  bool saveState(const uint8_t* buf, size_t len) override {
    if (fail_state_save) { fail_state_save = false; return false; }
    fs[0]["/ota_maint"] = std::vector<uint8_t>(buf, buf + len);
    return true;
  }
  bool hasFs(int f) override { return f == 0 || (f == 1 && has_fs2); }
  bool storage(int f, uint32_t& used, uint32_t& total) override {
    if (!hasFs(f)) return false;
    size_t b = 0;
    for (auto& kv : fs[f]) b += (kv.second.size() + 4095) / 4096 * 4096;
    used = b / 1024; total = f == 0 ? 28 : 2048;
    return true;
  }
  // flat directories: "/" lists the top level, a dir is any prefix "/d/" of a path
  int listDir(int f, const char* dir, int index, FileEntry& e) override {
    if (!hasFs(f)) return -1;
    std::string d = dir;
    if (d.empty() || d.back() != '/') d += '/';
    std::vector<std::pair<std::string, std::pair<bool, uint32_t>>> items;
    bool any = d == "/";
    for (auto& kv : fs[f]) {
      if (kv.first.compare(0, d.size(), d) != 0) continue;
      any = true;
      std::string rest = kv.first.substr(d.size());
      size_t slash = rest.find('/');
      if (slash != std::string::npos) {
        std::string sub = rest.substr(0, slash);
        bool seen = false;
        for (auto& it : items) if (it.first == sub) seen = true;
        if (!seen) items.push_back({ sub, { true, 0 } });
      } else {
        items.push_back({ rest, { false, (uint32_t)kv.second.size() } });
      }
    }
    if (!any) return -1;
    if (index >= (int)items.size()) return 0;
    snprintf(e.name, sizeof(e.name), "%s", items[index].first.c_str());
    e.dir = items[index].second.first;
    e.size = items[index].second.second;
    return 1;
  }
  bool exists(int f, const char* path, bool& dir) override {
    if (!hasFs(f)) return false;
    if (fs[f].count(path)) { dir = false; return true; }
    std::string d = std::string(path) + "/";
    for (auto& kv : fs[f]) if (kv.first.compare(0, d.size(), d) == 0) { dir = true; return true; }
    return false;
  }
  bool removeFile(int f, const char* path) override { return fs[f].erase(path) == 1; }

  int contactCount() override { return companion ? (int)contacts.size() : -1; }
  int contactMax() override { return max_contacts; }
  bool contactAt(int i, ContactRec& c) override {
    if (i < 0 || i >= (int)contacts.size()) return false;
    c = contacts[i];
    return true;
  }
  bool contactRemoveAt(int i) override {
    if (i < 0 || i >= (int)contacts.size()) return false;
    contacts.erase(contacts.begin() + i);
    removes_this_poll++;
    return true;
  }
  bool contactSetFlags(int i, uint8_t f) override { contacts[i].flags = f; return true; }
  int contactPut(const ContactRec& c) override {
    for (auto& x : contacts) {
      if (!memcmp(x.pub_key, c.pub_key, 32)) { x = c; return 1; }
    }
    if ((int)contacts.size() >= max_contacts) return -1;
    contacts.push_back(c);
    return 0;
  }
  void contactsChanged() override { changed++; }
  bool contactsSave() override {
    std::vector<uint8_t> f;
    for (auto& c : contacts) {
      uint8_t r[CREC];
      memset(r, 0, sizeof(r));
      memcpy(r, c.pub_key, 32); memcpy(&r[32], c.name, 32); r[64] = c.type; r[65] = c.flags;
      r[71] = c.out_path_len; memcpy(&r[72], &c.last_advert, 4); memcpy(&r[76], c.out_path, 64);
      f.insert(f.end(), r, r + CREC);
    }
    fs[has_fs2 ? 1 : 0]["/contacts3"] = f;
    saves++;
    return true;
  }
  int channelCount() override { return companion ? (int)channels.size() : -1; }
  bool channelAt(int i, char name[32], uint8_t secret[32]) override {
    if (i < 0 || i >= (int)channels.size()) return false;
    memcpy(name, channels[i].name, 32); memcpy(secret, channels[i].secret, 32);
    return true;
  }
  bool channelsSave() override {
    std::vector<uint8_t> f;
    for (auto& ch : channels) {
      uint8_t r[CHREC];
      memset(r, 0, sizeof(r));
      memcpy(&r[4], ch.name, 32); memcpy(&r[36], ch.secret, 32);
      f.insert(f.end(), r, r + CHREC);
    }
    fs[has_fs2 ? 1 : 0]["/channels2"] = f;
    return true;
  }
  bool formatSecondary() override {
    if (!has_fs2) return false;
    fs[1].clear();
    return true;
  }
  bool storedCounts(int& c, int& ch) override {
    Fs& f = fs[has_fs2 ? 1 : 0];
    c = f.count("/contacts3") ? f["/contacts3"].size() / CREC : 0;
    ch = 0;   // named (configured) channels; empty slots are saved too, as the companion does
    auto& chf = f["/channels2"];
    for (size_t o = 0; o + CHREC <= chf.size(); o += CHREC) if (chf[o + 4]) ch++;
    return true;
  }

  void loadFromFlash() {   // a power cycle: RAM comes back from the files
    Fs& f = fs[has_fs2 ? 1 : 0];
    contacts.clear();
    channels.clear();
    auto& cf = f["/contacts3"];
    for (size_t o = 0; o + CREC <= cf.size(); o += CREC) {
      ContactRec c;
      memset(&c, 0, sizeof(c));
      memcpy(c.pub_key, &cf[o], 32); memcpy(c.name, &cf[o + 32], 32); c.type = cf[o + 64]; c.flags = cf[o + 65];
      c.out_path_len = cf[o + 71]; memcpy(&c.last_advert, &cf[o + 72], 4); memcpy(c.out_path, &cf[o + 76], 64);
      contacts.push_back(c);
    }
    auto& chf = f["/channels2"];
    for (size_t o = 0; o + CHREC <= chf.size(); o += CHREC) {
      Channel ch;
      memcpy(ch.name, &chf[o + 4], 32); memcpy(ch.secret, &chf[o + 36], 32);
      channels.push_back(ch);
    }
  }
};

static void contactKey(int i, uint8_t key[32]) {
  SHA256 sha;
  uint8_t b[4] = { (uint8_t)i, (uint8_t)(i >> 8), 0x5A, 0xA5 };
  sha.update(b, 4);
  sha.finalize(key, 32);
}

static void addChannel(FakeNode& n, const char* name, const uint8_t* secret16) {
  Channel ch;
  memset(&ch, 0, sizeof(ch));
  snprintf(ch.name, sizeof(ch.name), "%s", name);
  if (secret16) memcpy(ch.secret, secret16, 16);
  else { SHA256 s; s.update(name, strlen(name)); uint8_t d[32]; s.finalize(d, 32); memcpy(ch.secret, d, 16); }
  n.channels.push_back(ch);
}

static bool readFull(uint8_t* p, size_t n) { return fread(p, 1, n, stdin) == n; }
static void out(const void* p, size_t n) {
  uint8_t h[2] = { (uint8_t)n, (uint8_t)(n >> 8) };
  fwrite(h, 1, 2, stdout);
  fwrite(p, 1, n, stdout);
  fflush(stdout);
}

int main(int argc, char** argv) {
  const char *pubhex = NULL, *board = "test_board", *selfhex = NULL;
  int drop = 0, ncontacts = 40, maxc = 350;
  unsigned seed = 1;
  bool companion = true, fs2 = true;
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--pubkey")) pubhex = argv[++i];
    else if (!strcmp(argv[i], "--board")) board = argv[++i];
    else if (!strcmp(argv[i], "--role")) companion = strcmp(argv[++i], "repeater") != 0;
    else if (!strcmp(argv[i], "--self")) selfhex = argv[++i];
    else if (!strcmp(argv[i], "--drop")) drop = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--seed")) seed = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--contacts")) ncontacts = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--max")) maxc = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--no-fs2")) fs2 = false;
  }
  if (!pubhex || strlen(pubhex) != 64) { fprintf(stderr, "usage: see source\n"); return 2; }
  srand(seed);
  uint8_t pub[32];
  fromHex(pub, pubhex, 32);

  FakeNode node;
  node.companion = companion;
  node.has_fs2 = companion && fs2;
  node.max_contacts = maxc;
  if (selfhex) fromHex(node.self, selfhex, 32); else memset(node.self, 0x5A, 32);
  // secrets the node holds: none may ever appear in a reply
  memset(node.identity, 0, sizeof(node.identity));
  memcpy(node.identity, "SECRET-IDENTITY-PRIVATE-KEY-0123", 32);
  node.fs[0]["/_main.id"] = std::vector<uint8_t>(node.identity, node.identity + 64);
  node.fs[0]["/prefs.json"] = bytes("{\"password\":\"SECRET-ADMIN-PASSWORD\",\"wifi_pwd\":\"SECRET-WIFI\"}");
  node.fs[0]["/ota_settings"] = bytes("MST1-SECRET-STATE");
  if (companion) {
    node.fs[0]["/overlay"] = bytes("OLY1#SECRET-OVERLAY-NAME");
    node.fs[0]["/ota_set_overlay"] = bytes("OLY1#SECRET-OVERLAY-COPY");
    node.fs[0]["/posrep"] = bytes("PRP1");
    for (int i = 0; i < ncontacts; i++) {
      ContactRec c;
      memset(&c, 0, sizeof(c));
      contactKey(i, c.pub_key);
      snprintf(c.name, sizeof(c.name), "node-%03d", i);
      c.type = 1 + i % 4;
      c.flags = i % 10 == 0 ? 1 : 0;
      c.out_path_len = 0xFF;
      c.last_advert = 1700000000u + i;
      node.contacts.push_back(c);
    }
    static const uint8_t pub_psk[16] = { 0x8b, 0x33, 0x87, 0xe9, 0xc5, 0xcd, 0xea, 0x6a, 0xc9, 0xe5, 0xed, 0xba, 0xa1, 0x15, 0xcd, 0x72 };
    addChannel(node, "Public", pub_psk);
    addChannel(node, "#secretgroup", NULL);                       // hashtag: the name IS the key
    static const uint8_t priv[16] = { 'S', 'E', 'C', 'R', 'E', 'T', '-', 'P', 'S', 'K', '-', 'B', 'Y', 'T', 'E', 'S' };
    addChannel(node, "family", priv);                             // a private channel with its own secret
    static const uint8_t zero[16] = { 0 };
    addChannel(node, "", zero);                                   // empty slots (MAX_GROUP_CHANNELS)
    addChannel(node, "", zero);
    node.contactsSave();
    node.channelsSave();
    node.saves = 0;
    if (node.has_fs2) {
      node.fs[1]["/adv_blobs"] = std::vector<uint8_t>(1000, 0);
      node.fs[1]["/ota-old.bin"] = std::vector<uint8_t>(300, 0xEE);
      node.fs[1]["/old/junk.bin"] = std::vector<uint8_t>(77, 1);
    }
  } else {
    node.fs[0]["/s_contacts"] = bytes("ACL-SECRET");
    node.fs[0]["/packet_log"] = std::vector<uint8_t>(500, 2);
  }

  uint8_t busy = 0;
  uint8_t requester[32];
  bool has_req = false;
  Maint* m = new Maint(node, pub, board);
  m->begin();
  uint32_t now = 1000;
  auto restart = [&]() {
    node.loadFromFlash();
    delete m;
    m = new Maint(node, pub, board);
    m->begin();
  };
  auto step = [&](uint32_t ms) {
    for (uint32_t t = 0; t < ms; t += 50) {
      now += 50;
      node.removes_this_poll = 0;
      m->poll(now, busy);
      if (node.removes_this_poll > node.max_removes_per_poll) node.max_removes_per_poll = node.removes_this_poll;
      m->loop(now);
      if (node.reboot_req) { node.reboot_req = false; restart(); }
    }
  };

  uint8_t req[600], reply[256];
  for (;;) {
    uint8_t hdr[2];
    if (!readFull(hdr, 2)) break;
    size_t len = hdr[0] | hdr[1] << 8;
    if (len == 0xFFFF) {
      uint8_t op;
      if (!readFull(&op, 1)) break;
      if (op == 1) {
        uint8_t b[4];
        readFull(b, 4);
        step(b[0] | b[1] << 8 | b[2] << 16 | (uint32_t)b[3] << 24);
        out("", 0);
      } else if (op == 2) {
        std::string s = "{\"contacts\": [";
        for (size_t i = 0; i < node.contacts.size(); i++) {
          char b[160];
          snprintf(b, sizeof b, "%s[\"%s\", %u, %u, \"%s\"]", i ? ", " : "", hex(node.contacts[i].pub_key, 32).c_str(),
                   node.contacts[i].type, node.contacts[i].flags, node.contacts[i].name);
          s += b;
        }
        s += "], \"channels\": [";
        for (size_t i = 0; i < node.channels.size(); i++) {
          s += (i ? ", \"" : "\"") + std::string(node.channels[i].name) + "\"";
        }
        s += "], \"files\": [";
        bool first = true;
        for (int f = 0; f < 2; f++) for (auto& kv : node.fs[f]) {
          char b[160];
          snprintf(b, sizeof b, "%s[%d, \"%s\", %zu]", first ? "" : ", ", f, kv.first.c_str(), kv.second.size());
          s += b;
          first = false;
        }
        char b[400];
        auto& id = node.fs[0]["/_main.id"];
        snprintf(b, sizeof b, "], \"identity\": \"%s\", \"identity_ok\": %d, \"counter\": %u, \"changed\": %d, \"saves\": %d, "
                 "\"max_removes_per_poll\": %d, \"reboots\": %d, \"working\": %d, \"reboot_due\": %d}",
                 hex(id.data(), id.size() < 8 ? id.size() : 8).c_str(),
                 (int)(id.size() == 64 && !memcmp(id.data(), node.identity, 64)), m->counter(), node.changed, node.saves,
                 node.max_removes_per_poll, node.reboots, (int)m->working(), (int)m->rebootDue());
        s += b;
        out(s.data(), s.size());
      } else if (op == 3) {
        restart();
        out("", 0);
      } else if (op == 5) {
        readFull(&busy, 1);
        out("", 0);
      } else if (op == 6) {
        node.fail_state_save = true;
        out("", 0);
      } else if (op == 7) {
        readFull(requester, 32);
        has_req = false;
        for (int i = 0; i < 32; i++) if (requester[i]) has_req = true;
        out("", 0);
      } else if (op == 8 || op == 9) {
        uint8_t n;
        readFull(&n, 1);
        std::string p(n, 0);
        readFull((uint8_t*)&p[0], n);
        node.fs[op == 8 ? 1 : 0][p] = std::vector<uint8_t>(10, 3);
        out("", 0);
      }
      continue;
    }
    if (len > sizeof(req) || !readFull(req, len)) break;
    int n = 0;
    if (rand() % 100 >= drop) {
      Ctx ctx = { has_req ? requester : NULL, busy, now / 1000, 0 };
      n = m->handle(req, len, reply, now, ctx);
      if (n > 0 && rand() % 100 < drop) n = 0;
    }
    step(50);   // the main loop's turn: verify + the command happen here
    out(reply, n);
  }
  return 0;
}

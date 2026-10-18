// Host simulator for signed settings over LoRa: the firmware's own
// lora_ota_settings::Settings over a fake node (prefs, a "flash" copy of
// them, a state file, a region table, a radio), behind a pipe. The sender
// and the node each have a radio setting; a request only gets through when
// they match, so a radio change that the sender does not follow is silent,
// as on the air.
//
// stdin:  u16 len, request (type byte first)          -> u16 len, reply body (0 = nothing heard)
//         u16 0xFFFF, op u8, args                     -> u16 len, text (control, never "lost")
//           op 1 tick u32 ms | 2 dump | 3 reboot | 4 sender radio u32 khz u32 hz u8 sf u8 cr
//           op 5 firmware pending u8
//
//   settings_sim --pubkey HEX --board TAG --role repeater|companion [--self HEX32] [--drop PCT] [--seed N]

#include "LoraOTASettings.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <set>
#include <string>
#include <vector>

using namespace lora_ota_settings;

static int hexval(char c) { return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10; }
static void fromHex(uint8_t* out, const char* hex, int n) {
  for (int i = 0; i < n; i++) out[i] = hexval(hex[2 * i]) << 4 | hexval(hex[2 * i + 1]);
}

struct Radio {
  uint32_t khz, hz;
  uint8_t sf, cr;
  bool operator==(const Radio& o) const { return khz == o.khz && hz == o.hz && sf == o.sf && cr == o.cr; }
};

class FakeNode : public Target {
public:
  bool repeater;
  uint8_t self[32];
  Values prefs, saved;          // RAM and "flash"
  std::vector<uint8_t> state;   // the state file
  std::set<std::string> regions, regions_saved, regions_snap;
  bool regions_snap_ok = false;
  Radio live;                   // what the radio hardware is set to
  int8_t tx_live = 0;
  int radio_applies = 0, writes = 0;
  bool fail_state_save = false;

  FakeNode(bool rep) : repeater(rep) {
    memset(&prefs, 0, sizeof(prefs));
    prefs.freq_khz = 910525; prefs.bw_hz = 62500; prefs.sf = 7; prefs.cr = 5;
    prefs.tx = 22; prefs.af_milli = 1000; prefs.path_hash_mode = 0; prefs.rxgain = 1;
    prefs.flood_max = 64; prefs.flood_max_unscoped = 64; prefs.flood_max_advert = 64;
    prefs.advert_interval_min = 0; prefs.flood_advert_interval_h = 12; prefs.repeat = 1;
    saved = prefs;
    live = { prefs.freq_khz, prefs.bw_hz, prefs.sf, prefs.cr };
    tx_live = prefs.tx;
  }
  uint32_t supported() override {
    uint32_t common = (1u << K_RADIO) | (1u << K_TX) | (1u << K_AF) | (1u << K_RXDELAY) | (1u << K_TXDELAY) |
                      (1u << K_DIRECT_TXDELAY) | (1u << K_MULTI_ACKS) | (1u << K_PATH_HASH_MODE) |
                      (1u << K_INT_THRESH) | (1u << K_AGC_RESET_INTERVAL) | (1u << K_RXGAIN);
    return repeater ? (1u << K_COUNT) - 1 : common;
  }
  void read(Values& v) override { v = prefs; }
  bool write(const Values& v, uint32_t mask) override { copyMasked(prefs, v, mask); saved = prefs; writes++; return true; }
  void applyRadio() override { live = { prefs.freq_khz, prefs.bw_hz, prefs.sf, prefs.cr }; tx_live = prefs.tx; radio_applies++; }
  int8_t maxTxPower() override { return 22; }
  const uint8_t* selfPubKey() override { return self; }
  int loadState(uint8_t* buf, size_t max) override {
    size_t n = state.size() < max ? state.size() : max;
    memcpy(buf, state.data(), n);
    return n;
  }
  bool saveState(const uint8_t* buf, size_t len) override {
    if (fail_state_save) return false;
    state.assign(buf, buf + len);
    return true;
  }
  bool regionsSnapshot() override { regions_snap = regions_saved; regions_snap_ok = true; return true; }
  bool regionsApply(const char* names) override {
    std::string s(names);
    size_t start = 0;
    for (;;) {
      size_t c = s.find(',', start);
      regions.insert(s.substr(start, c == std::string::npos ? std::string::npos : c - start));
      if (c == std::string::npos) break;
      start = c + 1;
    }
    regions_saved = regions;
    return true;
  }
  bool regionsRestore() override {
    if (!regions_snap_ok) return false;
    regions = regions_saved = regions_snap;
    return true;
  }
  int regionsExport(char* out, int max) override {
    std::string s;
    for (auto& r : regions) { if (!s.empty()) s += ","; s += r; }
    snprintf(out, max, "%s", s.c_str());
    return strlen(out);
  }
  void reboot() {   // RAM comes back from "flash", the radio from the prefs
    prefs = saved;
    regions = regions_saved;
    live = { prefs.freq_khz, prefs.bw_hz, prefs.sf, prefs.cr };
    tx_live = prefs.tx;
  }
};

static bool readFull(uint8_t* p, size_t n) { return fread(p, 1, n, stdin) == n; }
static void out(const void* p, size_t n) {
  uint8_t h[2] = { (uint8_t)n, (uint8_t)(n >> 8) };
  fwrite(h, 1, 2, stdout);
  fwrite(p, 1, n, stdout);
  fflush(stdout);
}

int main(int argc, char** argv) {
  const char *pubhex = NULL, *board = "test_board", *selfhex = NULL;
  bool repeater = true;
  int drop = 0;
  unsigned seed = 1;
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--pubkey")) pubhex = argv[++i];
    else if (!strcmp(argv[i], "--board")) board = argv[++i];
    else if (!strcmp(argv[i], "--role")) repeater = strcmp(argv[++i], "companion") != 0;
    else if (!strcmp(argv[i], "--self")) selfhex = argv[++i];
    else if (!strcmp(argv[i], "--drop")) drop = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--seed")) seed = atoi(argv[++i]);
  }
  if (!pubhex || strlen(pubhex) != 64) { fprintf(stderr, "usage: see source\n"); return 2; }
  srand(seed);
  uint8_t pub[32];
  fromHex(pub, pubhex, 32);
  FakeNode node(repeater);
  if (selfhex) fromHex(node.self, selfhex, 32); else memset(node.self, 0x5A, 32);
  if (repeater) { node.regions = node.regions_saved = { "ct" }; }
  Radio sender = node.live;
  bool fw_pending = false;

  Settings* s = new Settings(node, pub, board);
  s->begin();
  uint32_t now = 1000;
  auto step = [&](uint32_t ms) {
    for (uint32_t t = 0; t < ms; t += 50) {
      now += 50;
      s->poll(now, fw_pending);
      s->loop(now);
      s->takeRadioEvent();
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
        char txt[1200];
        const Values& v = node.saved;
        std::string regs;
        for (auto& r : node.regions_saved) { if (!regs.empty()) regs += ","; regs += r; }
        State st;
        memset(&st, 0, sizeof(st));
        if (node.state.size() == sizeof(st)) memcpy(&st, node.state.data(), sizeof(st));
        int n = snprintf(txt, sizeof txt,
          "{\"saved\": {\"radio\": [%u, %u, %u, %u], \"tx\": %d, \"af\": %u, \"flood.max\": %u, \"flood.max.unscoped\": %u, "
          "\"flood.advert.interval\": %u, \"path.hash.mode\": %u, \"loop.detect\": %u, \"regions\": \"%s\"}, "
          "\"ram_radio\": [%u, %u, %u, %u], \"live\": [%u, %u, %u, %u], \"tx_live\": %d, \"radio_applies\": %d, \"writes\": %d, "
          "\"version\": %u, \"pending_version\": %u, \"pending\": %d, \"busy\": %d}",
          v.freq_khz, v.bw_hz, v.sf, v.cr, v.tx, v.af_milli, v.flood_max, v.flood_max_unscoped, v.flood_advert_interval_h,
          v.path_hash_mode, v.loop_detect, regs.c_str(),
          node.prefs.freq_khz, node.prefs.bw_hz, node.prefs.sf, node.prefs.cr,
          node.live.khz, node.live.hz, node.live.sf, node.live.cr, node.tx_live, node.radio_applies, node.writes,
          st.version, st.pending_version, (int)s->pending(), (int)s->busy());
        out(txt, n);
      } else if (op == 3) {
        node.reboot();
        delete s;
        s = new Settings(node, pub, board);
        s->begin();
        out("", 0);
      } else if (op == 4) {
        uint8_t b[10];
        readFull(b, 10);
        sender.khz = b[0] | b[1] << 8 | b[2] << 16 | (uint32_t)b[3] << 24;
        sender.hz = b[4] | b[5] << 8 | b[6] << 16 | (uint32_t)b[7] << 24;
        sender.sf = b[8]; sender.cr = b[9];
        out("", 0);
      } else if (op == 5) {
        uint8_t b;
        readFull(&b, 1);
        fw_pending = b;
        out("", 0);
      } else if (op == 6) {   // the next state save fails
        node.fail_state_save = true;
        out("", 0);
      }
      continue;
    }
    if (len > sizeof(req) || !readFull(req, len)) break;
    int n = 0;
    if (sender == node.live && rand() % 100 >= drop) {
      n = s->handle(req, len, reply, now);
      if (n > 0 && rand() % 100 < drop) n = 0;
    }
    step(50);   // the main loop's turn: verify + apply happen here
    out(reply, n);
  }
  return 0;
}

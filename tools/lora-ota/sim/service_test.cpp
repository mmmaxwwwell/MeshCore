// Host test for LoraOTAService (src/helpers): the fast-radio switch, the
// confirm-or-roll-back window and the reboot after FINISH, against a fake
// platform and radio. Built with -ffast-math, like the nRF52 code that once
// refused 500 kHz as "> 500".
#include <stdio.h>
#include <string.h>
#include <vector>
#include <string>
#include "LoraOTAService.h"

unsigned long fake_millis = 1000;
static int fails = 0;
#define CHECK(c, ...) do { if (!(c)) { printf("FAIL " __VA_ARGS__); printf("\n"); fails++; } } while (0)

struct RamFlash : lora_ota::Flash {
  std::vector<uint8_t> m = std::vector<uint8_t>(1 << 20, 0xFF);
  size_t capacity() override { return m.size(); }
  bool erase(size_t len) override { memset(m.data(), 0xFF, len); return true; }
  bool write(size_t o, const uint8_t* s, size_t n) override { memcpy(&m[o], s, n); return true; }
  bool read(size_t o, uint8_t* d, size_t n) override { memcpy(d, &m[o], n); return true; }
  bool activate(size_t) override { return true; }
};

struct FakePlatform : LoraOTAPlatform {
  RamFlash fl;
  bool pending_at_boot = false, confirmed = false, rolled_back = false, installed = false, probation = false;
  lora_ota::Flash* flash() override { return &fl; }
  bool begin() override { return pending_at_boot; }
  bool confirm() override { confirmed = true; return true; }
  void rollback() override { rolled_back = true; }
  void install() override { installed = true; }
  void startProbation() override { probation = true; }
  bool runningSha(uint8_t sha[32]) override { memset(sha, 0xAB, 32); return true; }
  const char* describe() override { return "fake"; }
};
static FakePlatform plat;
LoraOTAPlatform& loraOtaPlatform() { return plat; }

struct FakeRadio : LoraOTARadio {
  std::vector<std::string> log;
  void otaTempRadio(float f, float bw, uint8_t sf, uint8_t cr) override {
    char b[64]; snprintf(b, sizeof b, "temp %.3f %.1f %u %u", f, bw, sf, cr); log.push_back(b);
  }
  void otaRestoreRadio() override { log.push_back("restore"); }
};

static std::vector<uint8_t> radioReq(uint32_t khz, uint32_t hz, uint8_t sf, uint8_t cr, uint16_t idle) {
  std::vector<uint8_t> r = {LORA_OTA_REQ_RADIO};
  for (int i = 0; i < 4; i++) r.push_back(khz >> (8 * i));
  for (int i = 0; i < 4; i++) r.push_back(hz >> (8 * i));
  r.push_back(sf); r.push_back(cr); r.push_back(idle); r.push_back(idle >> 8);
  for (int i = 0; i < 3; i++) r.push_back(0);   // AES padding, as on the air
  return r;
}

static void run(LoraOTAService& s, unsigned long ms) {
  for (unsigned long t = 0; t < ms; t += 100) { fake_millis += 100; s.loop(); }
}

int main() {
  uint8_t reply[200];
  { // fast radio: accepted at the default 919 MHz / 500 kHz / SF5, applied after the reply, dropped when quiet
    FakeRadio radio; LoraOTAService s; s.begin(radio);
    auto r = radioReq(919000, 500000, 5, 5, 90);
    int n = s.handleRequest(r.data(), r.size(), reply, 7);
    CHECK(n == 1 && reply[0] == lora_ota::OK, "500 kHz refused (status %d)", reply[0]);
    CHECK(radio.log.empty(), "switched before the reply could go out");
    run(s, 2000);
    CHECK(radio.log.size() == 1 && radio.log[0] == "temp 919.000 500.0 5 5", "temp radio: %s", radio.log.empty() ? "-" : radio.log[0].c_str());
    run(s, 60 * 1000);
    CHECK(radio.log.size() == 1, "dropped back while OTA traffic was still recent");
    for (int i = 0; i < 20; i++) {   // keep-alive: any OTA request resets the idle timer
      uint8_t st[] = {LORA_OTA_REQ_STATUS, 0, 0, 0, 0, 0, 0};
      s.handleRequest(st, sizeof st, reply, 7);
      run(s, 5000);
    }
    CHECK(radio.log.size() == 1, "dropped back during a live transfer");
    run(s, 91 * 1000);
    CHECK(radio.log.size() == 2 && radio.log[1] == "restore", "never dropped back after going quiet");
    auto bad = radioReq(919000, 500001, 5, 5, 90);
    s.handleRequest(bad.data(), bad.size(), reply, 7);
    CHECK(reply[0] == lora_ota::BAD_ARG, "501 kHz accepted");
    auto bad2 = radioReq(919000, 125000, 4, 5, 90);
    s.handleRequest(bad2.data(), bad2.size(), reply, 7);
    CHECK(reply[0] == lora_ota::BAD_ARG, "SF4 accepted");
  }
  { // an unconfirmed image: probation starts on the first loop pass, CONFIRM keeps it and names it
    plat = FakePlatform(); plat.pending_at_boot = true;
    FakeRadio radio; LoraOTAService s; s.begin(radio);
    CHECK(!plat.probation, "probation armed inside setup()");
    run(s, 100);
    CHECK(plat.probation, "probation never armed");
    uint8_t c[] = {LORA_OTA_REQ_CONFIRM, 0, 0, 0};
    int n = s.handleRequest(c, sizeof c, reply, 7);
    CHECK(n == 14 && reply[0] == lora_ota::OK && reply[1] == 1 && plat.confirmed, "confirm (n=%d)", n);
    CHECK(reply[6] == 0xAB && reply[13] == 0xAB, "CONFIRM does not carry the running image's sha");
    run(s, 120 * 1000);
    CHECK(!plat.rolled_back, "rolled back a confirmed image");
  }
  { // no CONFIRM: rolls back at LORA_OTA_CONFIRM_SECS
    plat = FakePlatform(); plat.pending_at_boot = true;
    FakeRadio radio; LoraOTAService s; s.begin(radio);
    run(s, (LORA_OTA_CONFIRM_SECS - 2) * 1000);
    CHECK(!plat.rolled_back, "rolled back early");
    run(s, 4000);
    CHECK(plat.rolled_back, "never rolled back");
  }
  printf(fails ? "%d FAILED\n" : "all passed\n", fails);
  return fails ? 1 : 0;
}

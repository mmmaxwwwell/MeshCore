// Host simulator for the LoRa OTA receiver: the firmware's own
// lora_ota::Receiver over a RAM "flash" that behaves like NOR (erase -> 0xFF,
// writes can only clear bits), behind a pipe that loses packets.
//
// stdin:  frames  u16 len, request (type byte first)
// stdout: one frame per request: u16 len, reply body (len 0 = nothing heard)
// Two control frames that never reach the receiver (reply: empty):
//   0xF0 ms u32   time passes on the target (a paced sender's gaps)
//   0xF1          the target reboots: a new Receiver over the same flash
//
//   ota_sim --board TAG --pubkey HEX [--capacity N] [--drop PCT] [--seed N]
//           [--corrupt-chunk I] [--pending] [--no-persist] --out FILE
//           [--base FILE --base-sha8 HEX [--patch-capacity N]]   (delta: the running image)

#include "LoraOTA.h"
#include "LoraOTADelta.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

static int hexval(char c) { return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10; }

class RamFlash : public lora_ota::Flash, public lora_ota::NorSessionStore {
public:
  std::vector<uint8_t> mem, sess = std::vector<uint8_t>(4096, 0x00);
  size_t erased = 0, activated = 0, saves = 0;
  long corrupt_off = -1;
  bool persist = true;
  RamFlash(size_t cap) : mem(cap, 0x00) { }
  // the session record: NOR too (a rewrite can only clear bits)
  bool reattach(size_t len) override { return persist && len <= erased; }
  bool saveSession(const uint8_t* h, size_t hl, const uint8_t* b, size_t bl, bool fresh) override {
    saves++;
    return persist && save(h, hl, b, bl, fresh);
  }
  bool loadSession(uint8_t* h, size_t hl, uint8_t* b, size_t bl) override { return persist && load(h, hl, b, bl); }
  void clearSession() override { if (persist) clear(); }
  bool sessErase() override { memset(sess.data(), 0xFF, sess.size()); return true; }
  bool sessWrite(size_t off, const uint8_t* src, size_t len) override {
    for (size_t i = 0; i < len; i++) sess[off + i] &= src[i];
    return true;
  }
  bool sessRead(size_t off, uint8_t* dest, size_t len) override { memcpy(dest, &sess[off], len); return true; }
  size_t sessSize() override { return sess.size(); }
  size_t capacity() override { return mem.size(); }
  bool erase(size_t len) override {
    erased = len;
    memset(mem.data(), 0xFF, len);
    return true;
  }
  bool write(size_t off, const uint8_t* src, size_t len) override {
    if (off + len > erased) { fprintf(stderr, "sim: write past erased range\n"); return false; }
    for (size_t i = 0; i < len; i++) {
      uint8_t b = src[i];
      if ((long)(off + i) == corrupt_off) { b ^= 0x01; corrupt_off = -1; }   // one bad write, once
      mem[off + i] &= b;   // NOR: a rewrite with different data corrupts, as on the chip
    }
    return true;
  }
  bool read(size_t off, uint8_t* dest, size_t len) override {
    memcpy(dest, &mem[off], len);
    return true;
  }
  bool activate(size_t len) override {
    activated = len;
    return true;
  }
};

// the running image (read-only) + a NOR area for the patch
class RamDelta : public lora_ota::DeltaStore {
public:
  std::vector<uint8_t> base;
  uint8_t sha8[8];
  RamFlash patch;
  bool done_called = false, persist = true;
  RamDelta(size_t cap) : patch(cap) { }
  bool baseSha8(uint8_t out[8]) override { memcpy(out, sha8, 8); return true; }
  size_t baseSize() override { return base.size(); }
  bool readBase(size_t off, uint8_t* dest, size_t len) override {
    if (off + len > base.size()) return false;
    memcpy(dest, &base[off], len);
    return true;
  }
  lora_ota::Status patchPrepare(size_t new_size, size_t patch_size) override {
    if (patch_size > patch.capacity()) return lora_ota::TOO_BIG;
    return patch.erase(patch_size) ? lora_ota::OK : lora_ota::FLASH_ERROR;
  }
  bool patchWrite(size_t off, const uint8_t* src, size_t len) override { return patch.write(off, src, len); }
  bool patchRead(size_t off, uint8_t* dest, size_t len) override {
    if (off + len > patch.erased) return false;
    return patch.read(off, dest, len);
  }
  void patchDone() override { done_called = true; patch.erased = 0; }   // e.g. LittleFS deletes the file
  bool patchReattach(size_t new_size, size_t patch_size) override { return persist && patch_size <= patch.erased; }
};

static bool readFull(uint8_t* p, size_t n) { return fread(p, 1, n, stdin) == n; }

int main(int argc, char** argv) {
  const char *board = NULL, *pubhex = NULL, *out = NULL;
  size_t capacity = 0x140000;
  int drop = 0;
  unsigned seed = 1;
  long corrupt = -1;
  bool pending = false, persist = true;
  const char *base_path = NULL, *base_sha = NULL;
  size_t patch_cap = 0x80000;
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--board")) board = argv[++i];
    else if (!strcmp(argv[i], "--pubkey")) pubhex = argv[++i];
    else if (!strcmp(argv[i], "--capacity")) capacity = strtoul(argv[++i], NULL, 0);
    else if (!strcmp(argv[i], "--drop")) drop = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--seed")) seed = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--corrupt-chunk")) corrupt = atol(argv[++i]);
    else if (!strcmp(argv[i], "--pending")) pending = true;
    else if (!strcmp(argv[i], "--no-persist")) persist = false;
    else if (!strcmp(argv[i], "--out")) out = argv[++i];
    else if (!strcmp(argv[i], "--base")) base_path = argv[++i];
    else if (!strcmp(argv[i], "--base-sha8")) base_sha = argv[++i];
    else if (!strcmp(argv[i], "--patch-capacity")) patch_cap = strtoul(argv[++i], NULL, 0);
  }
  if (!board || !pubhex || strlen(pubhex) != 64 || !out) { fprintf(stderr, "usage: see source\n"); return 2; }
  uint8_t pub[32];
  for (int i = 0; i < 32; i++) pub[i] = hexval(pubhex[2 * i]) << 4 | hexval(pubhex[2 * i + 1]);
  srand(seed);

  RamFlash flash(capacity);
  flash.persist = persist;
  long corrupt_chunk = corrupt;   // byte offset known once BEGIN fixes the chunk size
  lora_ota::Receiver* rx = new lora_ota::Receiver(flash, pub, board);
  static RamDelta delta(patch_cap);   // like the flash, it outlives a reboot
  delta.persist = persist;
  if (base_path) {
    FILE* f = fopen(base_path, "rb");
    if (!f || !base_sha || strlen(base_sha) != 16) { fprintf(stderr, "sim: --base needs a file and --base-sha8\n"); return 2; }
    uint8_t buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) delta.base.insert(delta.base.end(), buf, buf + n);
    fclose(f);
    for (int i = 0; i < 8; i++) delta.sha8[i] = hexval(base_sha[2 * i]) << 4 | hexval(base_sha[2 * i + 1]);
    rx->setDelta(&delta);
  }

  uint32_t now = 0;
  uint8_t req[256], reply[256];
  unsigned n_req = 0, n_dropped = 0, reboots = 0;
  for (;;) {
    uint8_t hdr[2];
    if (!readFull(hdr, 2)) break;
    size_t len = hdr[0] | hdr[1] << 8;
    if (len > sizeof(req) || !readFull(req, len)) break;
    if (len >= 1 && (req[0] == 0xF0 || req[0] == 0xF1)) {
      if (req[0] == 0xF0 && len >= 5) {   // time passes, in steps: the main loop keeps running
        uint32_t ms = req[1] | req[2] << 8 | req[3] << 16 | (uint32_t)req[4] << 24;
        for (uint32_t t = 0; t < ms; ) {
          uint32_t step = ms - t < 10000 ? ms - t : 10000;
          now += step; t += step;
          rx->loop(now);
        }
      } else if (req[0] == 0xF1) {
        delete rx;   // RAM is gone; the flash stays
        rx = new lora_ota::Receiver(flash, pub, board);
        if (base_path) rx->setDelta(&delta);
        reboots++;
      }
      uint8_t z[2] = {0, 0};
      fwrite(z, 1, 2, stdout);
      fflush(stdout);
      continue;
    }
    now += 50;
    n_req++;
    int n = 0;
    if (rand() % 100 < drop) {
      n_dropped++;                        // request lost on air
    } else {
      n = rx->handle(req, len, reply, now, (uint32_t)rand() | 1, pending);
      if (req[0] == LORA_OTA_REQ_BEGIN && n >= 8 && reply[0] == 0 && corrupt_chunk >= 0 && flash.corrupt_off < 0) {
        RamFlash& target = base_path ? delta.patch : flash;   // a delta's chunks land in the patch area
        target.corrupt_off = corrupt_chunk * reply[5];
        corrupt_chunk = -1;
      }
      if (n > 0 && rand() % 100 < drop) { n = 0; n_dropped++; }   // reply lost on air
    }
    rx->loop(now);
    rx->poll(now);   // the main loop's turn: BEGIN/FINISH work happens here
    uint8_t oh[2] = { (uint8_t)n, (uint8_t)(n >> 8) };
    fwrite(oh, 1, 2, stdout);
    fwrite(reply, 1, n, stdout);
    fflush(stdout);
  }

  fprintf(stderr, "sim: %u requests, %u lost, %u reboots, %zu session saves, activated %zu bytes%s\n",
          n_req, n_dropped, reboots, flash.saves, flash.activated, base_path && delta.done_called ? ", patch area released" : "");
  if (flash.activated) {
    FILE* f = fopen(out, "wb");
    fwrite(flash.mem.data(), 1, flash.activated, f);
    fclose(f);
  }
  return 0;
}

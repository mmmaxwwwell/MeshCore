// Host simulator for the LoRa OTA receiver: the firmware's own
// lora_ota::Receiver over a RAM "flash" that behaves like NOR (erase -> 0xFF,
// writes can only clear bits), behind a pipe that loses packets.
//
// stdin:  frames  u16 len, request (type byte first)
// stdout: one frame per request: u16 len, reply body (len 0 = nothing heard)
//
//   ota_sim --board TAG --pubkey HEX [--capacity N] [--drop PCT] [--seed N]
//           [--corrupt-chunk I] [--pending] --out FILE

#include "LoraOTA.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

static int hexval(char c) { return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10; }

class RamFlash : public lora_ota::Flash {
public:
  std::vector<uint8_t> mem;
  size_t erased = 0, activated = 0;
  long corrupt_off = -1;
  RamFlash(size_t cap) : mem(cap, 0x00) { }
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

static bool readFull(uint8_t* p, size_t n) { return fread(p, 1, n, stdin) == n; }

int main(int argc, char** argv) {
  const char *board = NULL, *pubhex = NULL, *out = NULL;
  size_t capacity = 0x140000;
  int drop = 0;
  unsigned seed = 1;
  long corrupt = -1;
  bool pending = false;
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--board")) board = argv[++i];
    else if (!strcmp(argv[i], "--pubkey")) pubhex = argv[++i];
    else if (!strcmp(argv[i], "--capacity")) capacity = strtoul(argv[++i], NULL, 0);
    else if (!strcmp(argv[i], "--drop")) drop = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--seed")) seed = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--corrupt-chunk")) corrupt = atol(argv[++i]);
    else if (!strcmp(argv[i], "--pending")) pending = true;
    else if (!strcmp(argv[i], "--out")) out = argv[++i];
  }
  if (!board || !pubhex || strlen(pubhex) != 64 || !out) { fprintf(stderr, "usage: see source\n"); return 2; }
  uint8_t pub[32];
  for (int i = 0; i < 32; i++) pub[i] = hexval(pubhex[2 * i]) << 4 | hexval(pubhex[2 * i + 1]);
  srand(seed);

  RamFlash flash(capacity);
  if (corrupt >= 0) flash.corrupt_off = corrupt * LORA_OTA_CHUNK;
  static lora_ota::Receiver rx(flash, pub, board);

  uint32_t now = 0;
  uint8_t req[256], reply[256];
  unsigned n_req = 0, n_dropped = 0;
  for (;;) {
    uint8_t hdr[2];
    if (!readFull(hdr, 2)) break;
    size_t len = hdr[0] | hdr[1] << 8;
    if (len > sizeof(req) || !readFull(req, len)) break;
    now += 50;
    n_req++;
    int n = 0;
    if (rand() % 100 < drop) {
      n_dropped++;                        // request lost on air
    } else {
      n = rx.handle(req, len, reply, now, (uint32_t)rand() | 1, pending);
      if (n > 0 && rand() % 100 < drop) { n = 0; n_dropped++; }   // reply lost on air
    }
    uint8_t oh[2] = { (uint8_t)n, (uint8_t)(n >> 8) };
    fwrite(oh, 1, 2, stdout);
    fwrite(reply, 1, n, stdout);
    fflush(stdout);
  }

  fprintf(stderr, "sim: %u requests, %u lost, activated %zu bytes\n", n_req, n_dropped, flash.activated);
  if (flash.activated) {
    FILE* f = fopen(out, "wb");
    fwrite(flash.mem.data(), 1, flash.activated, f);
    fclose(f);
  }
  return 0;
}

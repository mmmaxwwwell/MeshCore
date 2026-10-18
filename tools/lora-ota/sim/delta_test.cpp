// Host test of the firmware's delta decoder (src/helpers/LoraOTADelta.cpp):
// decodes a patch made by tools/lora-ota/delta.py and compares the result,
// in small and odd step budgets (the decoder is a resumable state machine),
// then feeds it corrupted and truncated copies, which must fail cleanly
// (build with -fsanitize=address,undefined to catch an out-of-bounds read).
//
//   delta_test BASE NEW PATCH [FUZZ_ROUNDS]
// exit 0 = all good

#include "LoraOTADelta.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

static std::vector<uint8_t> load(const char* path) {
  std::vector<uint8_t> v;
  FILE* f = fopen(path, "rb");
  if (!f) { perror(path); exit(2); }
  uint8_t buf[4096];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) v.insert(v.end(), buf, buf + n);
  fclose(f);
  return v;
}

class OutFlash : public lora_ota::Flash {
public:
  std::vector<uint8_t> mem;
  size_t high = 0;
  bool in_order = true;
  OutFlash(size_t n) : mem(n, 0xFF) { }
  size_t capacity() override { return mem.size(); }
  bool erase(size_t len) override { memset(mem.data(), 0xFF, len); return true; }
  bool write(size_t off, const uint8_t* src, size_t len) override {
    if (off + len > mem.size()) return false;
    if (off != high) in_order = false;   // the decoder must write strictly front to back
    for (size_t i = 0; i < len; i++) mem[off + i] &= src[i];
    high = off + len;
    return true;
  }
  bool read(size_t off, uint8_t* dest, size_t len) override { memcpy(dest, &mem[off], len); return true; }
  bool activate(size_t) override { return true; }
};

class Store : public lora_ota::DeltaStore {
public:
  const std::vector<uint8_t>* base;
  std::vector<uint8_t> patch;
  bool baseSha8(uint8_t out[8]) override { memset(out, 0, 8); return true; }
  size_t baseSize() override { return base->size(); }
  bool readBase(size_t off, uint8_t* dest, size_t len) override {
    if (off + len > base->size()) { fprintf(stderr, "base read out of range\n"); exit(3); }
    memcpy(dest, base->data() + off, len);
    return true;
  }
  lora_ota::Status patchPrepare(size_t, size_t) override { return lora_ota::OK; }
  bool patchWrite(size_t, const uint8_t*, size_t) override { return false; }
  bool patchRead(size_t off, uint8_t* dest, size_t len) override {
    if (off + len > patch.size()) { fprintf(stderr, "patch read out of range\n"); exit(3); }
    memcpy(dest, patch.data() + off, len);
    return true;
  }
};

static lora_ota::DeltaDecoder dec;   // ~2.8 KB: static, like on the radio

// 1 = decoded, -1 = refused, writes into out
static int decode(Store& s, OutFlash& out, uint32_t new_size, uint32_t budget) {
  if (!dec.start(&s, &out, s.patch.size(), new_size)) return -1;
  for (long guard = 0; guard < 100000000L; guard++) {
    int r = dec.step(budget);
    if (r != 0) return r;
  }
  fprintf(stderr, "decoder does not terminate\n");
  exit(3);
}

int main(int argc, char** argv) {
  if (argc < 4) { fprintf(stderr, "usage: delta_test BASE NEW PATCH [FUZZ_ROUNDS]\n"); return 2; }
  std::vector<uint8_t> base = load(argv[1]), want = load(argv[2]);
  Store s;
  s.base = &base;
  s.patch = load(argv[3]);
  int rounds = argc > 4 ? atoi(argv[4]) : 0;
  int fails = 0;

  const uint32_t budgets[] = { LORA_OTA_DELTA_STEP, 1, 7, 4096 };
  for (uint32_t b : budgets) {
    OutFlash out(want.size() + 4096);
    int r = decode(s, out, want.size(), b);
    bool ok = r == 1 && out.high == want.size() && memcmp(out.mem.data(), want.data(), want.size()) == 0 && out.in_order;
    printf("%s decode, step budget %u\n", ok ? "PASS" : "FAIL", b);
    if (!ok) fails++;
  }

  {   // the signed size must match the patch's
    OutFlash out(want.size() + 4096);
    bool ok = decode(s, out, want.size() + 1, LORA_OTA_DELTA_STEP) == -1;
    printf("%s refuses a patch for another image size\n", ok ? "PASS" : "FAIL");
    if (!ok) fails++;
  }
  if (!base.empty()) {   // a patch that wants more base than the target runs
    std::vector<uint8_t> shorter(base.begin(), base.end() - 1);
    Store s2 = s;
    s2.base = &shorter;
    OutFlash out(want.size() + 4096);
    bool ok = decode(s2, out, want.size(), LORA_OTA_DELTA_STEP) == -1;
    printf("%s refuses a base smaller than the patch's\n", ok ? "PASS" : "FAIL");
    if (!ok) fails++;
  }

  // corrupted / truncated patches: never crash, never write past the image,
  // and anything "decoded" is caught later by the signed sha (not here)
  srand(1);
  int refused = 0, wrong = 0, same = 0;
  for (int i = 0; i < rounds; i++) {
    Store c = s;
    int kind = rand() % 3;
    if (kind == 0) {
      size_t at = LORA_OTA_DELTA_HDR + rand() % (c.patch.size() - LORA_OTA_DELTA_HDR);
      c.patch[at] ^= 1 + rand() % 255;
    } else if (kind == 1) {
      c.patch.resize(rand() % c.patch.size());
    } else {
      for (int k = 0; k < 8; k++) {
        size_t at = LORA_OTA_DELTA_HDR + rand() % (c.patch.size() - LORA_OTA_DELTA_HDR);
        c.patch[at] = rand();
      }
    }
    OutFlash out(want.size() + 4096);
    int r = decode(c, out, want.size(), 1 + rand() % 5000);
    if (out.high > want.size() || !out.in_order) {
      printf("FAIL fuzz round %d wrote out of range\n", i);
      fails++;
    }
    if (r < 0) refused++;
    else if (memcmp(out.mem.data(), want.data(), want.size()) == 0) same++;
    else wrong++;
  }
  if (rounds) printf("PASS fuzz: %d rounds, %d refused, %d decoded to another image (the sha catches those), %d harmless\n",
                     rounds, refused, wrong, same);
  return fails ? 1 : 0;
}

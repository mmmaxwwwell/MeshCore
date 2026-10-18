// Host test for the nRF52 staging trick (src/helpers/LoraOTALfs.h): a file
// written full of 0xFF in littlefs v1, mapped to physical extents, then
// programmed raw out of order must read back as the image, both through
// littlefs and straight from the extents (what the RAM install copies), and
// must survive a remount and later filesystem traffic.
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include "LoraOTALfs.h"

extern "C" void* pvPortMalloc(size_t n) { return malloc(n); }   // Adafruit's littlefs allocates via FreeRTOS
extern "C" void vPortFree(void* p) { free(p); }

static const uint32_t BS = 4096, BLOCKS = 512;   // 2 MB, like the L1's P25Q16H
static std::vector<uint8_t> chip(BS * BLOCKS, 0xFF);
static int fails = 0;
#define CHECK(c, ...) do { if (!(c)) { printf("FAIL " __VA_ARGS__); printf("\n"); fails++; } } while (0)

static int bd_read(const struct lfs_config*, lfs_block_t b, lfs_off_t o, void* buf, lfs_size_t n) { memcpy(buf, &chip[b * BS + o], n); return 0; }
static int bd_prog(const struct lfs_config*, lfs_block_t b, lfs_off_t o, const void* buf, lfs_size_t n) {
  for (lfs_size_t i = 0; i < n; i++) chip[b * BS + o + i] &= ((const uint8_t*)buf)[i];   // NOR
  return 0;
}
static int bd_erase(const struct lfs_config*, lfs_block_t b) { memset(&chip[b * BS], 0xFF, BS); return 0; }
static int bd_sync(const struct lfs_config*) { return 0; }

static void rawWrite(const ImageMap& m, uint32_t off, const uint8_t* src, uint32_t len) {
  uint32_t pos = 0;
  for (uint16_t e = 0; e < m.n && len; e++) {
    const Extent& x = m.ext[e];
    if (off < pos + x.len) {
      uint32_t in = off - pos, n = x.len - in < len ? x.len - in : len;
      for (uint32_t i = 0; i < n; i++) chip[x.addr + in + i] &= src[i];
      src += n; off += n; len -= n;
    }
    pos += x.len;
  }
}

int main() {
  static uint8_t rbuf[256], pbuf[256], look[32];
  struct lfs_config cfg = {};
  cfg.read = bd_read; cfg.prog = bd_prog; cfg.erase = bd_erase; cfg.sync = bd_sync;
  cfg.read_size = 256; cfg.prog_size = 256; cfg.block_size = BS; cfg.block_count = BLOCKS;
  cfg.lookahead = 32; cfg.read_buffer = rbuf; cfg.prog_buffer = pbuf; cfg.lookahead_buffer = look;
  lfs_t lfs;
  CHECK(lfs_format(&lfs, &cfg) == 0, "format");
  CHECK(lfs_mount(&lfs, &cfg) == 0, "mount");

  // fragment the free space first, like a companion's contacts/messages store
  std::vector<uint8_t> junk(150000, 0x5A);
  for (int i = 0; i < 6; i++) {
    char p[16]; snprintf(p, sizeof p, "/junk%d", i);
    CHECK(lfsWriteFile(&lfs, p, junk.data(), 30000 + i * 7000, false), "junk %d", i);
  }
  lfs_remove(&lfs, "/junk1"); lfs_remove(&lfs, "/junk3"); lfs_remove(&lfs, "/junk4");

  const uint32_t SIZE = 420216;   // the L1 companion image
  std::vector<uint8_t> img(SIZE);
  srand(9);
  for (auto& b : img) b = rand();

  CHECK(lfsWriteFile(&lfs, "/ota-new.bin", NULL, SIZE, true), "fill file");
  static ImageMap m;
  CHECK(lfsMapFile(&lfs, "/ota-new.bin", SIZE, m), "map");
  uint32_t total = 0;
  for (uint16_t e = 0; e < m.n; e++) {
    CHECK(m.ext[e].addr % 4 == 0, "extent %u unaligned", e);
    CHECK(m.ext[e].addr / BS == (m.ext[e].addr + m.ext[e].len - 1) / BS, "extent %u crosses a block", e);
    total += m.ext[e].len;
  }
  CHECK(total == SIZE, "extents cover %u of %u", total, SIZE);
  printf("%u extents\n", m.n);

  // chunks arrive out of order, some twice
  const uint32_t CH = 156, N = (SIZE + CH - 1) / CH;
  std::vector<uint32_t> order(N);
  for (uint32_t i = 0; i < N; i++) order[i] = i;
  for (uint32_t i = N - 1; i > 0; i--) { uint32_t j = rand() % (i + 1); std::swap(order[i], order[j]); }
  for (uint32_t k = 0; k < N + N / 10; k++) {
    uint32_t i = order[k % N], len = i == N - 1 ? SIZE - i * CH : CH;
    rawWrite(m, i * CH, &img[i * CH], len);
  }

  std::vector<uint8_t> direct;   // what the install routine copies
  for (uint16_t e = 0; e < m.n; e++) direct.insert(direct.end(), &chip[m.ext[e].addr], &chip[m.ext[e].addr] + m.ext[e].len);
  CHECK(direct == img, "extents read back differs");

  auto readFile = [&](const char* p) {
    std::vector<uint8_t> out(SIZE + 16);
    lfs_file_t f;
    if (lfs_file_open(&lfs, &f, p, LFS_O_RDONLY) < 0) return std::vector<uint8_t>();
    lfs_ssize_t n = lfs_file_read(&lfs, &f, out.data(), out.size());
    lfs_file_close(&lfs, &f);
    out.resize(n < 0 ? 0 : n);
    return out;
  };
  CHECK(readFile("/ota-new.bin") == img, "littlefs read back differs");

  // remount, keep using the filesystem: the staged file must not move or change
  lfs_unmount(&lfs);
  CHECK(lfs_mount(&lfs, &cfg) == 0, "remount");
  for (int i = 0; i < 20; i++) {
    char p[16]; snprintf(p, sizeof p, "/later%d", i);
    CHECK(lfsWriteFile(&lfs, p, junk.data(), 20000, false), "later %d", i);
    if (i % 3 == 0) lfs_remove(&lfs, p);
  }
  CHECK(readFile("/ota-new.bin") == img, "file changed after more traffic");
  static ImageMap m2;
  CHECK(lfsMapFile(&lfs, "/ota-new.bin", SIZE, m2) && m2.n == m.n &&
        memcmp(m2.ext, m.ext, m.n * sizeof(Extent)) == 0, "extents moved");

  // a backup of the running image, the other file the install needs
  CHECK(lfsWriteFile(&lfs, "/ota-old.bin", img.data(), SIZE, false), "backup");
  CHECK(readFile("/ota-old.bin") == img, "backup read back");
  CHECK(readFile("/ota-new.bin") == img, "staged file hurt by the backup");

  printf(fails ? "%d FAILED\n" : "all passed\n", fails);
  return fails ? 1 : 0;
}

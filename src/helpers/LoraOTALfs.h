#pragma once

// littlefs helpers for staging a LoRa OTA image on nRF52 (LoraOTANrf52.cpp),
// kept free of Arduino so tools/lora-ota/sim can test them against littlefs
// on a simulated flash chip.

#include <stdint.h>
#include <string.h>
#ifdef ARDUINO
  #include <Adafruit_LittleFS.h>
#else
  #include "lfs.h"
#endif

#ifndef LORA_OTA_MAX_EXTENTS
  #define LORA_OTA_MAX_EXTENTS  384   // 1.5 MB of 4 KB blocks
#endif

struct Extent { uint32_t addr, len; };   // a run of image bytes at a flash address
struct ImageMap { uint32_t size; uint16_t n; Extent ext[LORA_OTA_MAX_EXTENTS]; };

// Physical extents of a file's first `size` bytes. Reading one byte resolves
// the file's current block/offset (littlefs v1 skips each block's ctz
// pointers), so each extent runs from there to the end of that block.
static inline bool lfsMapFile(lfs_t* l, const char* path, uint32_t size, ImageMap& m) {
  lfs_file_t f;
  m.size = size;
  m.n = 0;
  if (lfs_file_open(l, &f, path, LFS_O_RDONLY) < 0) return false;
  bool ok = true;
  uint8_t b;
  uint32_t bs = l->cfg->block_size;
  for (uint32_t pos = 0; pos < size; ) {
    if (lfs_file_seek(l, &f, pos, LFS_SEEK_SET) < 0 || lfs_file_read(l, &f, &b, 1) != 1) { ok = false; break; }
    uint32_t off = f.off - 1;
    uint32_t run = bs - off;
    if (run > size - pos) run = size - pos;
    if (m.n == LORA_OTA_MAX_EXTENTS || (off & 3)) { ok = false; break; }
    m.ext[m.n].addr = f.block * bs + off;
    m.ext[m.n].len = run;
    m.n++;
    pos += run;
  }
  lfs_file_close(l, &f);
  return ok;
}

// Write `size` bytes of src (or of 0xFF: allocated, still-erased blocks) as a new file.
// Always through a word-aligned RAM buffer: littlefs v1 hands an aligned full-page
// write straight to the block device, and nRF52 QSPI DMA cannot read internal
// flash (src is the running app when backing it up) or unaligned memory.
static inline bool lfsWriteFile(lfs_t* l, const char* path, const uint8_t* src, uint32_t size, bool fill_ff) {
  lfs_remove(l, path);
  lfs_file_t f;
  if (lfs_file_open(l, &f, path, LFS_O_WRONLY | LFS_O_CREAT | LFS_O_TRUNC) < 0) return false;
  static uint32_t words[64];
  uint8_t* buf = (uint8_t*)words;
  bool ok = true;
  for (uint32_t pos = 0; pos < size && ok; ) {
    uint32_t n = size - pos < sizeof(words) ? size - pos : sizeof(words);
    if (fill_ff) memset(buf, 0xFF, n); else memcpy(buf, src + pos, n);
    ok = lfs_file_write(l, &f, buf, n) == (lfs_ssize_t)n;
    pos += n;
  }
  return lfs_file_close(l, &f) >= 0 && ok;
}

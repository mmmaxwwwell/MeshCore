#pragma once

// The filesystem half of a lora_ota_maint::Target for the apps (companion,
// repeater, room server): file listing, delete, usage and the counter record
// on Arduino filesystems. Header-only and included only by the apps, so the
// platform-neutral LoraOTAMaint.cpp stays buildable on the host.

#include "LoraOTAMaint.h"

#ifdef LORA_OTA_ENABLED

#include <Arduino.h>
#include "IdentityStore.h"   // FILESYSTEM
#if defined(ESP32)
  #include <SPIFFS.h>
#endif

#define LORA_OTA_MAINT_FILE "/ota_maint"   // the replay counter (primary FS; a format of the secondary never touches it)

class LoraOTAMaintFsTarget : public lora_ota_maint::Target {
protected:
  FILESYSTEM* _fs[2];

  static File openRead(FILESYSTEM* fs, const char* path) {
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
    return fs->open(path, FILE_O_READ);
#elif defined(RP2040_PLATFORM)
    return fs->open(path, "r");
#else
    return fs->open(path, "r", false);
#endif
  }
  static File openWrite(FILESYSTEM* fs, const char* path) {
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
    fs->remove(path);
    return fs->open(path, FILE_O_WRITE);
#elif defined(RP2040_PLATFORM)
    return fs->open(path, "w");
#else
    return fs->open(path, "w", true);
#endif
  }
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  static int countBlock(void* p, lfs_block_t block) {
    (void)block;
    *(lfs_size_t*)p += 1;
    return 0;
  }
#endif

public:
  LoraOTAMaintFsTarget(FILESYSTEM* primary, FILESYSTEM* secondary) { _fs[0] = primary; _fs[1] = secondary; }

  bool hasFs(int f) override { return (f == 0 || f == 1) && _fs[f] != NULL; }

  bool storage(int f, uint32_t& used_kb, uint32_t& total_kb) override {
    if (!hasFs(f)) return false;
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
    lfs_t* l = _fs[f]->_getFS();
    if (!l || !l->cfg) return false;
    lfs_size_t blocks = 0;
    _fs[f]->_lockFS();
    int err = lfs_traverse(l, countBlock, &blocks);
    _fs[f]->_unlockFS();
    if (err) return false;
    used_kb = (uint32_t)(blocks * l->cfg->block_size / 1024);
    total_kb = (uint32_t)(l->cfg->block_count * l->cfg->block_size / 1024);
    return true;
#elif defined(ESP32)
    if (_fs[f] != (FILESYSTEM*)&SPIFFS) return false;
    used_kb = SPIFFS.usedBytes() / 1024;
    total_kb = SPIFFS.totalBytes() / 1024;
    return true;
#else
    return false;
#endif
  }

  int listDir(int f, const char* dir, int index, lora_ota_maint::FileEntry& e) override {
    if (!hasFs(f)) return -1;
    File root = openRead(_fs[f], dir);
    if (!root) return -1;
    if (!root.isDirectory()) { root.close(); return -1; }
    int got = 0;
    for (int i = 0;; i++) {
      File file = root.openNextFile();
      if (!file) break;
      if (i == index) {
        const char* nm = file.name();
        const char* slash = strrchr(nm, '/');   // some cores give the whole path
        strncpy(e.name, slash ? slash + 1 : nm, sizeof(e.name) - 1);
        e.name[sizeof(e.name) - 1] = 0;
        e.dir = file.isDirectory();
        e.size = e.dir ? 0 : file.size();
        file.close();
        got = 1;
        break;
      }
      file.close();
    }
    root.close();
    return got;
  }

  bool exists(int f, const char* path, bool& dir) override {
    if (!hasFs(f) || !_fs[f]->exists(path)) return false;
    File file = openRead(_fs[f], path);
    if (!file) return false;
    dir = file.isDirectory();
    file.close();
    return true;
  }

  bool removeFile(int f, const char* path) override { return hasFs(f) && _fs[f]->remove(path); }

  int loadState(uint8_t* buf, size_t max) override {
    if (!_fs[0]->exists(LORA_OTA_MAINT_FILE)) return 0;
    File file = openRead(_fs[0], LORA_OTA_MAINT_FILE);
    if (!file) return 0;
    int n = file.read(buf, max);
    file.close();
    return n;
  }
  bool saveState(const uint8_t* buf, size_t len) override {
    File file = openWrite(_fs[0], LORA_OTA_MAINT_FILE);
    if (!file) return false;
    bool ok = file.write(buf, len) == len;
    file.close();
    return ok;
  }
};

#endif

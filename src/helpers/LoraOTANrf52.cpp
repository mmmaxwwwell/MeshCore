// LoRa OTA on nRF52840 boards whose app keeps a LittleFS on QSPI flash
// (QSPIFLASH: the Wio Tracker L1 companions).
//
// The Adafruit bootloader has no rollback and the app region cannot hold two
// images, so:
//  * A new image is staged as a file in the QSPI LittleFS. BEGIN writes the
//    file full of 0xFF (so its blocks are allocated and still erased), records
//    each block's physical QSPI address, and chunks are then programmed raw at
//    those addresses (littlefs v1 does not checksum file data).
//  * Install backs the running image up to a second file, then a routine that
//    runs from RAM (SoftDevice off, interrupts off) copies the staged file into
//    the app region and resets. The bootloader settings say "invalid app"
//    while the app region is half written, so a power cut there leaves the
//    radio in the bootloader's BLE/USB DFU mode, never jumping into half an
//    image. The copy is verified; if it will not verify, the backup goes back.
//  * The new image boots on probation: an admin's CONFIRM within
//    LORA_OTA_CONFIRM_SECS, or it installs the backup. A boot counter catches
//    an image that keeps resetting after the OTA service starts, and the
//    hardware watchdog (started by the install, survives soft resets) catches
//    one that hangs. NOT covered: an image that dies before the OTA service
//    starts on every boot (no bootloader help to fall back on).

#include "LoraOTAService.h"

#if defined(LORA_OTA_ENABLED) && defined(NRF52_PLATFORM)

#include <Arduino.h>
#include <nrf.h>
#include <nrf_sdm.h>
#include <Adafruit_LittleFS.h>

#ifndef QSPIFLASH
  #error "LoRa OTA on nRF52 stages the image on the QSPI LittleFS (QSPIFLASH)"
#endif
#include <CustomLFS_QSPIFlash.h>
#define LORA_OTA_MAX_EXTENTS 384
#include "LoraOTALfs.h"

extern "C" uint32_t __flash_arduino_start, __flash_arduino_end, __etext, __data_start__, __data_end__;

#define APP_START    ((uint32_t)&__flash_arduino_start)
#define APP_END      ((uint32_t)&__flash_arduino_end)
#define PAGE         4096
#define BL_SETTINGS  0x000FF000UL   // Adafruit bootloader settings page (nRF52840)
#define BANK_VALID_APP    0x01
#define BANK_INVALID_APP  0xFF
#define WDT_SECS     120
#define MAX_TRIAL_BOOTS 3

#define NEW_PATH   "/ota-new.bin"
#define OLD_PATH   "/ota-old.bin"
#define STATE_PATH "/ota-state"


struct OtaState {
  uint32_t magic;
  uint8_t trial;      // running image is on probation
  uint8_t boots;      // probation boots so far
  uint8_t has_old;    // OLD_PATH holds the image to go back to
  uint8_t rolled_back;
};
#define STATE_MAGIC 0x4D434F31   // "MCO1"

static ImageMap new_map, old_map;   // in RAM: the install routine reads them with flash off

// ---------------------------------------------------------------- littlefs helpers

static lfs_t* lfs() { return QSPIFlash._getFS(); }

static bool mapFile(const char* path, uint32_t size, ImageMap& m) { return lfsMapFile(lfs(), path, size, m); }
static bool writeFile(const char* path, const uint8_t* src, uint32_t size, bool fill_ff) {
  return lfsWriteFile(lfs(), path, src, size, fill_ff);
}

static bool loadState(OtaState& s) {
  lfs_file_t f;
  memset(&s, 0, sizeof(s));
  if (lfs_file_open(lfs(), &f, STATE_PATH, LFS_O_RDONLY) < 0) return false;
  bool ok = lfs_file_read(lfs(), &f, &s, sizeof(s)) == sizeof(s) && s.magic == STATE_MAGIC;
  lfs_file_close(lfs(), &f);
  if (!ok) memset(&s, 0, sizeof(s));
  return ok;
}

static bool saveState(OtaState s) {
  s.magic = STATE_MAGIC;
  return writeFile(STATE_PATH, (const uint8_t*)&s, sizeof(s), false);
}

static uint32_t fileSize(const char* path) {
  struct lfs_info info;
  return lfs_stat(lfs(), path, &info) >= 0 ? info.size : 0;
}

static uint32_t runningImageSize() {
  return ((uint32_t)&__etext - APP_START) + ((uint32_t)&__data_end__ - (uint32_t)&__data_start__);
}

// ---------------------------------------------------------------- the install routine (RAM only)

// Runs while the app region is erased: everything it touches must be in RAM.
// No loop-to-memcpy/memset rewriting (those live in flash), long calls only.
#define RAMFUNC __attribute__((noinline, long_call, section(".data.lora_ota_ram"), \
                               optimize("no-tree-loop-distribute-patterns")))

static uint32_t ram_page[PAGE / 4];
static uint32_t ram_buf[64];   // one QSPI read: 256 bytes

static RAMFUNC void r_nvmc_wait() { while (NRF_NVMC->READY == 0) { } }

static RAMFUNC void r_wdt_feed() {
  if (NRF_WDT->RUNSTATUS) NRF_WDT->RR[0] = WDT_RR_RR_Reload;
}

static RAMFUNC void r_erase(uint32_t addr) {
  NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Een;
  r_nvmc_wait();
  NRF_NVMC->ERASEPAGE = addr;
  r_nvmc_wait();
  NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Ren;
  r_nvmc_wait();
}

static RAMFUNC void r_write_words(uint32_t addr, const uint32_t* src, uint32_t words) {
  NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Wen;
  r_nvmc_wait();
  volatile uint32_t* dst = (volatile uint32_t*)addr;
  for (uint32_t i = 0; i < words; i++) {
    dst[i] = src[i];
    r_nvmc_wait();
  }
  NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Ren;
  r_nvmc_wait();
}

static RAMFUNC bool r_qspi_read(uint32_t qaddr, uint32_t* dst, uint32_t len) {   // len % 4 == 0, <= 256
  NRF_QSPI->EVENTS_READY = 0;
  NRF_QSPI->READ.SRC = qaddr;
  NRF_QSPI->READ.DST = (uint32_t)dst;
  NRF_QSPI->READ.CNT = len;
  NRF_QSPI->TASKS_READSTART = 1;
  for (uint32_t spin = 0; NRF_QSPI->EVENTS_READY == 0; spin++) {
    if (spin > 10000000) return false;
  }
  NRF_QSPI->EVENTS_READY = 0;
  return true;
}

// bootloader settings: bank_0 (u16) @0, bank_0_crc (u16) @2, bank_1 (u16) @4, bank_0_size (u32) @8
static RAMFUNC void r_set_bank0(uint16_t state, uint32_t size) {
  volatile const uint32_t* src = (volatile const uint32_t*)BL_SETTINGS;
  for (uint32_t i = 0; i < PAGE / 4; i++) ram_page[i] = src[i];
  uint16_t* h = (uint16_t*)ram_page;
  h[0] = state;
  h[1] = 0;            // crc 0 = the bootloader does not check one
  if (size) ram_page[2] = size;
  r_erase(BL_SETTINGS);
  r_write_words(BL_SETTINGS, ram_page, PAGE / 4);
}

// copy a mapped image into the app region; true if it reads back identical
static RAMFUNC bool r_copy(const ImageMap* m) {
  uint32_t end = APP_START + ((m->size + PAGE - 1) & ~(PAGE - 1));
  for (uint32_t a = APP_START; a < end; a += PAGE) {
    r_erase(a);
    r_wdt_feed();
  }
  uint32_t dst = APP_START;
  for (uint16_t e = 0; e < m->n; e++) {
    for (uint32_t done = 0; done < m->ext[e].len; ) {
      uint32_t n = m->ext[e].len - done;
      if (n > sizeof(ram_buf)) n = sizeof(ram_buf);
      uint32_t rn = (n + 3) & ~3u;
      if (!r_qspi_read(m->ext[e].addr + done, ram_buf, rn)) return false;
      if (rn != n) {   // the image's last bytes: pad the final word with 0xFF
        volatile uint8_t* b = (volatile uint8_t*)ram_buf;
        for (uint32_t i = n; i < rn; i++) b[i] = 0xFF;
      }
      r_write_words(dst, ram_buf, rn / 4);
      dst += n;
      done += n;
    }
    r_wdt_feed();
  }
  dst = APP_START;   // verify against the source
  for (uint16_t e = 0; e < m->n; e++) {
    for (uint32_t done = 0; done < m->ext[e].len; ) {
      uint32_t n = m->ext[e].len - done;
      if (n > sizeof(ram_buf)) n = sizeof(ram_buf);
      if (!r_qspi_read(m->ext[e].addr + done, ram_buf, (n + 3) & ~3u)) return false;
      volatile const uint8_t* f = (volatile const uint8_t*)dst;
      const uint8_t* b = (const uint8_t*)ram_buf;
      for (uint32_t i = 0; i < n; i++) {
        if (f[i] != b[i]) return false;
      }
      dst += n;
      done += n;
    }
    r_wdt_feed();
  }
  return true;
}

static RAMFUNC __attribute__((noreturn)) void r_install(const ImageMap* first, const ImageMap* fallback) {
  r_set_bank0(BANK_INVALID_APP, 0);   // from here a power cut lands in the bootloader's DFU mode
  const ImageMap* done = NULL;
  for (int attempt = 0; attempt < 2 && !done; attempt++) {
    if (r_copy(first)) done = first;
  }
  for (int attempt = 0; attempt < 2 && !done && fallback; attempt++) {
    if (r_copy(fallback)) done = fallback;
  }
  if (done) r_set_bank0(BANK_VALID_APP, done->size);   // else: stays invalid -> DFU mode

  if (!NRF_WDT->RUNSTATUS) {   // catches a new image that hangs; survives the soft reset below
    NRF_WDT->CONFIG = 0;                     // paused while the CPU sleeps or is halted
    NRF_WDT->CRV = WDT_SECS * 32768;
    NRF_WDT->RREN = WDT_RREN_RR0_Msk;
    NRF_WDT->TASKS_START = 1;
  }
  __DSB();
  SCB->AIRCR = (0x5FAUL << SCB_AIRCR_VECTKEY_Pos) | SCB_AIRCR_SYSRESETREQ_Msk;
  __DSB();
  for (;;) { }
}

static void installNow(const ImageMap* first, const ImageMap* fallback) {
  sd_softdevice_disable();   // flash writes need it off; harmless if it never ran
  __disable_irq();
  r_install(first, fallback);
}

// ---------------------------------------------------------------- staging flash

class QspiFileFlash : public lora_ota::Flash {
public:
  size_t capacity() override {
    // the staged image AND a backup of the running one must fit; the two
    // existing files are replaced, so their blocks count as free
    lfs_t* l = lfs();
    QSPIFlash._lockFS();
    lfs_size_t used = 0;
    lfs_traverse(l, [](void* p, lfs_block_t) -> int { (*(lfs_size_t*)p)++; return 0; }, &used);
    uint32_t bs = l->cfg->block_size;
    uint32_t free_bytes = (l->cfg->block_count - used) * bs + fileSize(NEW_PATH) + fileSize(OLD_PATH);
    QSPIFlash._unlockFS();
    uint32_t need_spare = 16 * bs + runningImageSize() * bs / (bs - 8);   // margin + the backup
    uint32_t room = free_bytes > need_spare ? (free_bytes - need_spare) * (bs - 8) / bs : 0;   // ctz pointers
    uint32_t app = APP_END - APP_START;
    return room < app ? room : app;
  }
  bool erase(size_t len) override {
    QSPIFlash._lockFS();
    bool ok = writeFile(NEW_PATH, NULL, len, true) && mapFile(NEW_PATH, len, new_map);
    QSPIFlash._unlockFS();
    return ok;
  }
  bool write(size_t off, const uint8_t* src, size_t len) override { return rawIO(off, (uint8_t*)src, len, true); }
  bool read(size_t off, uint8_t* dest, size_t len) override { return rawIO(off, dest, len, false); }
  bool activate(size_t len) override { return len == new_map.size; }   // install() does the rest

private:
  bool rawIO(size_t off, uint8_t* buf, size_t len, bool write) {
    QSPIFlash._lockFS();
    bool ok = true;
    uint32_t pos = 0;   // image offset at the start of extent e
    for (uint16_t e = 0; e < new_map.n && len && ok; e++) {
      const Extent& x = new_map.ext[e];
      if (off < pos + x.len) {
        uint32_t in = off - pos, n = x.len - in < len ? x.len - in : len;
        ok = write ? QSPIFlash.rawWrite(x.addr + in, buf, n) : QSPIFlash.rawRead(x.addr + in, buf, n);
        buf += n; off += n; len -= n;
      }
      pos += x.len;
    }
    QSPIFlash._unlockFS();
    return ok && len == 0;
  }
};

// ---------------------------------------------------------------- platform

class Nrf52OtaPlatform : public LoraOTAPlatform {
  QspiFileFlash _flash;
  OtaState _st;
  char _desc[32];

  bool haveFs() { return lfs()->cfg != NULL; }   // mounted by the app before ota.begin()

public:
  lora_ota::Flash* flash() override { return haveFs() ? &_flash : NULL; }

  bool begin() override {
    if (!haveFs()) return false;
    QSPIFlash._lockFS();
    loadState(_st);
    bool pending = _st.trial;
    if (pending) {
      _st.boots++;
      saveState(_st);
    }
    QSPIFlash._unlockFS();
    if (pending && _st.boots > MAX_TRIAL_BOOTS) {
      MESH_DEBUG_PRINTLN("lora ota: new image keeps resetting, rolling back");
      rollback();
    }
    return pending;
  }

  bool confirm() override {
    QSPIFlash._lockFS();
    _st.trial = 0;
    _st.boots = 0;
    bool ok = saveState(_st);
    QSPIFlash._unlockFS();
    return ok;   // the watchdog keeps running (it cannot be stopped): feedWatchdog() carries on
  }

  void rollback() override {
    QSPIFlash._lockFS();
    bool ok = _st.has_old && mapFile(OLD_PATH, fileSize(OLD_PATH), old_map) && old_map.size > 0;
    if (ok) {
      _st.trial = 0;
      _st.boots = 0;
      _st.rolled_back = 1;
      ok = saveState(_st);
    }
    QSPIFlash._unlockFS();
    if (ok) installNow(&old_map, NULL);
  }

  void install() override {
    // back up the running image, then copy the staged one in (reverting to the backup if it will not verify)
    QSPIFlash._lockFS();
    uint32_t size = runningImageSize();
    bool ok = writeFile(OLD_PATH, (const uint8_t*)APP_START, size, false) && mapFile(OLD_PATH, size, old_map);
    if (ok) {
      _st.trial = 1;
      _st.boots = 0;
      _st.has_old = 1;
      _st.rolled_back = 0;
      ok = saveState(_st);
    }
    QSPIFlash._unlockFS();
    if (ok) installNow(&new_map, &old_map);
  }

  void feedWatchdog() override {
    if (NRF_WDT->RUNSTATUS) NRF_WDT->RR[0] = WDT_RR_RR_Reload;
  }

  const char* describe() override {
    snprintf(_desc, sizeof(_desc), "nrf52 app %luk%s", (unsigned long)(runningImageSize() / 1024),
             _st.rolled_back ? ", ROLLED BACK" : "");
    return _desc;
  }
};

LoraOTAPlatform& loraOtaPlatform() {
  static Nrf52OtaPlatform p;
  return p;
}

#endif

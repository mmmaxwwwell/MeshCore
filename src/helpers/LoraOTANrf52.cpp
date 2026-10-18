// LoRa OTA on nRF52840 boards with QSPI flash. Two ways to stage an image:
//  * QSPIFLASH (companions): the app keeps a LittleFS on the QSPI chip, so the
//    image and the backup are files in it.
//  * otherwise (repeaters, room servers): nothing else uses the chip, so the
//    image, the backup and the state sit in fixed raw slots on it; mounting a
//    filesystem there would only format the chip.
//
// The Adafruit bootloader has no rollback and the app region cannot hold two
// images, so:
//  * A new image is staged on QSPI. LittleFS: BEGIN writes the file full of
//    0xFF (so its blocks are allocated and still erased), records each block's
//    physical QSPI address, and chunks are then programmed raw at those
//    addresses (littlefs v1 does not checksum file data). Raw: BEGIN erases
//    the new-image slot, which is then one extent.
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
#include <SHA256.h>

extern "C" uint32_t __flash_arduino_start, __flash_arduino_end, __etext, __data_start__, __data_end__;

#define APP_START    ((uint32_t)&__flash_arduino_start)
#define APP_END      ((uint32_t)&__flash_arduino_end)
#define PAGE         4096
#define BL_SETTINGS  0x000FF000UL   // Adafruit bootloader settings page (nRF52840)
#define BANK_VALID_APP    0x01
#define BANK_INVALID_APP  0xFF
#define WDT_SECS     120
#define MAX_TRIAL_BOOTS 3

struct OtaState {
  uint32_t magic;
  uint8_t trial;      // running image is on probation
  uint8_t boots;      // probation boots so far
  uint8_t has_old;    // the backup holds the image to go back to
  uint8_t rolled_back;
};
#define STATE_MAGIC 0x4D434F31   // "MCO1"

#if defined(QSPIFLASH)
  #include <CustomLFS_QSPIFlash.h>
  #define LORA_OTA_MAX_EXTENTS 384
#else
  #include <nrfx_qspi.h>
  #define LORA_OTA_MAX_EXTENTS 1
#endif
#include "LoraOTALfs.h"

static ImageMap new_map, old_map;   // in RAM: the install routine reads them with flash off

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

#if defined(QSPIFLASH)

#define NEW_PATH   "/ota-new.bin"
#define OLD_PATH   "/ota-old.bin"
#define STATE_PATH "/ota-state"
#define SESS_PATH  "/ota-session"   // a LONG session's record (lora_ota::Receiver)

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


// the store the platform below uses: files on the app's LittleFS

static bool storeReady() { return lfs()->cfg != NULL; }   // mounted by the app before ota.begin()
static const char* storeWhy() { return "(no qspi fs)"; }
static void storeLock() { QSPIFlash._lockFS(); }
static void storeUnlock() { QSPIFlash._unlockFS(); }
static bool storeLoad(OtaState& s) { return loadState(s); }
static bool storeSave(OtaState s) { return saveState(s); }
static bool storeBackup(uint32_t size) {
  return writeFile(OLD_PATH, (const uint8_t*)APP_START, size, false) && mapFile(OLD_PATH, size, old_map);
}
static bool storeMapOld() { return mapFile(OLD_PATH, fileSize(OLD_PATH), old_map) && old_map.size > 0; }

// ---------------------------------------------------------------- staging flash (LittleFS)

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
    LORA_OTA_LOG("ota: staging %lu bytes", (unsigned long)len);
    bool ok = writeFile(NEW_PATH, NULL, len, true);
    LORA_OTA_LOG("ota: file %s t=%lu", ok ? "written" : "FAILED", millis());
    ok = ok && mapFile(NEW_PATH, len, new_map);
    LORA_OTA_LOG("ota: mapped %s, %u extents t=%lu", ok ? "ok" : "FAILED", new_map.n, millis());
    QSPIFlash._unlockFS();
    return ok;
  }
  bool write(size_t off, const uint8_t* src, size_t len) override { return rawIO(off, (uint8_t*)src, len, true); }
  bool read(size_t off, uint8_t* dest, size_t len) override { return rawIO(off, dest, len, false); }
  bool activate(size_t len) override { return len == new_map.size; }   // install() does the rest

  // LONG sessions: the staged file keeps its chunks across a reboot; the record is a file too
  bool reattach(size_t len) override {
    QSPIFlash._lockFS();
    bool ok = fileSize(NEW_PATH) == len && mapFile(NEW_PATH, len, new_map);
    QSPIFlash._unlockFS();
    return ok;
  }
  bool saveSession(const uint8_t* hdr, size_t hlen, const uint8_t* bitmap, size_t blen, bool fresh) override {
    static uint32_t words[64];   // word-aligned bounce, as lfsWriteFile
    uint8_t* buf = (uint8_t*)words;
    QSPIFlash._lockFS();
    lfs_file_t f;
    bool ok = lfs_file_open(lfs(), &f, SESS_PATH, LFS_O_WRONLY | LFS_O_CREAT | LFS_O_TRUNC) >= 0;
    if (ok) {
      for (size_t pos = 0; pos < hlen + blen && ok; ) {
        size_t n = hlen + blen - pos < sizeof(words) ? hlen + blen - pos : sizeof(words);
        for (size_t i = 0; i < n; i++) buf[i] = pos + i < hlen ? hdr[pos + i] : bitmap[pos + i - hlen];
        ok = lfs_file_write(lfs(), &f, buf, n) == (lfs_ssize_t)n;
        pos += n;
      }
      ok = lfs_file_close(lfs(), &f) >= 0 && ok;
    }
    QSPIFlash._unlockFS();
    return ok;
  }
  bool loadSession(uint8_t* hdr, size_t hlen, uint8_t* bitmap, size_t blen) override {
    QSPIFlash._lockFS();
    lfs_file_t f;
    bool ok = fileSize(SESS_PATH) == hlen + blen && lfs_file_open(lfs(), &f, SESS_PATH, LFS_O_RDONLY) >= 0;
    if (ok) {   // through a word-aligned bounce: littlefs may hand a big read straight to QSPI DMA
      static uint32_t words[64];
      uint8_t* buf = (uint8_t*)words;
      for (size_t pos = 0; pos < hlen + blen && ok; ) {
        size_t n = hlen + blen - pos < sizeof(words) ? hlen + blen - pos : sizeof(words);
        ok = lfs_file_read(lfs(), &f, buf, n) == (lfs_ssize_t)n;
        for (size_t i = 0; ok && i < n; i++) {
          if (pos + i < hlen) hdr[pos + i] = buf[i]; else bitmap[pos + i - hlen] = buf[i];
        }
        pos += n;
      }
      lfs_file_close(lfs(), &f);
    }
    QSPIFlash._unlockFS();
    return ok;
  }
  void clearSession() override {
    QSPIFlash._lockFS();
    if (fileSize(SESS_PATH)) lfs_remove(lfs(), SESS_PATH);
    QSPIFlash._unlockFS();
  }

private:
  // QSPI DMA takes word-aligned RAM buffers, word-aligned flash addresses and
  // whole words; a chunk sits anywhere in a packet. So everything goes through
  // an aligned bounce buffer, padded with 0xFF (programming 0xFF over erased
  // flash changes nothing; read padding is dropped).
  static bool qspiIO(uint32_t addr, uint8_t* buf, uint32_t n, bool write) {
    static uint32_t bounce[66];
    uint8_t* b = (uint8_t*)bounce;
    while (n) {
      uint32_t a = addr & ~3u, lead = addr - a;
      uint32_t take = n < 256 - lead ? n : 256 - lead;
      uint32_t total = (lead + take + 3) & ~3u;
      if (write) {
        memset(b, 0xFF, total);
        memcpy(b + lead, buf, take);
        if (!QSPIFlash.rawWrite(a, b, total)) return false;
      } else {
        if (!QSPIFlash.rawRead(a, b, total)) return false;
        memcpy(buf, b + lead, take);
      }
      addr += take; buf += take; n -= take;
    }
    return true;
  }

  bool rawIO(size_t off, uint8_t* buf, size_t len, bool write) {
    QSPIFlash._lockFS();
    bool ok = true;
    uint32_t pos = 0;   // image offset at the start of extent e
    for (uint16_t e = 0; e < new_map.n && len && ok; e++) {
      const Extent& x = new_map.ext[e];
      if (off < pos + x.len) {
        uint32_t in = off - pos, n = x.len - in < len ? x.len - in : len;
        ok = qspiIO(x.addr + in, buf, n, write);
        buf += n; off += n; len -= n;
      }
      pos += x.len;
    }
    QSPIFlash._unlockFS();
    return ok && len == 0;
  }
};

typedef QspiFileFlash StageFlash;

#else   // raw slots

// ---------------------------------------------------------------- raw QSPI slots

// Fixed addresses, so an update cannot move them under the running image. A
// slot holds a whole app region (792 KB on the S140 v7 layout).
#ifndef LORA_OTA_RAW_SLOT
  #define LORA_OTA_RAW_SLOT  0x0D0000UL                        // 832 KB
#endif
#define RAW_NEW    0UL
#define RAW_OLD    LORA_OTA_RAW_SLOT
#define RAW_STATE  (2 * LORA_OTA_RAW_SLOT)                     // one 4 KB sector
#define RAW_NEEDED (RAW_STATE + PAGE)
#define RAW_SESSION (RAW_STATE + PAGE)   // one more 4 KB sector: a LONG session's record, if the chip has it
#define QSPI_PAGE  256

struct RawState { OtaState st; uint32_t old_size; uint32_t spare; };   // whole words

static bool raw_up = false, raw_failed = false;
static uint32_t raw_old_size = 0;
static uint32_t raw_chip_size = 0;
static char raw_why[32] = "";   // why staging is unavailable, for `ota status`
static uint32_t bounce[QSPI_PAGE / 4 + 2];   // QSPI DMA: word-aligned RAM only

static bool rawBegin() {
  if (raw_up) return true;
  if (raw_failed) return false;
  raw_failed = true;   // one attempt per boot
#ifdef QSPI_FLASH_EN
  pinMode(QSPI_FLASH_EN, OUTPUT);   // boards that power the chip from a GPIO (ThinkNode M6)
  digitalWrite(QSPI_FLASH_EN, HIGH);
  delay(5);
#endif
  // A chip an earlier firmware left in deep power-down (it stays there while it
  // keeps power) never reports ready, so the peripheral's ACTIVATE would time
  // out polling it. Wake it first by hand: 0xAB (release from deep power-down)
  // clocked out on plain GPIOs, then tRES1.
  pinMode(PIN_QSPI_CS, OUTPUT);
  digitalWrite(PIN_QSPI_CS, HIGH);
  pinMode(PIN_QSPI_SCK, OUTPUT);
  digitalWrite(PIN_QSPI_SCK, LOW);
  pinMode(PIN_QSPI_IO0, OUTPUT);
  pinMode(PIN_QSPI_IO2, OUTPUT);   // WP and HOLD high: HOLD low would pause the chip
  digitalWrite(PIN_QSPI_IO2, HIGH);
  pinMode(PIN_QSPI_IO3, OUTPUT);
  digitalWrite(PIN_QSPI_IO3, HIGH);
  delayMicroseconds(10);
  digitalWrite(PIN_QSPI_CS, LOW);
  for (int bit = 7; bit >= 0; bit--) {   // SPI mode 0, MSB first
    digitalWrite(PIN_QSPI_IO0, (0xAB >> bit) & 1);
    delayMicroseconds(2);
    digitalWrite(PIN_QSPI_SCK, HIGH);
    delayMicroseconds(2);
    digitalWrite(PIN_QSPI_SCK, LOW);
  }
  digitalWrite(PIN_QSPI_CS, HIGH);
  delayMicroseconds(100);

  nrfx_qspi_config_t c;   // this nrfx has no QSPI defaults in its config, so no NRFX_QSPI_DEFAULT_CONFIG
  memset(&c, 0, sizeof(c));
  c.pins.sck_pin = g_ADigitalPinMap[PIN_QSPI_SCK];
  c.pins.csn_pin = g_ADigitalPinMap[PIN_QSPI_CS];
  c.pins.io0_pin = g_ADigitalPinMap[PIN_QSPI_IO0];
  c.pins.io1_pin = g_ADigitalPinMap[PIN_QSPI_IO1];
  c.pins.io2_pin = g_ADigitalPinMap[PIN_QSPI_IO2];
  c.pins.io3_pin = g_ADigitalPinMap[PIN_QSPI_IO3];
  c.prot_if.readoc = NRF_QSPI_READOC_FASTREAD;   // single line, 24-bit: every QSPI NOR does this
  c.prot_if.writeoc = NRF_QSPI_WRITEOC_PP;
  c.prot_if.addrmode = NRF_QSPI_ADDRMODE_24BIT;
  c.phy_if.sck_delay = 0x05;
  c.phy_if.spi_mode = NRF_QSPI_MODE_0;
  c.phy_if.sck_freq = NRF_QSPI_FREQ_32MDIV8;     // 4 MHz: within every QSPI NOR's slowest mode
  c.irq_priority = 7;
  nrfx_err_t err = nrfx_qspi_init(&c, NULL, NULL);   // no handler = blocking calls
  if (err == NRFX_ERROR_TIMEOUT) {   // nrfx waits only briefly for ACTIVATE: give the chip longer
    for (int i = 0; i < 250 && !NRF_QSPI->EVENTS_READY; i++) delay(1);
    if (NRF_QSPI->EVENTS_READY) err = NRFX_SUCCESS;
  }
  if (err != NRFX_SUCCESS) {
    snprintf(raw_why, sizeof(raw_why), "qspi init %08lX", (unsigned long)err);   // 0BAD0007: no chip answering (ThinkNode M6 Basalt)
    return false;
  }

  // and once more through the peripheral, in case the GPIO wake was too early
  nrf_qspi_cinstr_conf_t rel = NRFX_QSPI_DEFAULT_CINSTR(0xAB, NRF_QSPI_CINSTR_LEN_1B);
  nrfx_qspi_cinstr_xfer(&rel, NULL, NULL);
  delayMicroseconds(50);

  uint8_t id[3] = {0};   // JEDEC: manufacturer, type, log2(capacity)
  nrf_qspi_cinstr_conf_t rdid = NRFX_QSPI_DEFAULT_CINSTR(0x9F, NRF_QSPI_CINSTR_LEN_4B);
  err = nrfx_qspi_cinstr_xfer(&rdid, NULL, id);
  uint32_t size = (id[2] >= 16 && id[2] <= 28) ? (1UL << id[2]) : 0;
  LORA_OTA_LOG("ota: qspi %02X %02X %02X, %lu KB", id[0], id[1], id[2], (unsigned long)(size / 1024));
  if (err != NRFX_SUCCESS || size < RAW_NEEDED) {   // missing chip or too small for two slots
    snprintf(raw_why, sizeof(raw_why), "qspi id %02X%02X%02X", id[0], id[1], id[2]);
    return false;
  }
  raw_chip_size = size;
  raw_up = true;
  raw_failed = false;
  return true;
}

static bool rawErase(uint32_t addr, uint32_t len) {   // addr 4 KB aligned
  uint32_t end = (addr + len + PAGE - 1) & ~(PAGE - 1);
  while (addr < end) {
    bool big = (addr & 0xFFFF) == 0 && end - addr >= 0x10000;
    if (nrfx_qspi_erase(big ? NRF_QSPI_ERASE_LEN_64KB : NRF_QSPI_ERASE_LEN_4KB, addr) != NRFX_SUCCESS) return false;
    addr += big ? 0x10000 : PAGE;
  }
  return true;
}

// Any address, any length, any source (RAM, packet, or internal flash, which
// DMA cannot read): everything goes through the aligned bounce buffer, never
// across a 256-byte program page, padded with 0xFF (programming 0xFF over
// erased flash changes nothing; read padding is dropped).
static bool rawIO(uint32_t addr, uint8_t* buf, uint32_t n, bool write) {
  uint8_t* b = (uint8_t*)bounce;
  while (n) {
    uint32_t a = addr & ~3u, lead = addr - a;
    uint32_t room = QSPI_PAGE - (a & (QSPI_PAGE - 1));   // to the end of this program page
    uint32_t take = n < room - lead ? n : room - lead;
    uint32_t total = (lead + take + 3) & ~3u;
    if (write) {
      memset(b, 0xFF, total);
      memcpy(b + lead, buf, take);
      if (nrfx_qspi_write(b, total, a) != NRFX_SUCCESS) return false;
    } else {
      if (nrfx_qspi_read(b, total, a) != NRFX_SUCCESS) return false;
      memcpy(buf, b + lead, take);
    }
    addr += take; buf += take; n -= take;
  }
  return true;
}

static void setMap(ImageMap& m, uint32_t addr, uint32_t size) {
  m.size = size;
  m.n = 1;
  m.ext[0].addr = addr;
  m.ext[0].len = size;
}

// the store the platform below uses: raw slots

static bool storeReady() { return rawBegin(); }
static const char* storeWhy() { return raw_why; }
static void storeLock() { }
static void storeUnlock() { }

static bool storeLoad(OtaState& s) {
  RawState r;
  memset(&s, 0, sizeof(s));
  if (!rawIO(RAW_STATE, (uint8_t*)&r, sizeof(r), false) || r.st.magic != STATE_MAGIC) return false;
  s = r.st;
  raw_old_size = r.old_size <= RAW_OLD - RAW_NEW ? r.old_size : 0;
  return true;
}

static bool storeSave(OtaState s) {
  RawState r;
  memset(&r, 0xFF, sizeof(r));
  r.st = s;
  r.st.magic = STATE_MAGIC;
  r.old_size = raw_old_size;
  return rawErase(RAW_STATE, PAGE) && rawIO(RAW_STATE, (uint8_t*)&r, sizeof(r), true);
}

static bool storeBackup(uint32_t size) {
  if (size > LORA_OTA_RAW_SLOT) return false;
  bool ok = rawErase(RAW_OLD, size) && rawIO(RAW_OLD, (uint8_t*)APP_START, size, true);
  for (uint32_t off = 0; ok && off < size; off += QSPI_PAGE) {   // read back: the slot is the only way back
    uint8_t chk[QSPI_PAGE];
    uint32_t n = size - off < QSPI_PAGE ? size - off : QSPI_PAGE;
    ok = rawIO(RAW_OLD + off, chk, n, false) && memcmp(chk, (const uint8_t*)APP_START + off, n) == 0;
  }
  raw_old_size = ok ? size : 0;
  if (ok) setMap(old_map, RAW_OLD, size);
  return ok;
}

static bool storeMapOld() {
  if (raw_old_size == 0) return false;
  setMap(old_map, RAW_OLD, raw_old_size);
  return true;
}

// ---------------------------------------------------------------- staging flash (raw slot)

class QspiRawFlash : public lora_ota::Flash, public lora_ota::NorSessionStore {
public:
  size_t capacity() override {
    uint32_t app = APP_END - APP_START;
    return app < LORA_OTA_RAW_SLOT ? app : LORA_OTA_RAW_SLOT;
  }
  bool erase(size_t len) override {
    LORA_OTA_LOG("ota: staging %lu bytes", (unsigned long)len);
    bool ok = len <= capacity() && rawErase(RAW_NEW, len);
    if (ok) setMap(new_map, RAW_NEW, len);
    LORA_OTA_LOG("ota: slot %s t=%lu", ok ? "erased" : "FAILED", millis());
    return ok;
  }
  bool write(size_t off, const uint8_t* src, size_t len) override {
    return off + len <= new_map.size && rawIO(RAW_NEW + off, (uint8_t*)src, len, true);
  }
  bool read(size_t off, uint8_t* dest, size_t len) override {
    return off + len <= new_map.size && rawIO(RAW_NEW + off, dest, len, false);
  }
  bool activate(size_t len) override { return len == new_map.size; }   // install() does the rest

  // LONG sessions: the slot keeps its chunks across a reboot; the record has a sector of its own
  // (never the STATE sector: that one belongs to probation/rollback)
  bool reattach(size_t len) override {
    if (len > capacity()) return false;
    setMap(new_map, RAW_NEW, len);
    return true;
  }
  bool saveSession(const uint8_t* h, size_t hl, const uint8_t* b, size_t bl, bool fresh) override { return save(h, hl, b, bl, fresh); }
  bool loadSession(uint8_t* h, size_t hl, uint8_t* b, size_t bl) override { return load(h, hl, b, bl); }
  void clearSession() override { if (sessSize()) clear(); }
  size_t sessSize() override { return raw_chip_size >= RAW_SESSION + PAGE ? PAGE : 0; }
  bool sessErase() override { return sessSize() && rawErase(RAW_SESSION, PAGE); }
  bool sessWrite(size_t off, const uint8_t* src, size_t len) override {
    return off + len <= sessSize() && rawIO(RAW_SESSION + off, (uint8_t*)src, len, true);
  }
  bool sessRead(size_t off, uint8_t* dest, size_t len) override {
    return off + len <= sessSize() && rawIO(RAW_SESSION + off, dest, len, false);
  }
};
typedef QspiRawFlash StageFlash;

#endif   // QSPIFLASH

// ---------------------------------------------------------------- platform

class Nrf52OtaPlatform : public LoraOTAPlatform {
  StageFlash _flash;
  OtaState _st;
  char _desc[64];

public:
  lora_ota::Flash* flash() override { return storeReady() ? &_flash : NULL; }

  bool begin() override {
    if (!storeReady()) return false;
    storeLock();
    storeLoad(_st);
    bool pending = _st.trial;
    if (pending) {
      _st.boots++;
      storeSave(_st);
    }
    storeUnlock();
    if (pending && _st.boots > MAX_TRIAL_BOOTS) {
      MESH_DEBUG_PRINTLN("lora ota: new image keeps resetting, rolling back");
      rollback();
    }
    return pending;
  }

  bool confirm() override {
    storeLock();
    _st.trial = 0;
    _st.boots = 0;
    bool ok = storeSave(_st);
    storeUnlock();
    return ok;   // the watchdog keeps running (it cannot be stopped): feedWatchdog() carries on
  }

  void rollback() override {
    storeLock();
    bool ok = _st.has_old && storeMapOld();
    if (ok) {
      _st.trial = 0;
      _st.boots = 0;
      _st.rolled_back = 1;
      ok = storeSave(_st);
    }
    storeUnlock();
    if (ok) installNow(&old_map, NULL);
  }

  void install() override {
    // back up the running image, then copy the staged one in (reverting to the backup if it will not verify)
    storeLock();
    uint32_t size = runningImageSize();
    LORA_OTA_LOG("ota: backing up %lu bytes", (unsigned long)size);
    bool ok = storeBackup(size);
    LORA_OTA_LOG("ota: backup %s, %u extents; new image %lu bytes, %u extents", ok ? "ok" : "FAILED", old_map.n,
                 (unsigned long)new_map.size, new_map.n);
    if (ok) {
      _st.trial = 1;
      _st.boots = 0;
      _st.has_old = 1;
      _st.rolled_back = 0;
      ok = storeSave(_st);
    }
    storeUnlock();
    if (ok) installNow(&new_map, &old_map);
  }

  bool runningSha(uint8_t sha[32]) override {
    SHA256 h;
    h.update((const void*)APP_START, runningImageSize());
    h.finalize(sha, 32);
    return true;
  }

  void feedWatchdog() override {
    if (NRF_WDT->RUNSTATUS) NRF_WDT->RR[0] = WDT_RR_RR_Reload;
  }

  const char* describe() override {
    snprintf(_desc, sizeof(_desc), "nrf52 app %luk%s%s%s", (unsigned long)(runningImageSize() / 1024),
             _st.rolled_back ? ", ROLLED BACK" : "", storeReady() ? "" : ", NO STAGING ", storeReady() ? "" : storeWhy());
    return _desc;
  }
};

LoraOTAPlatform& loraOtaPlatform() {
  static Nrf52OtaPlatform p;
  return p;
}

#endif

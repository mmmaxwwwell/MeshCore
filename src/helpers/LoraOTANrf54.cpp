// LoRa OTA on nRF54L15 (XIAO nRF54L15 + andyshinn's nRF54_Bootloader). No QSPI
// chip: everything lives in RRAM, at fixed addresses below the bootloader's
// settings page (arch/nrf54l/ldscripts/xiao_nrf54l15_bootloader.ld):
//
//   app      0x008000-0x080000   the running image
//   slot     0x080000-0x0F8000   a new image is staged here
//   patch    0x0F8000-0x116000   a delta's patch (decoded from app + patch into slot)
//   state    0x116000            probation / rollback record
//   session  0x117000            a LONG session's record (lora_ota::Receiver)
//
// RRAM has no erase and is written a word at a time, so an "erase" fills 0xFF
// and a partial word keeps its other bytes (read, merge, write): unlike NOR
// flash, writing 0xFF over data would overwrite it.
//
// There is room for one spare image, not a new one AND a backup (the nRF52 way),
// so install SWAPS app and slot page by page, from a routine in RAM (interrupts
// off): the new image ends up in the app region and the old one in the slot,
// which IS the backup. Rollback swaps them back. As on nRF52:
//  * the bootloader settings say "invalid app" while the app region is half
//    written, so a power cut there leaves the radio in the bootloader's DFU
//    mode, never jumping into half an image (unlike nRF52, the slot is then
//    half swapped too: recovery is a DFU upload, over BLE or USB serial);
//  * the new image boots on probation: an admin's CONFIRM within
//    LORA_OTA_CONFIRM_SECS, or it swaps back. A boot counter catches an image
//    that keeps resetting after the OTA service starts, and the watchdog
//    (started by the install, survives soft resets) one that hangs. NOT
//    covered: an image that dies before the OTA service starts on every boot.
//  * Staging a new image overwrites the slot, so it drops the way back to the
//    image before the running one (BEGIN is refused while one is on probation).
//
// The bootloader is the Adafruit nRF52 one ported to nRF54L: same settings
// layout, same rule (bank_0 0x01 + crc 0 = valid, 0xFF = invalid, erased page =
// trust the image, flashed over SWD).

#include "LoraOTAService.h"

#if defined(LORA_OTA_ENABLED) && defined(NRF54_PLATFORM)

#include <Arduino.h>
#include <nrf54l15.h>
#include <SHA256.h>
#include <nrf54l15_regs.h>
#include <helpers/nrf54/NRF54Rram.h>

extern "C" uint32_t __app_region_start, __app_region_end, __app_image_end;

#define APP_START    ((uint32_t)&__app_region_start)
#define APP_END      ((uint32_t)&__app_region_end)
#define PAGE         4096
#define SLOT         0x080000UL
#define SLOT_SIZE    0x078000UL
#define PATCH        0x0F8000UL
#define PATCH_SIZE   0x01E000UL
#define STATE_ADDR   0x116000UL
#define SESS_ADDR    0x117000UL
#define BL_SETTINGS  0x14F000UL   // nRF54_Bootloader settings page (nRF54L15)
#define BANK_VALID_APP    0x01
#define BANK_INVALID_APP  0xFF
#define WDT_SECS     120
#define MAX_TRIAL_BOOTS 3
#define RRAM_WRITEBUF_BYTES 512   // RRAMC write buffer: up to 32 lines of 16 bytes
#define WDT          ((NRF_WDT_Type*)nrf54l15::WDT31_BASE)

struct OtaState {
  uint32_t magic;
  uint8_t trial;      // running image is on probation
  uint8_t boots;      // probation boots so far
  uint8_t has_old;    // the slot holds the image to go back to
  uint8_t rolled_back;
  uint32_t old_size;  // of the image in the slot
};
#define STATE_MAGIC 0x4D435432   // "MCT2"

static uint32_t runningImageSize() { return (uint32_t)&__app_image_end - APP_START; }

// ---------------------------------------------------------------- the install routine (RAM only)

// Runs while the app region is being rewritten: everything it touches must be in
// RAM. No loop-to-memcpy/memset rewriting (those live in flash), long calls only.
#define RAMFUNC __attribute__((noinline, long_call, section(".data.lora_ota_ram"), \
                               optimize("no-tree-loop-distribute-patterns")))

static uint32_t ram_a[PAGE / 4], ram_b[PAGE / 4];

static RAMFUNC bool r_wait(const volatile uint32_t* reg, uint32_t mask) {
  for (uint32_t n = 1000000; n; n--) {
    if (*reg & mask) return true;
  }
  return false;
}

static RAMFUNC void r_wdt_feed() {
  if (WDT->RUNSTATUS & WDT_RUNSTATUS_RUNSTATUSWDT_Msk) WDT->RR[0] = WDT_RR_RR_Reload;
}

// one 4 KB page, word-aligned
static RAMFUNC bool r_write_page(uint32_t addr, const uint32_t* src) {
  const uint32_t prev = NRF_RRAMC->CONFIG;
  bool ok = true;
  if ((prev & RRAMC_CONFIG_WRITEBUFSIZE_Msk) &&
      !(NRF_RRAMC->BUFSTATUS.WRITEBUFEMPTY & RRAMC_BUFSTATUS_WRITEBUFEMPTY_EMPTY_Msk)) {
    NRF_RRAMC->EVENTS_READY = 0;
    NRF_RRAMC->TASKS_COMMITWRITEBUF = 1;
    ok = r_wait(&NRF_RRAMC->READY, RRAMC_READY_READY_Msk);
  }
  for (uint32_t done = 0; ok && done < PAGE; done += RRAM_WRITEBUF_BYTES) {
    NRF_RRAMC->CONFIG = (prev & ~RRAMC_CONFIG_WRITEBUFSIZE_Msk) | RRAMC_CONFIG_WEN_Msk |
                        ((RRAM_WRITEBUF_BYTES / 16) << RRAMC_CONFIG_WRITEBUFSIZE_Pos);
    ok = r_wait(&NRF_RRAMC->READY, RRAMC_READY_READY_Msk);
    NRF_RRAMC->EVENTS_ACCESSERROR = 0;
    for (uint32_t i = done; ok && i < done + RRAM_WRITEBUF_BYTES; i += 4) {
      ok = r_wait(&NRF_RRAMC->READYNEXT, RRAMC_READYNEXT_READYNEXT_Msk);
      if (ok) *(volatile uint32_t*)(addr + i) = src[i / 4];
    }
    ok = ok && NRF_RRAMC->EVENTS_ACCESSERROR == 0;
    if (ok) {
      NRF_RRAMC->EVENTS_READY = 0;
      NRF_RRAMC->TASKS_COMMITWRITEBUF = 1;
      ok = r_wait(&NRF_RRAMC->READY, RRAMC_READY_READY_Msk);
    }
  }
  if (!ok) {
    NRF_RRAMC->EVENTS_READY = 0;
    NRF_RRAMC->TASKS_CLRWRITEBUF = 1;
    r_wait(&NRF_RRAMC->READY, RRAMC_READY_READY_Msk);
  }
  NRF_RRAMC->EVENTS_ACCESSERROR = 0;
  NRF_RRAMC->CONFIG = prev & ~RRAMC_CONFIG_WEN_Msk;
  r_wait(&NRF_RRAMC->READY, RRAMC_READY_READY_Msk);
  if (ok) {   // read back
    volatile const uint32_t* f = (volatile const uint32_t*)addr;
    for (uint32_t i = 0; i < PAGE / 4; i++) {
      if (f[i] != src[i]) return false;
    }
  }
  return ok;
}

static RAMFUNC bool r_write_page_retry(uint32_t addr, const uint32_t* src) {
  for (int attempt = 0; attempt < 3; attempt++) {
    if (r_write_page(addr, src)) return true;
  }
  return false;
}

static RAMFUNC void r_load(uint32_t* dst, uint32_t addr) {
  volatile const uint32_t* s = (volatile const uint32_t*)addr;
  for (uint32_t i = 0; i < PAGE / 4; i++) dst[i] = s[i];
}

// bootloader settings: bank_0 (u16) @0, bank_0_crc (u16) @2, bank_1 (u16) @4, bank_0_size (u32) @8
static RAMFUNC bool r_set_bank0(uint16_t state, uint32_t size) {
  r_load(ram_a, BL_SETTINGS);
  uint16_t* h = (uint16_t*)ram_a;
  h[0] = state;
  h[1] = 0;            // crc 0 = the bootloader does not check one
  if (size) ram_a[2] = size;
  return r_write_page_retry(BL_SETTINGS, ram_a);
}

// Swap the first `len` bytes (whole pages) of the app region and the slot, then
// mark the app valid with `app_size`. On a page that will not write, it stops
// with the app marked invalid: the bootloader's DFU mode, never half an image.
static RAMFUNC __attribute__((noreturn)) void r_swap(uint32_t len, uint32_t app_size) {
  bool ok = r_set_bank0(BANK_INVALID_APP, 0);   // from here a power cut lands in DFU mode
  if (!ok) {   // nothing swapped: the running image must not boot on probation (OtaState: trial @4, has_old @6)
    r_load(ram_a, STATE_ADDR);
    ((uint8_t*)ram_a)[4] = 0;
    ((uint8_t*)ram_a)[6] = 0;
    r_write_page_retry(STATE_ADDR, ram_a);
  }
  for (uint32_t off = 0; ok && off < len; off += PAGE) {
    r_load(ram_a, APP_START + off);
    r_load(ram_b, SLOT + off);
    ok = r_write_page_retry(APP_START + off, ram_b) && r_write_page_retry(SLOT + off, ram_a);
    r_wdt_feed();
  }
  if (ok) r_set_bank0(BANK_VALID_APP, app_size);

  if (!(WDT->RUNSTATUS & WDT_RUNSTATUS_RUNSTATUSWDT_Msk)) {   // catches a new image that hangs
    WDT->CONFIG = 0;                     // paused while the CPU sleeps or is halted
    WDT->CRV = WDT_SECS * 32768;
    WDT->RREN = WDT_RREN_RR0_Msk;
    WDT->TASKS_START = 1;
  }
  __DSB();
  *(volatile uint32_t*)0xE000ED0CUL = 0x05FA0004UL;   // SCB->AIRCR: VECTKEY + SYSRESETREQ (no SCB in this core's CMSIS)
  __DSB();
  for (;;) { }
}

// The bootloader settings page must take a write before anything is committed:
// rewrite its first word with its own value.
static bool settingsWritable() {
  uint32_t w = *(volatile const uint32_t*)BL_SETTINGS;
  return nrf54RramWriteWords(BL_SETTINGS, &w, 1) && *(volatile const uint32_t*)BL_SETTINGS == w;
}

static void swapNow(uint32_t a_size, uint32_t b_size, uint32_t new_app_size) {
  uint32_t len = a_size > b_size ? a_size : b_size;
  len = (len + PAGE - 1) & ~(PAGE - 1);
  if (len > SLOT_SIZE) return;
  __disable_irq();   // the BLE controller and everything else stop here; the swap resets the chip
  r_swap(len, new_app_size);
}

// ---------------------------------------------------------------- state

static bool loadState(OtaState& s) {
  memcpy(&s, (const void*)STATE_ADDR, sizeof(s));
  if (s.magic == STATE_MAGIC && s.old_size <= SLOT_SIZE) return true;
  memset(&s, 0, sizeof(s));
  return false;
}

static bool saveState(OtaState s) {
  s.magic = STATE_MAGIC;
  return nrf54RramWrite(STATE_ADDR, (const uint8_t*)&s, sizeof(s));
}

// ---------------------------------------------------------------- staging (the slot)

static uint32_t staged_size = 0;

class RramSlotFlash : public lora_ota::Flash, public lora_ota::NorSessionStore {
public:
  OtaState* st = NULL;   // the platform's state: staging drops the way back

  size_t capacity() override {
    uint32_t app = APP_END - APP_START;
    return app < SLOT_SIZE ? app : SLOT_SIZE;
  }
  bool erase(size_t len) override {
    if (len > capacity()) return false;
    if (st && st->has_old) {   // the slot is about to stop being the backup
      st->has_old = 0;
      st->old_size = 0;
      if (!saveState(*st)) return false;
    }
    LORA_OTA_LOG("ota: staging %lu bytes", (unsigned long)len);
    bool ok = nrf54RramFill(SLOT, (len + 3) & ~3u);
    staged_size = ok ? len : 0;
    LORA_OTA_LOG("ota: slot %s t=%lu", ok ? "cleared" : "FAILED", millis());
    return ok;
  }
  bool write(size_t off, const uint8_t* src, size_t len) override {
    return off + len <= staged_size && nrf54RramWrite(SLOT + off, src, len);
  }
  bool read(size_t off, uint8_t* dest, size_t len) override {
    if (off + len > staged_size) return false;
    memcpy(dest, (const void*)(SLOT + off), len);
    return true;
  }
  bool activate(size_t len) override { return len == staged_size; }   // install() does the rest

  // LONG sessions: the slot keeps its chunks across a reboot; the record has a page of its own
  bool reattach(size_t len) override {
    if (len > capacity()) return false;
    staged_size = len;
    return true;
  }
  bool saveSession(const uint8_t* h, size_t hl, const uint8_t* b, size_t bl, bool fresh) override { return save(h, hl, b, bl, fresh); }
  bool loadSession(uint8_t* h, size_t hl, uint8_t* b, size_t bl) override { return load(h, hl, b, bl); }
  void clearSession() override { clear(); }
  size_t sessSize() override { return PAGE; }
  bool sessErase() override { return nrf54RramFill(SESS_ADDR, PAGE); }
  bool sessWrite(size_t off, const uint8_t* src, size_t len) override {
    return off + len <= PAGE && nrf54RramWrite(SESS_ADDR + off, src, len);
  }
  bool sessRead(size_t off, uint8_t* dest, size_t len) override {
    if (off + len > PAGE) return false;
    memcpy(dest, (const void*)(SESS_ADDR + off), len);
    return true;
  }
};

// ---------------------------------------------------------------- delta store

static void runningImageSha(uint8_t sha[32]) {
  SHA256 h;
  h.update((const void*)APP_START, runningImageSize());
  h.finalize(sha, 32);
}

static uint32_t patch_size = 0;

class Nrf54DeltaStore : public lora_ota::DeltaStore {
public:
  bool baseSha8(uint8_t out[8]) override {
    uint8_t sha[32];
    runningImageSha(sha);
    memcpy(out, sha, 8);
    return true;
  }
  size_t baseSize() override { return runningImageSize(); }
  bool readBase(size_t off, uint8_t* dest, size_t len) override {   // RRAM is memory mapped
    if (off + len > runningImageSize()) return false;
    memcpy(dest, (const uint8_t*)APP_START + off, len);
    return true;
  }
  lora_ota::Status patchPrepare(size_t new_size, size_t psize) override {
    patch_size = 0;
    if (psize > PATCH_SIZE) return lora_ota::TOO_BIG;   // the sender sends it whole
    if (!nrf54RramFill(PATCH, (psize + 3) & ~3u)) return lora_ota::FLASH_ERROR;
    patch_size = psize;
    return lora_ota::OK;
  }
  bool patchReattach(size_t new_size, size_t psize) override {   // a LONG delta session after a reboot
    if (psize > PATCH_SIZE) return false;
    patch_size = psize;
    return true;
  }
  bool patchWrite(size_t off, const uint8_t* src, size_t len) override {
    return off + len <= patch_size && nrf54RramWrite(PATCH + off, src, len);
  }
  bool patchRead(size_t off, uint8_t* dest, size_t len) override {
    if (off + len > patch_size) return false;
    memcpy(dest, (const void*)(PATCH + off), len);
    return true;
  }
  void patchDone() override { patch_size = 0; }
};

// ---------------------------------------------------------------- platform

class Nrf54OtaPlatform : public LoraOTAPlatform {
  RramSlotFlash _flash;
  Nrf54DeltaStore _delta;
  OtaState _st;
  char _desc[64];

public:
  Nrf54OtaPlatform() { memset(&_st, 0, sizeof(_st)); _flash.st = &_st; }

  lora_ota::Flash* flash() override { return &_flash; }
  lora_ota::DeltaStore* deltaStore() override { return &_delta; }

  bool begin() override {
    loadState(_st);
    bool pending = _st.trial;
    if (pending) {
      _st.boots++;
      saveState(_st);
    }
    if (pending && _st.boots > MAX_TRIAL_BOOTS) {
      MESH_DEBUG_PRINTLN("lora ota: new image keeps resetting, rolling back");
      rollback();
    }
    return pending;
  }

  bool confirm() override {
    _st.trial = 0;
    _st.boots = 0;
    return saveState(_st);   // the watchdog keeps running (it cannot be stopped): feedWatchdog() carries on
  }

  void rollback() override {
    if (!_st.has_old || _st.old_size == 0 || !settingsWritable()) return;
    uint32_t running = runningImageSize(), old = _st.old_size;
    _st.trial = 0;
    _st.boots = 0;
    _st.rolled_back = 1;
    _st.old_size = running;   // after the swap the slot holds the image being dropped
    if (saveState(_st)) swapNow(running, old, old);
  }

  void install() override {
    uint32_t running = runningImageSize();
    LORA_OTA_LOG("ota: swapping in %lu bytes, keeping %lu", (unsigned long)staged_size, (unsigned long)running);
    if (staged_size == 0 || staged_size > SLOT_SIZE || !settingsWritable()) return;
    _flash.clearSession();   // the slot is about to hold the old image, not this session's chunks
    _st.trial = 1;
    _st.boots = 0;
    _st.has_old = 1;
    _st.rolled_back = 0;
    _st.old_size = running;
    if (saveState(_st)) swapNow(running, staged_size, staged_size);
  }

  bool runningSha(uint8_t sha[32]) override {
    runningImageSha(sha);
    return true;
  }

  void feedWatchdog() override {
    if (WDT->RUNSTATUS & WDT_RUNSTATUS_RUNSTATUSWDT_Msk) WDT->RR[0] = WDT_RR_RR_Reload;
  }

  const char* describe() override {
    snprintf(_desc, sizeof(_desc), "nrf54 app %luk%s%s", (unsigned long)(runningImageSize() / 1024),
             _st.has_old ? ", backup in slot" : "", _st.rolled_back ? ", ROLLED BACK" : "");
    return _desc;
  }
};

LoraOTAPlatform& loraOtaPlatform() {
  static Nrf54OtaPlatform p;
  return p;
}

#endif

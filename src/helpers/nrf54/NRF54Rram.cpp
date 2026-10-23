#include "NRF54Rram.h"

#include <Arduino.h>
#include <nrf54l15.h>

#define PAGE 4096
#define RRAM_WRITEBUF_BYTES 512   // RRAMC write buffer: up to 32 lines of 16 bytes

extern "C" bool nrf54l15_rram_transaction_try_lock(void);
extern "C" void nrf54l15_rram_transaction_unlock(void);


static bool rramWait(const volatile uint32_t& reg, uint32_t mask) {
  for (uint32_t n = 1000000; n; n--) {
    if (reg & mask) return true;
  }
  return false;
}

// Whole words at a word-aligned address; src NULL = fill 0xFF. The same RRAMC
// sequence as InternalFS (arch/nrf54l/InternalFileSystem): through the write
// buffer, one commit per 512 bytes, the buffer cleared if anything fails.
bool nrf54RramWriteWords(uint32_t addr, const uint32_t* src, uint32_t words) {
  if (!nrf54l15_rram_transaction_try_lock()) return false;
  const uint32_t prev = NRF_RRAMC->CONFIG;
  bool ok = true;
  if ((prev & RRAMC_CONFIG_WRITEBUFSIZE_Msk) &&
      !(NRF_RRAMC->BUFSTATUS.WRITEBUFEMPTY & RRAMC_BUFSTATUS_WRITEBUFEMPTY_EMPTY_Msk)) {
    NRF_RRAMC->EVENTS_READY = 0;
    NRF_RRAMC->TASKS_COMMITWRITEBUF = 1;
    ok = rramWait(NRF_RRAMC->READY, RRAMC_READY_READY_Msk);
  }
  uint32_t len = words * 4;
  for (uint32_t done = 0; ok && done < len; ) {
    uint32_t chunk = RRAM_WRITEBUF_BYTES - ((addr + done) % RRAM_WRITEBUF_BYTES);
    if (chunk > len - done) chunk = len - done;
    uint32_t lines = (((addr + done) & 0xF) + chunk + 15) / 16;
    NRF_RRAMC->CONFIG = (prev & ~RRAMC_CONFIG_WRITEBUFSIZE_Msk) | RRAMC_CONFIG_WEN_Msk |
                        (lines << RRAMC_CONFIG_WRITEBUFSIZE_Pos);
    ok = rramWait(NRF_RRAMC->READY, RRAMC_READY_READY_Msk);
    NRF_RRAMC->EVENTS_ACCESSERROR = 0;
    for (uint32_t i = done; ok && i < done + chunk; i += 4) {
      uint32_t w = src ? src[i / 4] : 0xFFFFFFFF;
      ok = rramWait(NRF_RRAMC->READYNEXT, RRAMC_READYNEXT_READYNEXT_Msk);
      if (ok) *(volatile uint32_t*)(addr + i) = w;
    }
    ok = ok && NRF_RRAMC->EVENTS_ACCESSERROR == 0;
    if (ok) {
      NRF_RRAMC->EVENTS_READY = 0;
      NRF_RRAMC->TASKS_COMMITWRITEBUF = 1;
      ok = rramWait(NRF_RRAMC->READY, RRAMC_READY_READY_Msk);
    }
    done += chunk;
  }
  if (!ok) {
    NRF_RRAMC->EVENTS_READY = 0;
    NRF_RRAMC->TASKS_CLRWRITEBUF = 1;
    rramWait(NRF_RRAMC->READY, RRAMC_READY_READY_Msk);
  }
  NRF_RRAMC->EVENTS_ACCESSERROR = 0;
  NRF_RRAMC->CONFIG = prev & ~RRAMC_CONFIG_WEN_Msk;
  ok = rramWait(NRF_RRAMC->READY, RRAMC_READY_READY_Msk) && ok;
  nrf54l15_rram_transaction_unlock();
  return ok;
}

// Any address, any length (src may be RRAM itself: it is copied word by word
// first). A partial word at either end keeps the bytes around it.
bool nrf54RramWrite(uint32_t addr, const uint8_t* src, uint32_t n) {
  static uint32_t buf[64];
  while (n) {
    uint32_t a = addr & ~3u, lead = addr - a;
    uint32_t take = n < sizeof(buf) - lead ? n : sizeof(buf) - lead;
    uint32_t total = (lead + take + 3) & ~3u;
    memcpy(buf, (const void*)a, total);   // current contents: the partial words keep their bytes
    if (src) memcpy((uint8_t*)buf + lead, src, take);
    else memset((uint8_t*)buf + lead, 0xFF, take);
    if (!nrf54RramWriteWords(a, buf, total / 4)) return false;
    if (memcmp((const void*)a, buf, total) != 0) return false;   // read back
    addr += take; n -= take;
    if (src) src += take;
  }
  return true;
}

bool nrf54RramFill(uint32_t addr, uint32_t len) {   // "erase", whole words
  for (uint32_t done = 0; done < len; done += PAGE) {
    uint32_t n = len - done < PAGE ? len - done : PAGE;
    if (!nrf54RramWriteWords(addr + done, NULL, (n + 3) / 4)) return false;
  }
  return true;
}


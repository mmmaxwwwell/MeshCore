#include "QSPIPowerSave.h"
#if defined(NRF52_PLATFORM) && defined(QSPI_POWERSAVE)
#include <nrfx_qspi.h>

namespace QSPIPowerSave {

static int (*orig_read)(const struct lfs_config*, lfs_block_t, lfs_off_t, void*, lfs_size_t);
static int (*orig_prog)(const struct lfs_config*, lfs_block_t, lfs_off_t, const void*, lfs_size_t);
static int (*orig_erase)(const struct lfs_config*, lfs_block_t);
static int (*orig_sync)(const struct lfs_config*);
static bool awake = true;     // begin() leaves it active
static bool installed = false;
static uint32_t last_access = 0;
static uint32_t n_sleeps = 0;

#define CMD_DEEP_POWER_DOWN   0xB9
#define CMD_RELEASE_DPD       0xAB

static void wake() {
  if (awake) return;
  uint32_t inten = NRF_QSPI->INTENSET;
  NRF_QSPI->INTENCLR = 0xFFFFFFFF;           // poll READY here; don't run the driver's handler
  NRF_QSPI->EVENTS_READY = 0;
  NRF_QSPI->TASKS_ACTIVATE = 1;
  uint32_t t = micros();
  while (!NRF_QSPI->EVENTS_READY && micros() - t < 10000) ;
  NRF_QSPI->EVENTS_READY = 0;
  NRF_QSPI->INTENSET = inten;
  nrf_qspi_cinstr_conf_t c = NRFX_QSPI_DEFAULT_CINSTR(CMD_RELEASE_DPD, NRF_QSPI_CINSTR_LEN_1B);
  nrfx_qspi_cinstr_xfer(&c, NULL, NULL);
  delayMicroseconds(50);                     // tRES1 (P25Q16H: 8 us; margin for other parts)
  awake = true;
}

static void sleep() {
  if (!awake) return;
  nrf_qspi_cinstr_conf_t c = NRFX_QSPI_DEFAULT_CINSTR(CMD_DEEP_POWER_DOWN, NRF_QSPI_CINSTR_LEN_1B);
  nrfx_qspi_cinstr_xfer(&c, NULL, NULL);
  NRF_QSPI->EVENTS_READY = 0;
  NRF_QSPI->TASKS_DEACTIVATE = 1;
  // anomaly 122: "QSPI uses current after being disabled" (as nrfx 2.x qspi_deactivate())
  *(volatile uint32_t *)0x40029010ul = 1ul;
  *(volatile uint32_t *)0x40029054ul = 1ul;
  awake = false;
  n_sleeps++;
}

static int w_read(const struct lfs_config* c, lfs_block_t b, lfs_off_t o, void* buf, lfs_size_t n) {
  wake(); int r = orig_read(c, b, o, buf, n); last_access = millis(); return r;
}
static int w_prog(const struct lfs_config* c, lfs_block_t b, lfs_off_t o, const void* buf, lfs_size_t n) {
  wake(); int r = orig_prog(c, b, o, buf, n); last_access = millis(); return r;
}
static int w_erase(const struct lfs_config* c, lfs_block_t b) {
  wake(); int r = orig_erase(c, b); last_access = millis(); return r;
}
static int w_sync(const struct lfs_config* c) {
  wake(); int r = orig_sync(c); last_access = millis(); return r;
}

void install(Adafruit_LittleFS& fs) {
  lfs_t* lfs = fs._getFS();
  if (installed || lfs == NULL || lfs->cfg == NULL) return;
  struct lfs_config* cfg = (struct lfs_config*) lfs->cfg;   // the driver's own (mutable) config
  orig_read = cfg->read;  cfg->read = w_read;
  orig_prog = cfg->prog;  cfg->prog = w_prog;
  orig_erase = cfg->erase; cfg->erase = w_erase;
  orig_sync = cfg->sync;  cfg->sync = w_sync;
  installed = true;
  last_access = millis();
}

void loop() {
  if (installed && awake && millis() - last_access > QSPI_IDLE_MS) sleep();
}

uint32_t sleeps() { return n_sleeps; }

}
#endif

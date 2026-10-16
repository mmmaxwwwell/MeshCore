#include "QSPIPowerSave.h"
#if defined(NRF52_PLATFORM) && (defined(QSPI_POWERSAVE) || defined(QSPI_RELEASE_DPD_AT_BOOT))
void qspiReleaseDeepPowerDown() {
  pinMode(PIN_QSPI_IO2, OUTPUT); digitalWrite(PIN_QSPI_IO2, HIGH);   // /WP
  pinMode(PIN_QSPI_IO3, OUTPUT); digitalWrite(PIN_QSPI_IO3, HIGH);   // /HOLD (low would pause it)
  pinMode(PIN_QSPI_CS, OUTPUT);  digitalWrite(PIN_QSPI_CS, HIGH);
  pinMode(PIN_QSPI_SCK, OUTPUT); digitalWrite(PIN_QSPI_SCK, LOW);    // SPI mode 0
  pinMode(PIN_QSPI_IO0, OUTPUT);
  delayMicroseconds(10);
  digitalWrite(PIN_QSPI_CS, LOW);
  for (int bit = 7; bit >= 0; bit--) {
    digitalWrite(PIN_QSPI_IO0, (0xAB >> bit) & 1);
    delayMicroseconds(1);
    digitalWrite(PIN_QSPI_SCK, HIGH);
    delayMicroseconds(1);
    digitalWrite(PIN_QSPI_SCK, LOW);
  }
  digitalWrite(PIN_QSPI_CS, HIGH);
  delayMicroseconds(50);   // tRES1
  // hand the pins back as inputs; nrfx_qspi_init() configures them
  pinMode(PIN_QSPI_SCK, INPUT); pinMode(PIN_QSPI_IO0, INPUT);
  pinMode(PIN_QSPI_IO2, INPUT); pinMode(PIN_QSPI_IO3, INPUT);
  pinMode(PIN_QSPI_CS, INPUT_PULLUP);
}
#endif

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
  awake = true;
}

static void sleep() {
  if (!awake) return;
  // The chip is NOT put in deep power-down: QSPI activation polls its status register, and a
  // chip in deep power-down never answers it (activation times out; seen on a Wio Tracker L1).
  // The milliamps are in the peripheral; the chip's standby is ~10-25 uA.
  NRF_QSPI->EVENTS_READY = 0;
  NRF_QSPI->TASKS_DEACTIVATE = 1;
  // anomaly 122: "QSPI uses current after being disabled" (as nrfx 2.x qspi_deactivate())
  *(volatile uint32_t *)0x40029010ul = 1ul;
  *(volatile uint32_t *)0x40029054ul = 1ul;
  awake = false;
  n_sleeps++;
}

static int w_read(const struct lfs_config* c, lfs_block_t b, lfs_off_t o, void* buf, lfs_size_t n) {
  wake();
  int r;
#ifdef QSPI_FAST_READ
  // CustomLFS's read waits with delay(1) after every transfer: a full RTOS tick (~1 ms) for a
  // 256-byte read that takes ~30 us, and one directory lookup is dozens of reads. Here: start
  // the transfer with the IRQ masked, spin on READY, then unmask -- the pending IRQ runs nrfx's
  // handler, which clears the driver's busy state (and harmlessly marks CustomLFS's op done).
  uint32_t addr = b * c->block_size + o;
  if (((uintptr_t)buf & 3) == 0 && (n & 3) == 0 && (addr & 3) == 0 && nrfx_is_in_ram(buf)) {
    NVIC_DisableIRQ(QSPI_IRQn);
    NRF_QSPI->EVENTS_READY = 0;
    nrfx_err_t e = nrfx_qspi_read(buf, n, addr);
    if (e == NRFX_SUCCESS) {
      uint32_t t = micros();
      while (!NRF_QSPI->EVENTS_READY && micros() - t < 20000) ;
    }
    NVIC_EnableIRQ(QSPI_IRQn);
    r = (e == NRFX_SUCCESS) ? 0 : orig_read(c, b, o, buf, n);
  } else
#endif
  r = orig_read(c, b, o, buf, n);
  last_access = millis();
  return r;
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

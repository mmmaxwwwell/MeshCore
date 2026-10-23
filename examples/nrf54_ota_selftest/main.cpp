// Hardware test of the nRF54 LoRa OTA platform (src/helpers/LoraOTANrf54.cpp)
// without a radio: drives staging, the RRAM swap install, probation, confirm
// and rollback from the USB serial bridge. Two builds that differ only in
// SELFTEST_TAG make a swap visible. Commands (115200, one per line):
//   status          tag, running image size + sha, OTA state
//   copy            stage THIS image through the Flash API (erase/write), compare, install
//   stage <size>    install an image already written to the slot (0x80000) over SWD
//   confirm         keep the running image
//   rollback        swap the previous image back in
//   reset           soft reset (probation boot counting)
//   radio ...       the board's `radio` command (radio roles map), without radios fitted

#include <Arduino.h>
#include <helpers/LoraOTAService.h>
#include <target.h>

#ifndef SELFTEST_TAG
  #define SELFTEST_TAG "A"
#endif

static LoraOTAPlatform* ota;
static bool pending;
static char line[48];
static uint8_t len;

static void status() {
  uint8_t sha[32];
  ota->runningSha(sha);
  Serial.printf("SELFTEST %s pending=%d %s sha=", SELFTEST_TAG, pending ? 1 : 0, ota->describe());
  for (int i = 0; i < 8; i++) Serial.printf("%02x", sha[i]);
  Serial.print("\r\n");
}

static void copySelf() {
  lora_ota::DeltaStore* d = ota->deltaStore();
  lora_ota::Flash* f = ota->flash();
  size_t size = d->baseSize();
  if (!f->erase(size)) { Serial.print("copy: erase FAILED\r\n"); return; }
  uint8_t buf[200], chk[200];
  for (size_t off = 0; off < size; off += 197) {   // odd chunks: unaligned partial words
    size_t n = size - off < 197 ? size - off : 197;
    d->readBase(off, buf, n);
    if (!f->write(off, buf, n)) { Serial.printf("copy: write FAILED at %u\r\n", (unsigned)off); return; }
  }
  for (size_t off = 0; off < size; off += sizeof(chk)) {
    size_t n = size - off < sizeof(chk) ? size - off : sizeof(chk);
    d->readBase(off, buf, n);
    if (!f->read(off, chk, n) || memcmp(buf, chk, n) != 0) {
      Serial.printf("copy: MISMATCH at %u\r\n", (unsigned)off);
      return;
    }
  }
  if (!f->activate(size)) { Serial.print("copy: activate FAILED\r\n"); return; }
  Serial.printf("copy: %u bytes staged and verified, installing\r\n", (unsigned)size);
  Serial.flush();
  delay(100);
  ota->install();
  Serial.print("install RETURNED\r\n");
}

static void command(const char* c) {
  if (strcmp(c, "status") == 0) status();
  else if (strcmp(c, "copy") == 0) copySelf();
  else if (strncmp(c, "stage ", 6) == 0) {
    size_t size = strtoul(c + 6, NULL, 0);
    if (!ota->flash()->reattach(size) || !ota->flash()->activate(size)) { Serial.print("stage: FAILED\r\n"); return; }
    Serial.printf("stage: installing %u bytes from the slot\r\n", (unsigned)size);
    Serial.flush();
    delay(100);
    ota->install();
    Serial.print("install RETURNED\r\n");
  } else if (strcmp(c, "confirm") == 0) {
    bool ok = ota->confirm();
    if (ok) pending = false;
    Serial.printf("confirm: %s\r\n", ok ? "ok" : "FAILED");
  } else if (strcmp(c, "rollback") == 0) {
    Serial.print("rollback: swapping back\r\n");
    Serial.flush();
    delay(100);
    ota->rollback();
    Serial.print("rollback RETURNED (no backup?)\r\n");
  } else if (strncmp(c, "radio", 5) == 0) {
    char reply[160] = "";
    if (!board.handleCommand(c, 0, reply)) strcpy(reply, "radio: not handled");
    Serial.printf("radio: %s\r\n", reply);
  } else if (strcmp(c, "reset") == 0) {
    Serial.flush();
    delay(100);
    NVIC_SystemReset();
  } else if (c[0]) Serial.printf("?? %s\r\n", c);
}

void setup() {
  Serial.begin(115200);
  delay(1500);
  ota = &loraOtaPlatform();
  pending = ota->begin();
  radio_roles.saved = radio_roles.running = radioRolesLoad();   // what radio_init() would read
  radio_roles.aux_ok = true;
  Serial.print("\r\n");
  status();
}

void loop() {
  ota->feedWatchdog();
  while (Serial.available()) {
    char ch = Serial.read();
    if (ch == '\r' || ch == '\n') {
      line[len] = 0;
      command(line);
      len = 0;
    } else if (len < sizeof(line) - 1) {
      line[len++] = ch;
    }
  }
}

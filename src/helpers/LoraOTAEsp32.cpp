// LoRa OTA on ESP32: stage in the spare OTA partition; the bootloader's own
// rollback (CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE in the Arduino build) keeps
// a new image PENDING_VERIFY until it is confirmed.

#include "LoraOTAService.h"

#if defined(LORA_OTA_ENABLED) && defined(ESP32)

#include <Arduino.h>
#include <esp_ota_ops.h>
#include <esp_partition.h>
#include <esp_task_wdt.h>

// Arduino's initArduino() marks the running image valid unless this says
// otherwise; we keep a new image PENDING_VERIFY until it is confirmed.
extern "C" bool verifyRollbackLater() { return true; }

// The last 4 KB sector of the staging partition holds a LONG session's record
// (lora_ota::NorSessionStore), so the image may use all but that sector.
#define SESS_SECTOR 0x1000

class EspOtaFlash : public lora_ota::Flash, public lora_ota::NorSessionStore {
  const esp_partition_t* _part;
  size_t imageRoom() const { return _part && _part->size > SESS_SECTOR ? _part->size - SESS_SECTOR : 0; }
public:
  EspOtaFlash() { _part = esp_ota_get_next_update_partition(NULL); }
  size_t capacity() override { return imageRoom(); }
  bool erase(size_t len) override {
    if (!_part || len > imageRoom()) return false;
    size_t end = (len + 0xFFFF) & ~(size_t)0xFFFF;   // whole 64 KB blocks
    if (end > imageRoom()) end = (len + 0xFFF) & ~(size_t)0xFFF;   // never into the session sector
    for (size_t off = 0; off < end; ) {
      size_t n = (off % 0x10000 == 0 && end - off >= 0x10000) ? 0x10000 : 0x1000;
      if (esp_partition_erase_range(_part, off, n) != ESP_OK) return false;
      off += n;
      delay(1);   // let the idle task and the radio ISR breathe between blocks
    }
    return true;
  }
  bool write(size_t off, const uint8_t* src, size_t len) override {
    return _part && off + len <= imageRoom() && esp_partition_write(_part, off, src, len) == ESP_OK;
  }
  bool read(size_t off, uint8_t* dest, size_t len) override {
    return _part && esp_partition_read(_part, off, dest, len) == ESP_OK;
  }
  bool activate(size_t len) override {
    return _part && esp_ota_set_boot_partition(_part) == ESP_OK;   // runs IDF's image verify
  }

  // LONG sessions: the partition keeps its chunks across a reboot
  bool reattach(size_t len) override { return _part && len <= imageRoom(); }
  bool saveSession(const uint8_t* h, size_t hl, const uint8_t* b, size_t bl, bool fresh) override { return save(h, hl, b, bl, fresh); }
  bool loadSession(uint8_t* h, size_t hl, uint8_t* b, size_t bl) override { return load(h, hl, b, bl); }
  void clearSession() override { clear(); }
  bool sessErase() override { return _part && esp_partition_erase_range(_part, imageRoom(), SESS_SECTOR) == ESP_OK; }
  bool sessWrite(size_t off, const uint8_t* src, size_t len) override {
    return _part && off + len <= SESS_SECTOR && esp_partition_write(_part, imageRoom() + off, src, len) == ESP_OK;
  }
  bool sessRead(size_t off, uint8_t* dest, size_t len) override {
    return _part && off + len <= SESS_SECTOR && esp_partition_read(_part, imageRoom() + off, dest, len) == ESP_OK;
  }
  size_t sessSize() override { return _part ? SESS_SECTOR : 0; }
};

class Esp32OtaPlatform : public LoraOTAPlatform {
  EspOtaFlash _flash;
  char _desc[24];
public:
  lora_ota::Flash* flash() override { return &_flash; }
  bool begin() override {
    esp_ota_img_states_t st;
    return esp_ota_get_state_partition(esp_ota_get_running_partition(), &st) == ESP_OK && st == ESP_OTA_IMG_PENDING_VERIFY;
  }
  void startProbation() override {
    // a hung new image resets, and the bootloader rolls back. Armed on the first loop pass,
    // not in setup(): companion setup alone can take ~20 s, past the default 5 s.
    esp_task_wdt_init(30, true);
    enableLoopWDT();
  }
  bool runningSha(uint8_t sha[32]) override {
    return esp_partition_get_sha256(esp_ota_get_running_partition(), sha) == ESP_OK;
  }
  bool confirm() override {
    if (esp_ota_mark_app_valid_cancel_rollback() != ESP_OK) return false;
    disableLoopWDT();
    return true;
  }
  void rollback() override { esp_ota_mark_app_invalid_rollback_and_reboot(); }
  void install() override { esp_restart(); }   // FINISH already set the boot partition
  const char* describe() override {
    snprintf(_desc, sizeof(_desc), "running %s", esp_ota_get_running_partition()->label);
    return _desc;
  }
};

LoraOTAPlatform& loraOtaPlatform() {
  static Esp32OtaPlatform p;
  return p;
}

#endif

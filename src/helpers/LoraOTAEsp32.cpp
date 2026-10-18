// LoRa OTA on ESP32: stage in the spare OTA partition; the bootloader's own
// rollback (CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE in the Arduino build) keeps
// a new image PENDING_VERIFY until it is confirmed.

#include "LoraOTAService.h"

#if defined(LORA_OTA_ENABLED) && defined(ESP32)

#include <Arduino.h>
#include <esp_ota_ops.h>
#include <esp_partition.h>

// Arduino's initArduino() marks the running image valid unless this says
// otherwise; we keep a new image PENDING_VERIFY until it is confirmed.
extern "C" bool verifyRollbackLater() { return true; }

class EspOtaFlash : public lora_ota::Flash {
  const esp_partition_t* _part;
public:
  EspOtaFlash() { _part = esp_ota_get_next_update_partition(NULL); }
  size_t capacity() override { return _part ? _part->size : 0; }
  bool erase(size_t len) override {
    if (!_part) return false;
    size_t end = (len + 0xFFFF) & ~(size_t)0xFFFF;   // whole 64 KB blocks
    if (end > _part->size) end = (len + 0xFFF) & ~(size_t)0xFFF;
    for (size_t off = 0; off < end; ) {
      size_t n = (off % 0x10000 == 0 && end - off >= 0x10000) ? 0x10000 : 0x1000;
      if (esp_partition_erase_range(_part, off, n) != ESP_OK) return false;
      off += n;
      delay(1);   // let the idle task and the radio ISR breathe between blocks
    }
    return true;
  }
  bool write(size_t off, const uint8_t* src, size_t len) override {
    return _part && esp_partition_write(_part, off, src, len) == ESP_OK;
  }
  bool read(size_t off, uint8_t* dest, size_t len) override {
    return _part && esp_partition_read(_part, off, dest, len) == ESP_OK;
  }
  bool activate(size_t len) override {
    return _part && esp_ota_set_boot_partition(_part) == ESP_OK;   // runs IDF's image verify
  }
};

class Esp32OtaPlatform : public LoraOTAPlatform {
  EspOtaFlash _flash;
  char _desc[24];
public:
  lora_ota::Flash* flash() override { return &_flash; }
  bool begin() override {
    esp_ota_img_states_t st;
    if (esp_ota_get_state_partition(esp_ota_get_running_partition(), &st) == ESP_OK && st == ESP_OTA_IMG_PENDING_VERIFY) {
      enableLoopWDT();   // a hung new image resets, and the bootloader rolls back
      return true;
    }
    return false;
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

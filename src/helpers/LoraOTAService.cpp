#include "LoraOTAService.h"

#ifdef LORA_OTA_ENABLED

#include <Arduino.h>
#include <Utils.h>
#include <esp_ota_ops.h>
#include <esp_partition.h>

// Arduino's initArduino() marks the running image valid unless this says
// otherwise; we keep a new image PENDING_VERIFY until `ota confirm`.
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

static EspOtaFlash ota_flash;

void LoraOTAService::begin(mesh::MainBoard& board) {
  _board = &board;
  uint8_t pubkey[32];
  if (!mesh::Utils::fromHex(pubkey, 32, LORA_OTA_PUBKEY)) return;   // bad build flag: feature off
  _rx = new lora_ota::Receiver(ota_flash, pubkey, LORA_OTA_BOARD);

  esp_ota_img_states_t st;
  if (esp_ota_get_state_partition(esp_ota_get_running_partition(), &st) == ESP_OK && st == ESP_OTA_IMG_PENDING_VERIFY) {
    _pending = true;
    _confirm_by = millis() + LORA_OTA_CONFIRM_MINS * 60 * 1000UL;
    enableLoopWDT();   // a hung new image resets, and the bootloader rolls back
  }
}

int LoraOTAService::handleRequest(const uint8_t* req, size_t len, uint8_t* reply, uint32_t random32) {
  if (!_rx) return 0;
  int n = _rx->handle(req, len, reply, millis(), random32, _pending);
  if (_rx->activated() && _reboot_at == 0) {
    _reboot_at = millis() + LORA_OTA_REBOOT_DELAY_MS;
  }
  return n;
}

bool LoraOTAService::handleCommand(const char* command, char* reply) {
  if (!_rx) {
    strcpy(reply, "ERR: lora ota disabled");
    return true;
  }
  if (strcmp(command, "status") == 0) {
    const esp_partition_t* run = esp_ota_get_running_partition();
    if (_pending) {
      long left = (long)(_confirm_by - millis()) / 1000;
      sprintf(reply, "PENDING VERIFY on %s: 'ota confirm' within %lds or it rolls back", run->label, left > 0 ? left : 0);
    } else if (_rx->activated()) {
      strcpy(reply, "image activated, rebooting");
    } else if (_rx->receiving()) {
      sprintf(reply, "receiving %u/%u chunks", _rx->received(), _rx->chunks());
    } else {
      sprintf(reply, "idle, running %s, board %s, %s", run->label, LORA_OTA_BOARD, LORA_OTA_MARKER);
    }
    return true;
  }
  if (strcmp(command, "confirm") == 0) {
    if (!_pending) {
      strcpy(reply, "OK - nothing pending");
    } else if (esp_ota_mark_app_valid_cancel_rollback() == ESP_OK) {
      _pending = false;
      disableLoopWDT();
      strcpy(reply, "OK - image confirmed");
    } else {
      strcpy(reply, "ERR: confirm failed");
    }
    return true;
  }
  if (strcmp(command, "rollback") == 0) {
    if (!_pending) {
      strcpy(reply, "ERR: only a pending image can roll back");
    } else {
      esp_ota_mark_app_invalid_rollback_and_reboot();   // returns only if no fallback image
      strcpy(reply, "ERR: no image to roll back to");
    }
    return true;
  }
  return false;
}

void LoraOTAService::loop() {
  if (!_rx) return;
  _rx->loop(millis());
  if (_reboot_at && (long)(millis() - _reboot_at) >= 0) {
    _board->reboot();
  }
  if (_pending && (long)(millis() - _confirm_by) >= 0) {
    MESH_DEBUG_PRINTLN("lora ota: not confirmed, rolling back");
    esp_ota_mark_app_invalid_rollback_and_reboot();
    _confirm_by = millis() + 60 * 1000UL;   // no fallback image: keep running, try again later
  }
}

#endif

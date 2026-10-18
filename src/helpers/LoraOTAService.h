#pragma once

// ESP32 glue for lora_ota::Receiver: the next OTA partition as its Flash,
// the bootloader's rollback as its safety net (a new image stays
// PENDING_VERIFY until an admin sends `ota confirm` over LoRa, else it rolls
// back), and the `ota ...` CLI.

#include "LoraOTA.h"

#ifdef LORA_OTA_ENABLED

#include <MeshCore.h>

#ifndef LORA_OTA_CONFIRM_MINS
  #define LORA_OTA_CONFIRM_MINS  15
#endif
#define LORA_OTA_REBOOT_DELAY_MS 6000   // after FINISH: room for the reply (and a retry of it)

class LoraOTAService {
  mesh::MainBoard* _board;
  lora_ota::Receiver* _rx;
  bool _pending;
  unsigned long _confirm_by;
  unsigned long _reboot_at;

public:
  LoraOTAService() : _board(NULL), _rx(NULL), _pending(false), _confirm_by(0), _reboot_at(0) { }
  void begin(mesh::MainBoard& board);
  // reply body for an OTA REQ (no tag); 0 = no reply
  int handleRequest(const uint8_t* req, size_t len, uint8_t* reply, uint32_t random32);
  // `ota ...` (command points past "ota "); false = not ours
  bool handleCommand(const char* command, char* reply);
  void loop();
  bool hasPendingWork() const { return _pending || _reboot_at != 0 || (_rx && _rx->receiving()); }
};

#endif

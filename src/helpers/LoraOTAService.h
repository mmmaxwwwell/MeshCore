#pragma once

// Glue between the mesh apps and lora_ota::Receiver: the confirm-or-roll-back
// window after an update, temporary fast radio settings for a transfer, and
// the `ota ...` CLI. The chip-specific half is a LoraOTAPlatform
// (LoraOTAEsp32.cpp, LoraOTANrf52.cpp); the app supplies a LoraOTARadio.

#include "LoraOTA.h"

#ifdef LORA_OTA_ENABLED

#include <MeshCore.h>

// -D LORA_OTA_DEBUG: step timings on Serial (BLE builds only: on a USB
// companion Serial IS the companion link)
#ifdef LORA_OTA_DEBUG
  #define LORA_OTA_LOG(...) do { Serial.printf(__VA_ARGS__); Serial.print("\r\n"); } while (0)
#else
  #define LORA_OTA_LOG(...) do { } while (0)
#endif

// a new image that hears no CONFIRM this long after boot rolls back
#ifndef LORA_OTA_CONFIRM_SECS
  #define LORA_OTA_CONFIRM_SECS  60
#endif
#define LORA_OTA_REBOOT_DELAY_MS   6000   // after FINISH: room for the reply (and a retry of it)
#define LORA_OTA_RADIO_DELAY_MS    1500   // after REQ_RADIO: room for the reply on the old settings
#define LORA_OTA_RADIO_MAX_IDLE_S  600

class LoraOTAPlatform {
public:
  virtual lora_ota::Flash* flash() = 0;       // where a new image is staged; NULL = no OTA
  virtual bool begin() = 0;                   // true = this boot is an unconfirmed new image
  virtual bool confirm() = 0;                 // keep the running image
  virtual void rollback() = 0;                // boot the previous image; returns only on failure
  virtual void install() = 0;                 // boot the staged (activated) image; returns only on failure
  virtual void startProbation() { }          // first loop pass of an unconfirmed image (not in setup)
  virtual bool runningSha(uint8_t sha[32]) = 0;   // SHA-256 of the running image, as signed
  virtual void feedWatchdog() { }
  virtual const char* describe() = 0;         // running slot etc., for `ota status`
};

LoraOTAPlatform& loraOtaPlatform();           // one per chip family

class LoraOTARadio {
public:
  virtual void otaTempRadio(float freq, float bw, uint8_t sf, uint8_t cr) = 0;
  virtual void otaRestoreRadio() = 0;
};

class LoraOTAService {
  LoraOTAPlatform* _platform;
  LoraOTARadio* _radio;
  lora_ota::Receiver* _rx;
  bool _pending, _probation_started;
  unsigned long _confirm_by, _reboot_at;
  // temporary radio settings: applied after the reply, dropped when OTA traffic stops
  float _t_freq, _t_bw;
  uint8_t _t_sf, _t_cr;
  uint16_t _t_idle_s;
  unsigned long _t_apply_at, _t_last;
  bool _t_active;

  void touchRadio();

public:
  LoraOTAService() : _platform(NULL), _radio(NULL), _rx(NULL), _pending(false), _probation_started(false), _confirm_by(0), _reboot_at(0),
                     _t_apply_at(0), _t_last(0), _t_active(false) { }
  void begin(LoraOTARadio& radio);
  // reply body for an OTA REQ (no tag); 0 = no reply
  int handleRequest(const uint8_t* req, size_t len, uint8_t* reply, uint32_t random32);
  // `ota ...` (command points past "ota "); false = not ours
  bool handleCommand(const char* command, char* reply);
  void loop();
  bool hasPendingWork() const {
    return _pending || _reboot_at || _t_apply_at || _t_active || (_rx && _rx->receiving());
  }
};

#endif

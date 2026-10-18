#include "LoraOTAService.h"

#ifdef LORA_OTA_ENABLED

#include <Arduino.h>
#include <Utils.h>

static uint32_t rd32(const uint8_t* p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24); }

void LoraOTAService::touchRadio() { _t_last = millis(); }

void LoraOTAService::begin(LoraOTARadio& radio) {
  _radio = &radio;
  _platform = &loraOtaPlatform();
  uint8_t pubkey[32];
  if (!mesh::Utils::fromHex(pubkey, 32, LORA_OTA_PUBKEY)) return;   // bad build flag: feature off
  _pending = _platform->begin();
  if (_pending) _confirm_by = millis() + LORA_OTA_CONFIRM_SECS * 1000UL;
  if (_platform->flash()) _rx = new lora_ota::Receiver(*_platform->flash(), pubkey, LORA_OTA_BOARD);
}

int LoraOTAService::handleRequest(const uint8_t* req, size_t len, uint8_t* reply, uint32_t random32) {
  if (!_platform || len < 1) return 0;
  touchRadio();

  if (req[0] == LORA_OTA_REQ_CONFIRM) {   // -> status, was_pending, uptime_s u32, running sha256[0:8]
    // the sha tells the sender WHICH image answered: after a rollback the old one answers too
    bool was = _pending;
    uint32_t up = millis() / 1000;
    bool ok = !_pending || _platform->confirm();
    if (ok) _pending = false;
    reply[0] = ok ? lora_ota::OK : lora_ota::FLASH_ERROR;
    reply[1] = was;
    memcpy(&reply[2], &up, 4);
    uint8_t sha[32];
    if (!_platform->runningSha(sha)) memset(sha, 0, sizeof(sha));
    memcpy(&reply[6], sha, 8);
    return 14;
  }

  if (req[0] == LORA_OTA_REQ_RADIO) {     // freq_khz u32, bw_hz u32, sf, cr, idle_s u16 -> status
    if (len < 13) { reply[0] = lora_ota::BAD_ARG; return 1; }
    float freq = rd32(&req[1]) / 1000.0f, bw = rd32(&req[5]) / 1000.0f;
    uint8_t sf = req[9], cr = req[10];
    uint16_t idle = req[11] | (req[12] << 8);
    if (freq < 150 || freq > 2500 || bw < 7 || bw > 500 || sf < 5 || sf > 12 || cr < 5 || cr > 8 ||
        idle < 10 || idle > LORA_OTA_RADIO_MAX_IDLE_S) {
      reply[0] = lora_ota::BAD_ARG;
      return 1;
    }
    _t_freq = freq; _t_bw = bw; _t_sf = sf; _t_cr = cr; _t_idle_s = idle;
    _t_apply_at = millis() + LORA_OTA_RADIO_DELAY_MS;
    reply[0] = lora_ota::OK;
    return 1;
  }

  if (!_rx) { reply[0] = lora_ota::BAD_STATE; return 1; }
  int n = _rx->handle(req, len, reply, millis(), random32, _pending);
  if (_rx->activated() && _reboot_at == 0) {
    _reboot_at = millis() + LORA_OTA_REBOOT_DELAY_MS;
  }
  return n;
}

bool LoraOTAService::handleCommand(const char* command, char* reply) {
  if (!_platform) {
    strcpy(reply, "ERR: lora ota disabled");
    return true;
  }
  if (strcmp(command, "status") == 0) {
    if (_pending) {
      long left = (long)(_confirm_by - millis()) / 1000;
      sprintf(reply, "PENDING VERIFY: confirm within %lds or it rolls back (%s)", left > 0 ? left : 0, _platform->describe());
    } else if (_rx && _rx->activated()) {
      strcpy(reply, "image activated, rebooting");
    } else if (_rx && _rx->receiving()) {
      sprintf(reply, "receiving %u/%u chunks", _rx->received(), _rx->chunks());
    } else {
      sprintf(reply, "idle, board %s, %s, %s", LORA_OTA_BOARD, _platform->describe(), LORA_OTA_MARKER);
    }
    return true;
  }
  if (strcmp(command, "confirm") == 0) {
    if (!_pending) {
      strcpy(reply, "OK - nothing pending");
    } else if (_platform->confirm()) {
      _pending = false;
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
      _platform->rollback();   // returns only if there is nothing to roll back to
      strcpy(reply, "ERR: no image to roll back to");
    }
    return true;
  }
  return false;
}

void LoraOTAService::loop() {
  if (!_platform) return;
  if (_pending && !_probation_started) {   // not in setup(): the rest of it may run long
    _probation_started = true;
    _platform->startProbation();
  }
  _platform->feedWatchdog();
  unsigned long now = millis();
  if (_rx) _rx->loop(now);

  if (_t_apply_at && (long)(now - _t_apply_at) >= 0) {
    _t_apply_at = 0;
    _radio->otaTempRadio(_t_freq, _t_bw, _t_sf, _t_cr);
    _t_active = true;
    touchRadio();
  }
  if (_t_active && !_reboot_at && (long)(now - _t_last) >= (long)_t_idle_s * 1000L) {
    _t_active = false;   // the transfer went quiet: back to the mesh, whatever happened
    _radio->otaRestoreRadio();
  }

  if (_reboot_at && (long)(now - _reboot_at) >= 0) {
    _reboot_at = 0;
    _platform->install();   // does not return on success
  }
  if (_pending && (long)(now - _confirm_by) >= 0) {
    MESH_DEBUG_PRINTLN("lora ota: not confirmed, rolling back");
    _platform->rollback();
    _confirm_by = now + 60 * 1000UL;   // nothing to roll back to: keep running, try again later
  }
}

#endif

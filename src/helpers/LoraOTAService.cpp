#include "LoraOTAService.h"

#ifdef LORA_OTA_ENABLED

#include <Arduino.h>
#include <Utils.h>

static uint32_t rd32(const uint8_t* p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24); }

void LoraOTAService::touchRadio() { _t_last = millis(); }

void LoraOTAService::begin(LoraOTARadio& radio) {
#ifdef LORA_OTA_DEBUG
  Serial.begin(115200);
#endif
  _radio = &radio;
  _platform = &loraOtaPlatform();
  uint8_t pubkey[32];
  if (!mesh::Utils::fromHex(pubkey, 32, LORA_OTA_PUBKEY)) return;   // bad build flag: feature off
  _pending = _platform->begin();
  LORA_OTA_LOG("ota: begin pending=%d", (int)_pending);
  if (_pending) _confirm_by = millis() + LORA_OTA_CONFIRM_SECS * 1000UL;
  if (_platform->flash()) {
    _rx = new lora_ota::Receiver(*_platform->flash(), pubkey, LORA_OTA_BOARD);
    _rx->setDelta(_platform->deltaStore());
  }
}

void LoraOTAService::beginSettings(lora_ota_settings::Target& target) {
  uint8_t pubkey[32];
  if (!_platform || !mesh::Utils::fromHex(pubkey, 32, LORA_OTA_PUBKEY)) return;
  _settings = new lora_ota_settings::Settings(target, pubkey, LORA_OTA_BOARD);
  _settings->begin();
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
    // check the integers: as floats, 500000 Hz / 1000 came out 500.00003 kHz on nRF52 (> 500)
    uint32_t f_khz = rd32(&req[1]), bw_hz = rd32(&req[5]);
    uint8_t sf = req[9], cr = req[10];
    uint16_t idle = req[11] | (req[12] << 8);
    float freq = f_khz / 1000.0f, bw = bw_hz / 1000.0f;   // RadioLib matches bandwidths with slack
    if (f_khz < 150000 || f_khz > 2500000 || bw_hz < 7000 || bw_hz > 500000 || sf < 5 || sf > 12 ||
        cr < 5 || cr > 8 || idle < 10 || idle > LORA_OTA_RADIO_MAX_IDLE_S) {
      reply[0] = lora_ota::BAD_ARG;
      return 1;
    }
    _t_freq = freq; _t_bw = bw; _t_sf = sf; _t_cr = cr; _t_idle_s = idle;
    _t_apply_at = millis() + LORA_OTA_RADIO_DELAY_MS;
    reply[0] = lora_ota::OK;
    return 1;
  }

  if (lora_ota_settings::Settings::isSettingsReq(req[0])) {
    if (!_settings) { reply[0] = lora_ota::BAD_STATE; return 1; }
    return _settings->handle(req, len, reply, millis());
  }

  if (!_rx) { reply[0] = lora_ota::BAD_STATE; return 1; }
  // a settings bundle on probation counts as unconfirmed too: one thing at a time
  return _rx->handle(req, len, reply, millis(), random32, _pending || (_settings && _settings->busy()));
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
      sprintf(reply, "receiving %u/%u chunks%s", _rx->received(), _rx->chunks(), _rx->idleLong() ? " (long session)" : "");
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
  if (_settings && strncmp(command, "settings", 8) == 0) {   // ota settings [confirm|revert]
    const char* op = command[8] == ' ' ? &command[9] : &command[8];
    if (strcmp(op, "confirm") == 0) {
      strcpy(reply, _settings->confirm() ? "OK - settings confirmed" : "ERR: nothing to confirm (or radio switch pending)");
    } else if (strcmp(op, "revert") == 0) {
      strcpy(reply, _settings->revertNow() ? "OK - settings reverted" : "ERR: nothing pending");
    } else if (_settings->pending()) {
      sprintf(reply, "settings v%lu PENDING: confirm within %lds or they revert", (unsigned long)_settings->pendingVersion(),
              _settings->secondsLeft(millis()));
    } else {
      sprintf(reply, "settings v%lu, nothing pending", (unsigned long)_settings->version());
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
  if (_rx) {
    _rx->loop(now);
    if (_rx->working()) {
      touchRadio();   // a long erase/verify is OTA activity: keep the transfer channel
      LORA_OTA_LOG("ota: poll start t=%lu", now);
      _rx->poll(now);
      now = millis();
      LORA_OTA_LOG("ota: poll done t=%lu receiving=%d activated=%d", now, (int)_rx->receiving(), (int)_rx->activated());
      touchRadio();
    }
    if (_rx->activated() && _reboot_at == 0) _reboot_at = now + LORA_OTA_REBOOT_DELAY_MS;
  }

  if (_settings) {
    if (_settings->working()) {
      touchRadio();
      _settings->poll(now, _pending);   // signature check + apply
      now = millis();
    }
    _settings->loop(now);   // radio switch, CONFIRM deadline
    if (_settings->takeRadioEvent()) {
      _t_active = false;   // the radio now follows the (new or restored) prefs, not the transfer channel
      _t_apply_at = 0;
    }
  }

  if (_t_apply_at && (long)(now - _t_apply_at) >= 0) {
    _t_apply_at = 0;
    _radio->otaTempRadio(_t_freq, _t_bw, _t_sf, _t_cr);
    LORA_OTA_LOG("ota: temp radio %.3f/%.1f/SF%u", _t_freq, _t_bw, _t_sf);
    _t_active = true;
    touchRadio();
  }
  if (_t_active && !_reboot_at && (long)(now - _t_last) >= (long)_t_idle_s * 1000L) {
    _t_active = false;   // the transfer went quiet: back to the mesh, whatever happened
    _radio->otaRestoreRadio();
    LORA_OTA_LOG("ota: radio restored");
  }

  if (_reboot_at && (long)(now - _reboot_at) >= 0) {
    _reboot_at = 0;
    LORA_OTA_LOG("ota: install t=%lu", now);
    _platform->install();   // does not return on success
    LORA_OTA_LOG("ota: install FAILED");
    _rx->reset();   // keep the running image; a new BEGIN may start over (no retry loop)
  }
  if (_pending && (long)(now - _confirm_by) >= 0) {
    MESH_DEBUG_PRINTLN("lora ota: not confirmed, rolling back");
    _platform->rollback();
    _confirm_by = now + 60 * 1000UL;   // nothing to roll back to: keep running, try again later
  }
}

#endif

#include "LoraOTA.h"

#if defined(LORA_OTA_ENABLED) || defined(LORA_OTA_HOST_TEST)

#include <string.h>
#include <SHA256.h>
#include <ed_25519.h>

namespace lora_ota {

static uint32_t rd32(const uint8_t* p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24); }
static uint16_t rd16(const uint8_t* p) { return p[0] | (p[1] << 8); }
static void wr32(uint8_t* p, uint32_t v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }
static void wr16(uint8_t* p, uint16_t v) { p[0] = v; p[1] = v >> 8; }

void buildManifest(uint8_t out[LORA_OTA_MANIFEST_LEN], const char* board, uint32_t size, const uint8_t sha[32]) {
  memcpy(out, "MCOTA1", 6);
  memset(&out[6], 0, LORA_OTA_BOARD_LEN);
  size_t n = strlen(board);
  memcpy(&out[6], board, n < LORA_OTA_BOARD_LEN ? n : LORA_OTA_BOARD_LEN);
  wr32(&out[6 + LORA_OTA_BOARD_LEN], size);
  memcpy(&out[6 + LORA_OTA_BOARD_LEN + 4], sha, 32);
}

Receiver::Receiver(Flash& flash, const uint8_t pubkey[32], const char* board) : _flash(&flash) {
  memcpy(_pubkey, pubkey, 32);
  strncpy(_board, board, LORA_OTA_BOARD_LEN);
  _board[LORA_OTA_BOARD_LEN] = 0;
  _state = IDLE;
  _session = _size = 0;
  _chunks = _received = 0;
  _chunk = LORA_OTA_CHUNK;
  _last_ms = 0;
}

uint16_t Receiver::firstMissing() const {
  for (uint16_t i = 0; i < _chunks; i++) {
    if (!hasChunk(i)) return i;
  }
  return _chunks;
}

int Receiver::handle(const uint8_t* req, size_t len, uint8_t* reply, uint32_t now_ms, uint32_t random32, bool pending_verify) {
  if (len < 1) return 0;
  const uint8_t* p = &req[1];
  len--;
  switch (req[0]) {
    case LORA_OTA_REQ_BEGIN:  return begin(p, len, reply, now_ms, random32, pending_verify);
    case LORA_OTA_REQ_DATA:   return data(p, len, now_ms);
    case LORA_OTA_REQ_STATUS: return status(p, len, reply, now_ms);
    case LORA_OTA_REQ_FINISH: return finish(p, len, reply);
    case LORA_OTA_REQ_ABORT:
      if (len < 4 || _state == IDLE || rd32(p) != _session) { reply[0] = BAD_SESSION; return 1; }
      if (_state == RECEIVING) _state = IDLE;   // an activated image stays activated
      reply[0] = _state == IDLE ? OK : BAD_STATE;
      return 1;
  }
  return 0;
}

// BEGIN: size u32, sha256[32], sig[64] [, chunk u8] -> status, session u32, chunk u8, chunks u16
int Receiver::begin(const uint8_t* p, size_t len, uint8_t* reply, uint32_t now_ms, uint32_t random32, bool pending) {
  memset(reply, 0, 8);
  if (len < 4 + 32 + 64) { reply[0] = BAD_ARG; return 1; }
  uint32_t size = rd32(p);
  const uint8_t* sha = &p[4];
  const uint8_t* sig = &p[36];
  uint8_t chunk = len > 100 ? p[100] : LORA_OTA_CHUNK;
  if (chunk > LORA_OTA_CHUNK) chunk = LORA_OTA_CHUNK;
  if (chunk < LORA_OTA_CHUNK_MIN) { reply[0] = BAD_ARG; return 1; }

  if (_state != IDLE && size == _size && chunk == _chunk && memcmp(sha, _sha, 32) == 0) {
    // a retry (lost reply) or a resume of the same image: same session, keep chunks
    _last_ms = now_ms;
  } else {
    if (pending) { reply[0] = PENDING_VERIFY; return 1; }   // confirm the running image first
    if (_state == DONE) { reply[0] = BAD_STATE; return 1; } // reboot pending into another image
    if (size == 0 || size > _flash->capacity() || (size + chunk - 1) / chunk > LORA_OTA_MAX_CHUNKS) {
      reply[0] = TOO_BIG; return 1;
    }
    uint8_t manifest[LORA_OTA_MANIFEST_LEN];
    buildManifest(manifest, _board, size, sha);
    if (!ed25519_verify(sig, manifest, sizeof(manifest), _pubkey)) { reply[0] = BAD_SIGNATURE; return 1; }

    _state = IDLE;
    if (!_flash->erase(size)) { reply[0] = FLASH_ERROR; return 1; }
    _size = size;
    memcpy(_sha, sha, 32);
    _chunk = chunk;
    _chunks = (size + chunk - 1) / chunk;
    _received = 0;
    memset(_bitmap, 0, sizeof(_bitmap));
    _session = random32 ? random32 : 1;
    _state = RECEIVING;
    _last_ms = now_ms;
  }
  reply[0] = OK;
  wr32(&reply[1], _session);
  reply[5] = _chunk;
  wr16(&reply[6], _chunks);
  return 8;
}

// DATA: session u32, index u16, bytes. Never replies.
int Receiver::data(const uint8_t* p, size_t len, uint32_t now_ms) {
  if (_state != RECEIVING || len < 6 || rd32(p) != _session) return 0;
  uint16_t idx = rd16(&p[4]);
  if (idx >= _chunks) return 0;
  size_t want = (idx == _chunks - 1) ? _size - (size_t)idx * _chunk : _chunk;
  if (len - 6 < want) return 0;   // datagrams arrive zero-padded to the AES block size
  _last_ms = now_ms;
  if (hasChunk(idx)) return 0;   // duplicate: flash bits only go 1 -> 0, never rewrite
  if (!_flash->write((size_t)idx * _chunk, &p[6], want)) return 0;
  _bitmap[idx >> 3] |= 1 << (idx & 7);
  _received++;
  return 0;
}

// STATUS: session u32, from u16 -> status, received u16, first_missing u16, bitmap[128]
int Receiver::status(const uint8_t* p, size_t len, uint8_t* reply, uint32_t now_ms) {
  memset(reply, 0, 5 + LORA_OTA_BITMAP_REPLY);
  if (len < 6 || _state == IDLE || rd32(p) != _session) { reply[0] = BAD_SESSION; return 1; }
  _last_ms = now_ms;
  uint16_t from = rd16(&p[4]);
  reply[0] = OK;
  wr16(&reply[1], _received);
  wr16(&reply[3], firstMissing());
  for (uint32_t j = 0; j < LORA_OTA_BITMAP_REPLY * 8; j++) {
    uint32_t i = from + j;
    if (i < _chunks && hasChunk(i)) reply[5 + (j >> 3)] |= 1 << (j & 7);
  }
  return 5 + LORA_OTA_BITMAP_REPLY;
}

Status Receiver::verifyImage() {
  static const char marker[] = LORA_OTA_MARKER;
  const size_t mlen = sizeof(marker) - 1;
  uint8_t buf[mlen - 1 + 1024];
  size_t carry = 0;
  bool found = false;
  SHA256 sha;
  for (size_t off = 0; off < _size; ) {
    size_t n = _size - off < 1024 ? _size - off : 1024;
    if (!_flash->read(off, &buf[carry], n)) return FLASH_ERROR;
    sha.update(&buf[carry], n);
    size_t have = carry + n;
    if (!found && have >= mlen) {
      for (size_t i = 0; i + mlen <= have; i++) {
        if (buf[i] == marker[0] && memcmp(&buf[i], marker, mlen) == 0) { found = true; break; }
      }
    }
    carry = have < mlen - 1 ? have : mlen - 1;   // keep a tail so a marker can straddle blocks
    memmove(buf, &buf[have - carry], carry);
    off += n;
  }
  uint8_t digest[32];
  sha.finalize(digest, 32);
  if (memcmp(digest, _sha, 32) != 0) return HASH_MISMATCH;
  if (!found) return NO_MARKER;
  return OK;
}

// FINISH: session u32 -> status. OK means the image is the next boot image.
int Receiver::finish(const uint8_t* p, size_t len, uint8_t* reply) {
  if (len < 4 || _state == IDLE || rd32(p) != _session) { reply[0] = BAD_SESSION; return 1; }
  if (_state == DONE) { reply[0] = OK; return 1; }   // retry after a lost reply
  if (_received != _chunks) { reply[0] = INCOMPLETE; return 1; }
  Status s = verifyImage();
  if (s == OK && !_flash->activate(_size)) s = ACTIVATE_FAILED;
  if (s == OK) {
    _state = DONE;
  } else if (s == HASH_MISMATCH || s == FLASH_ERROR) {
    memset(_bitmap, 0, sizeof(_bitmap));   // start over within the same session
    _received = 0;
    if (!_flash->erase(_size)) _state = IDLE;
  }
  reply[0] = s;
  return 1;
}

void Receiver::loop(uint32_t now_ms) {
  if (_state == RECEIVING && (uint32_t)(now_ms - _last_ms) > LORA_OTA_IDLE_MS) {
    _state = IDLE;
  }
}

}

#endif

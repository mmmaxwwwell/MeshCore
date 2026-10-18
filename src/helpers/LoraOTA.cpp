#include "LoraOTA.h"
#include "LoraOTADelta.h"

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
  _result = OK;
  _last_ms = 0;
  _flags = 0;
  _resumed = _save_fresh = false;
  _unsaved = 0;
  _unsaved_since = 0;
  _dstore = NULL;
  _dec = NULL;
  _decoded = false;
  _decoding = 0;
  _xfer = 0;
  memset(_base8, 0, sizeof(_base8));
}

void Receiver::setDelta(DeltaStore* store) {
  _dstore = store;
  if (store && !_dec) _dec = new DeltaDecoder();
}

// ---------------------------------------------------------------- LONG sessions: the persisted record

#define SESS_MAGIC 0x3253434D   // "MCS2"
#define SESS_HDR   56           // magic u32, size u32, chunk u8, flags u8, pad u16, sha256[32],
                                // DELTA: patch size u32, base sha256[0:8] (else 0)

bool NorSessionStore::save(const uint8_t* hdr, size_t hlen, const uint8_t* bitmap, size_t blen, bool fresh) {
  if (hlen + blen > sessSize()) return false;
  if (fresh && (!sessErase() || !sessWrite(0, hdr, hlen))) return false;
  uint8_t inv[64];
  for (size_t off = 0; off < blen; off += sizeof(inv)) {
    size_t n = blen - off < sizeof(inv) ? blen - off : sizeof(inv);
    for (size_t i = 0; i < n; i++) inv[i] = ~bitmap[off + i];
    if (!sessWrite(hlen + off, inv, n)) return false;
  }
  return true;
}

bool NorSessionStore::load(uint8_t* hdr, size_t hlen, uint8_t* bitmap, size_t blen) {
  if (hlen + blen > sessSize() || !sessRead(0, hdr, hlen) || !sessRead(hlen, bitmap, blen)) return false;
  for (size_t i = 0; i < blen; i++) bitmap[i] = ~bitmap[i];
  return true;
}

void NorSessionStore::clear() {
  uint8_t hdr[4];
  if (sessRead(0, hdr, 4) && rd32(hdr) == 0xFFFFFFFF) return;   // nothing there (erased)
  static const uint8_t zero[4] = {0, 0, 0, 0};
  sessWrite(0, zero, 4);   // magic 0: no record (no erase needed)
}

void Receiver::saveSession(bool fresh) {
  uint8_t hdr[SESS_HDR];
  memset(hdr, 0, sizeof(hdr));
  wr32(hdr, SESS_MAGIC);
  wr32(&hdr[4], _size);
  hdr[8] = _chunk;
  hdr[9] = _flags;
  memcpy(&hdr[12], _sha, 32);
  if (isDelta()) {   // the bitmap then names PATCH chunks: bind it to that patch and base
    wr32(&hdr[44], _xfer);
    memcpy(&hdr[48], _base8, 8);
  }
  _flash->saveSession(hdr, sizeof(hdr), _bitmap, (_chunks + 7) / 8, fresh);   // a failed save only costs a resend
  _unsaved = 0;
  _save_fresh = false;
}

// PREPARING a LONG session: an earlier session of this same image (same size, chunk
// size and SHA-256, so the same signature checked just now) left a record: take its
// chunks instead of erasing. The flash holds every chunk the record names, since the
// record is saved only after the chunks are written. A DELTA record names patch
// chunks, so it must also be for the same patch (size) against the same base;
// the image area holds no chunks then and is erased afresh for the decode.
bool Receiver::restoreSession() {
  uint8_t hdr[SESS_HDR];
  uint16_t chunks = (_xfer + _chunk - 1) / _chunk;
  if (!_flash->loadSession(hdr, sizeof(hdr), _bitmap, (chunks + 7) / 8)) return false;
  if (rd32(hdr) != SESS_MAGIC || rd32(&hdr[4]) != _size || hdr[8] != _chunk || memcmp(&hdr[12], _sha, 32) != 0) return false;
  if ((hdr[9] ^ _flags) & LORA_OTA_FLAG_DELTA) return false;
  if (isDelta()) {
    if (rd32(&hdr[44]) != _xfer || memcmp(&hdr[48], _base8, 8) != 0) return false;
    if (!_flash->erase(_size) || !_dstore->patchReattach(_size, _xfer)) return false;
  } else if (!_flash->reattach(_size)) return false;
  memset(&_bitmap[(chunks + 7) / 8], 0, sizeof(_bitmap) - (chunks + 7) / 8);
  if (chunks % 8) _bitmap[chunks / 8] &= (1 << (chunks % 8)) - 1;
  _chunks = chunks;
  _received = 0;
  for (uint16_t i = 0; i < _chunks; i++) {
    if (hasChunk(i)) _received++;
  }
  return true;
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
      if (_state == RECEIVING || _state == PREPARING) _state = IDLE;   // an activated image stays activated
      // a LONG record stays (no flash work in the receive path): the next BEGIN of another image clears it
      reply[0] = _state == IDLE ? OK : BAD_STATE;
      return 1;
  }
  return 0;
}

// BEGIN: size u32, sha256[32], sig[64] [, chunk u8 [, flags u8 [, base_sha8[8], patch_size u32]]]
//   -> status, session u32, chunk u8, chunks u16, flags u8
// size/sha/sig always describe the NEW image. With LORA_OTA_FLAG_DELTA the
// DATA chunks carry patch_size bytes of patch against the running image,
// which must be the one named by base_sha8 (else BASE_MISMATCH).
// A new image answers WORKING; poll() checks the signature and prepares the
// staging area, and a repeated BEGIN then gets OK + session (or the error).
int Receiver::begin(const uint8_t* p, size_t len, uint8_t* reply, uint32_t now_ms, uint32_t random32, bool pending) {
  memset(reply, 0, 9);
  if (len < 4 + 32 + 64) { reply[0] = BAD_ARG; return 1; }
  uint32_t size = rd32(p);
  const uint8_t* sha = &p[4];
  const uint8_t* sig = &p[36];
  uint8_t chunk = len > 100 ? p[100] : LORA_OTA_CHUNK;
  uint8_t flags = (len > 101 ? p[101] : 0) & (LORA_OTA_FLAG_LONG | LORA_OTA_FLAG_DELTA);   // the flags this receiver knows
  if (chunk > LORA_OTA_CHUNK) chunk = LORA_OTA_CHUNK;
  if (chunk < LORA_OTA_CHUNK_MIN) { reply[0] = BAD_ARG; return 1; }
  bool delta = flags & LORA_OTA_FLAG_DELTA;
  uint32_t xfer = size;
  const uint8_t* base8 = NULL;
  if (delta) {
    if (len < LORA_OTA_BEGIN_DELTA_LEN || !_dstore || !_dec) { reply[0] = BAD_ARG; return 1; }   // sender: send it whole
    base8 = &p[102];
    xfer = rd32(&p[110]);
  }

  // LONG may change within a session; DELTA and its patch may not
  bool same = size == _size && chunk == _chunk && memcmp(sha, _sha, 32) == 0 && delta == isDelta() &&
              (!delta || (xfer == _xfer && memcmp(base8, _base8, 8) == 0));
  if (same && _state == PREPARING) { reply[0] = WORKING; return 1; }
  if (same && _state == IDLE && _result != OK) {   // the preparation failed: report it once
    reply[0] = _result;
    _result = OK;
    _size = 0;
    return 1;
  }
  if (_state != IDLE && same) {
    // a retry (lost reply) or a resume of the same image: same session, keep chunks
    _last_ms = now_ms;
    if ((flags ^ _flags) & LORA_OTA_FLAG_LONG) {   // e.g. a fast transfer resumed slowly over the mesh
      // to LONG: loop() writes a record of what is here; from LONG: the record just stops
      // growing (an older record names fewer chunks, never wrong ones)
      _save_fresh = _state == RECEIVING && (flags & LORA_OTA_FLAG_LONG);
      _flags = (_flags & ~LORA_OTA_FLAG_LONG) | (flags & LORA_OTA_FLAG_LONG);
    }
  } else {
    if (pending) { reply[0] = PENDING_VERIFY; return 1; }   // confirm the running image first
    if (_state == DONE || _state == VERIFYING) { reply[0] = BAD_STATE; return 1; }
    if (size == 0 || xfer == 0 || (xfer + chunk - 1) / chunk > LORA_OTA_MAX_CHUNKS) { reply[0] = TOO_BIG; return 1; }
    _size = size;
    _xfer = xfer;
    if (delta) memcpy(_base8, base8, 8);
    _chunk = chunk;
    memcpy(_sha, sha, 32);
    memcpy(_sig, sig, 64);
    _flags = flags;
    _session = random32 ? random32 : 1;
    _result = OK;
    _state = PREPARING;
    _last_ms = now_ms;
    reply[0] = WORKING;
    return 1;
  }
  reply[0] = OK;
  wr32(&reply[1], _session);
  reply[5] = _chunk;
  wr16(&reply[6], _chunks);
  reply[8] = _flags;   // accepted flags (an older receiver's 8-byte reply reads as 0: none)
  return 9;
}

// DATA: session u32, index u16, bytes. Never replies.
int Receiver::data(const uint8_t* p, size_t len, uint32_t now_ms) {
  if (_state != RECEIVING || len < 6 || rd32(p) != _session) return 0;
  uint16_t idx = rd16(&p[4]);
  if (idx >= _chunks) return 0;
  size_t want = (idx == _chunks - 1) ? _xfer - (size_t)idx * _chunk : _chunk;
  if (len - 6 < want) return 0;   // datagrams arrive zero-padded to the AES block size
  _last_ms = now_ms;
  if (hasChunk(idx)) return 0;   // duplicate: flash bits only go 1 -> 0, never rewrite
  bool ok = isDelta() ? _dstore->patchWrite((size_t)idx * _chunk, &p[6], want) : _flash->write((size_t)idx * _chunk, &p[6], want);
  if (!ok) return 0;
  _bitmap[idx >> 3] |= 1 << (idx & 7);
  _received++;
  if (isLong() && _unsaved++ == 0) _unsaved_since = now_ms;   // saved from loop(), not the receive path
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

// FINISH: session u32 -> status. WORKING while poll() checks the image; OK
// once it is the next boot image.
int Receiver::finish(const uint8_t* p, size_t len, uint8_t* reply) {
  if (len < 4 || _state == IDLE || _state == PREPARING || rd32(p) != _session) { reply[0] = BAD_SESSION; return 1; }
  if (_state == DONE) { reply[0] = OK; return 1; }   // retry after a lost reply
  if (_state == VERIFYING) { reply[0] = WORKING; return 1; }
  if (_result != OK) {   // what the last verify found (HASH_MISMATCH: the chunks are being resent)
    reply[0] = _result;
    _result = OK;
    return 1;
  }
  if (_received != _chunks) { reply[0] = INCOMPLETE; return 1; }
  _state = VERIFYING;
  _decoding = (isDelta() && !_decoded) ? 1 : 0;   // a patch: poll() decodes it into the image first
  reply[0] = WORKING;
  return 1;
}

// erase the staging area (and, for a delta, the patch's) for a fresh pass
Status Receiver::restage() {
  _decoded = false;
  _decoding = 0;
  _flash->clearSession();   // before the erase: a record must never name erased chunks
  if (_dstore) _dstore->patchDone();   // a stale patch must not eat the room the image needs
  if (!_flash->erase(_size)) return FLASH_ERROR;
  return isDelta() ? _dstore->patchPrepare(_size, _xfer) : OK;
}

Status Receiver::prepare() {
  uint8_t manifest[LORA_OTA_MANIFEST_LEN];
  buildManifest(manifest, _board, _size, _sha);
  if (_size > _flash->capacity()) return TOO_BIG;
  if (!ed25519_verify(_sig, manifest, sizeof(manifest), _pubkey)) return BAD_SIGNATURE;
  if (isDelta()) {
    uint8_t running[8];
    if (!_dstore->baseSha8(running) || memcmp(running, _base8, 8) != 0) return BASE_MISMATCH;
  }
  _decoded = false;
  _decoding = 0;
  _resumed = isLong() && restoreSession();   // chunks of an earlier session of this image
  return _resumed ? OK : restage();
}

// a slice of the patch decode: WORKING = more to do, OK = the image is written
Status Receiver::decodeStep() {
  if (_decoding == 1) {
    if (!_dec->start(_dstore, _flash, _xfer, _size)) { _decoding = 0; return HASH_MISMATCH; }
    _decoding = 2;
  }
  int r = _dec->step(LORA_OTA_DELTA_STEP);
  if (r == 0) return WORKING;
  _decoding = 0;
  _decoded = r > 0;
  return _decoded ? OK : HASH_MISMATCH;   // a bad patch: start over, like a bad image
}

void Receiver::poll(uint32_t now_ms) {
  if (_state == PREPARING) {
    Status s = prepare();
    if (s != OK) {
      _state = IDLE;   // the next BEGIN with this image reports s
      _result = s;
      return;
    }
    if (!_resumed) {
      _chunks = (_xfer + _chunk - 1) / _chunk;
      _received = 0;
      memset(_bitmap, 0, sizeof(_bitmap));
      if (isLong()) saveSession(true);
    }
    _unsaved = 0;
    _state = RECEIVING;
    _last_ms = now_ms;
  } else if (_state == VERIFYING) {
    Status s = _decoding ? decodeStep() : OK;
    if (s == WORKING) {
      _last_ms = now_ms;
      return;
    }
    if (s == OK) s = verifyImage();
    if (s == OK && isDelta()) _dstore->patchDone();   // free its room before the install needs it
    if (s == OK && !_flash->activate(_size)) s = ACTIVATE_FAILED;
    if (s == OK) {
      _state = DONE;
      _flash->clearSession();
      return;
    }
    _result = s;   // the next FINISH reports it
    _state = RECEIVING;
    _last_ms = now_ms;
    if (s == HASH_MISMATCH || s == FLASH_ERROR) {
      memset(_bitmap, 0, sizeof(_bitmap));   // start over within the same session
      _received = 0;
      if (restage() != OK) _state = IDLE;
      else if (isLong()) saveSession(true);
    }
  }
}

void Receiver::loop(uint32_t now_ms) {
  if (_state != RECEIVING) return;
  if (isLong() && (_save_fresh || _unsaved >= LORA_OTA_SAVE_CHUNKS ||
                   (_unsaved && (uint32_t)(now_ms - _unsaved_since) >= LORA_OTA_SAVE_MS))) {
    saveSession(_save_fresh);
  }
  if ((uint32_t)(now_ms - _last_ms) > (isLong() ? LORA_OTA_LONG_IDLE_MS : LORA_OTA_IDLE_MS)) {
    if (isLong() && _unsaved) saveSession(false);
    _state = IDLE;   // a LONG session's record stays: a BEGIN of the same image picks it up again
  }
}

}

#endif

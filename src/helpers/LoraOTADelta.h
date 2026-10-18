#pragma once

// Delta (changes-only) LoRa OTA: the DATA chunks carry a patch that rebuilds
// the new image from the one the target runs now. Format and encoder:
// tools/lora-ota/delta.py. The patch is not trusted: the receiver decodes it
// into the normal staging area and then checks the result against the
// SIGNED size + sha256 exactly as for a full image (Receiver::verifyImage).
//
// Platform glue is a DeltaStore: where the running (base) image is read
// from and where the patch is staged while the new image is written.

#include "LoraOTA.h"

#define LORA_OTA_DELTA_MAGIC     "MCD1"
#define LORA_OTA_DELTA_HDR       13      // magic[4], flags u8, base_size u32, new_size u32
#define LORA_OTA_DELTA_FLAG_DEFLATE  0x01   // body is raw deflate (RFC 1951) ...
#define LORA_OTA_DELTA_WIN_BITS      11     // ... made with a window of at most 2 KiB
#define LORA_OTA_DELTA_STEP      32768   // new-image bytes per Receiver::poll() call

namespace lora_ota {

class DeltaStore {
public:
  virtual bool baseSha8(uint8_t out[8]) = 0;     // the running image's sha256[0:8], as CONFIRM reports it
  virtual size_t baseSize() = 0;                 // readable bytes of the running image
  virtual bool readBase(size_t off, uint8_t* dest, size_t len) = 0;
  // room for a patch of patch_size next to a new image of new_size (already
  // erased in the Flash), erased: OK, TOO_BIG or FLASH_ERROR
  virtual Status patchPrepare(size_t new_size, size_t patch_size) = 0;
  virtual bool patchWrite(size_t off, const uint8_t* src, size_t len) = 0;
  virtual bool patchRead(size_t off, uint8_t* dest, size_t len) = 0;
  virtual void patchDone() { }                   // decoded (or failed): the room may be freed
};

// Streams patch -> new image: patch read front to back once, base read
// mostly in order, new image written strictly in order. ~3.6 KB of RAM, no
// big stack frames (it runs from poll() on the nRF52's 4 KB loop stack).
class DeltaDecoder {
  DeltaStore* _store;
  Flash* _out;
  uint32_t _patch_size, _new_size, _base_size;
  uint32_t _pin;                 // patch bytes read
  uint32_t _out_pos;             // new-image bytes produced (written or buffered)
  int32_t _bpos;                 // base cursor
  bool _deflate, _failed;
  // record state
  uint32_t _add_left, _zero_left, _lit_left, _extra_left;
  int32_t _seek;
  bool _in_add, _in_rec;
  // inflate state: pulls bytes on demand, so only the block/match is kept
  uint32_t _bitbuf;
  uint8_t _bitcnt;
  bool _blk_final, _inf_end;
  uint8_t _blk_type;           // 0 stored, 1/2 huffman, 0xFF = need a block header
  uint16_t _stored_left;
  uint16_t _m_dist, _m_left;
  uint32_t _w_pos;             // bytes inflated so far
  uint16_t _lencnt[16], _lensym[288], _distcnt[16], _distsym[32];
  uint8_t _lens[288 + 32];
  // buffers
  uint8_t _pbuf[128];
  uint16_t _pbuf_len, _pbuf_at;
  uint8_t _bbuf[128];
  int32_t _bbuf_off;
  uint16_t _bbuf_len;
  uint8_t _obuf[256];
  uint16_t _obuf_len;
  uint32_t _obuf_off;
  uint8_t _win[1 << LORA_OTA_DELTA_WIN_BITS];

  bool rawByte(uint8_t& b);
  bool bits(uint8_t n, uint32_t& v);
  bool symbol(const uint16_t* cnt, const uint16_t* sym, uint16_t& s);
  bool blockHeader();
  bool inflateByte(uint8_t& b);
  bool bodyByte(uint8_t& b);
  bool varint(uint32_t& v);
  bool baseByte(uint32_t off, uint8_t& b);
  bool put(uint8_t b);
  bool flush();
  bool finished();

public:
  DeltaDecoder() : _store(0), _out(0), _failed(true) { }
  // false: the header is bad or does not fit this base / signed size
  bool start(DeltaStore* store, Flash* out, uint32_t patch_size, uint32_t new_size);
  // runs until about `budget` new-image bytes are out: 1 = done (all written,
  // patch consumed exactly), 0 = call again, -1 = the patch is bad / I/O failed
  int step(uint32_t budget);
};

}

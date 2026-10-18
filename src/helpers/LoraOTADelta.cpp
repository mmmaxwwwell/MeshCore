#include "LoraOTADelta.h"

#if defined(LORA_OTA_ENABLED) || defined(LORA_OTA_HOST_TEST)

#include <string.h>

namespace lora_ota {

#define WIN   (1u << LORA_OTA_DELTA_WIN_BITS)

static uint32_t rd32(const uint8_t* p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24); }

bool DeltaDecoder::start(DeltaStore* store, Flash* out, uint32_t patch_size, uint32_t new_size) {
  _store = store;
  _out = out;
  _failed = true;
  uint8_t h[LORA_OTA_DELTA_HDR];
  if (patch_size < LORA_OTA_DELTA_HDR || !store->patchRead(0, h, sizeof(h))) return false;
  if (memcmp(h, LORA_OTA_DELTA_MAGIC, 4) != 0 || (h[4] & ~LORA_OTA_DELTA_FLAG_DEFLATE) != 0) return false;
  _base_size = rd32(&h[5]);
  if (rd32(&h[9]) != new_size || _base_size > store->baseSize()) return false;
  _deflate = h[4] & LORA_OTA_DELTA_FLAG_DEFLATE;
  _patch_size = patch_size;
  _new_size = new_size;
  _pin = LORA_OTA_DELTA_HDR;
  _out_pos = 0;
  _bpos = 0;
  _in_rec = _in_add = false;
  _add_left = _zero_left = _lit_left = _extra_left = 0;
  _seek = 0;
  _bitbuf = 0;
  _bitcnt = 0;
  _blk_final = _inf_end = false;
  _blk_type = 0xFF;
  _stored_left = 0;
  _m_dist = _m_left = 0;
  _w_pos = 0;
  _pbuf_len = _pbuf_at = 0;
  _bbuf_off = -1;
  _bbuf_len = 0;
  _obuf_len = 0;
  _obuf_off = 0;
  _failed = false;
  return true;
}

// next byte of the patch as stored
bool DeltaDecoder::rawByte(uint8_t& b) {
  if (_pbuf_at == _pbuf_len) {
    if (_pin >= _patch_size) return false;
    uint32_t n = _patch_size - _pin < sizeof(_pbuf) ? _patch_size - _pin : sizeof(_pbuf);
    if (!_store->patchRead(_pin, _pbuf, n)) return false;
    _pin += n;
    _pbuf_len = n;
    _pbuf_at = 0;
  }
  b = _pbuf[_pbuf_at++];
  return true;
}

// ---------------------------------------------------------------- inflate (RFC 1951)
// Pull-based: the patch sits in flash, so a byte is always there to read and
// no bit-level state has to survive between calls; only the current block
// and match do. Huffman decoding is puff's canonical count/symbol walk:
// slow per bit, tiny in RAM, and plenty for a patch of tens of KB.

static const uint16_t LBASE[29] = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
                                    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
static const uint8_t LEXT[29] = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
static const uint16_t DBASE[30] = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
                                    1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };
static const uint8_t DEXT[30] = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };
static const uint8_t CLORDER[19] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };

// canonical code from code lengths; false if over-subscribed (incomplete is
// allowed: an unused code then fails in symbol())
static bool construct(uint16_t* cnt, uint16_t* sym, const uint8_t* lens, uint16_t n) {
  uint16_t offs[16];
  for (int l = 0; l < 16; l++) cnt[l] = 0;
  for (uint16_t s = 0; s < n; s++) cnt[lens[s]]++;
  int left = 1;
  for (int l = 1; l < 16; l++) {
    left = (left << 1) - cnt[l];
    if (left < 0) return false;
  }
  offs[1] = 0;
  for (int l = 1; l < 15; l++) offs[l + 1] = offs[l] + cnt[l];
  for (uint16_t s = 0; s < n; s++) {
    if (lens[s]) sym[offs[lens[s]]++] = s;
  }
  return true;
}

bool DeltaDecoder::bits(uint8_t n, uint32_t& v) {
  while (_bitcnt < n) {
    uint8_t b;
    if (!rawByte(b)) return false;
    _bitbuf |= (uint32_t)b << _bitcnt;
    _bitcnt += 8;
  }
  v = _bitbuf & ((1UL << n) - 1);
  _bitbuf >>= n;
  _bitcnt -= n;
  return true;
}

bool DeltaDecoder::symbol(const uint16_t* cnt, const uint16_t* sym, uint16_t& s) {
  int code = 0, first = 0, index = 0;
  for (int l = 1; l < 16; l++) {
    uint32_t b;
    if (!bits(1, b)) return false;
    code |= b;
    int count = cnt[l];
    if (code - count < first) {
      s = sym[index + (code - first)];
      return true;
    }
    index += count;
    first = (first + count) << 1;
    code <<= 1;
  }
  return false;   // not a code in this table
}

bool DeltaDecoder::blockHeader() {
  uint32_t v;
  if (!bits(3, v)) return false;
  _blk_final = v & 1;
  _blk_type = v >> 1;
  if (_blk_type == 0) {   // stored: byte aligned LEN, NLEN
    _bitbuf = 0;
    _bitcnt = 0;
    uint8_t b[4];
    for (int i = 0; i < 4; i++) {
      if (!rawByte(b[i])) return false;
    }
    _stored_left = b[0] | (b[1] << 8);
    return (uint16_t)~_stored_left == (uint16_t)(b[2] | (b[3] << 8));
  }
  if (_blk_type == 1) {   // fixed codes
    uint16_t i = 0;
    for (; i < 144; i++) _lens[i] = 8;
    for (; i < 256; i++) _lens[i] = 9;
    for (; i < 280; i++) _lens[i] = 7;
    for (; i < 288; i++) _lens[i] = 8;
    construct(_lencnt, _lensym, _lens, 288);
    for (i = 0; i < 30; i++) _lens[i] = 5;
    construct(_distcnt, _distsym, _lens, 30);
    return true;
  }
  if (_blk_type != 2) return false;
  uint32_t hlit, hdist, hclen;
  if (!bits(5, hlit) || !bits(5, hdist) || !bits(4, hclen)) return false;
  hlit += 257;
  hdist += 1;
  hclen += 4;
  if (hlit > 286 || hdist > 30) return false;
  for (int i = 0; i < 19; i++) _lens[i] = 0;
  for (uint32_t i = 0; i < hclen; i++) {
    if (!bits(3, v)) return false;
    _lens[CLORDER[i]] = v;
  }
  if (!construct(_lencnt, _lensym, _lens, 19)) return false;   // the code-length code, for now
  uint16_t at = 0;
  while (at < hlit + hdist) {
    uint16_t sym;
    if (!symbol(_lencnt, _lensym, sym)) return false;
    if (sym < 16) { _lens[at++] = sym; continue; }
    uint8_t len = 0;
    uint32_t rep;
    if (sym == 16) {
      if (at == 0 || !bits(2, rep)) return false;
      len = _lens[at - 1];
      rep += 3;
    } else if (sym == 17) {
      if (!bits(3, rep)) return false;
      rep += 3;
    } else {
      if (!bits(7, rep)) return false;
      rep += 11;
    }
    if (at + rep > hlit + hdist) return false;
    while (rep--) _lens[at++] = len;
  }
  if (_lens[256] == 0) return false;   // no end-of-block code
  if (!construct(_lencnt, _lensym, _lens, hlit)) return false;
  return construct(_distcnt, _distsym, &_lens[hlit], hdist);
}

// next inflated byte; false at the end of the stream (_inf_end) or on an error
bool DeltaDecoder::inflateByte(uint8_t& b) {
  for (;;) {
    if (_m_left) {
      b = _win[(_w_pos - _m_dist) & (WIN - 1)];
      _m_left--;
      break;
    }
    if (_blk_type == 0xFF) {
      if (_inf_end || !blockHeader()) return false;
      continue;
    }
    if (_blk_type == 0) {
      if (_stored_left) {
        if (!rawByte(b)) return false;
        _stored_left--;
        break;
      }
    } else {
      uint16_t sym;
      if (!symbol(_lencnt, _lensym, sym)) return false;
      if (sym < 256) { b = sym; break; }
      if (sym > 256) {
        sym -= 257;
        uint32_t extra, dsym16;
        uint16_t dsym;
        if (sym >= 29 || !bits(LEXT[sym], extra)) return false;
        _m_left = LBASE[sym] + extra;
        if (!symbol(_distcnt, _distsym, dsym) || dsym >= 30 || !bits(DEXT[dsym], dsym16)) return false;
        uint32_t dist = DBASE[dsym] + dsym16;
        if (dist > WIN || dist > _w_pos) return false;   // reaches past the window or the start
        _m_dist = dist;
        continue;
      }
    }
    // end of block (stored: its bytes are out)
    _blk_type = 0xFF;
    if (_blk_final) {
      _inf_end = true;
      return false;
    }
  }
  _win[_w_pos++ & (WIN - 1)] = b;
  return true;
}

// next byte of the body: through inflate if the patch is compressed
bool DeltaDecoder::bodyByte(uint8_t& b) {
  return _deflate ? inflateByte(b) : rawByte(b);
}

bool DeltaDecoder::varint(uint32_t& v) {
  v = 0;
  for (int sh = 0; sh <= 28; sh += 7) {
    uint8_t b;
    if (!bodyByte(b)) return false;
    v |= (uint32_t)(b & 0x7F) << sh;
    if (!(b & 0x80)) return true;
  }
  return false;
}

bool DeltaDecoder::baseByte(uint32_t off, uint8_t& b) {
  if (_bbuf_off < 0 || off < (uint32_t)_bbuf_off || off >= (uint32_t)_bbuf_off + _bbuf_len) {
    uint32_t n = _base_size - off < sizeof(_bbuf) ? _base_size - off : sizeof(_bbuf);
    if (!_store->readBase(off, _bbuf, n)) return false;
    _bbuf_off = off;
    _bbuf_len = n;
  }
  b = _bbuf[off - _bbuf_off];
  return true;
}

bool DeltaDecoder::flush() {
  if (_obuf_len == 0) return true;
  if (!_out->write(_obuf_off, _obuf, _obuf_len)) return false;
  _obuf_off += _obuf_len;
  _obuf_len = 0;
  return true;
}

bool DeltaDecoder::put(uint8_t b) {
  if (_out_pos >= _new_size) return false;
  _obuf[_obuf_len++] = b;
  _out_pos++;
  return _obuf_len < sizeof(_obuf) || flush();
}

// everything out, the body ends here, and the patch is consumed to its last byte
bool DeltaDecoder::finished() {
  if (_in_rec || !flush()) return false;
  if (_deflate) {
    uint8_t b;
    if (inflateByte(b) || !_inf_end) return false;   // more body, or a broken stream
  }
  return _pbuf_at == _pbuf_len && _pin == _patch_size;
}

int DeltaDecoder::step(uint32_t budget) {
  if (_failed) return -1;
  uint32_t stop = _out_pos + budget;
  while (_out_pos < stop) {
    if (!_in_rec) {
      if (_out_pos == _new_size) break;
      uint32_t add, extra, zz;
      if (!varint(add) || !varint(extra) || !varint(zz)) goto bad;
      _seek = (int32_t)(zz >> 1) ^ -(int32_t)(zz & 1);
      if (add > _new_size - _out_pos || extra > _new_size - _out_pos - add) goto bad;
      if (_bpos < 0 || add > _base_size || (uint32_t)_bpos > _base_size - add) goto bad;
      _add_left = add;
      _extra_left = extra;
      _zero_left = _lit_left = 0;
      _in_add = false;
      _in_rec = true;
    }
    uint8_t b, d;
    if (_zero_left) {                 // NEW = BASE
      if (!baseByte(_bpos, b) || !put(b)) goto bad;
      _bpos++; _zero_left--; _add_left--;
    } else if (_lit_left) {           // NEW = BASE + diff
      if (!baseByte(_bpos, b) || !bodyByte(d) || !put(b + d)) goto bad;
      _bpos++; _lit_left--; _add_left--;
    } else if (_add_left) {           // the next (zeros, n) pair of the add-region
      uint32_t z, n;
      if (!varint(z) || !varint(n) || z > _add_left || n > _add_left - z || z + n == 0) goto bad;
      _zero_left = z;
      _lit_left = n;
    } else if (_extra_left) {         // literal bytes of NEW
      if (!bodyByte(b) || !put(b)) goto bad;
      _extra_left--;
    } else {                          // record done: move the base cursor
      int64_t np = (int64_t)_bpos + _seek;
      if (np < 0 || np > (int64_t)_base_size) goto bad;
      _bpos = (int32_t)np;
      _in_rec = false;
    }
  }
  if (_out_pos < _new_size || _in_rec) return 0;
  if (!finished()) goto bad;
  return 1;
bad:
  _failed = true;
  return -1;
}

}

#endif

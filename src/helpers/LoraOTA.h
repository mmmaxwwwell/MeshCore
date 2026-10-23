#pragma once

// Firmware over LoRa: the receiver half of a chunked, signed image transfer
// carried in admin REQ datagrams (see docs in tools/lora-ota/README.md).
// Platform-neutral: flash access goes through lora_ota::Flash, so the same
// code runs on the radio and in the host simulator (tools/lora-ota/sim).

#include <stdint.h>
#include <stddef.h>

#if (defined(ESP32) || defined(NRF52_PLATFORM) || defined(NRF54_PLATFORM)) && defined(LORA_OTA_PUBKEY) && defined(LORA_OTA_BOARD)
  #define LORA_OTA_ENABLED 1
#endif

#define LORA_OTA_REQ_BEGIN   0x60
#define LORA_OTA_REQ_DATA    0x61
#define LORA_OTA_REQ_STATUS  0x62
#define LORA_OTA_REQ_FINISH  0x63
#define LORA_OTA_REQ_ABORT   0x64
#define LORA_OTA_REQ_CONFIRM 0x65   // handled by LoraOTAService, not the Receiver
#define LORA_OTA_REQ_RADIO   0x66   // ditto: temporary fast radio settings for the transfer

// a REQ datagram holds 163 bytes after the 4-byte tag; DATA spends 7 on
// type + session + index. The sender picks the chunk size in BEGIN (a stock
// companion's 176-byte command frame leaves room for 136); this is the cap.
#define LORA_OTA_CHUNK          156
#define LORA_OTA_CHUNK_MIN      16
#define LORA_OTA_MAX_CHUNKS     16384                  // 2.5 MB
#define LORA_OTA_BITMAP_REPLY   128                    // chunks per STATUS = 1024
#define LORA_OTA_IDLE_MS        (5 * 60 * 1000UL)      // abandon a silent session
#define LORA_OTA_LONG_IDLE_MS   (6 * 60 * 60 * 1000UL) // ... a silent LONG session (slow, over the mesh)
#define LORA_OTA_SAVE_CHUNKS    16                     // LONG: persist the bitmap every this many new chunks
#define LORA_OTA_SAVE_MS        (5 * 60 * 1000UL)      // ... or this long after the first unsaved one

// BEGIN flags (payload offset 101, after the chunk byte); the reply echoes the accepted ones.
// Both may be set.
#define LORA_OTA_FLAG_DELTA     0x01   // DATA carries a patch against the running image (LoraOTADelta.h);
                                       // the BEGIN continues: base sha256[0:8] @102 (what CONFIRM reports
                                       // for the running image), patch size u32 @110
#define LORA_OTA_FLAG_LONG      0x02   // slow transfer over the mesh: long idle timeout, persisted bitmap
#define LORA_OTA_BEGIN_DELTA_LEN 114
#define LORA_OTA_BOARD_LEN      32

// Every LoRa-OTA-capable image carries this string; FINISH refuses an image
// without it, so nobody can OTA into firmware that cannot confirm/roll back.
#define LORA_OTA_MARKER         "MCOTA-ROLLBACK-v1"

namespace lora_ota {

enum Status : uint8_t {
  OK = 0,
  BAD_STATE = 1,
  BAD_SESSION = 2,
  BAD_SIGNATURE = 3,
  TOO_BIG = 4,
  FLASH_ERROR = 5,
  INCOMPLETE = 6,
  HASH_MISMATCH = 7,
  NO_MARKER = 8,
  ACTIVATE_FAILED = 9,
  PENDING_VERIFY = 10,
  BAD_ARG = 11,
  WORKING = 12,   // BEGIN/FINISH accepted, the work runs from poll(): ask again
  BASE_MISMATCH = 13,   // a delta BEGIN names a base that is not the running image
};

class DeltaStore;
class DeltaDecoder;

class Flash {
public:
  virtual size_t capacity() = 0;
  virtual bool erase(size_t len) = 0;     // erase at least [0, len)
  virtual bool write(size_t off, const uint8_t* src, size_t len) = 0;
  virtual bool read(size_t off, uint8_t* dest, size_t len) = 0;
  virtual bool activate(size_t len) = 0;  // make it the next boot image

  // LONG sessions: re-open the staging area of an earlier session without erasing it
  // (it already holds `len` bytes' worth of chunks), and a small persistent record of
  // that session. Optional: a Flash without them restarts a LONG transfer after a reboot.
  virtual bool reattach(size_t len) { return false; }
  // the record: hdr (fixed size) + bitmap, which within one record only ever GAINS bits,
  // so a NOR store may program it again in place. fresh = a new record (erase first).
  virtual bool saveSession(const uint8_t* hdr, size_t hlen, const uint8_t* bitmap, size_t blen, bool fresh) { return false; }
  virtual bool loadSession(uint8_t* hdr, size_t hlen, uint8_t* bitmap, size_t blen) { return false; }
  virtual void clearSession() { }
};

// A session record on raw NOR flash (one erase sector of its own). The bitmap is
// stored inverted (erased 0xFF = missing), so saving more chunks only clears bits:
// no erase per save, and a save cut by a power loss is still a correct (older) record.
class NorSessionStore {
public:
  virtual bool sessErase() = 0;   // the record's sector
  virtual bool sessWrite(size_t off, const uint8_t* src, size_t len) = 0;
  virtual bool sessRead(size_t off, uint8_t* dest, size_t len) = 0;
  virtual size_t sessSize() = 0;
  bool save(const uint8_t* hdr, size_t hlen, const uint8_t* bitmap, size_t blen, bool fresh);
  bool load(uint8_t* hdr, size_t hlen, uint8_t* bitmap, size_t blen);
  void clear();
};

// signed message: "MCOTA1" || board[32] (NUL padded) || size u32 LE || sha256
#define LORA_OTA_MANIFEST_LEN  (6 + LORA_OTA_BOARD_LEN + 4 + 32)
void buildManifest(uint8_t out[LORA_OTA_MANIFEST_LEN], const char* board, uint32_t size, const uint8_t sha[32]);

class Receiver {
  Flash* _flash;
  uint8_t _pubkey[32];
  char _board[LORA_OTA_BOARD_LEN + 1];

  // PREPARING (after BEGIN) and VERIFYING (after FINISH) do their heavy work in
  // poll(), from the main loop: not inside the radio receive path, whose stack
  // is small on nRF52 (4 KB) and which must not stall for seconds
  enum { IDLE, PREPARING, RECEIVING, VERIFYING, DONE } _state;
  uint8_t _sig[64];
  Status _result;   // outcome of the last poll() work, reported to the next BEGIN/FINISH
  uint32_t _session;
  uint32_t _size;
  uint16_t _chunks;
  uint16_t _received;
  uint8_t _chunk;
  uint8_t _sha[32];
  uint32_t _last_ms;
  uint8_t _bitmap[LORA_OTA_MAX_CHUNKS / 8];
  uint8_t _flags;          // accepted BEGIN flags of this session
  bool _resumed;           // PREPARING may reattach a persisted LONG session instead of erasing
  bool _save_fresh;        // LONG: the persisted record must be (re)started
  uint16_t _unsaved;       // LONG: chunks received since the last save
  uint32_t _unsaved_since;
  // delta: DATA carries _xfer bytes of patch (else _xfer == _size, the image itself)
  DeltaStore* _dstore;
  DeltaDecoder* _dec;
  bool _decoded;
  uint8_t _decoding;   // 0 no, 1 to start, 2 running
  uint8_t _base8[8];
  uint32_t _xfer;

  bool isLong() const { return _flags & LORA_OTA_FLAG_LONG; }
  bool isDelta() const { return _flags & LORA_OTA_FLAG_DELTA; }
  bool restoreSession();
  void saveSession(bool fresh);

  bool hasChunk(uint16_t i) const { return _bitmap[i >> 3] & (1 << (i & 7)); }
  uint16_t firstMissing() const;
  int begin(const uint8_t* p, size_t len, uint8_t* reply, uint32_t now_ms, uint32_t random32, bool pending);
  int data(const uint8_t* p, size_t len, uint32_t now_ms);
  int status(const uint8_t* p, size_t len, uint8_t* reply, uint32_t now_ms);
  int finish(const uint8_t* p, size_t len, uint8_t* reply);
  Status verifyImage();
  Status prepare();
  Status restage();
  Status decodeStep();

public:
  Receiver(Flash& flash, const uint8_t pubkey[32], const char* board);

  static bool isOtaReq(uint8_t type) { return type >= LORA_OTA_REQ_BEGIN && type <= LORA_OTA_REQ_RADIO; }

  // req[0] is the request type. Writes the reply body (no tag) and returns
  // its length; 0 = send nothing (DATA). reply needs 5 + LORA_OTA_BITMAP_REPLY bytes.
  int handle(const uint8_t* req, size_t len, uint8_t* reply, uint32_t now_ms, uint32_t random32, bool pending_verify);

  void loop(uint32_t now_ms);           // drops a session idle for LORA_OTA_IDLE_MS (LONG: _LONG_IDLE_MS); LONG saves
  void poll(uint32_t now_ms);           // the heavy part of BEGIN/FINISH; call from the main loop
  // delta updates: base image + patch staging (NULL = full images only)
  void setDelta(DeltaStore* store);
  void reset() { _state = IDLE; _size = 0; }   // e.g. the install of an activated image failed
  bool working() const { return _state == PREPARING || _state == VERIFYING; }
  bool receiving() const { return _state == RECEIVING || working(); }
  bool activated() const { return _state == DONE; }
  // a LONG session between packets: nothing to do until the next one, so the node may sleep
  bool idleLong() const { return _state == RECEIVING && isLong(); }
  uint16_t received() const { return _received; }
  uint16_t chunks() const { return _chunks; }
};

}

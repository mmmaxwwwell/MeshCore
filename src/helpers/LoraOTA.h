#pragma once

// Firmware over LoRa: the receiver half of a chunked, signed image transfer
// carried in admin REQ datagrams (see docs in tools/lora-ota/README.md).
// Platform-neutral: flash access goes through lora_ota::Flash, so the same
// code runs on the radio and in the host simulator (tools/lora-ota/sim).

#include <stdint.h>
#include <stddef.h>

#if (defined(ESP32) || defined(NRF52_PLATFORM)) && defined(LORA_OTA_PUBKEY) && defined(LORA_OTA_BOARD)
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
};

class Flash {
public:
  virtual size_t capacity() = 0;
  virtual bool erase(size_t len) = 0;     // erase at least [0, len)
  virtual bool write(size_t off, const uint8_t* src, size_t len) = 0;
  virtual bool read(size_t off, uint8_t* dest, size_t len) = 0;
  virtual bool activate(size_t len) = 0;  // make it the next boot image
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

  bool hasChunk(uint16_t i) const { return _bitmap[i >> 3] & (1 << (i & 7)); }
  uint16_t firstMissing() const;
  int begin(const uint8_t* p, size_t len, uint8_t* reply, uint32_t now_ms, uint32_t random32, bool pending);
  int data(const uint8_t* p, size_t len, uint32_t now_ms);
  int status(const uint8_t* p, size_t len, uint8_t* reply, uint32_t now_ms);
  int finish(const uint8_t* p, size_t len, uint8_t* reply);
  Status verifyImage();

public:
  Receiver(Flash& flash, const uint8_t pubkey[32], const char* board);

  static bool isOtaReq(uint8_t type) { return type >= LORA_OTA_REQ_BEGIN && type <= LORA_OTA_REQ_RADIO; }

  // req[0] is the request type. Writes the reply body (no tag) and returns
  // its length; 0 = send nothing (DATA). reply needs 5 + LORA_OTA_BITMAP_REPLY bytes.
  int handle(const uint8_t* req, size_t len, uint8_t* reply, uint32_t now_ms, uint32_t random32, bool pending_verify);

  void loop(uint32_t now_ms);           // drops a session idle for LORA_OTA_IDLE_MS
  void poll(uint32_t now_ms);           // the heavy part of BEGIN/FINISH; call from the main loop
  bool working() const { return _state == PREPARING || _state == VERIFYING; }
  bool receiving() const { return _state == RECEIVING || working(); }
  bool activated() const { return _state == DONE; }
  uint16_t received() const { return _received; }
  uint16_t chunks() const { return _chunks; }
};

}

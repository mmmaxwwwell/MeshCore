#pragma once

// Maintenance over LoRa: read a node's state, and change it with commands the
// owner signs. Every request is a REQ datagram (end-to-end encrypted with the
// sender/target shared secret) that the app only hands over from a favourite
// (companion) or a logged-in admin (repeater, room server), like LoRa OTA.
//
//  * Read-only requests (MNT_READ: status, file list, contacts, channels)
//    change nothing and return public data only: never a key, a password, a
//    channel secret, the overlay name or any file's contents. A channel whose
//    secret is derived from its name (a hashtag channel: the name IS the key)
//    is listed with its name cut short.
//  * Everything that changes or deletes anything is a SIGNED COMMAND: ed25519
//    with the compiled-in LORA_OTA_PUBKEY (the firmware/settings key) over
//    "MCMNT1" || body, bound to this node (public key prefix) or its board
//    tag, with a counter that must be newer than the last one this node took
//    (persisted before the command runs: a command can never run twice). The
//    signature is checked before anything in the body is believed.
//
// Platform-neutral like LoraOTASettings.cpp: the app supplies a Target, so the
// same code runs on the radio and in the host simulator (tools/lora-ota/sim).
// Work that touches flash or many contacts runs from poll() (main loop), never
// in the receive path; EXEC answers WORKING meanwhile. Protocol and security
// model: tools/lora-ota/README.md "Maintenance".

#include <stdint.h>
#include <stddef.h>
#include "LoraOTA.h"

#define LORA_OTA_REQ_MNT_READ  0x6A   // op u8, args                         -> status, data (no signature: changes nothing)
#define LORA_OTA_REQ_MNT_DATA  0x6B   // total u16, offset u16, n u8, bytes  -> status, have u16 (upload a signed command)
#define LORA_OTA_REQ_MNT_EXEC  0x6C   // total u16, sha256(cmd)[0:8]         -> WORKING, then status, counter u32, op u8, result

#define LORA_OTA_MNT_DOMAIN     "MCMNT1"   // firmware signs "MCOTA1", settings "MCSET1": none passes for another
#define LORA_OTA_MNT_MAX_CMD    256        // body + sig[64]
#define LORA_OTA_MNT_REPLY      128        // reply body budget (a REQ reply holds a little more)
#define LORA_OTA_MNT_REBOOT_MS  6000       // REBOOT: this long after the reply
#define LORA_OTA_MNT_SLICE      8          // PRUNE: contacts removed per main-loop pass
#define LORA_OTA_MNT_MIN_PREFIX 6
#define LORA_OTA_MNT_NAME       48         // file names in a listing (longer ones are cut)
#define LORA_OTA_MNT_PATH       64

// MNT_READ ops (read-only)
#define LORA_OTA_MNT_RD_STATUS    0   // -> see README
#define LORA_OTA_MNT_RD_FILES     1   // fs u8, start u16, dir path (to the end; default "/")
#define LORA_OTA_MNT_RD_CONTACTS  2   // start u16, types u8 (bit per ADV type; 0 = all), flags u8
#define LORA_OTA_MNT_RD_CHANNELS  3   // start u8

#define LORA_OTA_MNT_CF_NONFAV    0x01   // contacts: only those that are not favourites
#define LORA_OTA_MNT_CF_NONAMES   0x02   // contacts: leave the names out (more per page)

// signed ops (the op byte of a command body)
#define LORA_OTA_MNT_OP_DELETE_CONTACTS 0x10   // flags u8 (bit0 also favourites), plen u8, n u8, n x prefix
#define LORA_OTA_MNT_OP_PRUNE           0x11   // types u8: delete every contact of those ADV types that is not a favourite
#define LORA_OTA_MNT_OP_FAVOURITE       0x12   // on u8, plen u8, prefix
#define LORA_OTA_MNT_OP_ADD_CONTACT     0x13   // pubkey[32], type, flags, out_path_len, last_advert u32, path, name
#define LORA_OTA_MNT_OP_FORMAT_EXTRAFS  0x14   // (none): format the secondary FS, save contacts + channels back from RAM
#define LORA_OTA_MNT_OP_DELETE_FILE     0x15   // fs u8, path
#define LORA_OTA_MNT_OP_REBOOT          0x16   // (none): reboot LORA_OTA_MNT_REBOOT_MS after the reply
#define LORA_OTA_MNT_OP_SET_CHANNEL     0x17   // index u8, nlen u8, name, [secret 16]: no secret = a hashtag channel
#define LORA_OTA_MNT_OP_DELETE_CHANNEL  0x18   // index u8

#define LORA_OTA_MNT_DEL_FORCE  0x01   // DELETE_CONTACTS: favourites too (never the requester)

// what else is going on, from the service: format and reboot wait for all of it
#define LORA_OTA_MNT_BUSY_FW_PENDING  0x01   // an unconfirmed firmware image (its rollback copy may be on the FS)
#define LORA_OTA_MNT_BUSY_OTA         0x02   // a firmware transfer in progress (staged on the FS), or its install due
#define LORA_OTA_MNT_BUSY_SETTINGS    0x04   // a settings bundle on probation (or its reboot due)

// STATUS flags byte
#define LORA_OTA_MNT_ST_FW_PENDING  0x01
#define LORA_OTA_MNT_ST_OTA         0x02
#define LORA_OTA_MNT_ST_SETTINGS    0x04
#define LORA_OTA_MNT_ST_WORKING     0x08
#define LORA_OTA_MNT_ST_REBOOT_DUE  0x10
#define LORA_OTA_MNT_ST_HAS_FS2     0x20

#define LORA_OTA_MNT_STATE_MAGIC 0x31544E4Du   // "MNT1"

namespace lora_ota_maint {

// status codes 24+ (0-12 are lora_ota::Status, 16-23 lora_ota_settings::Status; both reused where they fit:
// 3 bad signature, 6 incomplete, 7 hash mismatch, 11 bad arg, 12 working, 16 counter not newer,
// 17 another node/board, 20 does not parse, 22 not on this node, 23 could not save)
enum Status : uint8_t {
  NOT_FOUND = 24,   // no such contact / file
  PROTECTED = 25,   // a protected file, the node itself, or the requester's own contact (it would cut off access)
  FULL = 26,        // contact table full
  BUSY = 27,        // a firmware image / transfer / settings bundle is in flight: confirm it or let it finish first
  AMBIGUOUS = 28,   // a prefix that matches more than one contact
};

enum Role : uint8_t { COMPANION = 0, REPEATER = 1, ROOM_SERVER = 2 };

struct ContactRec {   // public data only
  uint8_t pub_key[32];
  char name[32];
  uint8_t type, flags, out_path_len;
  uint8_t out_path[64];
  uint32_t last_advert;
};

struct FileEntry {
  char name[LORA_OTA_MNT_NAME];
  uint32_t size;
  bool dir;
};

class Target {
public:
  virtual Role role() = 0;
  virtual const char* fwVersion() = 0;
  virtual uint16_t battMilliVolts() = 0;
  virtual const uint8_t* selfPubKey() = 0;              // 32 bytes
  virtual void reboot() = 0;                             // save what needs saving, reboot; does not return on the radio
  // the counter record (a small file on the PRIMARY filesystem, which format never touches)
  virtual int loadState(uint8_t* buf, size_t max) = 0;   // bytes read; 0 / -1 = none yet
  virtual bool saveState(const uint8_t* buf, size_t len) = 0;

  // filesystems: 0 = primary (identity, prefs), 1 = secondary (companion ExtraFS: contacts, channels)
  virtual bool hasFs(int fs) = 0;
  virtual bool storage(int fs, uint32_t& used_kb, uint32_t& total_kb) = 0;
  virtual int listDir(int fs, const char* dir, int index, FileEntry& e) = 0;   // 1 = entry, 0 = end, -1 = no such dir
  virtual bool exists(int fs, const char* path, bool& dir) = 0;
  virtual bool removeFile(int fs, const char* path) = 0;

  // contacts (companions; -1 = no contact table)
  virtual int contactCount() { return -1; }
  virtual int contactMax() { return 0; }
  virtual bool contactAt(int i, ContactRec& c) { (void)i; (void)c; return false; }
  virtual bool contactRemoveAt(int i) { (void)i; return false; }   // later ones move down by one
  virtual bool contactSetFlags(int i, uint8_t flags) { (void)i; (void)flags; return false; }
  virtual int contactPut(const ContactRec& c) { (void)c; return -1; }   // 0 added, 1 updated, -1 table full
  virtual void contactsChanged() { }                                   // schedule a save (the app's lazy write)
  virtual bool contactsSave() { return false; }                        // save now
  // channels (companions; -1 = none): slots, and the configured ones (channelAt false for an empty slot).
  // The secret only goes into the hashtag check, never into a reply
  virtual int channelCount() { return -1; }
  virtual bool channelAt(int i, char name[32], uint8_t secret[32]) { (void)i; (void)name; (void)secret; return false; }
  virtual bool channelsSave() { return false; }
  // set slot i, as the app's CMD_SET_CHANNEL: name (NUL-terminated, "" = empty slot) and a 128-bit
  // secret (zeros for an empty slot). The caller wipes its copies; the app should wipe its own
  virtual bool channelSet(int i, const char* name, const uint8_t secret16[16]) { (void)i; (void)name; (void)secret16; return false; }
  // format the secondary FS (only that one), and count what the store holds afterwards
  // (contacts; configured, i.e. named, channels)
  virtual bool formatSecondary() { return false; }
  virtual bool storedCounts(int& contacts, int& channels) { (void)contacts; (void)channels; return false; }
};

// a file that must never be deleted over LoRa (identity, prefs, keys, the
// counter record, OTA's rollback copy and state, contacts/channels/ACL tables):
// matched on the last path component; "." / ".." / empty components refused too
bool isProtectedPath(const char* path);
// a channel whose 16-byte secret is SHA-256(name)[0:16]: knowing the name is knowing the key
bool nameKeyed(const char* name, const uint8_t secret[32]);

struct Ctx {
  const uint8_t* requester;   // 32-byte public key of whoever sent this request (NULL: an admin, not a contact)
  uint8_t busy;               // LORA_OTA_MNT_BUSY_*
  uint32_t uptime_s;
  uint32_t settings_version;
};

class Maint {
  Target* _t;
  uint8_t _pubkey[32];
  char _board[LORA_OTA_BOARD_LEN + 1];
  uint32_t _counter;   // last command taken: anything not newer is refused

  uint8_t _buf[LORA_OTA_MNT_MAX_CMD];
  uint16_t _total, _have;
  uint8_t _hash[8];
  enum { IDLE, VERIFYING, RUNNING, DONE } _phase;
  uint8_t _req[32];
  bool _has_req;

  // the command running (RUNNING) and its outcome (DONE)
  uint8_t _op, _types, _step;
  int _scan;
  uint16_t _n1, _n2;
  int _c_before, _ch_before;
  uint8_t _status;
  uint32_t _res_counter;
  uint8_t _res[16];
  uint8_t _res_len;

  bool _reboot_due;
  uint32_t _reboot_at;

  uint8_t verifyAndStart(uint8_t busy);
  void step();
  void finish(uint8_t status);
  int findPrefix(const uint8_t* prefix, int plen, int& count);
  bool isRequester(const uint8_t* key) const;
  uint8_t execDelete(const uint8_t* a, size_t n);
  uint8_t execFavourite(const uint8_t* a, size_t n);
  uint8_t execAdd(const uint8_t* a, size_t n);
  uint8_t execDeleteFile(const uint8_t* a, size_t n);
  uint8_t execSetChannel(const uint8_t* a, size_t n);
  uint8_t execDeleteChannel(const uint8_t* a, size_t n);
  int configuredChannels();
  int readStatus(uint8_t* reply, const Ctx& ctx);
  int readFiles(const uint8_t* p, size_t len, uint8_t* reply);
  int readContacts(const uint8_t* p, size_t len, uint8_t* reply);
  int readChannels(const uint8_t* p, size_t len, uint8_t* reply);

public:
  Maint(Target& t, const uint8_t pubkey[32], const char* board);

  static bool isMaintReq(uint8_t type) { return type >= LORA_OTA_REQ_MNT_READ && type <= LORA_OTA_REQ_MNT_EXEC; }

  void begin();   // load the counter
  // req[0] is the type; reply body (no tag), its length; reply needs LORA_OTA_MNT_REPLY bytes
  int handle(const uint8_t* req, size_t len, uint8_t* reply, uint32_t now_ms, const Ctx& ctx);
  void poll(uint32_t now_ms, uint8_t busy);   // signature check + the command, from the main loop
  void loop(uint32_t now_ms);                 // a REBOOT that is due
  bool working() const { return _phase == VERIFYING || _phase == RUNNING; }
  bool busy() const { return working() || _reboot_due; }
  bool rebootDue() const { return _reboot_due; }
  uint32_t counter() const { return _counter; }
};

}

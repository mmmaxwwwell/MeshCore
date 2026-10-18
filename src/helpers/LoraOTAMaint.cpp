#include "LoraOTAMaint.h"
#include "LoraOTASettings.h"

#if defined(LORA_OTA_ENABLED) || defined(LORA_OTA_HOST_TEST)

#include <string.h>
#include <SHA256.h>
#include <ed_25519.h>

namespace lora_ota_maint {

using lora_ota_settings::STALE_VERSION;
using lora_ota_settings::WRONG_TARGET;
using lora_ota_settings::BAD_FORMAT;
using lora_ota_settings::NOT_SUPPORTED;
using lora_ota_settings::STORE_ERROR;

static uint32_t rd32(const uint8_t* p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24); }
static uint16_t rd16(const uint8_t* p) { return p[0] | (p[1] << 8); }
static void wr32(uint8_t* p, uint32_t v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }
static void wr16(uint8_t* p, uint16_t v) { p[0] = v; p[1] = v >> 8; }

// last path components that are never deleted over LoRa. The contents of NO
// file are ever returned (a listing is names + sizes), so this is about deletion.
static const char* const PROTECTED_NAMES[] = {
  "prefs.json", "new_prefs", "com_prefs",                     // node prefs (passwords, keys, settings)
  "ota_settings", "ota_set_overlay", "ota_set_regions",       // signed settings: replay counter + probation copies
  "ota_maint",                                                // this module's replay counter
  "ota-state", "ota-old.bin", "ota-new.bin", "ota-session", "ota-patch.bin",   // firmware rollback + staging
  "overlay", "posrep",                                        // overlay name (a key), position report config
  "contacts3", "channels2",                                   // contact + channel tables (channel secrets)
  "s_contacts", "regions2",                                   // repeater/room ACL (admin keys), region table
  "identity",                                                 // the identity directory itself
};

bool isProtectedPath(const char* path) {
  if (!path || path[0] != '/') return true;
  size_t len = strlen(path);
  if (len >= LORA_OTA_MNT_PATH || path[len - 1] == '/') return true;   // too long, the root, or a directory
  const char* p = path;
  const char* first = NULL;
  const char* last = NULL;
  size_t first_len = 0, last_len = 0;
  for (;;) {
    while (*p == '/') p++;
    if (!*p) break;
    const char* s = p;
    while (*p && *p != '/') p++;
    size_t n = p - s;
    if ((n == 1 && s[0] == '.') || (n == 2 && s[0] == '.' && s[1] == '.')) return true;
    for (const char* c = s; c < p; c++) if ((uint8_t)*c < ' ' || (uint8_t)*c > '~') return true;
    if (!first) { first = s; first_len = n; }
    last = s;
    last_len = n;
  }
  if (!last) return true;
  if (first != last && first_len == 8 && memcmp(first, "identity", 8) == 0) return true;   // /identity/...
  if (last_len >= 3 && memcmp(&last[last_len - 3], ".id", 3) == 0) return true;            // _main.id and kin
  for (size_t i = 0; i < sizeof(PROTECTED_NAMES) / sizeof(PROTECTED_NAMES[0]); i++) {
    if (strlen(PROTECTED_NAMES[i]) == last_len && memcmp(PROTECTED_NAMES[i], last, last_len) == 0) return true;
  }
  return false;
}

bool nameKeyed(const char* name, const uint8_t secret[32]) {
  uint8_t d[32];
  size_t n = 0;
  while (n < 32 && name[n]) n++;
  SHA256 sha;
  sha.update(name, n);
  sha.finalize(d, 32);
  bool keyed = memcmp(d, secret, 16) == 0;
  memset(d, 0, sizeof(d));
  return keyed;
}

Maint::Maint(Target& t, const uint8_t pubkey[32], const char* board) : _t(&t) {
  memcpy(_pubkey, pubkey, 32);
  strncpy(_board, board, LORA_OTA_BOARD_LEN);
  _board[LORA_OTA_BOARD_LEN] = 0;
  _counter = 0;
  _total = _have = 0;
  _phase = IDLE;
  _has_req = false;
  _op = _types = _step = 0;
  _scan = 0;
  _n1 = _n2 = 0;
  _c_before = _ch_before = 0;
  _status = lora_ota::OK;
  _res_counter = 0;
  _res_len = 0;
  _reboot_due = false;
  _reboot_at = 0;
}

void Maint::begin() {
  uint8_t buf[8];
  int n = _t->loadState(buf, sizeof(buf));
  if (n >= 8 && rd32(buf) == LORA_OTA_MNT_STATE_MAGIC) _counter = rd32(&buf[4]);
}

bool Maint::isRequester(const uint8_t* key) const { return _has_req && memcmp(key, _req, 32) == 0; }

static ContactRec s_c;   // static: poll() runs on the 4 KB nRF52 loop stack

// index of the contact whose key starts with prefix (the first, if several); count = how many do
int Maint::findPrefix(const uint8_t* prefix, int plen, int& count) {
  int found = -1, n = _t->contactCount();
  count = 0;
  for (int i = 0; i < n; i++) {
    if (_t->contactAt(i, s_c) && memcmp(s_c.pub_key, prefix, plen) == 0) {
      if (count++ == 0) found = i;
    }
  }
  return found;
}

static bool validPathLen(uint8_t l) {
  if (l == 0xFF) return true;   // unknown: flood
  uint8_t count = l & 63, size = (l >> 6) + 1;
  return size != 4 && count * size <= 64;
}
static size_t pathBytes(uint8_t l) { return l == 0xFF ? 0 : (size_t)(l & 63) * ((l >> 6) + 1); }

// the shape of each command's arguments, checked before its counter is spent
static uint8_t checkArgs(uint8_t op, const uint8_t* a, size_t n) {
  switch (op) {
    case LORA_OTA_MNT_OP_DELETE_CONTACTS: {
      if (n < 3) return BAD_FORMAT;
      uint8_t plen = a[1], cnt = a[2];
      if (plen < LORA_OTA_MNT_MIN_PREFIX || plen > 32 || cnt == 0 || n != 3 + (size_t)plen * cnt) return BAD_FORMAT;
      if (a[0] & ~LORA_OTA_MNT_DEL_FORCE) return BAD_FORMAT;
      return lora_ota::OK;
    }
    case LORA_OTA_MNT_OP_PRUNE:
      return n == 1 && a[0] != 0 && !(a[0] & 1) ? (uint8_t)lora_ota::OK : (uint8_t)BAD_FORMAT;   // bit per ADV type 1..7
    case LORA_OTA_MNT_OP_FAVOURITE: {
      if (n < 2 || a[0] > 1) return BAD_FORMAT;
      uint8_t plen = a[1];
      return plen >= LORA_OTA_MNT_MIN_PREFIX && plen <= 32 && n == 2 + (size_t)plen ? (uint8_t)lora_ota::OK : (uint8_t)BAD_FORMAT;
    }
    case LORA_OTA_MNT_OP_ADD_CONTACT: {   // pubkey[32], type, flags, out_path_len, last_advert u32, path, name
      if (n < 39) return BAD_FORMAT;
      uint8_t type = a[32], pl = a[34];
      if (type < 1 || type > 4 || !validPathLen(pl)) return BAD_FORMAT;
      size_t at = 39 + pathBytes(pl);
      if (n <= at || n - at > 31) return BAD_FORMAT;   // a name of 1..31 bytes
      for (size_t i = at; i < n; i++) if (a[i] == 0) return BAD_FORMAT;
      return lora_ota::OK;
    }
    case LORA_OTA_MNT_OP_FORMAT_EXTRAFS:
    case LORA_OTA_MNT_OP_REBOOT:
      return n == 0 ? (uint8_t)lora_ota::OK : (uint8_t)BAD_FORMAT;
    case LORA_OTA_MNT_OP_DELETE_FILE:   // fs u8, path
      if (n < 3 || a[0] > 1 || n - 1 >= LORA_OTA_MNT_PATH || a[1] != '/') return BAD_FORMAT;
      for (size_t i = 1; i < n; i++) if (a[i] == 0) return BAD_FORMAT;
      return lora_ota::OK;
  }
  return NOT_SUPPORTED;
}

void Maint::finish(uint8_t status) {
  _status = status;
  _phase = DONE;
}

// static: poll() runs on the 4 KB nRF52 loop stack
static uint8_t s_msg[6 + LORA_OTA_MNT_MAX_CMD];

uint8_t Maint::verifyAndStart(uint8_t busy) {
  _res_len = 0;
  if (_total < 64 + 7) return BAD_FORMAT;
  size_t blen = _total - 64;
  const uint8_t* body = _buf;
  const uint8_t* sig = &_buf[blen];

  // 1. the signature, over DOMAIN || body: before anything in the body is believed
  memcpy(s_msg, LORA_OTA_MNT_DOMAIN, 6);
  memcpy(&s_msg[6], body, blen);
  bool good = ed25519_verify(sig, s_msg, 6 + blen, _pubkey);
  memset(s_msg, 0, sizeof(s_msg));
  if (!good) return lora_ota::BAD_SIGNATURE;

  // 2. counter u32, target kind u8, target len u8, target, op u8, args
  size_t i = 0;
  uint32_t counter = rd32(body); i = 4;
  uint8_t tkind = body[i++], tlen = body[i++];
  if (i + tlen + 1 > blen) return BAD_FORMAT;
  const uint8_t* tgt = &body[i]; i += tlen;
  if (tkind == 1) {   // node: public key prefix
    if (tlen < LORA_OTA_MNT_MIN_PREFIX || tlen > 32 || memcmp(tgt, _t->selfPubKey(), tlen) != 0) return WRONG_TARGET;
  } else if (tkind == 2) {   // board tag (LORA_OTA_BOARD)
    if (tlen != strlen(_board) || memcmp(tgt, _board, tlen) != 0) return WRONG_TARGET;
  } else {
    return WRONG_TARGET;
  }
  if (counter <= _counter) return STALE_VERSION;
  uint8_t op = body[i++];
  const uint8_t* a = &body[i];
  size_t n = blen - i;
  uint8_t s = checkArgs(op, a, n);
  if (s != lora_ota::OK) return s;

  // 3. can this node do it, now? (nothing spent yet: the same command may come again later)
  bool contacts_op = op == LORA_OTA_MNT_OP_DELETE_CONTACTS || op == LORA_OTA_MNT_OP_PRUNE ||
                     op == LORA_OTA_MNT_OP_FAVOURITE || op == LORA_OTA_MNT_OP_ADD_CONTACT;
  if (contacts_op && _t->contactCount() < 0) return NOT_SUPPORTED;
  if (op == LORA_OTA_MNT_OP_FORMAT_EXTRAFS && (!_t->hasFs(1) || _t->contactCount() < 0 || _t->channelCount() < 0)) {
    return NOT_SUPPORTED;
  }
  if ((op == LORA_OTA_MNT_OP_FORMAT_EXTRAFS || op == LORA_OTA_MNT_OP_REBOOT) && busy) return BUSY;
  if (op == LORA_OTA_MNT_OP_DELETE_FILE && !_t->hasFs(a[0])) return NOT_SUPPORTED;
  if (_reboot_due) return BUSY;

  // 4. spend the counter BEFORE acting: a command never runs twice, even across a power cut
  uint8_t st[8];
  wr32(st, LORA_OTA_MNT_STATE_MAGIC);
  wr32(&st[4], counter);
  if (!_t->saveState(st, sizeof(st))) return STORE_ERROR;
  _counter = counter;
  _res_counter = counter;
  _op = op;

  // 5. run it: the quick ones now, the long ones a slice per main-loop pass
  switch (op) {
    case LORA_OTA_MNT_OP_DELETE_CONTACTS: return execDelete(a, n);
    case LORA_OTA_MNT_OP_FAVOURITE: return execFavourite(a, n);
    case LORA_OTA_MNT_OP_ADD_CONTACT: return execAdd(a, n);
    case LORA_OTA_MNT_OP_DELETE_FILE: return execDeleteFile(a, n);
    case LORA_OTA_MNT_OP_REBOOT:
      _reboot_due = true;
      _reboot_at = 0;   // timed from the next loop(), after the reply has gone out
      return lora_ota::OK;
    case LORA_OTA_MNT_OP_PRUNE:
      _types = a[0];
      _scan = _t->contactCount();   // from the end: a removal only moves contacts already looked at
      _n1 = _n2 = 0;
      _phase = RUNNING;
      return lora_ota::WORKING;
    case LORA_OTA_MNT_OP_FORMAT_EXTRAFS:
      _step = 0;
      _phase = RUNNING;
      return lora_ota::WORKING;
  }
  return NOT_SUPPORTED;
}

// -> deleted, not_found, ambiguous, skipped (favourites without FORCE, the requester)
uint8_t Maint::execDelete(const uint8_t* a, size_t n) {
  (void)n;
  bool force = a[0] & LORA_OTA_MNT_DEL_FORCE;
  uint8_t plen = a[1], cnt = a[2];
  uint8_t del = 0, missing = 0, amb = 0, skipped = 0;
  for (int k = 0; k < cnt; k++) {
    const uint8_t* prefix = &a[3 + k * plen];
    int count, idx = findPrefix(prefix, plen, count);
    if (count == 0) { missing++; continue; }
    if (count > 1) { amb++; continue; }
    if (!_t->contactAt(idx, s_c)) { missing++; continue; }
    if (isRequester(s_c.pub_key) || ((s_c.flags & 1) && !force)) { skipped++; continue; }
    if (_t->contactRemoveAt(idx)) del++; else missing++;
  }
  if (del) _t->contactsChanged();
  _res[0] = del; _res[1] = missing; _res[2] = amb; _res[3] = skipped;
  _res_len = 4;
  return lora_ota::OK;
}

uint8_t Maint::execFavourite(const uint8_t* a, size_t n) {
  (void)n;
  bool on = a[0];
  int count, idx = findPrefix(&a[2], a[1], count);
  if (count == 0) return NOT_FOUND;
  if (count > 1) return AMBIGUOUS;
  if (!_t->contactAt(idx, s_c)) return NOT_FOUND;
  if (!on && isRequester(s_c.pub_key)) return PROTECTED;   // it would cut off the very radio asking
  uint8_t f = on ? (s_c.flags | 1) : (s_c.flags & ~1);
  if (f != s_c.flags) {
    if (!_t->contactSetFlags(idx, f)) return STORE_ERROR;
    _t->contactsChanged();
  }
  return lora_ota::OK;
}

// -> 0 added, 1 updated
static ContactRec s_new;
uint8_t Maint::execAdd(const uint8_t* a, size_t n) {
  memset(&s_new, 0, sizeof(s_new));
  memcpy(s_new.pub_key, a, 32);
  if (memcmp(s_new.pub_key, _t->selfPubKey(), 32) == 0) return PROTECTED;   // not the node itself
  s_new.type = a[32];
  s_new.flags = a[33];
  s_new.out_path_len = a[34];
  s_new.last_advert = rd32(&a[35]);
  size_t pb = pathBytes(s_new.out_path_len);
  memcpy(s_new.out_path, &a[39], pb);
  memcpy(s_new.name, &a[39 + pb], n - 39 - pb);
  // updating the requester's own contact must keep it a favourite: else it cuts off the very radio asking
  if (isRequester(s_new.pub_key) && !(s_new.flags & 1)) return PROTECTED;
  int r = _t->contactPut(s_new);
  if (r < 0) return FULL;
  _t->contactsChanged();
  _res[0] = (uint8_t)r;
  _res_len = 1;
  return lora_ota::OK;
}

uint8_t Maint::execDeleteFile(const uint8_t* a, size_t n) {
  char path[LORA_OTA_MNT_PATH];
  memcpy(path, &a[1], n - 1);
  path[n - 1] = 0;
  if (isProtectedPath(path)) return PROTECTED;
  bool dir;
  if (!_t->exists(a[0], path, dir)) return NOT_FOUND;
  if (dir) return PROTECTED;   // files only
  return _t->removeFile(a[0], path) ? (uint8_t)lora_ota::OK : (uint8_t)STORE_ERROR;
}

// one slice of a long command (PRUNE, FORMAT_EXTRAFS)
void Maint::step() {
  if (_op == LORA_OTA_MNT_OP_PRUNE) {
    int removed = 0;
    while (_scan > 0 && removed < LORA_OTA_MNT_SLICE) {
      int i = --_scan;
      if (!_t->contactAt(i, s_c) || s_c.type > 7 || !(_types & (1 << s_c.type))) continue;
      if ((s_c.flags & 1) || isRequester(s_c.pub_key)) { _n2++; continue; }   // favourites stay
      if (_t->contactRemoveAt(i)) { _n1++; removed++; }
    }
    if (_scan > 0) return;
    if (_n1) _t->contactsChanged();
    // -> deleted u16, kept favourites u16, contacts left u16
    wr16(_res, _n1); wr16(&_res[2], _n2); wr16(&_res[4], (uint16_t)_t->contactCount());
    _res_len = 6;
    finish(lora_ota::OK);
    return;
  }
  if (_op == LORA_OTA_MNT_OP_FORMAT_EXTRAFS) {
    // identity, prefs and both replay counters live on the primary FS, which this never touches.
    // Contacts and channels are in RAM: format, then save them back, then count what landed.
    switch (_step++) {
      case 0:
        _c_before = _t->contactCount();
        _ch_before = configuredChannels();
        if (!_t->formatSecondary()) {
          _t->contactsSave();   // whatever the format left, put the tables back
          _t->channelsSave();
          finish(STORE_ERROR);
        }
        return;
      case 1:
        if (!_t->contactsSave()) { _t->channelsSave(); finish(STORE_ERROR); }
        return;
      case 2:
        if (!_t->channelsSave()) finish(STORE_ERROR);
        return;
      default: {
        int c = -1, ch = -1;
        bool ok = _t->storedCounts(c, ch);
        // -> contacts before u16, contacts stored u16, channels before u8, channels stored u8
        wr16(_res, (uint16_t)_c_before); wr16(&_res[2], (uint16_t)c);
        _res[4] = (uint8_t)_ch_before; _res[5] = (uint8_t)ch;
        _res_len = 6;
        finish(ok && c == _c_before && ch == _ch_before ? (uint8_t)lora_ota::OK : (uint8_t)STORE_ERROR);
        return;
      }
    }
  }
  finish(NOT_SUPPORTED);
}

void Maint::poll(uint32_t now_ms, uint8_t busy) {
  (void)now_ms;
  if (_phase == VERIFYING) {
    uint8_t s = verifyAndStart(busy);
    memset(_buf, 0, sizeof(_buf));   // a new upload starts at offset 0; a repeated EXEC gets the stored result
    _have = 0;
    if (s != lora_ota::WORKING) finish(s);
    return;
  }
  if (_phase == RUNNING) step();
}

void Maint::loop(uint32_t now_ms) {
  if (!_reboot_due) return;
  if (_reboot_at == 0) {
    _reboot_at = now_ms + LORA_OTA_MNT_REBOOT_MS;
    if (_reboot_at == 0) _reboot_at = 1;
  } else if ((int32_t)(now_ms - _reboot_at) >= 0) {
    _reboot_due = false;
    _reboot_at = 0;
    _t->reboot();   // does not return on the radio
  }
}

// ---------------------------------------------------------------- read-only requests

int Maint::configuredChannels() {
  int n = _t->channelCount(), got = 0;
  if (n < 0) return -1;
  char name[32];
  uint8_t secret[32];
  for (int i = 0; i < n; i++) {
    name[0] = 0;
    if (_t->channelAt(i, name, secret) && name[0]) got++;
  }
  memset(secret, 0, sizeof(secret));
  return got;
}

int Maint::readStatus(uint8_t* r, const Ctx& ctx) {
  uint32_t u0 = 0, t0 = 0, u1 = 0xFFFFFFFFu, t1 = 0xFFFFFFFFu;
  _t->storage(0, u0, t0);
  bool fs2 = _t->hasFs(1);
  if (fs2 && !_t->storage(1, u1, t1)) { u1 = t1 = 0xFFFFFFFFu; }
  int nc = _t->contactCount(), fav = 0;
  for (int i = 0; i < nc; i++) if (_t->contactAt(i, s_c) && (s_c.flags & 1)) fav++;
  int nch = configuredChannels();
  r[0] = lora_ota::OK;
  r[1] = _t->role();
  r[2] = ((ctx.busy & LORA_OTA_MNT_BUSY_FW_PENDING) ? LORA_OTA_MNT_ST_FW_PENDING : 0) |
         ((ctx.busy & LORA_OTA_MNT_BUSY_OTA) ? LORA_OTA_MNT_ST_OTA : 0) |
         ((ctx.busy & LORA_OTA_MNT_BUSY_SETTINGS) ? LORA_OTA_MNT_ST_SETTINGS : 0) |
         (working() ? LORA_OTA_MNT_ST_WORKING : 0) | (_reboot_due ? LORA_OTA_MNT_ST_REBOOT_DUE : 0) |
         (fs2 ? LORA_OTA_MNT_ST_HAS_FS2 : 0);
  wr32(&r[3], ctx.uptime_s);
  wr16(&r[7], _t->battMilliVolts());
  wr32(&r[9], u0); wr32(&r[13], t0); wr32(&r[17], u1); wr32(&r[21], t1);
  wr16(&r[25], nc < 0 ? 0xFFFF : (uint16_t)nc);
  wr16(&r[27], nc < 0 ? 0 : (uint16_t)_t->contactMax());
  wr16(&r[29], (uint16_t)fav);
  r[31] = nch < 0 ? 0xFF : (uint8_t)nch;
  wr32(&r[32], ctx.settings_version);
  wr32(&r[36], _counter);
  int n = 40;
  const char* fw = _t->fwVersion();
  size_t fl = strlen(fw);
  if (fl > 40) fl = 40;
  r[n++] = fl;
  memcpy(&r[n], fw, fl); n += fl;
  size_t bl = strlen(_board);
  if (n + 1 + bl > LORA_OTA_MNT_REPLY) bl = LORA_OTA_MNT_REPLY - n - 1;
  r[n++] = bl;
  memcpy(&r[n], _board, bl); n += bl;
  return n;
}

// a path from a request: up to its end or the first NUL (requests arrive zero-padded)
static bool takePath(const uint8_t* p, size_t len, char* out) {
  size_t n = 0;
  while (n < len && p[n]) n++;
  if (n == 0) { strcpy(out, "/"); return true; }
  if (n >= LORA_OTA_MNT_PATH || p[0] != '/') return false;
  memcpy(out, p, n);
  out[n] = 0;
  for (const char* s = out; *s; s++) {
    if (s[0] == '.' && s[1] == '.') return false;
    if ((uint8_t)*s < ' ' || (uint8_t)*s > '~') return false;
  }
  return true;
}

static FileEntry s_fe;

// fs u8, start u16, dir -> status, next u16 (0xFFFF = end), entries: kind u8 (1 = dir), size u32, nlen u8, name
int Maint::readFiles(const uint8_t* p, size_t len, uint8_t* r) {
  char dir[LORA_OTA_MNT_PATH];
  if (len < 3 || p[0] > 1 || !takePath(&p[3], len - 3, dir)) { r[0] = lora_ota::BAD_ARG; return 1; }
  if (!_t->hasFs(p[0])) { r[0] = NOT_SUPPORTED; return 1; }
  int idx = rd16(&p[1]);
  int n = 3;
  for (;; idx++) {
    int got = _t->listDir(p[0], dir, idx, s_fe);
    if (got < 0) { r[0] = NOT_FOUND; return 1; }
    if (got == 0) { idx = 0xFFFF; break; }
    s_fe.name[LORA_OTA_MNT_NAME - 1] = 0;
    size_t nl = strlen(s_fe.name);
    if (n + 6 + nl > LORA_OTA_MNT_REPLY) {
      if (n > 3) break;                 // next page
      nl = LORA_OTA_MNT_REPLY - n - 6;  // one name longer than a reply: cut it
    }
    r[n++] = s_fe.dir ? 1 : 0;
    wr32(&r[n], s_fe.size); n += 4;
    r[n++] = nl;
    memcpy(&r[n], s_fe.name, nl); n += nl;
  }
  r[0] = lora_ota::OK;
  wr16(&r[1], (uint16_t)idx);
  return n;
}

// start u16, types u8, flags u8 -> status, total u16, next u16 (0xFFFF = end),
// entries: prefix[6], type u8, flags u8, last_advert u32, nlen u8, name (none with NONAMES)
int Maint::readContacts(const uint8_t* p, size_t len, uint8_t* r) {
  int total = _t->contactCount();
  if (total < 0) { r[0] = NOT_SUPPORTED; return 1; }
  if (len < 4) { r[0] = lora_ota::BAD_ARG; return 1; }
  int idx = rd16(p);
  uint8_t types = p[2], flags = p[3];
  int n = 5;
  for (; idx < total; idx++) {
    if (!_t->contactAt(idx, s_c)) continue;
    if (types && (s_c.type > 7 || !(types & (1 << s_c.type)))) continue;
    if ((flags & LORA_OTA_MNT_CF_NONFAV) && (s_c.flags & 1)) continue;
    size_t nl = (flags & LORA_OTA_MNT_CF_NONAMES) ? 0 : strnlen(s_c.name, 31);
    size_t need = 12 + ((flags & LORA_OTA_MNT_CF_NONAMES) ? 0 : 1 + nl);
    if (n + need > LORA_OTA_MNT_REPLY) break;
    memcpy(&r[n], s_c.pub_key, 6); n += 6;
    r[n++] = s_c.type;
    r[n++] = s_c.flags;
    wr32(&r[n], s_c.last_advert); n += 4;
    if (!(flags & LORA_OTA_MNT_CF_NONAMES)) {
      r[n++] = nl;
      memcpy(&r[n], s_c.name, nl); n += nl;
    }
  }
  r[0] = lora_ota::OK;
  wr16(&r[1], (uint16_t)total);
  wr16(&r[3], idx >= total ? 0xFFFF : (uint16_t)idx);
  return n;
}

// start u8 -> status, next u8 (0xFF = end), entries: index u8, kind u8 (bit0: name-keyed, name cut), nlen u8, name
int Maint::readChannels(const uint8_t* p, size_t len, uint8_t* r) {
  int total = _t->channelCount();
  if (total < 0) { r[0] = NOT_SUPPORTED; return 1; }
  int idx = len > 0 ? p[0] : 0;
  int n = 2;
  char name[33];
  uint8_t secret[32];
  for (; idx < total; idx++) {
    memset(name, 0, sizeof(name));
    if (!_t->channelAt(idx, name, secret) || !name[0]) continue;   // an empty slot
    name[32] = 0;
    bool keyed = name[0] && nameKeyed(name, secret);
    memset(secret, 0, sizeof(secret));
    size_t nl = strnlen(name, 31);
    if (keyed && nl > 3) nl = 3;   // the name IS the key: only enough to recognise it
    if (n + 3 + nl > LORA_OTA_MNT_REPLY) break;
    r[n++] = idx;
    r[n++] = keyed ? 1 : 0;
    r[n++] = nl;
    memcpy(&r[n], name, nl); n += nl;
  }
  memset(name, 0, sizeof(name));
  memset(secret, 0, sizeof(secret));
  r[0] = lora_ota::OK;
  r[1] = idx >= total ? 0xFF : idx;
  return n;
}

int Maint::handle(const uint8_t* req, size_t len, uint8_t* reply, uint32_t now_ms, const Ctx& ctx) {
  (void)now_ms;
  if (len < 1) return 0;
  const uint8_t* p = &req[1];
  len--;
  switch (req[0]) {
    case LORA_OTA_REQ_MNT_READ: {
      if (len < 1) { reply[0] = lora_ota::BAD_ARG; return 1; }
      if (_phase == RUNNING) { reply[0] = lora_ota::WORKING; return 1; }   // tables are changing: ask again
      switch (p[0]) {
        case LORA_OTA_MNT_RD_STATUS: return readStatus(reply, ctx);
        case LORA_OTA_MNT_RD_FILES: return readFiles(&p[1], len - 1, reply);
        case LORA_OTA_MNT_RD_CONTACTS: return readContacts(&p[1], len - 1, reply);
        case LORA_OTA_MNT_RD_CHANNELS: return readChannels(&p[1], len - 1, reply);
      }
      reply[0] = NOT_SUPPORTED;
      return 1;
    }
    case LORA_OTA_REQ_MNT_DATA: {   // total u16, offset u16, n u8, bytes -> status, have u16
      if (len < 5) { reply[0] = lora_ota::BAD_ARG; return 1; }
      uint16_t total = rd16(p), off = rd16(&p[2]);
      uint8_t n = p[4];
      if (total == 0 || total > LORA_OTA_MNT_MAX_CMD || n > len - 5 || off + n > total) {
        reply[0] = lora_ota::BAD_ARG; return 1;
      }
      if (working()) { reply[0] = lora_ota::WORKING; wr16(&reply[1], _have); return 3; }
      if (off == 0 || total != _total) {   // a new command (always sent from offset 0)
        _total = total;
        _have = 0;
        _phase = IDLE;
      }
      if (off <= _have) {   // in order: anything past a gap waits for the resend
        memcpy(&_buf[off], &p[5], n);
        if (off + n > _have) _have = off + n;
      }
      reply[0] = lora_ota::OK;
      wr16(&reply[1], _have);
      return 3;
    }
    case LORA_OTA_REQ_MNT_EXEC: {   // total u16, sha256[0:8] -> status, counter u32, op u8, result
      if (len < 10) { reply[0] = lora_ota::BAD_ARG; return 1; }
      uint16_t total = rd16(p);
      const uint8_t* h = &p[2];
      if (working() && memcmp(h, _hash, 8) == 0) { reply[0] = lora_ota::WORKING; return 1; }
      if (_phase == DONE && memcmp(h, _hash, 8) == 0) {   // the result (again, if a reply got lost)
        reply[0] = _status;
        wr32(&reply[1], _res_counter);
        reply[5] = _op;
        memcpy(&reply[6], _res, _res_len);
        return 6 + _res_len;
      }
      if (working()) { reply[0] = lora_ota::BAD_STATE; return 1; }
      if (total != _total || _have < _total) { reply[0] = lora_ota::INCOMPLETE; wr16(&reply[1], _have); return 3; }
      uint8_t d[32];
      SHA256 sha;
      sha.update(_buf, _total);
      sha.finalize(d, 32);
      if (memcmp(d, h, 8) != 0) { reply[0] = lora_ota::HASH_MISMATCH; return 1; }
      memcpy(_hash, h, 8);
      _has_req = ctx.requester != NULL;
      if (_has_req) memcpy(_req, ctx.requester, 32); else memset(_req, 0, 32);
      _op = 0;
      _res_counter = 0;
      _res_len = 0;
      _phase = VERIFYING;   // the signature check runs from poll(), not in the receive path
      reply[0] = lora_ota::WORKING;
      return 1;
    }
  }
  return 0;
}

}

#endif

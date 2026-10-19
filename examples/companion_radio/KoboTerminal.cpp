#include "KoboTerminal.h"
#include <Adafruit_TinyUSB.h>

// Companion protocol codes (MyMesh.cpp).
#define CMD_APP_START 1
#define CMD_SEND_TXT_MSG 2
#define CMD_SEND_CHANNEL_TXT_MSG 3
#define CMD_GET_CONTACTS 4
#define CMD_SET_DEVICE_TIME 6
#define CMD_SEND_SELF_ADVERT 7
#define CMD_SYNC_NEXT_MESSAGE 10
#define CMD_DEVICE_QUERY 22
#define RESP_CONTACTS_START 2
#define RESP_CONTACT 3
#define RESP_END_OF_CONTACTS 4
#define RESP_SELF_INFO 5
#define RESP_NO_MORE_MESSAGES 10
#define RESP_CONTACT_MSG_RECV_V3 16
#define RESP_CHANNEL_MSG_RECV_V3 17
#define PUSH_ADVERT 0x80
#define PUSH_MSG_WAITING 0x83
#define TXT_PLAIN 0
#define TXT_SIGNED_PLAIN 2

// Terminal protocol v0 (kobo-mesh app/src/proto.rs).
#define T_CLEAR 0x01
#define T_FILL 0x02
#define T_TEXT 0x03
#define T_REFRESH 0x04
#define T_HELLO 0x80
#define T_TOUCH 0x81
#define T_TIME 0x82

static const uint16_t W = 1072, H = 1448, M = 40;
static const uint16_t BAR_Y = 1300, BAR_H = 120;
static const uint16_t LIST_Y = 140, ROW_H = 118, CHAT_ROW_H = 100;
static const char *QUICK[] = {"OK", "Yes", "No", "On my way", "Where are you?"};
static const int NQUICK = 5;

static Adafruit_USBD_WebUSB vendor;  // descriptor only; IO via tud_vendor_*

// ---- time (from the Kobo's clock) -----------------------------------------
static uint32_t base_unix = 0, base_ms = 0;
static int32_t utc_off = 0;  // seconds, local = UTC + utc_off (from the Kobo)
static uint32_t nowUnix() { return base_unix ? base_unix + (millis() - base_ms) / 1000 : 0; }

// ---- Kobo output ------------------------------------------------------------
// A stalled reader (relay gone) must never wedge the mesh loop.
static bool put(const uint8_t *b, size_t n) {
  uint32_t t0 = millis();
  while (n) {
    size_t w = tud_vendor_write(b, n);
    if (w) { b += w; n -= w; t0 = millis(); continue; }
    tud_vendor_write_flush();
    if (millis() - t0 > 500) return false;
    yield();
  }
  return true;
}
static bool g_ok = true;
static void frame(const uint8_t *p, uint16_t n) {
  if (!g_ok) return;
  uint8_t h[2] = {(uint8_t)n, (uint8_t)(n >> 8)};
  g_ok = put(h, 2) && put(p, n);
}
static void le16(uint8_t *p, uint16_t v) { p[0] = v; p[1] = v >> 8; }
static void tClear(uint8_t g) { uint8_t p[2] = {T_CLEAR, g}; frame(p, 2); }
static void tFill(uint16_t x, uint16_t y, uint16_t w, uint16_t h, uint8_t g) {
  uint8_t p[10] = {T_FILL}; le16(p + 1, x); le16(p + 3, y); le16(p + 5, w); le16(p + 7, h); p[9] = g;
  frame(p, 10);
}
static void tText(uint16_t x, uint16_t y, uint8_t size, bool bold, uint8_t g, const char *s, size_t maxn = 180) {
  uint8_t p[200] = {T_TEXT}; le16(p + 1, x); le16(p + 3, y); p[5] = size; p[6] = bold; p[7] = g;
  size_t n = strnlen(s, min(maxn, sizeof(p) - 8)); memcpy(p + 8, s, n);
  frame(p, 8 + n);
}
static void tRefresh(uint16_t x, uint16_t y, uint16_t w, uint16_t h, uint8_t mode) {
  uint8_t p[10] = {T_REFRESH}; le16(p + 1, x); le16(p + 3, y); le16(p + 5, w); le16(p + 7, h); p[9] = mode;
  frame(p, 10);
  tud_vendor_write_flush();
}

// Touch targets of the screen currently drawn.
enum Act : uint8_t { A_NONE, A_INBOX, A_CONTACTS, A_PUBLIC, A_ADVERT, A_OPEN_CONTACT, A_OPEN_MSG, A_QUICK, A_BACK };
struct Hit { uint16_t x, y, w, h; Act act; int16_t arg; };
static Hit hits[40];
static int nhits = 0;
static void hit(uint16_t x, uint16_t y, uint16_t w, uint16_t h, Act a, int16_t arg = 0) {
  if (nhits < 40) hits[nhits++] = {x, y, w, h, a, arg};
}

// ---- lifecycle --------------------------------------------------------------
void KoboTerminal::begin() {
  vendor.begin();
  if (TinyUSBDevice.mounted()) {  // interface added after enumeration: re-enumerate
    TinyUSBDevice.detach();
    delay(10);
    TinyUSBDevice.attach();
  }
}

void KoboTerminal::queueCmd(const uint8_t *p, size_t n) {
  if (_txn >= MAX_TX || n > MAX_FRAME_SIZE) return;
  int slot = (_txh + _txn) % MAX_TX;
  memcpy(_tx[slot], p, n);
  _txlen[slot] = n;
  _txn++;
}

size_t KoboTerminal::checkRecvFrame(uint8_t dest[]) {
  if (!_enabled || !_txn) return 0;
  size_t n = _txlen[_txh];
  memcpy(dest, _tx[_txh], n);
  _txh = (_txh + 1) % MAX_TX;
  _txn--;
  return n;
}

void KoboTerminal::requestSync() {
  if (_syncing) return;
  _syncing = true;
  uint8_t c = CMD_SYNC_NEXT_MESSAGE;
  queueCmd(&c, 1);
}

// ---- mesh -> UI -----------------------------------------------------------------
size_t KoboTerminal::writeFrame(const uint8_t f[], size_t n) {
  if (!_enabled || n == 0) return n;
  switch (f[0]) {
    case RESP_SELF_INFO:
      if (n > 58) { size_t l = min(n - 58, sizeof(_self) - 1); memcpy(_self, f + 58, l); _self[l] = 0; _dirty = true; }
      break;
    case RESP_CONTACTS_START: _ncontacts = 0; break;
    case RESP_CONTACT: onContact(f, n); break;
    case RESP_END_OF_CONTACTS: _dirty = true; break;
    case PUSH_ADVERT: { uint8_t c = CMD_GET_CONTACTS; queueCmd(&c, 1); } break;
    case PUSH_MSG_WAITING: requestSync(); break;
    case RESP_NO_MORE_MESSAGES: _syncing = false; break;
    case RESP_CONTACT_MSG_RECV_V3:  // [16][snr4][r][r][from6][path][type][ts4][signed: 4][text]
      if (n >= 16) {
        Msg m = {};
        m.snr4 = (int8_t)f[1];
        memcpy(m.from, f + 4, 6);
        memcpy(&m.ts, f + 12, 4);
        size_t off = f[11] == TXT_SIGNED_PLAIN ? 20 : 16;
        if (n > off) { size_t l = min(n - off, sizeof(m.text) - 1); memcpy(m.text, f + off, l); }
        addMsg(m);
      }
      _syncing = false; requestSync();
      break;
    case RESP_CHANNEL_MSG_RECV_V3:  // [17][snr4][r][r][chan][path][type][ts4][text]
      if (n >= 11) {
        Msg m = {};
        m.channel = true; m.chan = f[4]; m.snr4 = (int8_t)f[1];
        memcpy(&m.ts, f + 7, 4);
        size_t l = min(n - 11, sizeof(m.text) - 1); memcpy(m.text, f + 11, l);
        addMsg(m);
      }
      _syncing = false; requestSync();
      break;
  }
  return n;
}

void KoboTerminal::onContact(const uint8_t *f, size_t n) {
  // [3][pub 32][type][flags][path_len][path 64][name 32][last_advert 4]...
  if (n < 1 + 32 + 3 + 64 + 32 || _ncontacts >= MAX_UI_CONTACTS) return;
  uint8_t type = f[33];
  if (type != 1 && type != 3) return;  // people and rooms
  Contact &c = _contacts[_ncontacts++];
  memcpy(c.key, f + 1, 6);
  c.type = type;
  memcpy(c.name, f + 100, 32);
  c.name[32] = 0;
}

void KoboTerminal::addMsg(const Msg &m) {
  if (_nmsgs == MAX_UI_MSGS) { memmove(_msgs, _msgs + 1, sizeof(Msg) * (MAX_UI_MSGS - 1)); _nmsgs--; }
  _msgs[_nmsgs++] = m;
  _dirty = true;
}

int KoboTerminal::findContact(const uint8_t *k) const {
  for (int i = 0; i < _ncontacts; i++) if (!memcmp(_contacts[i].key, k, 6)) return i;
  return -1;
}
const char *KoboTerminal::nameFor(const uint8_t *k) const {
  int i = findContact(k);
  if (i >= 0) return _contacts[i].name;
  static char hex[13];
  for (int j = 0; j < 6; j++) sprintf(hex + 2 * j, "%02x", k[j]);
  return hex;
}

// ---- actions ----------------------------------------------------------------------
void KoboTerminal::sendText(const char *text) {
  uint8_t p[MAX_FRAME_SIZE];
  uint32_t ts = nowUnix();
  size_t tl = strlen(text);
  Msg m = {};
  m.out = true; m.ts = ts;
  strncpy(m.text, text, sizeof(m.text) - 1);
  if (_chat_contact < 0) {  // public channel 0
    p[0] = CMD_SEND_CHANNEL_TXT_MSG; p[1] = TXT_PLAIN; p[2] = 0;
    memcpy(p + 3, &ts, 4); memcpy(p + 7, text, tl);
    queueCmd(p, 7 + tl);
    m.channel = true;
  } else {
    p[0] = CMD_SEND_TXT_MSG; p[1] = TXT_PLAIN; p[2] = 0;
    memcpy(p + 3, &ts, 4); memcpy(p + 7, _contacts[_chat_contact].key, 6); memcpy(p + 13, text, tl);
    queueCmd(p, 13 + tl);
    memcpy(m.from, _contacts[_chat_contact].key, 6);
  }
  addMsg(m);
}

// ---- Kobo input ---------------------------------------------------------------------
void KoboTerminal::pollKobo() {
  while (tud_vendor_available() && _rxn < sizeof(_rx)) _rxn += tud_vendor_read(_rx + _rxn, sizeof(_rx) - _rxn);
  while (_rxn >= 2) {
    uint16_t n = _rx[0] | (_rx[1] << 8);
    if (n == 0 || n > sizeof(_rx) - 2) { _rxn = 0; break; }  // lost sync
    if (_rxn < 2u + n) break;
    onKoboFrame(_rx + 2, n);
    memmove(_rx, _rx + 2 + n, _rxn - 2 - n);
    _rxn -= 2 + n;
  }
}

void KoboTerminal::onKoboFrame(const uint8_t *p, uint16_t n) {
  if (p[0] == T_HELLO) {
    _kobo_up = true; g_ok = true; _full = true; _dirty = true;
    uint8_t q[2] = {CMD_DEVICE_QUERY, 3};
    queueCmd(q, 2);
    uint8_t s[] = {CMD_APP_START, 0, 0, 0, 0, 0, 0, 0, 'k', 'o', 'b', 'o'};
    queueCmd(s, sizeof(s));
    uint8_t c = CMD_GET_CONTACTS;
    queueCmd(&c, 1);
    _syncing = false; requestSync();
  } else if (p[0] == T_TIME && n >= 5) {  // [0x82][unix u32][utc_offset i32, optional]
    memcpy(&base_unix, p + 1, 4);
    if (n >= 9) memcpy(&utc_off, p + 5, 4);
    base_ms = millis();
    uint8_t t[5] = {CMD_SET_DEVICE_TIME};
    memcpy(t + 1, &base_unix, 4);
    queueCmd(t, 5);
  } else if (p[0] == T_TOUCH && n >= 6 && p[5] == 0) {  // touch down
    onTouch(p[1] | (p[2] << 8), p[3] | (p[4] << 8));
  }
}

void KoboTerminal::onTouch(uint16_t x, uint16_t y) {
  for (int i = 0; i < nhits; i++) {
    const Hit &h = hits[i];
    if (x < h.x || y < h.y || x >= h.x + h.w || y >= h.y + h.h) continue;
    switch (h.act) {
      case A_INBOX: case A_BACK: _screen = INBOX; break;
      case A_CONTACTS: _screen = CONTACTS; { uint8_t c = CMD_GET_CONTACTS; queueCmd(&c, 1); } break;
      case A_PUBLIC: _screen = CHAT; _chat_contact = -1; break;
      case A_ADVERT: { uint8_t a[2] = {CMD_SEND_SELF_ADVERT, 1}; queueCmd(a, 2); } break;  // 1 = flood
      case A_OPEN_CONTACT: _screen = CHAT; _chat_contact = h.arg; break;
      case A_OPEN_MSG: {
        const Msg &m = _msgs[h.arg];
        _screen = CHAT;
        _chat_contact = m.channel ? -1 : findContact(m.from);
        if (!m.channel && _chat_contact < 0) _screen = INBOX;  // unknown sender: no contact to reply to
      } break;
      case A_QUICK: sendText(QUICK[h.arg]); break;
      default: break;
    }
    _dirty = true;
    return;
  }
}

// ---- drawing ------------------------------------------------------------------------
void KoboTerminal::drawButton(uint16_t x, uint16_t y, uint16_t w, uint16_t h, const char *label) {
  tFill(x, y, w, h, 0x00);
  tFill(x + 4, y + 4, w - 8, h - 8, 0xff);
  tText(x + 24, y + h / 2 + 14, 40, true, 0x00, label);
}

void KoboTerminal::drawHeader(const char *title) {
  tText(M, 84, 56, true, 0x00, title);
  char s[48];
  snprintf(s, sizeof(s), "%s", _self[0] ? _self : "kobo-mesh");
  tText(W - M - 320, 84, 30, false, 0x55, s, 20);
  tFill(M, 112, W - 2 * M, 4, 0x00);
}

static void fmtTime(uint32_t ts, char *out, size_t n) {
  if (!ts) { snprintf(out, n, "--:--"); return; }
  uint32_t d = (uint32_t)((int64_t)ts + utc_off) % 86400;  // local, offset from the Kobo
  snprintf(out, n, "%02lu:%02lu", (unsigned long)(d / 3600), (unsigned long)((d / 60) % 60));
}

void KoboTerminal::draw() {
  nhits = 0;
  tClear(0xff);
  char line[200], t[8];
  if (_screen == INBOX) {
    drawHeader("Messages");
    int rows = (BAR_Y - LIST_Y) / ROW_H;
    for (int r = 0; r < rows && r < _nmsgs; r++) {
      int i = _nmsgs - 1 - r;
      const Msg &m = _msgs[i];
      uint16_t y = LIST_Y + r * ROW_H;
      fmtTime(m.ts, t, sizeof(t));
      if (m.channel) snprintf(line, sizeof(line), "%s #%u  %s", m.out ? "me ->" : "", m.chan, t);
      else snprintf(line, sizeof(line), "%s%s  %s", m.out ? "me -> " : "", nameFor(m.from), t);
      tText(M, y + 44, 34, true, 0x00, line);
      tText(M, y + 90, 32, false, 0x33, m.text, 52);
      tFill(M, y + ROW_H - 6, W - 2 * M, 2, 0xaa);
      hit(0, y, W, ROW_H, A_OPEN_MSG, i);
    }
    if (!_nmsgs) tText(M, LIST_Y + 80, 36, false, 0x55, "No messages yet.");
    uint16_t bw = (W - 2 * M - 2 * 24) / 3;
    drawButton(M, BAR_Y, bw, BAR_H, "Contacts"); hit(M, BAR_Y, bw, BAR_H, A_CONTACTS);
    drawButton(M + bw + 24, BAR_Y, bw, BAR_H, "Public"); hit(M + bw + 24, BAR_Y, bw, BAR_H, A_PUBLIC);
    drawButton(M + 2 * (bw + 24), BAR_Y, bw, BAR_H, "Advert"); hit(M + 2 * (bw + 24), BAR_Y, bw, BAR_H, A_ADVERT);
  } else if (_screen == CONTACTS) {
    snprintf(line, sizeof(line), "Contacts (%d)", _ncontacts);
    drawHeader(line);
    int rows = (BAR_Y - LIST_Y) / 92;
    for (int r = 0; r < rows && r < _ncontacts; r++) {
      uint16_t y = LIST_Y + r * 92;
      snprintf(line, sizeof(line), "%s%s", _contacts[r].type == 3 ? "[room] " : "", _contacts[r].name);
      tText(M, y + 60, 40, false, 0x00, line);
      tFill(M, y + 88, W - 2 * M, 2, 0xaa);
      hit(0, y, W, 92, A_OPEN_CONTACT, r);
    }
    if (!_ncontacts) tText(M, LIST_Y + 80, 36, false, 0x55, "No contacts yet. Advert, then wait.");
    drawButton(M, BAR_Y, W - 2 * M, BAR_H, "Back"); hit(M, BAR_Y, W - 2 * M, BAR_H, A_BACK);
  } else {  // CHAT
    drawHeader(_chat_contact < 0 ? "Public" : _contacts[_chat_contact].name);
    // messages for this peer, newest at the bottom of the list area
    int idx[MAX_UI_MSGS], k = 0;
    for (int i = 0; i < _nmsgs; i++) {
      const Msg &m = _msgs[i];
      bool mine = _chat_contact < 0 ? (m.channel && m.chan == 0)
                                    : (!m.channel && !memcmp(m.from, _contacts[_chat_contact].key, 6));
      if (mine) idx[k++] = i;
    }
    uint16_t quickY = BAR_Y - 2 * 100 - 20;
    int rows = (quickY - LIST_Y) / CHAT_ROW_H;
    int first = k > rows ? k - rows : 0;
    for (int r = 0; first + r < k; r++) {
      const Msg &m = _msgs[idx[first + r]];
      uint16_t y = LIST_Y + r * CHAT_ROW_H;
      fmtTime(m.ts, t, sizeof(t));
      snprintf(line, sizeof(line), "%s  %s", m.out ? "me" : (_chat_contact < 0 ? "" : nameFor(m.from)), t);
      tText(m.out ? 300 : M, y + 34, 26, true, 0x55, line);
      tText(m.out ? 300 : M, y + 78, 34, false, 0x00, m.text, m.out ? 38 : 50);
    }
    if (!k) tText(M, LIST_Y + 80, 36, false, 0x55, "Nothing here yet.");
    // quick replies: 3 + 2 buttons
    uint16_t qw3 = (W - 2 * M - 2 * 16) / 3, qw2 = (W - 2 * M - 16) / 2;
    for (int q = 0; q < NQUICK; q++) {
      bool top = q < 3;
      uint16_t w = top ? qw3 : qw2, x = M + (top ? q : q - 3) * (w + 16), y = quickY + (top ? 0 : 100);
      drawButton(x, y, w, 88, QUICK[q]);
      hit(x, y, w, 88, A_QUICK, q);
    }
    drawButton(M, BAR_Y, W - 2 * M, BAR_H, "Back"); hit(M, BAR_Y, W - 2 * M, BAR_H, A_BACK);
  }
  // GL16 normally; a full GC16 flash every 10 draws (and the first) clears ghosting.
  bool full = _full || (++_draws % 10 == 0);
  tRefresh(0, 0, W, H, full ? 1 : 0);
  _full = false;
  if (!g_ok) _kobo_up = false;  // reader stalled: stop drawing until the next HELLO
}

void KoboTerminal::loop() {
  pollKobo();
  if (_kobo_up && _dirty && millis() - _last_draw > 250) {
    _dirty = false;
    _last_draw = millis();
    draw();
  }
}

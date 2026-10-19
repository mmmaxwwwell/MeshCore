#pragma once

// KoboTerminal: an e-ink messenger UI that lives INSIDE the companion firmware.
// It is a second companion client (a BaseSerialInterface on the
// MultiSerialInterface, next to the USB serial one): it speaks the normal
// companion protocol to MyMesh, and draws on a Kobo over the kobo-mesh
// terminal protocol v0 (~/git/kobo-mesh/app/src/proto.rs) on a USB vendor
// bulk interface. Touches come back on the same interface.

#include <Arduino.h>
#include <helpers/BaseSerialInterface.h>

class KoboTerminal : public BaseSerialInterface {
public:
  void begin();

  // BaseSerialInterface: MyMesh <-> this UI, in companion frames.
  void enable() override { _enabled = true; }
  void disable() override { _enabled = false; }
  bool isEnabled() const override { return _enabled; }
  bool isConnected() const override { return _enabled && _kobo_up; }
  bool isWriteBusy() const override { return false; }
  size_t writeFrame(const uint8_t src[], size_t len) override;  // mesh -> UI
  size_t checkRecvFrame(uint8_t dest[]) override;                // UI -> mesh
  void loop() override;

private:
  enum Screen : uint8_t { INBOX, CONTACTS, CHAT, KEYB };
  enum { MAX_UI_CONTACTS = 48, MAX_UI_MSGS = 32, MAX_TX = 8 };

  struct Contact {
    uint8_t key[6];
    uint8_t type;
    char name[33];
  };
  struct Msg {
    bool out, channel;
    uint8_t chan;
    uint8_t from[6];  // DM peer (in or out)
    int8_t snr4;
    uint32_t ts;
    char text[150];
  };

  bool _enabled = false, _kobo_up = false, _dirty = false, _full = true;
  bool _syncing = false;
  bool _draft_dirty = false, _shift = false, _nums = false;
  char _draft[140] = "";
  Screen _screen = INBOX;
  int _chat_contact = -1;  // index into _contacts, or -1 = public channel 0
  uint32_t _last_draw = 0, _draws = 0;
  char _self[33] = "";

  Contact _contacts[MAX_UI_CONTACTS];
  int _ncontacts = 0;
  Msg _msgs[MAX_UI_MSGS];
  int _nmsgs = 0;

  // UI -> mesh command queue
  uint8_t _tx[MAX_TX][MAX_FRAME_SIZE];
  uint8_t _txlen[MAX_TX];
  int _txh = 0, _txn = 0;
  void queueCmd(const uint8_t *p, size_t n);

  // Kobo link
  uint8_t _rx[64];
  size_t _rxn = 0;
  void pollKobo();
  void onKoboFrame(const uint8_t *p, uint16_t n);
  void onTouch(uint16_t x, uint16_t y);

  // companion frames from the mesh
  void onContact(const uint8_t *f, size_t n);
  void addMsg(const Msg &m);
  int findContact(const uint8_t *key6) const;
  const char *nameFor(const uint8_t *key6) const;

  // actions
  void sendText(const char *text);
  void requestSync();

  // drawing (protocol v0)
  void draw();
  void drawHeader(const char *title);
  void drawDraft();
  void drawKeyboard();
  void keyPress(int code);
  void drawButton(uint16_t x, uint16_t y, uint16_t w, uint16_t h, const char *label);
};

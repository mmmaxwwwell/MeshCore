#include <Arduino.h>   // needed for PlatformIO
#include <Mesh.h>

#include "MyMesh.h"

#ifdef ETHERNET_ENABLED
  #define ETHERNET_CLI_BANNER "MeshCore Room Server CLI"
  #include <helpers/nrf52/EthernetCLI.h>
#endif

#ifdef DISPLAY_CLASS
  #include "UITask.h"
  static UITask ui_task(display);
#endif

StdRNG fast_rng;
SimpleMeshTables tables;
MyMesh the_mesh(board, radio_driver, *new ArduinoMillis(), fast_rng, rtc_clock, tables);

void halt() {
  while (1) ;
}

static char command[MAX_POST_TEXT_LEN+1];

#if defined(ESP32)
// powersaving: first sleep this long after boot (time to reach the CLI)
#define POWERSAVING_FIRSTSLEEP_MILLIS  (120 * 1000UL)
// ...and this long after the user button is pressed. A sleeping ESP32-S3
// cannot answer USB enumeration, so: press the button, then plug in a computer.
#define POWERSAVING_BUTTON_AWAKE_MILLIS  (120 * 1000UL)
static unsigned long stay_awake_until = 0;

static bool usbHostConnected() {
#if ARDUINO_USB_MODE && ARDUINO_USB_CDC_ON_BOOT
  return HWCDC::isConnected();   // a host is polling the USB-Serial/JTAG port
#else
  return false;
#endif
}
#endif
#ifdef ETHERNET_ENABLED
static char ethernet_command[MAX_POST_TEXT_LEN+1];
#endif

void setup() {
  Serial.begin(115200);
  delay(1000);

  board.begin();
#if defined(ESP32) && defined(PIN_USER_BTN)
  pinMode(PIN_USER_BTN, INPUT_PULLUP);   // powersaving stay-awake button
#endif

#ifdef HAS_EXTERNAL_WATCHDOG
  external_watchdog.begin();
#endif

#ifdef DISPLAY_CLASS
  if (display.begin()) {
    display.startFrame();
    display.setCursor(0, 0);
    display.print("Please wait...");
    display.endFrame();
  }
#endif

  if (!radio_init()) { halt(); }

  fast_rng.begin(radio_driver.getRngSeed());

  FILESYSTEM* fs;
#if defined(NRF52_PLATFORM)
  InternalFS.begin();
  fs = &InternalFS;
  IdentityStore store(InternalFS, "");
#elif defined(RP2040_PLATFORM)
  LittleFS.begin();
  fs = &LittleFS;
  IdentityStore store(LittleFS, "/identity");
  store.begin();
#elif defined(ESP32)
  SPIFFS.begin(true);
  fs = &SPIFFS;
  IdentityStore store(SPIFFS, "/identity");
#else
  #error "need to define filesystem"
#endif
  if (!store.load("_main", the_mesh.self_id)) {
    the_mesh.self_id = radio_new_identity();   // create new random identity
    int count = 0;
    while (count < 10 && (the_mesh.self_id.pub_key[0] == 0x00 || the_mesh.self_id.pub_key[0] == 0xFF)) {  // reserved id hashes
      the_mesh.self_id = radio_new_identity(); count++;
    }
    store.save("_main", the_mesh.self_id);
  }

  Serial.print("Room ID: ");
  mesh::Utils::printHex(Serial, the_mesh.self_id.pub_key, PUB_KEY_SIZE); Serial.println();

  command[0] = 0;
#ifdef ETHERNET_ENABLED
  ethernet_command[0] = 0;
#endif

  sensors.begin();

  the_mesh.begin(fs);
#if defined(ESP32)
  board.setOTAPassword(the_mesh.getNodePrefs()->password);   // WPA2 OTA AP keyed with the admin password
#endif

#ifdef DISPLAY_CLASS
  ui_task.begin(the_mesh.getNodePrefs(), FIRMWARE_BUILD_DATE, FIRMWARE_VERSION);
#endif

#ifdef ETHERNET_ENABLED
  ethernet_start_task();
#endif

  // send out initial zero hop Advertisement to the mesh
#if ENABLE_ADVERT_ON_BOOT == 1
  the_mesh.sendSelfAdvertisement(16000, false);
#endif

  board.onBootComplete();
}

void loop() {
  int len = strlen(command);
  while (Serial.available() && len < sizeof(command)-1) {
    char c = Serial.read();
    if (c != '\n') {
      command[len++] = c;
      command[len] = 0;
    }
    Serial.print(c);
  }
  if (len == sizeof(command)-1) {  // command buffer full
    command[sizeof(command)-1] = '\r';
  }

  if (len > 0 && command[len - 1] == '\r') {  // received complete line
    command[len - 1] = 0;  // replace newline with C string null terminator
    char reply[160];
    reply[0] = 0;
#ifdef ETHERNET_ENABLED
    if (!ethernet_handle_command(command, reply)) {
      the_mesh.handleCommand(0, command, reply);
    }
#else
    the_mesh.handleCommand(0, command, reply);  // NOTE: there is no sender_timestamp via serial!
#endif
    if (reply[0]) {
      Serial.print("  -> "); Serial.println(reply);
    }

    command[0] = 0;  // reset command buffer
  }

#ifdef ETHERNET_ENABLED
  ethernet_loop_maintain();
  if (ethernet_read_line(ethernet_command, sizeof(ethernet_command))) {
    char reply[160];
    reply[0] = 0;
    if (!ethernet_handle_command(ethernet_command, reply)) {
      the_mesh.handleCommand(0, ethernet_command, reply);
    }
    ethernet_send_reply(reply);
    ethernet_command[0] = 0;
  }
#endif

  the_mesh.loop();
  sensors.loop();
#ifdef DISPLAY_CLASS
  ui_task.loop();
#endif
  rtc_clock.tick();
#ifdef HAS_EXTERNAL_WATCHDOG
  external_watchdog.loop();
#endif

#if defined(ESP32)
  board.otaLoop();   // closes an idle `start ota` window after 10 min

  // Light sleep kills USB serial, so never while a computer is attached: on
  // a charger it sleeps, on the desk the CLI keeps working.
#ifdef PIN_USER_BTN
  if (digitalRead(PIN_USER_BTN) == LOW) {   // button held (active low)
    stay_awake_until = millis() + POWERSAVING_BUTTON_AWAKE_MILLIS;
  }
#endif
  if (the_mesh.getNodePrefs()->powersaving_enabled && !usbHostConnected()
      && the_mesh.millisHasNowPassed(POWERSAVING_FIRSTSLEEP_MILLIS)
      && (stay_awake_until == 0 || the_mesh.millisHasNowPassed(stay_awake_until))
      && !the_mesh.hasPendingWork()) {
#ifdef PIN_USER_BTN
    gpio_wakeup_enable((gpio_num_t)PIN_USER_BTN, GPIO_INTR_LOW_LEVEL);   // button also wakes it
#endif
    unsigned long t0 = millis();
    board.sleep(30);   // wakes on a LoRa packet (DIO1), the button, or after 30 s
    the_mesh.noteSleep(millis() - t0);
#ifdef PIN_USER_BTN
    gpio_wakeup_disable((gpio_num_t)PIN_USER_BTN);
#endif
  }
#endif
}

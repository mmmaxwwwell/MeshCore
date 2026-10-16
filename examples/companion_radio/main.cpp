#include <Arduino.h>   // needed for PlatformIO
#include <Mesh.h>
#include "MyMesh.h"

// Believe it or not, this std C function is busted on some platforms!
static uint32_t _atoi(const char* sp) {
  uint32_t n = 0;
  while (*sp && *sp >= '0' && *sp <= '9') {
    n *= 10;
    n += (*sp++ - '0');
  }
  return n;
}

// interface manager
#include <helpers/MultiSerialInterface.h>
MultiSerialInterface interface_manager;

// include bluetooth interface
#if defined(BLE_PIN_CODE)
  #ifdef ESP32
    // include esp32 bluetooth interface
    #include <helpers/esp32/SerialBLEInterface.h>
    SerialBLEInterface bluetooth_interface;
  #elif defined(NRF52_PLATFORM)
    // include nrf52 bluetooth interface
    #include <helpers/nrf52/SerialBLEInterface.h>
    SerialBLEInterface bluetooth_interface;
  #elif defined(RP2040_PLATFORM)
    // include rp2040 (Pico W / CYW43) bluetooth interface
    #include <helpers/rp2040/SerialBLEInterface.h>
    SerialBLEInterface bluetooth_interface;
  #else
    #error "SerialBLEInterface is not defined for this platform"
  #endif
#endif

// include wifi interface
#ifdef ENABLE_WIFI_INTERFACE
  #ifndef WIFI_SSID
    #define WIFI_SSID ""
  #endif
  #ifndef WIFI_PWD
    #define WIFI_PWD ""
  #endif
  #ifndef TCP_PORT
    #define TCP_PORT 5000
  #endif
  #ifndef WIFI_RETRY_INTERVAL
    #if defined(RP2040_PLATFORM)
      #define WIFI_RETRY_INTERVAL 30000   // each attempt blocks loop(), so retry less often
    #else
      #define WIFI_RETRY_INTERVAL 10000   // millis between reconnect attempts
    #endif
  #endif
  #ifndef WIFI_RETRY_TIMEOUT
    #define WIFI_RETRY_TIMEOUT 5000     // RP2040: cap on how long one join may block loop()
  #endif
  #if defined(ESP32) || defined(RP2040_PLATFORM)
    #include <helpers/wifi/SerialWifiInterface.h>
    SerialWifiInterface wifi_interface;
  #else
    #error "SerialWifiInterface is not defined for this platform"
  #endif
#endif

// include usb interface
#if defined(ENABLE_USB_INTERFACE)
  #include <helpers/ArduinoSerialInterface.h>
  ArduinoSerialInterface usb_serial_interface;
#endif

// include ethernet interface
#if defined(ETHERNET_ENABLED)
  #include <helpers/ethernet/EthernetInterface.h>
  ETHERNET_CLASS ethernet_interface;
#endif

// include hardware serial interface
#if defined(SERIAL_RX)
  #include <helpers/ArduinoSerialInterface.h>
  ArduinoSerialInterface hardware_serial_interface;
  HardwareSerial companion_serial(1);
#endif

// platform file system
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  #include <InternalFileSystem.h>
  #if defined(QSPIFLASH)
    #include <CustomLFS_QSPIFlash.h>
    DataStore store(InternalFS, QSPIFlash, rtc_clock);
  #else
    #if defined(EXTRAFS)
      #include <CustomLFS.h>
      CustomLFS ExtraFS(0xD4000, 0x19000, 128);
      DataStore store(InternalFS, ExtraFS, rtc_clock);
    #else
      DataStore store(InternalFS, rtc_clock);
    #endif
  #endif
#elif defined(RP2040_PLATFORM)
  #include <LittleFS.h>
  DataStore store(LittleFS, rtc_clock);
#elif defined(ESP32)
  #include <SPIFFS.h>
  DataStore store(SPIFFS, rtc_clock);
#endif

/* GLOBAL OBJECTS */
#ifdef DISPLAY_CLASS
  #include "UITask.h"
  UITask ui_task(&board, &interface_manager);
#endif

StdRNG fast_rng;
SimpleMeshTables tables;
MyMesh the_mesh(radio_driver, fast_rng, rtc_clock, tables, store);

/* END GLOBAL OBJECTS */

#ifdef SAFE_BOOT
  #include <helpers/nrf52/SafeBoot.h>
#endif
#if defined(QSPI_POWERSAVE) || defined(QSPI_RELEASE_DPD_AT_BOOT)
  #include <helpers/nrf52/QSPIPowerSave.h>
#endif
#ifdef LOOP_TASK_BLOCKING
  // The loop task used to sleep in sd_app_evt_wait() while staying runnable, so FreeRTOS never
  // reached tickless idle and its 1024 Hz tick woke the CPU for a full loop pass every ~1 ms.
  // Now it blocks: the LoRa IRQ wakes it at once, everything else within LOOP_MAX_SLEEP_MS
  // (BLE/USB data sit in driver buffers; a LoRa packet at our settings is >50 ms on air).
  #ifndef LOOP_MAX_SLEEP_MS
    #define LOOP_MAX_SLEEP_MS  10
  #endif
  static TaskHandle_t loop_task = NULL;
  extern "C" void loopWakeFromISR() {
    if (loop_task) {
      BaseType_t woken = pdFALSE;
      vTaskNotifyGiveFromISR(loop_task, &woken);
      portYIELD_FROM_ISR(woken);
    }
  }
#endif

void halt() {
  while (1) ;
}

/* WIFI RECONNECT TRACKERS */
#ifdef ENABLE_WIFI_INTERFACE
  bool wifi_needs_reconnect = false;
  unsigned long last_wifi_reconnect_attempt = 0;
  char wifi_ssid[33] = WIFI_SSID;   // replaced by stored prefs at boot, if set
  char wifi_pwd[64] = WIFI_PWD;
  bool wifi_was_connected = false;
  bool wifi_enabled = false;   // set at boot from prefs; false also when the effective SSID is blank
#endif

void setup() {
#ifdef SAFE_BOOT
  SafeBoot::begin();   // first: a crash anywhere below must count
#endif
  Serial.begin(115200);
#ifdef CONTACTS_SELFTEST
  { unsigned long t = millis(); while (!Serial && millis() - t < 15000) delay(10); delay(300); }
  Serial.println("DBG boot");
#endif
  board.begin();

#ifdef HAS_EXTERNAL_WATCHDOG
  external_watchdog.begin();
#endif

#ifdef DISPLAY_CLASS
  DisplayDriver* disp = NULL;
  if (display.begin()) {
    disp = &display;
    disp->startFrame();
  #ifdef ST7789
    disp->setTextSize(2);
  #endif
    disp->drawTextCentered(disp->width() / 2, 28, "Loading...");
    disp->endFrame();
  }
#endif

  if (!radio_init()) { halt(); }

  fast_rng.begin(radio_driver.getRngSeed());

#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  InternalFS.begin();
  #if defined(QSPIFLASH)
  #if defined(QSPI_POWERSAVE) || defined(QSPI_RELEASE_DPD_AT_BOOT)
    qspiReleaseDeepPowerDown();
  #endif
    if (!QSPIFlash.begin()) {
      // debug output might not be available at this point, might be too early. maybe should fall back to InternalFS here?
      MESH_DEBUG_PRINTLN("CustomLFS_QSPIFlash: failed to initialize");
    } else {
      MESH_DEBUG_PRINTLN("CustomLFS_QSPIFlash: initialized successfully");
    #ifdef QSPI_POWERSAVE
      QSPIPowerSave::install(QSPIFlash);
    #endif
    #ifdef QSPI_LFS_LOOKAHEAD
      // littlefs v1 traverses the WHOLE filesystem every time its lookahead window of free
      // blocks runs out; CustomLFS sets 32 blocks but allocates a 32-byte (256-bit) buffer.
      // lfs_alloc() reads cfg->lookahead at each refill, so widening it after mount is safe.
      ((struct lfs_config*) QSPIFlash._getFS()->cfg)->lookahead = QSPI_LFS_LOOKAHEAD;
    #endif
    }
  #else
  #if defined(EXTRAFS)
      ExtraFS.begin();
  #endif
  #endif
  store.begin();
#ifdef CONTACTS_SELFTEST
  {
    unsigned long t = millis(); while (!Serial && millis() - t < 15000) delay(10);
    {
      FILESYSTEM* fs = store.getSecondaryFS() ? store.getSecondaryFS() : store.getPrimaryFS();
      Serial.printf("DBG fs=%s used=%lu/%lu KB contacts3=%d adv_blobs=%d cver=%d\n",
        store.getSecondaryFS() ? "qspi" : "internal", (unsigned long)store.getStorageUsedKb(),
        (unsigned long)store.getStorageTotalKb(), fs->exists("/contacts3"), fs->exists("/adv_blobs"), fs->exists("/cver"));
      fs->remove("/tst");
      File f = fs->open("/tst", FILE_O_WRITE);
      Serial.printf("DBG open /tst write: %d\n", (bool)f);
      if (f) { Serial.printf("DBG wrote %d\n", (int)f.write((const uint8_t *)"hello", 5)); f.close(); }
      Serial.printf("DBG /tst exists=%d\n", fs->exists("/tst"));
      fs->remove("/tst");
    }
    store.setContactDirPrefix('t');
    store.removeContactFiles();
    bool ok = the_mesh.contactStoreSelfTest(&store, Serial);
    store.removeContactFiles();
    store.setContactDirPrefix('c');
    Serial.println(ok ? "ST RESULT PASS" : "ST RESULT FAIL");
    for (;;) {   // test build: never touch the real contacts. USB stays up for the 1200-baud touch.
  #ifdef SAFE_BOOT
      SafeBoot::loop();   // feeds, and marks the boot healthy after 30 s
  #endif
      delay(3000);
      extern const char* st_summary;
      Serial.print(st_summary);
      Serial.println(ok ? "ST RESULT PASS" : "ST RESULT FAIL");
    }
  }
#endif
  the_mesh.begin();
#elif defined(RP2040_PLATFORM)
  LittleFS.begin();
  store.begin();
  the_mesh.begin();
#elif defined(ESP32)
  SPIFFS.begin(true);
  store.begin();
  the_mesh.begin();
#else
  #error "need to define filesystem"
#endif

#ifdef BLE_PIN_CODE // 123456 by default
  if (the_mesh.getNodePrefs()->ble_pin == 0) {
#ifdef DISPLAY_CLASS
    if (disp != NULL && BLE_PIN_CODE == 123456) {
      StdRNG rng;
      the_mesh.setBLEPin(rng.nextInt(100000, 999999)); // random pin each session
    } else {
      the_mesh.setBLEPin(BLE_PIN_CODE); // otherwise static pin
    }
#else
    the_mesh.setBLEPin(BLE_PIN_CODE); // otherwise static pin
#endif
  } else {
    the_mesh.setBLEPin(the_mesh.getNodePrefs()->ble_pin);
  }
#else
  the_mesh.setBLEPin(0);
#endif

// add bluetooth interface
#if defined(BLE_PIN_CODE)
  bluetooth_interface.begin(BLE_NAME_PREFIX, the_mesh.getNodePrefs()->node_name, the_mesh.getBLEPin());
  interface_manager.addInterface(InterfaceType::Bluetooth, &bluetooth_interface);
#endif

// add wifi interface
#ifdef ENABLE_WIFI_INTERFACE
  // use wifi ssid and password from prefs if ssid is not empty, otherwise use the build flag defaults
  if (the_mesh.getNodePrefs()->wifi_ssid[0]) {
    strcpy(wifi_ssid, the_mesh.getNodePrefs()->wifi_ssid);
    strcpy(wifi_pwd, the_mesh.getNodePrefs()->wifi_pwd);
  }
  // only start wifi if enabled and ssid is not empty
  wifi_enabled = the_mesh.getNodePrefs()->wifi_enabled;
  if (wifi_enabled && wifi_ssid[0]) {
#if defined(ESP32)
    board.setInhibitSleep(true);   // prevent sleep when WiFi is active
    WiFi.setAutoReconnect(true);

    WiFi.onEvent([](WiFiEvent_t event, WiFiEventInfo_t info){
        if (event == ARDUINO_EVENT_WIFI_STA_DISCONNECTED) {
            WIFI_DEBUG_PRINTLN("WiFi disconnected (reason=%s). Flagging for reconnect...",
              WiFi.disconnectReasonName((wifi_err_reason_t)info.wifi_sta_disconnected.reason));
            wifi_needs_reconnect = true;
        } else if (event == ARDUINO_EVENT_WIFI_STA_GOT_IP) {
            WIFI_DEBUG_PRINTLN("WiFi connected successfully!");
            wifi_needs_reconnect = false;
        }
    });
#endif

    WIFI_DEBUG_PRINTLN("connecting to %s", wifi_ssid);

#if defined(RP2040_PLATFORM)
    // the join itself blocks inside the core (CYW43::begin busy-waits for the
    // association), so every attempt stalls the mesh loop. beginNoBlock() only skips the
    // extra DHCP wait. Give the first connect a full window, then bound the retries below.
    WiFi.beginNoBlock(wifi_ssid, wifi_pwd);
    last_wifi_reconnect_attempt = millis();   // let DHCP finish before the poll can retry
#else
    WiFi.begin(wifi_ssid, wifi_pwd);
#endif
    wifi_interface.begin(TCP_PORT);
    interface_manager.addInterface(InterfaceType::WiFi, &wifi_interface);
  } else {
    WIFI_DEBUG_PRINTLN("wifi disabled");
  }
#endif

// add usb interface
#if defined(ENABLE_USB_INTERFACE)
  usb_serial_interface.begin(Serial);
  interface_manager.addInterface(InterfaceType::USB, &usb_serial_interface);
#endif

// add ethernet interface
#if defined(ETHERNET_ENABLED)
  ethernet_interface.begin();
  interface_manager.addInterface(InterfaceType::Ethernet, &ethernet_interface);
#endif

// add hardware serial interface
#if defined(SERIAL_RX)
  companion_serial.setPins(SERIAL_RX, SERIAL_TX);
  companion_serial.begin(115200);
  hardware_serial_interface.begin(companion_serial);
  interface_manager.addInterface(InterfaceType::HardwareSerial, &hardware_serial_interface);
#endif

  the_mesh.startInterface(interface_manager);
  sensors.begin();

#if ENV_INCLUDE_GPS == 1
  the_mesh.applyGpsPrefs();
#endif

#ifdef DISPLAY_CLASS
  ui_task.begin(disp, &sensors, the_mesh.getNodePrefs());  // still want to pass this in as dependency, as prefs might be moved
  the_mesh.setListener(&ui_task);
#endif

  board.onBootComplete();
}

void loop() {
#ifdef SAFE_BOOT
  SafeBoot::loop();
#endif
  the_mesh.loop();
  interface_manager.loop();
  sensors.loop();
#ifdef DISPLAY_CLASS
  ui_task.loop();
#endif
  rtc_clock.tick();
  board.loop();
#ifdef HAS_EXTERNAL_WATCHDOG
  external_watchdog.loop();
#endif

#ifdef QSPI_POWERSAVE
  QSPIPowerSave::loop();
#endif

  if (!the_mesh.hasPendingWork()) {
#if defined(NRF52_PLATFORM) && defined(LOOP_TASK_BLOCKING)
    if (loop_task == NULL) loop_task = xTaskGetCurrentTaskHandle();
    ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(LOOP_MAX_SLEEP_MS));   // idle task -> tickless sleep
#elif defined(NRF52_PLATFORM)
    board.sleep(0); // nrf ignores seconds param, sleeps whenever possible
#endif
  }

#ifdef ENABLE_WIFI_INTERFACE
  if (wifi_enabled) {
    // RP2040 has no WiFi event callbacks, so poll the link state instead
  #if defined(RP2040_PLATFORM)
      wifi_needs_reconnect = (WiFi.status() != WL_CONNECTED);
      if (wifi_was_connected == wifi_needs_reconnect) {   // link state changed
        wifi_was_connected = !wifi_needs_reconnect;
        if (wifi_was_connected) {
          WIFI_DEBUG_PRINTLN("connected, listening on %s:%d", WiFi.localIP().toString().c_str(), TCP_PORT);
        } else {
          WIFI_DEBUG_PRINTLN("link lost");
        }
      }
  #endif

    // Safely attempt to reconnect if flagged. On RP2040 each attempt blocks the mesh loop
    // for up to WIFI_RETRY_TIMEOUT, so retry less often and cap how long a join may stall.
    if (wifi_needs_reconnect && (millis() - last_wifi_reconnect_attempt > WIFI_RETRY_INTERVAL)) {
      WIFI_DEBUG_PRINTLN("Attempting manual WiFi reconnect to %s (status %d)...", wifi_ssid, WiFi.status());
    #if defined(RP2040_PLATFORM)
        WiFi.setTimeout(WIFI_RETRY_TIMEOUT);
        WiFi.beginNoBlock(wifi_ssid, wifi_pwd);   // no reconnect() on this platform
    #else
        WiFi.disconnect();
        WiFi.reconnect();
    #endif
      last_wifi_reconnect_attempt = millis();
    }
  }
#endif
}

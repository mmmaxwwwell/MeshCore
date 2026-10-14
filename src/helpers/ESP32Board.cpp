#ifdef ESP_PLATFORM

#include "ESP32Board.h"
#include <target.h>

#if defined(ADMIN_PASSWORD) && !defined(DISABLE_WIFI_OTA)   // Repeater or Room Server only
#include <WiFi.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <AsyncElegantOTA.h>

#include <SPIFFS.h>

#ifndef OTA_IDLE_TIMEOUT_MILLIS
  #define OTA_IDLE_TIMEOUT_MILLIS  (10 * 60 * 1000UL)
#endif

bool ESP32Board::startOTAUpdate(const char* id, char reply[]) {
  if (ota_server) {
    strcpy(reply, "Err - OTA already running");
    return true;
  }
  if (ota_password && strlen(ota_password) < 8) {   // WPA2 needs 8..63 chars
    strcpy(reply, "Err - admin password must be 8+ chars for WPA2 OTA");
    return true;
  }
  inhibit_sleep = true;   // prevent sleep during OTA
  WiFi.softAP("MeshCore-OTA", ota_password);   // NULL = open AP (upstream default)

  sprintf(reply, "Started: http://%s/update", WiFi.softAPIP().toString().c_str());
  MESH_DEBUG_PRINTLN("startOTAUpdate: %s", reply);

  static char id_buf[60];
  sprintf(id_buf, "%s (%s)", id, getManufacturerName());
  static char home_buf[90];
  sprintf(home_buf, "<H2>Hi! I am a MeshCore Repeater. ID: %s</H2>", id);

  AsyncWebServer* server = new AsyncWebServer(80);

  server->on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send(200, "text/html", home_buf);
  });
  server->on("/log", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send(SPIFFS, "/packet_log", "text/plain");
  });

  AsyncElegantOTA.setID(id_buf);
  AsyncElegantOTA.begin(server);    // Start ElegantOTA
  server->begin();
  ota_server = server;
  ota_off_at = millis() + OTA_IDLE_TIMEOUT_MILLIS;
  if (ota_password) strcat(reply, " (WPA2: admin password)");

  return true;
}

void ESP32Board::otaLoop() {
  if (ota_server == NULL || (long)(millis() - ota_off_at) < 0) return;
  if (WiFi.softAPgetStationNum() > 0) {   // someone is still on: give them another minute
    ota_off_at = millis() + 60 * 1000UL;
    return;
  }
  ((AsyncWebServer*)ota_server)->end();
  delete (AsyncWebServer*)ota_server;
  ota_server = NULL;
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_OFF);
  inhibit_sleep = false;
  MESH_DEBUG_PRINTLN("OTA window closed (idle)");
}

#else
bool ESP32Board::startOTAUpdate(const char* id, char reply[]) {
  return false; // not supported
}
void ESP32Board::otaLoop() { }
#endif

void ESP32Board::powerOff() {
  enterDeepSleep(0); // Do not wakeup
}

void ESP32Board::enterDeepSleep(uint32_t secs) {
  // Power off the display if any
#ifdef DISPLAY_CLASS
  display.turnOff();
#endif

  // Power off LoRa
  radio_driver.powerOff();

  // Keep LoRa inactive during deepsleep
  digitalWrite(P_LORA_NSS, HIGH);
#if defined(CONFIG_IDF_TARGET_ESP32C3) || defined(CONFIG_IDF_TARGET_ESP32C6)
  gpio_hold_en((gpio_num_t)P_LORA_NSS);
#else
  rtc_gpio_hold_en((gpio_num_t)P_LORA_NSS);
#endif

  // Power off GPS if any
  if (sensors.getLocationProvider() != NULL) {
    sensors.getLocationProvider()->stop();
  }

  // Flush serial buffers
  Serial.flush();
  delay(100);

  // Clear stale wakeup sources to avoid ghost wakeup
  // This is required when Power Management and automatic lightsleep are enabled
  esp_sleep_disable_wakeup_source(ESP_SLEEP_WAKEUP_ALL);

  if (secs > 0) {
    esp_sleep_enable_timer_wakeup(secs * 1000000ULL);
  }

  // Finally set ESP32 into deepsleep
  esp_deep_sleep_start(); // CPU halts here and never returns!
}
#endif

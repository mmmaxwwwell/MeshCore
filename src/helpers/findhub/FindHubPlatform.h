#pragma once

// What the portable Fast Pair / Find Hub code needs from the board: RNG, time,
// persistence, the buzzer and GATT notifications. nrf52/FindHubService implements
// it on Bluefruit; the native tests implement it with fakes.

#include <stdint.h>
#include <stddef.h>
#include "FindHubCrypto.h"

namespace findhub {

constexpr size_t MAX_ACCOUNT_KEYS = 5;   // spec minimum is 5

// Persisted Fast Pair account keys, most recently used first.
struct AccountKeyData {
  uint8_t count;
  uint8_t owner;                          // index of the owner account key, 0xFF = none
  uint8_t keys[MAX_ACCOUNT_KEYS][AK_LEN];
};

enum BatteryLevel : uint8_t {
  BATTERY_UNSUPPORTED = 0,
  BATTERY_NORMAL = 1,
  BATTERY_LOW = 2,
  BATTERY_CRITICAL = 3,
};

class FindHubPlatform {
public:
  virtual ~FindHubPlatform() {}
  virtual void randomBytes(uint8_t* dest, size_t len) = 0;
  virtual uint32_t millis() = 0;
  virtual uint32_t beaconClock() = 0;          // FHN clock, seconds, survives reboots
  virtual int8_t calibratedPower() = 0;        // dBm at 0 m
  virtual BatteryLevel batteryLevel() = 0;
  virtual bool saveAccountKeys(const AccountKeyData* d) = 0;  // NULL = erase
  virtual bool saveEik(const uint8_t* eik) = 0;               // NULL = erase
  virtual void ringStart() = 0;                // start (or keep) sounding
  virtual void ringStop() = 0;
  virtual void notify(uint8_t conn, const uint8_t* data, size_t len) = 0;  // Beacon Actions notifications
};

}  // namespace findhub

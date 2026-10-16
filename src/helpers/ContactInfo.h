#pragma once

#include <Arduino.h>
#include <Mesh.h>

#define OUT_PATH_UNKNOWN   0xFF

struct ContactInfo {
  mesh::Identity id;
  char name[32];
  uint8_t type;   // on of ADV_TYPE_*
  uint8_t flags;
  uint8_t out_path_len;
  mutable bool shared_secret_valid; // flag to indicate if shared_secret has been calculated
  uint8_t out_path[MAX_PATH_SIZE];
  uint32_t last_advert_timestamp;   // by THEIR clock
  uint32_t lastmod;  // by OUR clock
  int32_t gps_lat, gps_lon;    // 6 dec places
  uint32_t sync_since;

  const uint8_t* getSharedSecret(const mesh::LocalIdentity& self_id) const {
    if (!shared_secret_valid) {
      self_id.calcSharedSecret(shared_secret, id.pub_key);
      shared_secret_valid = true;
    }
    return shared_secret;
  }

  // fixed 152-byte storage record (the companion's '/contacts3' layout)
  #define CONTACT_REC_SIZE  152
  void writeRecord(uint8_t rec[CONTACT_REC_SIZE]) const {
    memset(rec, 0, CONTACT_REC_SIZE);
    memcpy(&rec[0], id.pub_key, 32);
    memcpy(&rec[32], name, 32);
    rec[64] = type;
    rec[65] = flags;
    memcpy(&rec[67], &sync_since, 4);
    rec[71] = out_path_len;
    memcpy(&rec[72], &last_advert_timestamp, 4);
    memcpy(&rec[76], out_path, 64);
    memcpy(&rec[140], &lastmod, 4);
    memcpy(&rec[144], &gps_lat, 4);
    memcpy(&rec[148], &gps_lon, 4);
  }
  void readRecord(const uint8_t rec[CONTACT_REC_SIZE]) {
    id = mesh::Identity(&rec[0]);
    memcpy(name, &rec[32], 32);
    type = rec[64];
    flags = rec[65];
    memcpy(&sync_since, &rec[67], 4);
    out_path_len = rec[71];
    memcpy(&last_advert_timestamp, &rec[72], 4);
    memcpy(out_path, &rec[76], 64);
    memcpy(&lastmod, &rec[140], 4);
    memcpy(&gps_lat, &rec[144], 4);
    memcpy(&gps_lon, &rec[148], 4);
    shared_secret_valid = false;
  }

  bool isFav() const { return flags & 0x01; }
  bool isTelemBaseAllowed() const { return flags & 0x02; }
  bool isTelemLocAllowed() const { return flags & 0x04; }
  bool isTelemEnvAllowed() const { return flags & 0x08; }
  bool isRemoteCLIAllowed() const { return flags & 0x10; }

private:
  mutable uint8_t shared_secret[PUB_KEY_SIZE];
};

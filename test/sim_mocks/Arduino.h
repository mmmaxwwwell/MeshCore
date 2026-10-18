#pragma once

#include <cstdint>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "Stream.h"

// Host simulator only: what MeshCore's mesh sources take from the Arduino core.
inline char* ltoa(long v, char* buf, int base) {
  if (base == 16) sprintf(buf, "%lx", v); else sprintf(buf, "%ld", v);
  return buf;
}

// IdentityStore.h wants a filesystem type; the simulator never persists.
struct SimFile { operator bool() const { return false; } };
struct SimFS {
  bool mkdir(const char*) { return true; }
  SimFile open(const char*, ...) { return {}; }
  bool exists(const char*) { return false; }
  bool remove(const char*) { return true; }
};
#define FILESYSTEM SimFS

inline uint32_t g_mock_millis = 0;

using std::isnan;

inline uint32_t millis() {
  return g_mock_millis;
}

inline void delay(uint32_t ms) {
  g_mock_millis += ms;
}

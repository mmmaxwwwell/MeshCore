#pragma once
#include <stdint.h>
namespace mesh {
struct Utils {
  static bool fromHex(uint8_t* dest, int n, const char* hex) {
    for (int i = 0; i < n; i++) {
      unsigned v;
      if (sscanf(hex + 2 * i, "%2x", &v) != 1) return false;
      dest[i] = v;
    }
    return true;
  }
};
}

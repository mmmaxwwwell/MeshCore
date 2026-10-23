#pragma once

#include <stdint.h>

// Writing the nRF54L's RRAM from the app (interrupts on, code running from RRAM).
// RRAM has no erase and is written a word at a time: a "fill" writes 0xFF, and a
// partial word keeps its other bytes (read, merge, write), unlike NOR flash where
// programming 0xFF over data changes nothing. Every write is read back.

bool nrf54RramWriteWords(uint32_t addr, const uint32_t* src, uint32_t words);   // word aligned; src NULL = 0xFF
bool nrf54RramWrite(uint32_t addr, const uint8_t* src, uint32_t n);            // any address/length; src NULL = 0xFF
bool nrf54RramFill(uint32_t addr, uint32_t len);                               // 0xFF, whole words

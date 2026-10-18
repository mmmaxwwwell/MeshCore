#pragma once
// host stand-ins for the bits of Arduino LoraOTAService.cpp uses
#include <stdint.h>
#include <string.h>
#include <stdio.h>
extern unsigned long fake_millis;
static inline unsigned long millis() { return fake_millis; }

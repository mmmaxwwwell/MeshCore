// Link-only stand-in for rweather/Crypto's global hardware RNG: Ed25519/
// Curve25519 key generation references it, but the simulator never calls those
// paths (SimNode seeds its own deterministic mesh::RNG). Aborts if ever used.
#include <RNG.h>
#include <stdlib.h>

RNGClass::RNGClass() {}
RNGClass::~RNGClass() {}
void RNGClass::rand(uint8_t*, size_t) { abort(); }
RNGClass RNG;

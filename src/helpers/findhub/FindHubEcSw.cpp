// Software elliptic-curve backend (micro-ecc). Used by the native tests and by
// builds without the nRF52840 CryptoCell (FINDHUB_EC_CC310 unset).
#ifndef FINDHUB_EC_CC310

#include "FindHubCrypto.h"

#include <string.h>
#include <uECC.h>

namespace findhub {

bool ecSecp160r1MulG(const uint8_t k[SECP160R1_PRIV_LEN], uint8_t x[EID_LEN]) {
  uint8_t pub[40];
  bool ok = uECC_compute_public_key(k, pub, uECC_secp160r1()) == 1;
  if (ok) memcpy(x, pub, EID_LEN);
  memset(pub, 0, sizeof(pub));
  return ok;
}

bool ecdhP256(const uint8_t priv[P256_PRIV_LEN], const uint8_t pub[P256_PUB_LEN], uint8_t secret[32]) {
  uECC_Curve curve = uECC_secp256r1();
  // An off-curve point would make the "shared secret" depend on our private key
  // in a way an attacker can probe (invalid-curve attack).
  if (!uECC_valid_public_key(pub, curve)) return false;
  return uECC_shared_secret(pub, priv, secret, curve) == 1;
}

}  // namespace findhub

#endif

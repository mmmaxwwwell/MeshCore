// nRF52840 CryptoCell (CC310) elliptic-curve backend for helpers/findhub.
// Selected by FINDHUB_EC_CC310; the core's nRFCrypto.begin() (NRF52Board::begin,
// USE_CC310_HW_CRYPTO) has already powered and initialised the CryptoCell.
//
// CC310 has no "public key from private key" call that takes our scalar, so k*G
// is ECDH(k, G): the shared secret IS the x coordinate of k*G. Runs on the main
// loop only (FindHubService queues every BLE request there), like MeshCore's own
// CC310 SHA/AES/Ed25519 use, so the static work buffers are never shared.
#ifdef FINDHUB_EC_CC310

#include <helpers/findhub/FindHubCrypto.h>

#include <string.h>
#include <Adafruit_nRFCrypto.h>
#include "nrf_cc310/include/crys_ecpki_build.h"
#include "nrf_cc310/include/crys_ecpki_dh.h"
#include "nrf_cc310/include/crys_ecpki_domain.h"

namespace findhub {

// SEC 2 secp160r1 base point, uncompressed (PC = 0x04 || X || Y).
static const uint8_t SECP160R1_G[1 + 2 * 20] = {
  0x04,
  0x4A, 0x96, 0xB5, 0x68, 0x8E, 0xF5, 0x73, 0x28, 0x46, 0x64, 0x69, 0x89, 0x68, 0xC3, 0x8B, 0xB9, 0x13, 0xCB, 0xFC, 0x82,
  0x23, 0xA6, 0x28, 0x55, 0x31, 0x68, 0x94, 0x7D, 0x59, 0xDC, 0xC9, 0x12, 0x04, 0x23, 0x51, 0x37, 0x7A, 0xC5, 0xFB, 0x32,
};

static CRYS_ECPKI_UserPublKey_t s_pub;
static CRYS_ECPKI_UserPrivKey_t s_priv;
static CRYS_ECDH_TempData_t s_dh_tmp;
static CRYS_ECPKI_BUILD_TempData_t s_build_tmp;

static bool ecdh(CRYS_ECPKI_DomainID_t id, const uint8_t* priv, size_t priv_len,
                 const uint8_t* pub_pc, size_t pub_len, bool full_check, uint8_t* secret, size_t secret_len) {
  const CRYS_ECPKI_Domain_t* dom = CRYS_ECPKI_GetEcDomain(id);
  if (!dom) return false;
  CRYSError_t rc = full_check
    ? CRYS_ECPKI_BuildPublKeyFullCheck(dom, (uint8_t*)pub_pc, pub_len, &s_pub, &s_build_tmp)
    : CRYS_ECPKI_BuildPublKey(dom, (uint8_t*)pub_pc, pub_len, &s_pub);
  if (rc == CRYS_OK) rc = CRYS_ECPKI_BuildPrivKey(dom, priv, priv_len, &s_priv);
  uint32_t out_len = (uint32_t)secret_len;
  if (rc == CRYS_OK) rc = CRYS_ECDH_SVDP_DH(&s_pub, &s_priv, secret, &out_len, &s_dh_tmp);
  memset(&s_priv, 0, sizeof(s_priv));
  memset(&s_dh_tmp, 0, sizeof(s_dh_tmp));
  return rc == CRYS_OK && out_len == secret_len;
}

bool ecSecp160r1MulG(const uint8_t k[SECP160R1_PRIV_LEN], uint8_t x[EID_LEN]) {
  // G needs no validation; the private key may be 161 bits (n is), so all 21 bytes go in.
  return ecdh(CRYS_ECPKI_DomainID_secp160r1, k, SECP160R1_PRIV_LEN, SECP160R1_G, sizeof(SECP160R1_G),
              false, x, EID_LEN);
}

bool ecdhP256(const uint8_t priv[P256_PRIV_LEN], const uint8_t pub[P256_PUB_LEN], uint8_t secret[32]) {
  uint8_t pc[1 + P256_PUB_LEN];
  pc[0] = 0x04;
  memcpy(&pc[1], pub, P256_PUB_LEN);
  // Full check: an off-curve point from the Seeker must not reach the multiplication.
  return ecdh(CRYS_ECPKI_DomainID_secp256r1, priv, P256_PRIV_LEN, pc, sizeof(pc), true, secret, 32);
}

}  // namespace findhub

#endif

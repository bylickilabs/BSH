// 1. Curve25519 Schlüsselgenerierung und ECDH (C, für Mikrocontroller)

// ecc_curve25519.h
#ifndef ECC_CURVE25519_H
#define ECC_CURVE25519_H

#include <stdint.h>

void generate_private_key(uint8_t priv[32]);
void generate_public_key(const uint8_t priv[32], uint8_t pub[32]);
int compute_shared_secret(const uint8_t priv[32], const uint8_t peer_pub[32], uint8_t secret[32]);

#endif

// 2. AES-256 GCM Implementierung (C)

// aes_gcm.h
#ifndef AES_GCM_H
#define AES_GCM_H

#include <stdint.h>
#include <stddef.h>

int aes_gcm_encrypt(const uint8_t *key, const uint8_t *nonce,
                    const uint8_t *plaintext, size_t plen,
                    uint8_t *ciphertext, uint8_t *tag);

int aes_gcm_decrypt(const uint8_t *key, const uint8_t *nonce,
                    const uint8_t *ciphertext, size_t clen,
                    const uint8_t *tag, uint8_t *plaintext);

#endif

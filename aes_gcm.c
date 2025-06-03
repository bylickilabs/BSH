// aes_gcm.c
#include "aes_gcm.h"
#include "mbedtls/gcm.h"

int aes_gcm_encrypt(const uint8_t *key, const uint8_t *nonce,
                    const uint8_t *plaintext, size_t plen,
                    uint8_t *ciphertext, uint8_t *tag) {
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    int ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plen, nonce, 12,
                                       NULL, 0, plaintext, ciphertext, 16, tag);
    mbedtls_gcm_free(&gcm);
    return ret;
}

int aes_gcm_decrypt(const uint8_t *key, const uint8_t *nonce,
                    const uint8_t *ciphertext, size_t clen,
                    const uint8_t *tag, uint8_t *plaintext) {
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    int ret = mbedtls_gcm_auth_decrypt(&gcm, clen, nonce, 12,
                                       NULL, 0, tag, 16, ciphertext, plaintext);
    mbedtls_gcm_free(&gcm);
    return ret;
}

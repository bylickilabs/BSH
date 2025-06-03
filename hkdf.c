// hkdf.c
#include "hkdf.h"
#include "mbedtls/md.h"

void hkdf_extract(const uint8_t *salt, size_t salt_len,
                  const uint8_t *ikm, size_t ikm_len,
                  uint8_t *prk) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_hmac(md, salt, salt_len, ikm, ikm_len, prk);
}

void hkdf_expand(const uint8_t *prk, size_t prk_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *okm, size_t okm_len) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    uint8_t T[32];
    uint8_t counter = 1;
    size_t pos = 0;
    size_t n = (okm_len + 31) / 32;
    size_t i;
    size_t t_len = 0;

    for (i = 0; i < n; i++) {
        mbedtls_md_context_t ctx;
        mbedtls_md_init(&ctx);
        mbedtls_md_setup(&ctx, md, 1);
        mbedtls_md_hmac_starts(&ctx, prk, prk_len);
        if (i != 0)
            mbedtls_md_hmac_update(&ctx, T, t_len);
        mbedtls_md_hmac_update(&ctx, info, info_len);
        mbedtls_md_hmac_update(&ctx, &counter, 1);
        mbedtls_md_hmac_finish(&ctx, T);
        mbedtls_md_free(&ctx);
        t_len = 32;

        size_t to_copy = (okm_len - pos) > 32 ? 32 : (okm_len - pos);
        memcpy(okm + pos, T, to_copy);
        pos += to_copy;
        counter++;
    }
}

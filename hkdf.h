// 3. HKDF Schlüsselableitung (C)

// hkdf.h
#ifndef HKDF_H
#define HKDF_H

#include <stdint.h>
#include <stddef.h>

void hkdf_extract(const uint8_t *salt, size_t salt_len,
                  const uint8_t *ikm, size_t ikm_len,
                  uint8_t *prk);

void hkdf_expand(const uint8_t *prk, size_t prk_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *okm, size_t okm_len);

#endif

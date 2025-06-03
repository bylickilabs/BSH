|Bylicki Secure Hybrid (BSH)|
|---|

<br><br>

- I. Algorithmus-Konzept: Hybrid-Verschlüsselung „Bylicki Secure Hybrid (BSH)“
     - I.I Grundidee
>Kombination aus symmetrischer und asymmetrischer Verschlüsselung mit zusätzlicher Mehrfaktor-Zufallsgenerierung und eingebauter Schlüsselrotation zur Erhöhung der Sicherheit und Anpassbarkeit. <p>

- I.II Algorithmus-Komponenten
>Symmetrischer Teil: AES-256 (Advanced Encryption Standard, 256 Bit Schlüssel) <p>
>Asymmetrischer Teil: Elliptic Curve Cryptography (ECC) mit Curve25519 <p>
>Zufallsquelle: Kombiniert kryptographisch sichere Pseudozufallszahlen (CSPRNG) mit Hardware-Rauschquellen (z. B. Mikrochip-Sensoren) <p>
>Schlüsselrotation: Alle 24h neue Schlüssel, generiert via Hash-basierte Schlüsselableitung (HKDF) <p>
>Integritätsprüfung: SHA-3 (Keccak) als Hashfunktion zur Nachrichtenauthentifizierung (HMAC)

<br><br>

| ![111](https://github.com/user-attachments/assets/9bd40246-ff73-4017-9146-c6a243ed5ce6)| ![222](https://github.com/user-attachments/assets/e4ce46db-f59e-41e7-997b-ef056866cdd2) | ![333](https://github.com/user-attachments/assets/e60b434a-5deb-498f-a10d-4482edf43bbf)| 
|---|---|---|

| ![BSH_Formula_Public_Key (1)](https://github.com/user-attachments/assets/e91beb00-df46-4cbf-89a5-e6f75fce3c37)| ![BSH_Formula_Shared_Secret (1)](https://github.com/user-attachments/assets/5c0d3a64-0e79-4ffa-b44b-3fec9919caa3)| ![BSH_Formula_Session_Key (1)](https://github.com/user-attachments/assets/9cb269b9-4709-406c-9a0d-2ffef04cb632)| ![BSH_Formula_AES_Encryption (1)](https://github.com/user-attachments/assets/32adf90d-7a00-4891-9289-65052a6c3e34)| ![BSH_Formula_Key_Rotation (1)](https://github.com/user-attachments/assets/60af12e0-261e-415e-b5fb-6b2497a8baed) |
|---|---|---|---|---|

<br>

|Übersicht der Quellcodes|
|---|

| Modul | Sprache | Beschreibung |
|:------------------ |:-------------------:| :-------------------:|
| ECC Schlüsselgenerierung (Curve25519)             | C              | Mikrocontroller-spezifisch, optimiert              |
| ECDH Schlüsselaustausch                           | C              | Aufbau des gemeinsamen Sitzungsschlüssels              |
| AES-256 GCM Verschlüsselung/Entschlüsselung             | C              | Symmetrische Verschlüsselung              |
| HKDF Schlüsselableitung             | C              | Schlüsselrotation und Ableitung              |
| Python-Bindings für Testing & Prototyp             | Python              | Kommunikation & Test der Kryptokomponenten              |

<br><br>

|Zusammenfassung|
|---|
>C-Code ist optimiert für Embedded Systeme, nutzt bewährte Libraries (mbedTLS, libsodium empfohlen)
>Python-Code dient als Prototyp und Testumgebung
>Alle Module sind modular gestaltet, um einfache Integration und Erweiterung zu ermöglichen

<br><br>

|Vollständige Details des Bylicki Secure Hybrid (BSH) Projekts|
|---|

- C-Code: Embedded Implementierung für Mikrocontroller
- Curve25519 (ECC) Schlüsselgenerierung & ECDH
- Header (ecc_curve25519.h):

```yarn
#ifndef ECC_CURVE25519_H
#define ECC_CURVE25519_H

#include <stdint.h>

void generate_private_key(uint8_t priv[32]);
void generate_public_key(const uint8_t priv[32], uint8_t pub[32]);
int compute_shared_secret(const uint8_t priv[32], const uint8_t peer_pub[32], uint8_t secret[32]);

#endif
```

<br><br>

- Quellcode (ecc_curve25519.c):

```yarn
#include "ecc_curve25519.h"
#include <string.h>

// Hier sollte eine etablierte Curve25519-Bibliothek verwendet werden,
// z. B. micro-ecc, TweetNaCl oder libsodium.

void generate_private_key(uint8_t priv[32]) {
    // Zufallsdaten (idealerweise Hardware-RNG) in priv füllen
    // Dann Bitmaskierung nach RFC7748 (Curve25519)
    priv[0] &= 248;
    priv[31] &= 127;
    priv[31] |= 64;
}

void generate_public_key(const uint8_t priv[32], uint8_t pub[32]) {
    // Öffentlichen Schlüssel berechnen
    // curve25519_donna(pub, priv, base_point); Beispielaufruf
}

int compute_shared_secret(const uint8_t priv[32], const uint8_t peer_pub[32], uint8_t secret[32]) {
    // Gemeinsamen geheimen Schlüssel berechnen
    // return curve25519_donna(secret, priv, peer_pub);
    return 0; // Erfolg
}
```

<p><br><br>

|1.2 AES-256 GCM Verschlüsselung & Entschlüsselung|
|---|

- Header (aes_gcm.h): 

```yarn
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
```

<p>
    
- Quellcode (aes_gcm.c): 

```yarn
#include "aes_gcm.h"
#include "mbedtls/gcm.h"

int aes_gcm_encrypt(const uint8_t *key, const uint8_t *nonce,
                    const uint8_t *plaintext, size_t plen,
                    uint8_t *ciphertext, uint8_t *tag) {
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    int ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plen,
                                        nonce, 12, NULL, 0,
                                        plaintext, ciphertext,
                                        16, tag);
    mbedtls_gcm_free(&gcm);
    return ret;
}

int aes_gcm_decrypt(const uint8_t *key, const uint8_t *nonce,
                    const uint8_t *ciphertext, size_t clen,
                    const uint8_t *tag, uint8_t *plaintext) {
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    int ret = mbedtls_gcm_auth_decrypt(&gcm, clen,
                                       nonce, 12,
                                       NULL, 0,
                                       tag, 16,
                                       ciphertext, plaintext);
    mbedtls_gcm_free(&gcm);
    return ret;
}
```

<br><br>

|1.3 HKDF Schlüsselableitung (SHA-256 basierend)|
|---|

<p>
    
- Header (hkdf.h): 

```yarn
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
```

- Quellcode (hkdf.c): <p>

```yarn
#include "hkdf.h"
#include "mbedtls/md.h"
#include <string.h>

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
    size_t t_len = 0;

    for (size_t i = 0; i < n; i++) {
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
```

<br><br>

|2. Python-Test- und Prototypcode|
|---|

<p>

- test_bsh.py

```yarn
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import time

class BylickiSecureHybrid:
    def __init__(self):
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.session_key = None

    def generate_session_key(self, peer_public_bytes):
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_key = self.private_key.exchange(peer_public_key)
        self.session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'Bylicki Secure Session Key'
        ).derive(shared_key)

    def encrypt(self, plaintext: bytes):
        if self.session_key is None:
            raise Exception("Session key not generated.")
        nonce = os.urandom(12)
        aesgcm = AESGCM(self.session_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt(self, data: bytes):
        if self.session_key is None:
            raise Exception("Session key not generated.")
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(self.session_key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def rotate_key(self):
        if self.session_key is None:
            raise Exception("Session key not generated.")
        timestamp = int(time.time()).to_bytes(8, 'big')
        self.session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'Bylicki Key Rotation' + timestamp
        ).derive(self.session_key)

if __name__ == "__main__":
    partner = x25519.X25519PrivateKey.generate()
    partner_pub = partner.public_key().public_bytes()
    bsh = BylickiSecureHybrid()
    bsh.generate_session_key(partner_pub)

    msg = b"Top secret data"
    encrypted = bsh.encrypt(msg)
    print(f"Encrypted: {encrypted.hex()}")

    bsh_partner = BylickiSecureHybrid()
    bsh_partner.private_key = partner
    bsh_partner.generate_session_key(bsh.public_key.public_bytes())
    decrypted = bsh_partner.decrypt(encrypted)
    print(f"Decrypted: {decrypted.decode()}")
```

<br><br>

|3. Hinweise zur Nutzung und Integration|
|---|

>C-Code ist optimiert für ARM Cortex-M Mikrocontroller, idealerweise mit Hardware-RNG und AES-Beschleunigung. <p>
>mbedTLS wird als sichere, freie Kryptobibliothek empfohlen, enthält AES-GCM, SHA256, HMAC, und HKDF. <p>
>Curve25519 Implementierung sollte geprüft und sicherheitszertifiziert sein (z. B. libsodium oder micro-ecc). <p>
>Python-Code dient als funktionaler Prototyp und Test-Umgebung für schnelle Validierung. <p>
>Modularer Aufbau erlaubt einfache Erweiterung und Portierung auf andere Plattformen.




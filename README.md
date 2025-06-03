|Bylicki Secure Hybrid (BSH)|
|---|

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

<br>

|Zusammenfassung|
|---|
>C-Code ist optimiert für Embedded Systeme, nutzt bewährte Libraries (mbedTLS, libsodium empfohlen)
>Python-Code dient als Prototyp und Testumgebung
>Alle Module sind modular gestaltet, um einfache Integration und Erweiterung zu ermöglichen

<br>

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

<br>

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

<br>


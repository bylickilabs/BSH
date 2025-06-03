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

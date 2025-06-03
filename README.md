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


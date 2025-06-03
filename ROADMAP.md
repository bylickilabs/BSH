# Roadmap für Bylicki Secure Hybrid (BSH)

## Q1 2025: Initiales Setup und Grundlegende Implementierungen

### Meilensteine:
- **Initiales Repository und Infrastruktur**
  - Einrichtung des GitHub-Repositories mit grundlegenden Projektdateien (README, LICENSE, etc.).
  - Implementierung der CI/CD Pipeline zur Automatisierung von Builds und Tests.
  - Setup der ersten Version der Dokumentation und API-Referenz.

- **Asymmetrische Schlüsselgenerierung (ECC)**
  - Implementierung der Curve25519 Schlüsselgenerierung.
  - Integration von elliptischen Kurvenoperationen zur sicheren Schlüsselerzeugung.
  - Erstellen von Tests zur Validierung der Schlüsselerzeugung.

---

## Q2 2025: Erweiterung der Funktionen und Sicherstellung der Sicherheit

### Meilensteine:
- **Schlüsselvereinbarung mit ECDH**
  - Integration des Elliptic Curve Diffie-Hellman (ECDH)-Protokolls für den sicheren Schlüsselaustausch.
  - Automatisierung des Austauschs öffentlicher Schlüssel und Berechnung des gemeinsamen geheimen Werts.
  
- **Sitzungsschlüssel-Ableitung und AES-GCM Verschlüsselung**
  - Implementierung des HKDF (Hash-based Key Derivation Function) zur Ableitung des Sitzungsschlüssels.
  - Integration der AES-256 Verschlüsselung im Galois/Counter Mode (GCM) zur Sicherstellung von Vertraulichkeit und Integrität.
  
- **Sicherheitsprüfungen und Penetrationstests**
  - Durchführung von Penetrationstests auf die initiale Implementierung, um Schwachstellen zu identifizieren.
  - Sicherheitspatches und Optimierungen basierend auf den Ergebnissen der Penetrationstests.

---

## Q3 2025: Optimierung, Skalierbarkeit und Plattformunterstützung

### Meilensteine:
- **Schlüsselrotation und Zeitstempel-basierte Erneuerung**
  - Implementierung der Schlüsselrotation mit Zeitstempeln, die eine regelmäßige Erneuerung der Sitzungsschlüssel ermöglicht.
  - Sicherstellung der Kompatibilität der Schlüsselrotation mit bestehenden Kommunikationseinrichtungen.
  
- **Plattformkompatibilität und Support für Embedded-Systeme**
  - Portierung des Systems auf Mikrocontroller-Architekturen wie ARM Cortex-M.
  - Sicherstellung der Kompatibilität auf Embedded-Plattformen und Optimierung für geringe Speicher- und CPU-Ressourcen.

- **Zusätzliche Sicherheitsfeatures**
  - Hinzufügen von Schutzmaßnahmen gegen mögliche Angriffe (z. B. Brute-Force und Replay-Angriffe).
  - Verbesserung des Random Number Generators (RNG) und der Entropiequelle zur Erhöhung der Sicherheit.

---

## Q4 2025: Erweiterte Funktionen und Verfügbarkeit für Entwickler

### Meilensteine:
- **Dokumentation und API-Referenz**
  - Vervollständigung der Projekt- und API-Dokumentation.
  - Bereitstellung von Beispielanwendungen und Codebeispielen zur Unterstützung von Entwicklern.

- **Unterstützung für zusätzliche Plattformen (z. B. RISC-V)**
  - Erweiterung der Plattformunterstützung, z. B. für RISC-V und weitere Embedded-Systeme.
  - Portierung der gesamten Codebasis auf zusätzliche Architekturen und Durchführung von Performance-Tests.

- **Stabilisierung und Release-Kandidaten**
  - Fehlerbehebung und Optimierung basierend auf den Ergebnissen von Tests und Reviews.
  - Erstellung und Veröffentlichung eines stabilen Release-Kandidaten für die erste stabile Version von BSH.
  - Integration in den Mainstream-Marktplatz für Sicherheitsbibliotheken und Anwendungen.

---

## Q1 2026: Langfristige Verbesserungen und Community-Engagement

### Meilensteine:
- **Community-Beiträge und Open-Source-Integration**
  - Förderung von Open-Source-Beiträgen und Community-Engagement.
  - Unterstützung von Entwicklern bei der Erweiterung und Anpassung von BSH für ihre Anwendungsfälle.
  
- **Langfristige Sicherheitsupdates und -patches**
  - Fortlaufende Überwachung auf Sicherheitslücken und zeitnahe Bereitstellung von Patches.
  - Entwicklung einer kontinuierlichen Wartungsstrategie für zukünftige Sicherheitsanforderungen.
  
- **Erweiterung der Funktionen**
  - Einführung zusätzlicher Verschlüsselungsmethoden und -algorithmen.
  - Verbesserung der Benutzererfahrung und Performance basierend auf Benutzerfeedback und Marktanforderungen.

---

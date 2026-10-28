# Hydra Threat Signatures v1

Hydra now has a signed local threat-intelligence engine with four data classes:

- SHA-256 exact matches for known malicious APK/payloads.
- Network domains/IPs/URLs from signed Hydra packs.
- A small Android-safe YARA subset for APK static scanning.
- Cryptographically signed updates using ECDSA P-256 / SHA-256.

## Important source/licensing decision

ThreatFox and URLhaus community APIs require an Auth-Key for bulk exports/API access, and their documentation notes that commercial/for-profit use may require the enhanced abuse.ch commercial API. Hydra therefore does **not** ship a shared API key inside the APK. Instead, an external pack builder can ingest exports obtained under the applicable terms and produce a Hydra-signed pack. This also lets the Android app verify one trusted envelope rather than trusting arbitrary third-party downloads.

The public YARA ecosystem is heterogeneous. YARA-Rules is GPL-2.0-only, while YARA Forge aggregates many repositories with different licenses. Hydra's bundled seed rules are original Hydra rules. Third-party rules may only be added to a distributed pack after their individual license/attribution requirements are checked.

## Update flow

`source export -> Hydra pack builder -> signed envelope -> physical HTTPS -> signature verification -> structural validation -> post-install re-verification -> active pack`

The Android side never contains the private signing key.

## Current limitation

FIX99 infrastructure includes the updater and pack builder, but a public production feed URL has intentionally not been hardcoded because no Hydra-owned feed endpoint has been established yet. The feed URL can be configured in the app preferences/programmatically later, without changing the signature engine.


## Hardening notes

- The bundled seed pack is non-expiring so a device without a configured remote feed never silently loses its baseline signatures.
- Remote packs may expire; expired packs are never activated.
- A signed pack older than the currently active pack is rejected.
- The updater avoids Hydra's VPN network when a physical network is available, preventing self-blocking of the threat feed.

- Public-key SHA-256 fingerprint (DER/SPKI): `765eaae840dafcd3e8adb3b5f8f16d4d0478a0e73736a895c980b5406afc65b8`
- The APK never contains the private signing key.
- The production remote feed remains intentionally unconfigured until a Hydra-owned HTTPS endpoint is established.

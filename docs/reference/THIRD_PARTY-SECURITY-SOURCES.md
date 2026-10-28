# Hydra third-party security sources

Hydra uses third-party security feeds with explicit separation between generic ad/tracker blocklists and threat intelligence.

## Active default domain sources

- Steven Black hosts — adware + malware. Project/source: https://github.com/StevenBlack/hosts
- HaGeZi Multi PRO mini — advertising, tracking and privacy domains. Project/source: https://github.com/hagezi/dns-blocklists
- 1Hosts Lite — general-purpose ads/trackers/malware domain blocking, chosen for a smaller footprint. Project/source: https://github.com/badmojr/1Hosts
- HaGeZi Threat Intelligence mini — threat-focused domains. Project/source: https://github.com/hagezi/dns-blocklists

The Threat Intelligence source is now also persisted into Hydra's dedicated live threat-intel domain store so a confirmed match is distinguished from a normal advertising/tracking block.

## Optional / operator-fed sources

- OISD Big is retained as an optional source but is not enabled by default on older devices.
- ThreatFox and URLhaus can be used by a controlled pack builder/operator. Their current community APIs require an Auth-Key for automated access; API keys must never be embedded in the Hydra APK. See their current API documentation before using or redistributing data.

## Signed threat pack

Hydra's signed threat-pack format supports SHA-256 hashes, domains, IPs, URLs and YARA-Lite rules. Packs are verified with ECDSA P-256 before activation. A third-party feed should be converted to a Hydra-signed pack by a trusted build/feed service rather than trusted directly by the mobile application.
## Real Android malware dataset used by the build-time AI trainer

- MH-100K Android Malware Dataset — 101,975 Android applications with static features and malware/benign labels derived from VirusTotal metadata; licensed CC BY 4.0. Hydra does not bundle the dataset in the APK. The `train_hydra_apk_ai_mh100k.py` tool consumes a local copy and exports a compact model for embedding. Source: https://huggingface.co/datasets/hendriow/mh100k

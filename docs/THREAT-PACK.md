# Signed threat pack

The app can receive IPs, domains and YARA‑Lite rules from a **signed pack** (ECDSA P‑256 / SHA‑256).
It is installed only if the signature verifies with the public key compiled into the app; a tampered
pack is discarded.

## Default state
- The pack bundled in the app (`assets/hydra_threat_pack_v1.json`) contains **YARA‑Lite rules only** and is signed with the project's original key — the same public key that is in `app/build.gradle.kts` and in `ThreatSignatureVerifier.DEFAULT_PUBLIC_KEY_B64`. Both must match; `ThreatKeyConsistencyTest` checks it.
- A blank `HYDRA_THREAT_PUBLIC_KEY` is treated as unset (the default key is used).
- **The default build already has a feed URL:** `https://raw.githubusercontent.com/hydraroot/Hydra_Firewall/threat-pack/hydra_threat_pack.json`. The app checks for a new pack about **once every 24 hours** (inexact alarm, scheduled when the VPN service starts and after boot), or on demand with *Update now* in Security Center. Override it at build time with `HYDRA_THREAT_FEED_URL`.
- The feed must use `https://`, downloads are capped at 20 MB and go over the physical network.
- **A build with nothing configured** uses the default key, and the bundled pack verifies against it, so the YARA‑Lite feed starts with content. This is what a normal public build does.
- **Warning if you set `HYDRA_THREAT_PUBLIC_KEY` to your own key** (see below): the app stops accepting the default key, so the bundled pack in `assets/` is rejected until you re-sign it with your private key by running `tools/rebuild_bundled_pack.sh`. If you set `HYDRA_THREAT_PUBLIC_KEY` in GitHub (Settings → Variables) for the CI workflow but do not re-sign the bundled pack in the repo, the public build made by that Action will have an empty/rejected bundled feed.

## Verify a pack
`pip install cryptography`, then `python tools/verify_threat_pack.py <file or URL>` (uses the key in `app/build.gradle.kts`; `--key` for another one). It prints `FIRMA VALIDA` when the signature is valid.

## Run it with your own key (recommended for forks)
1. `tools/generate_signing_key.sh` → creates `secrets/hydra_threat_signing_key.pem` (private — back it up, never commit it) and the public key in Base64.
2. In `local.properties` set `HYDRA_THREAT_PUBLIC_KEY=<public>` and `HYDRA_THREAT_FEED_URL=<your feed URL>`.
3. `tools/rebuild_bundled_pack.sh` → re-signs the bundled pack with your key (otherwise the app would reject the original and start with no signatures).
4. In GitHub add the secret `HYDRA_THREAT_SIGNING_KEY` (the PEM contents) and, optionally, `ABUSECH_AUTH_KEY` (free at https://auth.abuse.ch/). `.github/workflows/threat-pack.yml` generates and publishes the pack daily to the `threat-pack` branch.
5. Build the app (`./build.sh`).

If you have the project's original private key you can skip 1–2 and use it in 3.

## Feeds supported by `tools/build_hydra_threat_pack.py`
| Feed | Key | What it provides |
|---|---|---|
| Feodo Tracker (`--feodo`) | no | Botnet C2 IPs |
| URLhaus (`--urlhaus-api`) | optional | Hosts that distribute malware (host only: literal IP → IP, domain → domain) |
| ThreatFox (`--threatfox-api`) | yes (`ABUSECH_AUTH_KEY`) | IOCs from the last few days |
| Manual exports (`--threatfox-export`, `--urlhaus-export`, `--feodo-file`, `--urlhaus-text-file`) | — | for offline use |

> The abuse.ch endpoints are written according to their public documentation but **were not tested live**; each feed fails in isolation (a warning in the log) and `--min-indicators` prevents publishing an empty pack if all of them fail.

## False-positive protections
Threat matches block traffic, so the generator:
- excludes domains of widely used legitimate services (GitHub, Google, Cloudflare, Discord, Telegram, etc.) even if a feed lists them;
- discards private, local or reserved IPs;
- limits the size (150,000 domains / 60,000 IPs), prioritizing the highest-confidence entries;
- uses expiry (14 days in the workflow): an expired pack is ignored and the app falls back to the bundled one.

The safe list is bounded and **not exhaustive**: review `SAFE_DOMAIN_SUFFIXES` for your use.

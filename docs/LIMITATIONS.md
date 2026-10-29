# Scope and limits (read before relying on it)

**Hydra is a per-app firewall with DNS/SNI filtering. It is not an antivirus.**

## What it does well
- Decide which apps reach the internet, and over which network (Wi‑Fi or mobile data).
- Block ads, trackers and known-malicious domains/IPs that use the system DNS, SNI, or IPs in the threat pack.
- Warn about new apps and show where each app connects.

## What it does NOT guarantee
- **Malware detection.** The APK scanner is static and heuristic. The MH‑100K model is a secondary signal that warns and never blocks (in its own report, at threshold 0.5, precision is ~64 % and 5.6 % of legitimate apps are false positives). "AI Lite" was trained on synthetic data and is not evidence of real detection.
- **Encrypted traffic.** It does not decrypt HTTPS: it blocks by domain name (SNI) or IP. Apps with their own DoH/ECH or direct IPs can bypass domain filtering. QUIC/HTTP3 is covered only indirectly.
- **Apps in Essential / No firewall mode** are outside the VPN filtering to the extent they are configured that way.
- **"Block all" is not a full kill switch.** It only blocks traffic that enters the tunnel: Hydra itself and excluded / "No firewall" apps stay outside. For a hard cutoff use Android's Always-on VPN + "Block connections without VPN".
- **Another VPN.** Android allows one active VPN at a time.
- **Malware with system/root privileges** can ignore the VPN.

## Performance and compatibility
- TCP/UDP forwarding runs in user space: more battery use and some extra latency compared with a native firewall.
- Nominal limit of 768 simultaneous sessions (TCP 128+128, UDP 256+256). IPv6 does not have full parity (ESP and unsupported headers are rejected). The TCP packet queue is bounded; under sustained overload packets are dropped and TCP retransmits.
- Android 7–9 identify the app that owns each connection by reading `/proc/net`; it can fail transiently (the connection is then dropped, "fail closed").
- If the owning app of a connection cannot be identified, the connection is dropped: Hydra does not infer identity from the destination IP.
- IPv6 link-local and multicast are intentionally not routed through Hydra; NAT64 prefixes are.
- New apps start blocked: at first you will see apps without internet until you approve them.

## Privacy
- No telemetry. Hydra's own connections are: blocklists (GitHub/OISD, only when you ask), encrypted DNS, and the signed threat feed (about daily).
- Sensitive permissions: `QUERY_ALL_PACKAGES` (app names/icons) and `PACKAGE_USAGE_STATS` (local statistics). `allowBackup=false`.

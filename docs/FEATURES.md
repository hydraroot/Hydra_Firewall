# Features — everything Hydra does

This guide explains each feature of Hydra Firewall: what it does, how to use it, and what it
cannot do. For a short overview see the [README](../README.md); for the internals see
[HOW-IT-WORKS.md](HOW-IT-WORKS.md).

**Contents**
1. [Rules: who may connect](#1-rules-who-may-connect)
2. [First-connection prompt](#2-first-connection-prompt)
3. [Quarantine and trusted apps](#3-quarantine-and-trusted-apps)
4. [Network filtering](#4-network-filtering)
5. [Threat intelligence](#5-threat-intelligence)
6. [Security Engine](#6-security-engine)
7. [Visibility: history, analyzer, statistics](#7-visibility-history-analyzer-statistics)
8. [Configuration, profiles and backup](#8-configuration-profiles-and-backup)
9. [Protecting Hydra itself](#9-protecting-hydra-itself)
10. [Reliability](#10-reliability)
11. [Tabs and modes](#11-tabs-and-modes)

---

## 1. Rules: who may connect

Every app can have its **own decision for Wi‑Fi and for mobile data**. The decision for an app is
one of these *modes*:

| Mode | What it means |
|---|---|
| **Allow** | The app goes through Hydra with the normal protections (domain blocklist, secure DNS, SNI/QUIC/JA3 filtering, threat protection). Wi‑Fi and mobile switches decide where it may connect. |
| **Block** | No network access for the app. |
| **Permissive** | The app stays inside Hydra, but compatibility layers are relaxed (optional domain and QUIC filtering) for apps that break under filtering. Strong threat/IP protection stays on. Wi‑Fi/mobile switches still apply, and Permissive does **not** exempt the app from *Block all*. |
| **Permissive‑compat** | A temporary **diagnostic** variant of Permissive: the normal ad/tracker blocklist and QUIC domain filter are bypassed to find out whether filtering is what breaks an app. |
| **Personalized** | You choose which protections apply to that app only: ad/tracker blocklist, secure DNS, HTTPS SNI filter, QUIC protection, TLS fingerprint protection, known-threat protection, block local network. Wi‑Fi/mobile stay separate switches. |
| **No firewall** | The app is **excluded from the VPN** and uses Android's normal network. Hydra does not filter or see its traffic, and the Wi‑Fi/mobile switches do not apply. Meant for banking or special apps that refuse to work through a filtered network. |
| **System essential** | Some system components are allowed automatically so the phone keeps working. Threat/IP rules and global lockdown still apply. |

When you allow an app that has no rule yet, **both Wi‑Fi and mobile start ON**; turn off the one you
do not want.

### Global policy
- **Blacklist mode** (default): traffic is allowed unless a rule blocks it.
- **Whitelist mode**: stricter — only apps with explicit permission are allowed; new apps are blocked.
- **Default Wi‑Fi / default mobile**: the decision applied to apps without an explicit rule. If *Ask on first connection* is on, the prompt appears before this default is used.
- **Allow unknown UID**: what to do when Hydra cannot identify the owning app (off by default → blocked).
- **Allow local network**: access to private and link-local IPv4 ranges.
- **Roaming and screen-off rules**, and **schedules** that change an app's access by time of day.

### Block all
An emergency switch that blocks **everything that goes through Hydra's tunnel**, with no per-app rules.
Exceptions: Hydra itself and apps set to *No firewall* (compatibility mode) are outside the tunnel and
are **not** blocked. It is not a full kill switch — for a hard cutoff use Android's *Always-on VPN* plus
*Block connections without VPN*.

## 2. First-connection prompt

When an app with no rule connects for the first time, Hydra shows a prompt (and a notification if the
app is in the background) with these choices:

- **Allow** — keep the app inside Hydra with normal protection. Time-limited choices (10 minutes, 1 hour) and *always* are available.
- **Permissive** — allow with relaxed compatibility layers.
- **No firewall** — let the app use the normal network outside Hydra.
- **Block** — deny the app.
- **Personalized** — pick protections for this app only, then apply.
- **Details** — explains *why the app is connecting*: the resolved domain, matches in the blocklists or threat pack, what the port means, where the app was installed from and how old it is, and how often it retried.

Wi‑Fi and mobile start ON when you allow. Turn the prompt off with *Ask on first connection* in Settings
(new apps then follow the global default).

## 3. Quarantine and trusted apps

- **New-app quarantine** (optional, off by default; *Security → Quarantine*). When enabled, newly installed apps are held in a network quarantine until you review them. It is a network control only — Hydra never silently uninstalls or modifies an APK, and apps that already exist are not retroactively quarantined.
- **Trusted apps** (optional, off by default). Apps from trusted sources can be allowed automatically; with it off, every new app asks.
- **System-app safety labels.** Before you block a system app, Hydra labels it **high risk** (known critical components such as the system UI, settings, telephony, Google Play services), **caution** (providers, connectivity components) or **undetermined**. Hydra never claims a package is safe to block just because it is a system app. See [`reference/SYSTEM_APP_SAFETY.md`](reference/SYSTEM_APP_SAFETY.md) (Spanish).

## 4. Network filtering

### Domain blocklist (ads, trackers, malware)
A list of about 18,000 domains is **bundled in the APK** and active from the first run (license-compatible
sources only — see [THIRD_PARTY_NOTICES](../THIRD_PARTY_NOTICES.md)). Blocked DNS lookups are answered
with `0.0.0.0`, so the app simply fails to resolve the name. Optional live lists can be downloaded **when
you ask**: HaGeZi (including the *Threat Intelligence* list), 1Hosts, StevenBlack and OISD. Custom
domain rules are supported.

> The row **"Threat intelligence (0 domains)"** in Security Center counts the dedicated malware list
> (HaGeZi Threat Intelligence mini). It stays at 0 until you run an update with that source enabled — that
> is expected on a fresh install.

### Secure DNS
Hydra can intercept IPv4 DNS (UDP/53) and forward it over encrypted **DNS‑over‑TLS** (default) with
**DNS‑over‑HTTPS** as a fallback, using Cloudflare, Google or Quad9. This protects the DNS transport.
An app that uses DoH *inside its own HTTPS connection* hides the queried name from Hydra.

### HTTPS filtering by server name (SNI)
Hydra reads the TLS ClientHello to learn the server name and applies domain rules to it. Nothing is
decrypted.

### TLS fingerprints (JA3 / JA3N / HYDRA-lite)
Optionally, Hydra computes a fingerprint of the TLS client and checks it against a known-bad list. It
can reveal a client stack even when the domain changes or is behind a CDN. A match is an *indicator*:
legitimate apps that use the same library or WebView can share a fingerprint.

### QUIC / HTTP3
QUIC cannot be read like TLS-over-TCP, so Hydra works on a best-effort basis by correlating the traffic
with the DNS answer the same app resolved earlier. QUIC protection can be switched per app.

### IP blocking and port rules (Advanced mode)
- **IP blocking** stops traffic to specific destinations.
- **Advanced rules** control TCP/UDP by protocol and port. Rules you created stay active even when the tab is hidden.
- A **rule-conflict analyzer** reports rules that contradict or duplicate each other.

### IPv6, local network and special cases
- **Block IPv6** drops all IPv6 immediately and apps fall back to IPv4, where every filter applies.
- Otherwise Hydra routes IPv6 global and ULA traffic (and NAT64 `64:ff9b::/96`) through the firewall. IPv6 link-local and multicast are intentionally left to Android for local discovery.
- **Block local network** (per app or globally) denies connections to private addresses.
- **ICMP/ICMPv6** echo is answered locally by Hydra; IPv6 fragments are reassembled.

## 5. Threat intelligence

Hydra can load a **signed threat pack** with malicious IPs, domains and **YARA‑Lite** rules. Sources
include abuse.ch (Feodo Tracker, URLhaus, ThreatFox).

- **Verified before use.** The pack is accepted only if its ECDSA P‑256 / SHA‑256 signature matches the public key compiled into the app.
- **Updated automatically** about once a day, or on demand with *Update now*. Downloads use the physical network, require HTTPS and are capped at 20 MB.
- **Fails safe.** An expired or invalid pack is ignored and the pack bundled in the APK is used.
- **Built to avoid false positives.** The generator excludes widely used legitimate services, drops private/reserved IPs and caps the size.
- **Status screen** in Security Center shows age, indicator counts and source.

Details, keys and how to run your own feed: [THREAT-PACK.md](THREAT-PACK.md).

## 6. Security Engine

The Security Engine adds *evidence for investigation* on top of the firewall. It does **not** replace
network policy and is **not** a malware detector.

### APK scanner
Analyzes an APK file or an installed app: SHA‑256, package/version, signing-certificate fingerprints,
requested permissions, number of activities/services/receivers/providers, exported components,
Accessibility services, Device Admin receivers, overlay and package-install capability, debuggable status,
native `.so` libraries and DEX files, plus YARA‑Lite rules. Everything is analyzed **locally**; no APK is
uploaded.

### APP RISK
Combines indicators into a **0–100 score** with levels SAFE, LOW, MEDIUM, HIGH and CRITICAL.
High-impact combinations (for example Accessibility plus overlay or package-install capability) weigh
more. It is a signal, not a verdict — legitimate apps can have all of these.

### Behavior engine
Correlates metadata Hydra already collects — connections, destinations, DNS activity, DNS blocks, unusual
ports, known-bad TLS fingerprints — into a per-app behavior score. It does not inspect encrypted payloads
and does not change firewall decisions by itself. *Local behavior learning* builds a per-app traffic
baseline on the phone (it needs **traffic recording enabled in the Analyzer tab**, which is off by default).

### On-device models
- A compact model trained from the **MH‑100K** Android malware dataset (CC BY 4.0).
- A lightweight "AI Lite" heuristic model trained on synthetic data.

Both are **secondary signals that warn and never block by themselves**. In the MH‑100K report, at threshold
0.5, precision is about 64 % and 5.6 % of legitimate apps are false positives.

### Security events and status
Important findings (APK scans, security indicators) are recorded as events. *Security status*
summarizes quarantine, TLS fingerprinting, service state, update/Doze monitoring, unexpected stops and
rule conflicts.

## 7. Visibility: history, analyzer, statistics

- **Connections**: history of app, destination, protocol, port, decision and time — to understand what an app contacts and why a connection was allowed or blocked.
- **Analyzer** (Advanced): live traffic by app, DNS, blocked connections and destinations. *Learning analysis* only builds suggestions and never changes decisions.
- **Statistics**: traffic totals over time, with allowed and blocked traffic counted separately.
- **Usage insights**: per-app ranking for the session, today and the last 7 days, with flags such as "uploads more than it downloads". Stored only on the phone.
- **Self-test** and **live test** (Advanced): synthetic checks of the VPN service, ICMP responder, DNS block response, `/proc/net` UID parsing, log file and real DNS/TCP through the tunnel.
- **Diagnostic log** you can read through ADB.

## 8. Configuration, profiles and backup

- **Profiles** (Advanced) save and reuse groups of firewall settings (for example "normal", "strict", "temporary").
- **Export / import** the whole configuration (rules, schedules, advanced rules, IP exceptions, permissive apps) as a file. Rules are matched **by app name**, so the file is portable; apps not installed are skipped and reported. The PIN, fingerprint, history and statistics are deliberately not exported. A copy is saved automatically before an import, with an **Undo** button.
- Only import files you created yourself: a foreign file could allow apps you currently block.
- **Language** (System / Spanish / English), **theme** (system / light / dark), **low-power mode**, UI refresh rate, history size and screen-off options.

## 9. Protecting Hydra itself

- **PIN** of 5 to 8 digits (stored with PBKDF2; attempt limiting with delays up to 5 minutes that a clock change cannot shorten) and **fingerprint** unlock. Older 4-digit PINs keep working until changed. The PIN protects Hydra's screen, not the phone: root/ADB/Settings access can still stop the VPN.
- `allowBackup=false`: Android does not back up Hydra's data.
- **Tamper monitoring**: detects the service being stopped without a recorded request.
- Signed threat packs and a signed release process (see [BUILD.md](BUILD.md)).

## 10. Reliability

- **Restart after boot** and **recovery scheduler** for the VPN service.
- **Always-on VPN** guidance: Android can keep Hydra as an Always-on VPN, and *Lockdown* blocks apps from bypassing it. Lockdown is stronger but can leave apps without network if the VPN is down, so use it intentionally. Hydra will not claim a system kill switch that Android does not provide.
- **Doze / update monitoring** to explain stops caused by the system.
- **Fail closed**: if Hydra cannot identify the app that owns a connection, the connection is dropped.

## 11. Tabs and modes

| Mode | Tabs |
|---|---|
| **Normal** (default) | Protection · Rules · Connections · Statistics · Security · Settings · Help · About |
| **Advanced** | Adds IP/Ports · Analyzer · Profiles · Test |

Switching modes never deletes rules.

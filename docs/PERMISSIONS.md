# Permissions: what each one is for

Review of every permission in `AndroidManifest.xml` (version 2.3.0). Nothing is requested "just in case".

| Permission | Needed for | Sensitive for Google Play? | Notes |
|---|---|---|---|
| `INTERNET`, `ACCESS_NETWORK_STATE` | Forwarding allowed traffic; threat-pack, blocklist and update checks; Wi‑Fi vs mobile | No | |
| `BIND_VPN_SERVICE` (service) | The firewall itself (local VPN, no remote server) | Yes: VPN apps must complete the VpnService declaration | The VPN is local only; traffic is never sent to a Hydra server |
| `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SYSTEM_EXEMPTED` | Keep the VPN service alive | Declaration of the foreground-service type | `systemExempted` applies to VPN apps |
| `POST_NOTIFICATIONS` | First-connection prompts, antivirus and update alerts | No | |
| `RECEIVE_BOOT_COMPLETED` | Restore the firewall after reboot | No | |
| `USE_BIOMETRIC` | Fingerprint unlock of the app | No | `USE_FINGERPRINT` is limited to Android 9 and below (`maxSdkVersion=28`) |
| `QUERY_ALL_PACKAGES` | Per-app rules need the full list of installed apps (name, icon, UID); the antivirus checks all apps | **Yes**: requires a declaration | Core purpose of a firewall/antivirus. Suggested declaration: "Hydra Firewall applies network rules per installed app and scans installed apps against a malware signature pack; it cannot work without seeing all installed apps." |
| `PACKAGE_USAGE_STATS` | Local usage statistics (optional, user grants it in system settings) | Special access | Optional; the app works without it |
| `REQUEST_INSTALL_PACKAGES` | Installing a Hydra update downloaded by the in-app updater (GitHub APK only) | **Yes**: Play restricts it, and self-updating outside Play violates Play policy | **Do not ship this permission or the updater in the Google Play build.** Keep them only in the GitHub APK |

## Recommendation for a Google Play build

1. Build the Play bundle without `REQUEST_INSTALL_PACKAGES` and with the in-app updater disabled (Play updates the app itself).
2. Complete the VpnService, foreground-service and `QUERY_ALL_PACKAGES` declarations with the texts above.
3. Keep the GitHub APK (updater included) as the direct-download channel.

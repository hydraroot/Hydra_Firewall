# Build and install

## Requirements
- JDK 17
- Android SDK with platform 35 (Android Studio installs it)
- A phone with Android 7.0+ and USB debugging (to install with `adb`), or transfer the APK by hand

## 1. Quick test (debug APK)
```bash
./build.sh              # tests + app/build/outputs/apk/debug/app-debug.apk
./build.sh install      # also installs via adb
```
Windows: `./BUILD-AND-INSTALL.ps1` (uses `ANDROID_HOME` / `%LOCALAPPDATA%\Android\Sdk`; does not overwrite your `local.properties`).

The debug APK installs directly (enable "install unknown apps" if you transfer it by hand).

> **Updating a debug build:** debug APKs are signed with a debug key. APKs built on different machines — including each GitHub Actions run — have different keys, and Android refuses to update an app signed with another key. Export your configuration, uninstall, then install the new APK. A release keystore (below) avoids this.

## 2. Signed release APK
1. Create the keystore **once** and back it up (without it you cannot update the installed app):
   ```bash
   keytool -genkeypair -v -keystore hydra-release.jks -alias hydra -keyalg RSA -keysize 4096 -validity 10000
   ```
2. Copy `local.properties.example` to `local.properties` and fill in `HYDRA_KEYSTORE_FILE`, `HYDRA_KEYSTORE_PASSWORD`, `HYDRA_KEY_ALIAS`, `HYDRA_KEY_PASSWORD`.
3. `./build.sh release` → `app/build/outputs/apk/release/app-release.apk`.

Without a keystore the release stays `unsigned` and Android will not install it.
The variables can also come from the environment (useful in CI). Never commit `local.properties` or `.jks` files.

### Key backups (do this before publishing)

There are **two** different private keys in this project, and losing either has consequences that cannot be undone:

| Key | File | If you lose it |
|---|---|---|
| App signing keystore | `hydra-release.jks` (the one created above) | You cannot publish an update that Android accepts as "the same app" over existing installs. You would have to ship with a different `applicationId` and everyone would reinstall from scratch, losing their configuration. |
| Threat-pack signing private key | `secrets/hydra_threat_signing_key.pem` (created by `tools/generate_signing_key.sh`) | You cannot publish threat-pack updates the app will accept (`ThreatSignatureVerifier` rejects them without the right signature). You must generate a new key and publish it as `HYDRA_THREAT_PUBLIC_KEY` in all future builds — people who already installed the old app keep the old key until they update. |

Neither should live only on the machine where you build:

1. **Never commit them** (`.gitignore` already excludes `*.jks` and `secrets/`, but double-check before the first public push).
2. Keep a copy of each in **at least two places** outside that machine — for example a password manager with attachments (Bitwarden, 1Password) and a USB drive or external disk stored separately. A single cloud backup is not enough if that account is compromised or lost.
3. Store each key's passwords/alias with it (`HYDRA_KEYSTORE_PASSWORD`, `HYDRA_KEY_ALIAS`, `HYDRA_KEY_PASSWORD`) — a keystore without its password is as useless as not having it.
4. GitHub Actions secrets (`HYDRA_KEYSTORE_BASE64`, `HYDRA_THREAT_SIGNING_KEY`, etc.) are needed for CI but **do not replace** the backup: if the repository is deleted or you lose access to the GitHub organization, those secrets are lost with it.

## 3. Build on GitHub (no Android Studio)
Push the project to a repository. `.github/workflows/android.yml` runs the tests and publishes the debug APK as an artifact (*Actions* tab).
For a signed release when you create a `vX.Y.Z` tag, add these *secrets*: `HYDRA_KEYSTORE_BASE64` (`base64 -w0 hydra-release.jks`), `HYDRA_KEYSTORE_PASSWORD`, `HYDRA_KEY_ALIAS`, `HYDRA_KEY_PASSWORD`.

## Migrating from the `com.example.firewall` ID
The installable ID changed to `com.hydraroot.firewall` (override with `HYDRA_APPLICATION_ID`). The code used to live in the `com.example.firewall` package; the namespace is now `com.hydra.firewall`. Android treats the old and new IDs as different apps, so it **does not update** the old one:
1. In the **old** version: *Profiles* tab → **Export** (saves a `.json`; it does not include the PIN, history or statistics).
2. Install the new version (the two can coexist for a while, but **do not enable both VPNs at once**).
3. In the new one: install/open your apps, *Profiles* → **Import**. Rules are applied by app name; apps not installed are skipped and reported. An automatic copy is saved and there is an **Undo** button.
4. Uninstall the old version. Set the PIN and fingerprint again (they are deliberately not exported).

> Import only your own files: a file from someone else could allow apps you currently block.

## First use on the phone
1. Open the app and accept the VPN dialog and the notification permission.
2. Exclude Hydra from battery optimization (otherwise Android may kill the service).
3. With "Trusted apps" off, new apps ask for confirmation on their first connection.
4. Try it first with non-critical apps and use **Self-test** to validate DNS/SNI/TCP.
5. You cannot use another VPN at the same time.

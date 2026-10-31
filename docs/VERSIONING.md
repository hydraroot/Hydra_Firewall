# Versioning and updates

The version lives in one file: [`version.properties`](../version.properties) (`VERSION_NAME=MAJOR.MINOR.PATCH`).

| Change | Example | Command |
|---|---|---|
| Small (fixes, texts) | 1.1.0 → 1.1.**1** | `python tools/bump_version.py patch` |
| Medium (new features) | 1.1.3 → 1.**2**.0 | `python tools/bump_version.py minor` |
| Large (major changes) | 1.4.2 → **2**.0.0 | `python tools/bump_version.py major` |

`versionCode = major × 10000 + minor × 100 + patch` (minor and patch ≤ 99), so it always grows with the version.

Android only updates an app when the APK is signed with the **same key** and the `versionCode` is **not lower**.
Debug APKs built by GitHub Actions use a different temporary key every run, so they force an uninstall. Configure the
four signing secrets (`HYDRA_KEYSTORE_BASE64`, `HYDRA_KEYSTORE_PASSWORD`, `HYDRA_KEY_ALIAS`, `HYDRA_KEY_PASSWORD`) and the
CI publishes a signed `hydra-release-apk` artifact on every push that installs as an update. Full guide (Spanish):
[`es/VERSIONING.md`](es/VERSIONING.md). Keep an offline backup of the keystore: without it you cannot update the installed app.

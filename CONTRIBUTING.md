# Contributing to Hydra Firewall

Thanks for your interest. This guide is short on purpose; the project is small and most contributions
are welcome without much ceremony.

## Before writing code

- For small changes (typos, docs, targeted fixes): just open a Pull Request.
- For big changes (a new feature, a refactor, a change in network/firewall behavior): open an issue first describing what and why, so you do not work on something that ends up rejected for design reasons.
- For security vulnerabilities: **do not** use a public issue — follow [`SECURITY.md`](SECURITY.md).

## Development environment

See [`docs/BUILD.md`](docs/BUILD.md) to build and install. In short:

```bash
./build.sh install      # tests + debug APK + install via adb
```

Requires JDK 17 and the Android SDK (Android Studio includes them).

## Before opening the PR

- `./gradlew testDebugUnitTest` must pass.
- If you touched `tools/build_hydra_threat_pack.py` or `tools/rebuild_bundled_blocklist.py`, also run `python3 -m unittest discover -s tools -v`.
- If you add a third-party data source (blocklist, threat feed, library), confirm its license is compatible with GPL‑3.0 and add it to `THIRD_PARTY_NOTICES.md` or `third_party/licenses/` as appropriate — see there which licenses were already evaluated and why some were left out.
- If you change something visible to the user (rules, UI, permissions, what is blocked by default), add a line to `CHANGELOG.md`.

## Style

- Kotlin + Jetpack Compose in `app/`, following the style already present in the file you are touching rather than an external guide.
- Python in `tools/` loosely follows `black`/PEP 8; prefer readable and testable over following a rule to the letter.
- Commits and PRs may be in Spanish or English; the repo already mixes both.

## What to expect from review

This is a project with a part-time maintainer, so review can take a while. A small PR focused on one
thing is reviewed faster than a large one that mixes several changes.

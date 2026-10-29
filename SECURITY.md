# Security policy

Hydra Firewall intercepts all of a phone's network traffic (local VPN, no root) and makes blocking
decisions. We take seriously any flaw that could:

- let through traffic that should be blocked (leak outside the VPN, rule bypass, unfiltered DNS/SNI/QUIC when it should be filtered);
- expose user data (rules, history, statistics, PIN) to another app or to a process without permissions;
- allow an unsigned or tampered threat pack or list update to be accepted by `ThreatSignatureVerifier`;
- compromise the app's signature or the release keystore.

## How to report a vulnerability

**Do not open a public issue for vulnerabilities.** A public issue is visible to everyone before a
fix exists, including people who intend to exploit it.

Options, preferred first:

1. **GitHub Security Advisories** (preferred): from the repository's *Security* tab → *Report a vulnerability*. This opens a private report visible only to the maintainers, with its own discussion thread.
2. If you cannot use Security Advisories, open an empty issue asking for a private contact channel, without describing the problem, and we will continue there.

Include, if you have it:

- App version (tag or commit) and the Android version where you tested.
- Steps to reproduce, or a minimal PoC.
- What you expected to happen and what actually happened.
- Estimated impact (traffic leak, rule bypass, data leak, etc.).

## What to expect

- Acknowledgement of receipt within a reasonable time.
- Once the flaw is confirmed, we work on a fix before any public mention (coordinated disclosure). If you wish, we credit you in the `CHANGELOG` when the fix is published.
- For low-impact flaws or ones that are already public knowledge, a normal issue is fine.

## Scope

In scope: the app code (`app/`), the pack signing and generation scripts (`tools/`), and the CI workflows (`.github/workflows/`).

Out of scope: vulnerabilities in third-party dependencies that are already known and have no upstream fix (report them to the corresponding project), and social engineering against individual users.

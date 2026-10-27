# Security policy

Nullveil handles sensitive things (your network lookups, which apps you use, the microphone), so we take
reports seriously.

## Reporting a vulnerability

Please report privately through **GitHub Security Advisories**: Security tab -> "Report a vulnerability".
Do not open a public issue for security problems.

Include: what you found, how to reproduce it, the Android version and phone, and the impact you think it has.
This is a volunteer project, so there is no response-time guarantee, but we will acknowledge and fix real issues
as fast as we can and credit you if you want.

## What we especially care about

- Anything that lets an app, another user or a network attacker bypass the shield or read Nullveil's data.
- Any path where **audio** (Mic Guard) or **lookups / app lists** are stored, logged or sent anywhere.
- Weaknesses in encrypted storage (`SecureStore`) or encrypted DNS (`DotClient`).
- Unexpected exported components or permissions.

## Supported versions

Only the latest release is supported while the project is in alpha.

## Verifying releases

Release APKs are signed with one key. The fingerprint is in the README; check it before installing.

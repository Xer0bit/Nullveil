# Contributing to Nullveil

Thank you. Nullveil exists so people can stay free with their own choices; contributions of every kind help
(code, device test reports, translations, docs, ideas).

## Ground rules (the privacy rules are not negotiable)

- **No tracking, ever**: no analytics, ads, crash reporters, accounts or third-party SDKs.
- **No new network use** without a discussion first. Today the only network use is forwarding allowed DNS lookups.
- **No new dependencies** without a discussion first. They must be FOSS and GPL-3.0-compatible.
- **Never log or store user data** (domains, app lists, audio, locations). Logs stay in memory.
- **Mic Guard must never store or send audio.** Any change near `MicGuardService` gets extra review.
- Don't promise what Android doesn't allow without root (white noise, fake camera, per-app permission revoking).

## Build and test

See the [README](README.md#build-from-source). Before opening a pull request:

```sh
(cd rust && cargo test)
./gradlew assembleDebug lint testDebugUnitTest
```

Engine logic lives in `rust/src/lib.rs`. Change it with a test (the existing tests show the style).

## Pull requests

1. Open an issue first for anything bigger than a small fix, so we can agree on the approach.
2. Keep the change small and focused; match the surrounding code style.
3. Describe what you tested and on which phone / Android version.
4. By contributing you agree your work is licensed under **GPL-3.0-or-later**, the project license.

## Reporting problems

- Bugs and ideas: open an issue (templates provided). **Do not paste your own domains or installed-app lists**
  unless you are comfortable with them being public.
- Security problems: see [SECURITY.md](SECURITY.md). Please do not open a public issue.

## Releases

Release APKs are signed with a key kept outside this repository. Maintainers build with
`./gradlew assembleRelease` after pointing `NULLVEIL_KEYSTORE_PROPERTIES` (or `~/.nullveil/keystore.properties`) at a
properties file with `storeFile`, `storePassword`, `keyAlias`, `keyPassword`. Never commit a keystore or its passwords.

# Privacy Android App (Java)

Privacy-first Android app, written in **Java** (not Kotlin). Project is new; no code yet.

## Product goal
Give the user control over what other apps can get from their hardware, instead of just blocking: ad/tracker traffic gets fake or empty data, location can be faked, mic/camera can be turned off per app. Reference design: DuckDuckGo App Tracking Protection (open source, Apache 2.0, github.com/duckduckgo/Android).
- **Access level: no root, and NO companion apps (user decision: install Nullveil only; no Shizuku).** Built: local `VpnService` for tracker traffic, mock location provider, mic-use watcher, permission audit. Mic/camera enforcement per app is NOT built; the only no-root, single-app route is an in-app Wireless-debugging link (self-ADB, needs ~3 FOSS deps + one-time pairing) which gives apps silence via `appops ... ignore`. Ask before adding it.
- Out of scope without root: mic white-noise injection, fake camera feed, sensor spoofing. Do not promise these in UI or docs.
- **Architecture:** Rust core (packet processing, tracker matching) called from the Java UI over JNI, built with `cargo-ndk`. Java stays the app shell.
- The VPN needs a local-only `VpnService`; it must never forward user traffic to any server we run. The `INTERNET` rule below applies to the VPN as a documented exception once it exists.

## Current state (app name: Nullveil)
- **No fixed domain lists.** `VeilService` = DNS-only local VPN (one /32 route to fake resolver `10.111.0.2`). The Rust engine (`rust/src/lib.rs`, `decide`) scores each lookup: background activity, tracker-like words, random-looking hostname, third-party vs the app's own domain, domain shared by many apps, steady beaconing, mic/camera/location permission. Score >= 6 (strict: 4) blocks it with a sinkhole answer (A->0.0.0.0, AAAA->::) and the app is listed under CAUGHT. Foreground apps are exempt except obvious trackers in strict mode.
- Background = screen off, or (with Usage Access granted) not the app in front. `Watch.java`.
- Overrides: tap a lookup -> always allow/block (`Settings.java`, pushed to Rust via `Native.setRules`).
- Tabs: SHIELD (VPN, stats, controls, latest catches), WATCH (filters ALL/BLOCKED/SUSPICIOUS + CLEAR; per-app cards with LOCK IN BACKGROUND / TRUST, per-lookup cards with BLOCK / ALLOW, mic log; rules are encrypted and cached in `Settings`, app modes applied in `VeilService`; suspicious = score >= 3 but let through), APPS (real app icons + names; apps Nullveil caught first, then apps holding mic/cam/location; tap opens Nullveil's OWN app page with what it saw + LOCK/TRUST. Design rule from the user: never redirect to Android's per-app permission settings; only unavoidable system consent screens (VPN, usage access, battery, Private DNS, Always-on VPN, notifications, mock location) may open), GHOST (mock location via `GhostService`; the app-op `android:mock_location` was set on the dev phone with `adb shell appops set io.github.xer0bit.nullveil android:mock_location allow`, other users must pick Nullveil in Developer options), SETUP (status + one-tap shortcut for each permission). App icon: adaptive vector (ring + slash) in `res/drawable/ic_launcher_*.xml`.
- **Mic Guard** (`MicGuardService.java`, Shield pill): Nullveil holds a privacy-sensitive AudioRecord in a microphone foreground service so Android's concurrent-capture policy gives other apps SILENCE (https://developer.android.com/media/platform/sharing-audio-input). Audio is read and dropped, never stored/sent. If our own capture is reported silenced we restart it (`reclaim`). Needs RECORD_AUDIO for Nullveil; shows the system mic indicator; cannot auto-start at boot; phone calls always get audio; white noise is impossible without root (silence is the max). `MicWatch` ignores our own capture and shows "heard SILENCE" when other apps' configs are silenced. NOT yet verified on the dev phone (Xiaomi HyperOS 3 / Android 16): check that a recording app's config reports silenced.
- **Ghost mode** (tab GHOST): UI never says "mock location"/Developer options. Needs the app-op `android:mock_location`, which only the shell can grant (`adb shell appops set io.github.xer0bit.nullveil android:mock_location allow`, already done on the dev phone); Setup row "Ghost mode access" explains and copies the command. A fully in-app unlock needs the unbuilt Wireless-debugging link.
- Non-blocked lookups go to the phone's own DNS server by default. Optional ENCRYPTED DNS pill (Shield tab) cycles OFF / Quad9 / Cloudflare: DNS-over-TLS (`DotClient.java`, one reused connection, cert name verified, IPv4 then IPv6, falls back to plain and counts it in `Events.plainFallbacks`). The user picks the resolver; never switch resolvers silently. Quad9 resets the TLS handshake on the dev's network (Cloudflare works).
- Stored overrides are AES-256-GCM encrypted with an Android Keystore key (`SecureStore.java`, `Settings.java`); old plain-text lists migrate automatically; if the Keystore fails nothing is written. Logs/events are memory-only.
- Per-lookup speed: usage-access check cached 3 s (`Watch`), uid->package cached, forward pool bounded to 16 threads.
- Known limits: DNS only shows suspicious behaviour, it cannot prove theft. Private DNS/DoH and hard-coded IPs bypass it. Per-app attribution depends on Android reporting the real app UID for DNS (check on device; unknown apps are scored without app signals). Mic/camera enforcement is not built (see Access level). `MicWatch` only detects "something is recording" and what was in front; Android hides which app. No mic noise / fake camera / sensor spoofing without root.
- Style: near-black `#0A0A0C`, acid green `#C6FF3D`, monospace. Keep UI minimal.
- App id / package: `io.github.xer0bit.nullveil` (permanent: changing it later breaks updates for installed users). License: GPL-3.0-or-later (SPDX header on every source file).

## Privacy rules (non-negotiable)
- No analytics, ads, crash-reporting, or tracking SDKs (no Firebase, Crashlytics, AdMob, Facebook, etc.).
- No `INTERNET` permission unless the user explicitly approves it for a named feature.
- Request the fewest permissions possible; justify each in the commit message.
- Data stays on-device. Store sensitive data with `EncryptedSharedPreferences` / Android Keystore, never plaintext.
- `android:allowBackup="false"`, `usesCleartextTraffic="false"`, no exported components without `android:permission`.
- Never log user data (`Log.*` of PII/secrets is a bug). Strip logs in release builds.
- Prefer AndroidX / platform APIs over third-party libs. Every new dependency needs approval and a FOSS license.
- No Google Play Services dependency (keeps the app F-Droid/GrapheneOS friendly).

## Stack
- Java 21 toolchain on host; app source/target compat Java 17. Gradle (Groovy DSL) with the Gradle wrapper.
- AndroidX, Material Components, ViewBinding. minSdk 26, targetSdk = latest stable.
- Android SDK at `~/Android/Sdk` (path in git-ignored `local.properties`).
- AGP 8.7.3, Gradle 8.9, compileSdk/targetSdk 35. Release builds minify and strip `Log.*` (`app/proguard-rules.pro`).

## Commands
- Build: `./gradlew assembleDebug`
- Lint: `./gradlew lint`
- Unit tests: `./gradlew testDebugUnitTest`
- Rust core (`rust/`, no crates so far): `cd rust && cargo test`. Gradle's `cargoNdk` task builds all 4 ABIs into `app/src/main/jniLibs` before every build (needs NDK 27.2.12479018 and `cargo-ndk`).
- JNI names must match the Java class: `Java_io_github_xer0bit_nullveil_Native_<method>` in `rust/src/lib.rs` ↔ `Native.java`.

## Tooling to use
- Java code intelligence: `jdtls-lsp` plugin (enabled for this project).
- Skills: `ecc:android-clean-architecture`, `ecc:java-coding-standards`, `ecc:security-review`, `ecc:gradle-build` (build failures), `superpowers:test-driven-development`.
- `rea` MCP: audit our own built APK (permissions, strings, trackers, network calls) before release; `adb` is available.
- Personal connectors (Gmail, Drive, Upwork, Zapier) are denied in this project; keep it that way.

## Workflow
- Never read or commit keystores, `local.properties`, `*.jks`, `.env` (denied in `.claude/settings.json`).
- Run lint + unit tests before declaring a task done.

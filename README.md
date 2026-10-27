# Nullveil

**Take your phone back from Big Tech trackers. Your device, your choices.**

Nullveil is a free, open-source Android app that watches what other apps do behind your back and
lets you decide: sinkhole tracker lookups, lock an app while you are not using it, keep your
microphone to yourself, and show apps a different position. No accounts, no analytics, no server.

> **Status: early alpha (0.1.0).** It works on the developer's phone; it has not been tested on
> many devices. Read [What it can't do](#what-it-cant-do) before you rely on it.

## What it does

| Tab | What you get |
|---|---|
| **Shield** | A local, DNS-only VPN. A behaviour engine (written in Rust) scores every lookup and sinkholes the ones that look like tracking. **There is no fixed domain list**: it looks at *behaviour* (background activity, tracker-like names, random-looking hostnames, third-party domains, domains shared by many apps, steady beaconing, apps holding mic/camera/location). |
| **Watch** | Every app with tracking activity, with one-tap **BLOCK / ALLOW** per domain and **LOCK IN BACKGROUND / TRUST** per app. Filters for blocked and suspicious lookups. |
| **Apps** | Real app icons and names. Apps Nullveil caught first. Tap one for Nullveil's own page about it (no redirect to Android settings). |
| **Ghost** | Show every app a different position. |
| **Setup** | Status and a one-tap fix for everything Nullveil needs. |

Also: **Mic Guard** (Nullveil holds the microphone so other apps hear silence), a **mic activity
watcher** that alerts when something records while you are not using an app, optional **encrypted DNS**
(DNS-over-TLS, you pick Quad9 or Cloudflare), and **encrypted storage** of your rules
(AES-256-GCM, key in the Android Keystore / StrongBox).

## What it can't do

Honesty matters more than marketing:

- **DNS level only.** Nullveil sees *which domain* an app looks up, never page contents. DNS-over-HTTPS
  inside an app, a strict "Private DNS" setting, and hard-coded IP addresses bypass it.
- **It shows suspicious behaviour, it cannot prove theft.** Expect some false positives; that is why
  every decision can be overruled with one tap.
- **No white noise.** Without root, the best a normal app can give another app is *silence* (Mic Guard).
- **Mic Guard** shows Android's mic indicator with Nullveil as the user, needs the mic permission for
  Nullveil itself, cannot start by itself after a reboot, and relies on Android's concurrent-capture
  rules ([docs](https://developer.android.com/media/platform/sharing-audio-input)). Audio is read only
  to keep hold of the mic and is dropped immediately: never stored, never sent. Verified so far on
  **one phone** (Xiaomi HyperOS 3, Android 16: a WhatsApp voice note recorded as complete silence); not yet on many.
- **Ghost mode needs a one-time unlock that no app can skip without root.** Android only lets an app show
  other apps a different position after you pick it as the "mock location app" (Developer options), or after
  Android's shell grants it (`adb shell appops set io.github.xer0bit.nullveil android:mock_location allow`).
  This is an Android security rule, the same for every GPS-spoofing app. The Setup tab explains both ways.
- **No root features.** No fake camera feed, no sensor spoofing, no per-app permission revoking.

## Privacy model

- No analytics, ads, accounts, crash reporters or third-party SDKs. Dependencies: AndroidX, Material
  Components (Java) and the `jni` crate (Rust).
- The only network use is forwarding the lookups it lets through, to your phone's own DNS server (or,
  if you turn it on, over TLS to the resolver you chose).
- Logs live in memory only. Your rules are stored encrypted.
- Permissions, and why:

| Permission | Why |
|---|---|
| `BIND_VPN_SERVICE` (VPN consent) | Capture DNS lookups. Only DNS is routed through it. |
| `INTERNET`, `ACCESS_NETWORK_STATE` | Forward allowed lookups; find the phone's DNS server. |
| `PACKAGE_USAGE_STATS` (Usage access) | Know which app is in front, to tell background activity apart. |
| `QUERY_ALL_PACKAGES` | Show app names, icons and which apps hold mic/camera/location. |
| `RECORD_AUDIO`, `FOREGROUND_SERVICE_MICROPHONE` | Mic Guard. Audio is discarded. |
| `ACCESS_MOCK_LOCATION`, `FOREGROUND_SERVICE_SPECIAL_USE` | Ghost mode. |
| `POST_NOTIFICATIONS`, `FOREGROUND_SERVICE` | Foreground notices (Ghost, Mic Guard) and mic alerts. |
| `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` | Keep the shield running. |

## Install

1. Download `nullveil-<version>.apk` from the [latest release](../../releases/latest).
2. Check the checksum (`sha256sum nullveil-<version>.apk`) against the `.sha256` file.
3. Check the signing key matches this fingerprint:

   ```
   apksigner verify --print-certs nullveil-<version>.apk
   Signer #1 certificate SHA-256 digest: 90bf8a920c74516bfae9d9fc999a7ca2eddd4c5d5e2305e0a3a329dd735d2cf8
   ```
   (colon form: `90:BF:8A:92:0C:74:51:6B:FA:E9:D9:FC:99:9A:7C:A2:ED:DD:4C:5D:5E:23:05:E0:A3:A3:29:DD:73:5D:2C:F8`)
4. Install it and open **Setup** to grant what is needed.

Requires Android 8.0 (API 26) or newer. Developed on Android 16.

## Build from source

You need JDK 17+, the Android SDK (platform 35, build-tools 35), NDK `27.2.12479018`, Rust with the
four Android targets, and `cargo-ndk`:

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
cargo install cargo-ndk --locked
echo "sdk.dir=$HOME/Android/Sdk" > local.properties   # path to your Android SDK

(cd rust && cargo test)                               # the behaviour engine
./gradlew assembleDebug lint testDebugUnitTest        # builds the Rust core for every ABI too
```

Release builds are signed with a key that is **not** in this repository; without it
`./gradlew assembleRelease` produces an unsigned APK (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## How it works

```
apps --DNS--> 10.111.0.2 (fake resolver, the only route in the tunnel)
                 |
          VeilService (Java) reads the TUN device
                 |  JNI
          Rust core: parse DNS packet -> score the lookup -> sinkhole or forward
                 |
   blocked: reply 0.0.0.0 / ::      allowed: your phone's DNS (or DNS-over-TLS)
```

- `rust/src/lib.rs` - packet parsing and the behaviour engine (unit-tested).
- `app/src/main/java/io/github/xer0bit/nullveil/` - UI, VPN service, Mic Guard, Ghost, encrypted storage.
- [CLAUDE.md](CLAUDE.md) - design notes and decisions (useful to humans too).

## Contributing

All help is welcome: engine ideas, device testing reports, translations, UI polish, docs.
Start with [CONTRIBUTING.md](CONTRIBUTING.md). By taking part you agree to the
[Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

## License

[GPL-3.0-or-later](LICENSE). Free for everyone, and every fork stays free.

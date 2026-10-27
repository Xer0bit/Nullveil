// SPDX-License-Identifier: GPL-3.0-or-later
//! Nullveil core: DNS-only tracker sinkhole. Pure functions + a thin JNI layer.
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jbyteArray, jint, jstring};
use jni::JNIEnv;
use std::collections::HashSet;
use std::ptr::null_mut;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------- behaviour engine (no fixed domain lists) ----------------

use std::collections::HashMap;
use std::sync::Mutex;

const TRACKER_WORDS: &[&str] = &[
    "ads", "ad", "adserver", "adsystem", "adservice", "track", "tracker", "tracking", "trk", "analytics",
    "analytic", "telemetry", "metrics", "metric", "pixel", "beacon", "stats", "crash", "crashlytics",
    "collect", "collector", "events", "insights", "attribution", "measurement", "diagnostics", "logging",
    "sdk", "gtm", "rum", "clicks", "impression", "impressions", "ping",
];
const SLD_PARTS: &[&str] = &["co", "com", "org", "net", "gov", "ac", "edu", "or", "ne"];
const NOISE: &[&str] = &["com", "org", "net", "android", "app", "apps", "mobile", "www", "the", "google", "samsung"];

#[derive(Default)]
struct State {
    allow: HashSet<String>,
    block: HashSet<String>,
    reach: HashMap<String, HashSet<String>>, // registrable domain -> apps that asked for it
    hits: HashMap<(String, String), Vec<u64>>, // (app, registrable domain) -> recent lookup times (ms)
}

fn state() -> &'static Mutex<State> {
    static S: OnceLock<Mutex<State>> = OnceLock::new();
    S.get_or_init(Default::default)
}

/// Your own overrides, one domain per line. They match the domain and all its subdomains.
pub fn set_rules(allow: &str, block: &str) {
    let parse = |t: &str| t.lines().map(|l| l.trim().to_ascii_lowercase()).filter(|l| !l.is_empty()).collect();
    let mut st = state().lock().unwrap_or_else(|e| e.into_inner());
    st.allow = parse(allow);
    st.block = parse(block);
}

fn suffix_match(set: &HashSet<String>, name: &str) -> bool {
    let mut s = name;
    loop {
        if set.contains(s) {
            return true;
        }
        match s.find('.') {
            Some(i) => s = &s[i + 1..],
            None => return false,
        }
    }
}

/// example.com / example.co.uk. ponytail: heuristic, not the public-suffix list; add psl if it misfires.
fn registrable(name: &str) -> String {
    let l: Vec<&str> = name.split('.').collect();
    let n = l.len();
    let keep = if n >= 3 && l[n - 1].len() == 2 && SLD_PARTS.contains(&l[n - 2]) { 3 } else { 2 };
    l[n.saturating_sub(keep)..].join(".")
}

fn tracker_like(name: &str) -> bool {
    let labels: Vec<&str> = name.split('.').collect();
    labels[..labels.len().saturating_sub(1)]
        .iter()
        .flat_map(|l| l.split(|c: char| c == '-' || c == '_' || c.is_ascii_digit()))
        .any(|t| TRACKER_WORDS.contains(&t))
}

/// Long, high-entropy leftmost label: looks like an identifier or data smuggled in a hostname.
fn random_looking(name: &str) -> bool {
    let l = name.split('.').next().unwrap_or("");
    if l.len() < 24 {
        return false;
    }
    let mut freq = [0u32; 256];
    l.bytes().for_each(|b| freq[b as usize] += 1);
    let n = l.len() as f64;
    let h: f64 = freq.iter().filter(|&&c| c > 0).map(|&c| { let p = c as f64 / n; -p * p.log2() }).sum();
    h >= 3.3
}

/// A word from the app's package name appears in the domain's name (com.spotify.music ~ spotify.com).
fn first_party(app: &str, reg: &str) -> bool {
    let sld = reg.split('.').next().unwrap_or("");
    app.split('.').any(|p| p.len() >= 4 && !NOISE.contains(&p) && sld.contains(p))
}

/// At least 5 lookups at a steady rhythm (spread under 25% of the mean gap, gap over 3 s).
fn beaconing(h: &[u64]) -> bool {
    if h.len() < 5 {
        return false;
    }
    let gaps: Vec<u64> = h.windows(2).map(|w| w[1].saturating_sub(w[0])).collect();
    let mean = gaps.iter().sum::<u64>() / gaps.len() as u64;
    mean >= 3000 && gaps.iter().all(|&g| g.abs_diff(mean) * 4 <= mean)
}

pub struct Input<'a> {
    pub name: &'a str,
    pub app: &'a str, // package name, "uid:N" or "?" when unknown
    pub background: bool,
    pub perms: u8, // bit 1 mic, 2 camera, 4 location: granted to this app
    pub strict: bool,
    pub now_ms: u64,
}

pub struct Verdict {
    pub block: bool,
    pub score: i32,
    pub reasons: Vec<&'static str>,
}

pub fn decide(i: &Input) -> Verdict {
    let name = i.name.trim_end_matches('.').to_ascii_lowercase();
    let mut st = state().lock().unwrap_or_else(|e| e.into_inner());
    if suffix_match(&st.allow, &name) {
        return Verdict { block: false, score: 0, reasons: vec!["allowed by you"] };
    }
    if suffix_match(&st.block, &name) {
        return Verdict { block: true, score: 99, reasons: vec!["blocked by you"] };
    }
    if st.reach.len() > 5000 || st.hits.len() > 5000 {
        st.reach.clear();
        st.hits.clear();
    }
    let reg = registrable(&name);
    let known = i.app != "?" && !i.app.starts_with("uid:");
    let (named, random) = (tracker_like(&name), random_looking(&name));
    let mut score = 0;
    let mut reasons = vec![];
    let mut add = |pts: i32, why: &'static str| {
        score += pts;
        reasons.push(why);
    };
    if named { add(3, "tracker-like name"); }
    if random { add(4, "random-looking name"); }
    if i.background { add(3, "background"); }
    if known {
        let fp = first_party(i.app, &reg);
        let apps = st.reach.entry(reg.clone()).or_default();
        if apps.len() < 64 { apps.insert(i.app.to_string()); }
        match apps.len() {
            0..=2 => {}
            3..=5 => add(1, "seen in several apps"),
            _ => add(2, "shared by many apps"),
        }
        if !fp { add(1, "third-party"); } else if !named && !random { add(-3, "own service"); }
        if i.background && i.perms != 0 && !fp { add(1, "app holds mic/camera/location"); }
        let h = st.hits.entry((i.app.to_string(), reg)).or_default();
        h.push(i.now_ms);
        if h.len() > 8 { h.remove(0); }
        if beaconing(h) { add(2, "steady beaconing"); }
    }
    // You are using the app right now: leave it alone, except in strict mode for obvious trackers.
    let exempt = !i.background && !(i.strict && (named || random));
    let threshold = if i.strict { 4 } else { 6 };
    Verdict { block: score >= threshold && !exempt, score, reasons }
}

/// A DNS question found inside an IPv4/UDP packet addressed to port 53.
pub struct Query {
    pub name: String,
    pub qtype: u16,
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    dns: usize,
    qend: usize,
}

pub fn parse(pkt: &[u8]) -> Option<Query> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 || pkt[9] != 17 {
        return None;
    }
    let ihl = (pkt[0] & 15) as usize * 4;
    let dns = ihl + 8;
    if ihl < 20 || pkt.len() < dns + 12 {
        return None;
    }
    let be = |i: usize| u16::from_be_bytes([pkt[i], pkt[i + 1]]);
    if be(ihl + 2) != 53 {
        return None;
    }
    let d = &pkt[dns..];
    if d[2] & 0x80 != 0 || u16::from_be_bytes([d[4], d[5]]) != 1 {
        return None; // a response, or not exactly one question
    }
    let (mut i, mut name) = (12, String::new());
    loop {
        let l = *d.get(i)? as usize;
        i += 1;
        if l == 0 {
            break;
        }
        if l & 0xC0 != 0 {
            return None; // compression never appears in a question
        }
        let label = d.get(i..i + l)?;
        i += l;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
    }
    if d.len() < i + 4 {
        return None;
    }
    Some(Query {
        name,
        qtype: u16::from_be_bytes([d[i], d[i + 1]]),
        src: pkt[12..16].try_into().ok()?,
        dst: pkt[16..20].try_into().ok()?,
        sport: be(ihl),
        dport: 53,
        dns,
        qend: dns + i + 4,
    })
}

/// Sinkhole answer: A -> 0.0.0.0, AAAA -> ::, anything else -> empty NOERROR.
/// Apps get a fast, valid "success" that goes nowhere, instead of retrying a failure.
pub fn sinkhole_dns(pkt: &[u8], q: &Query) -> Vec<u8> {
    let mut r = pkt[q.dns..q.qend].to_vec();
    r[2] = 0x80 | (r[2] & 0x01); // QR=1, keep RD
    r[3] = 0x80; // RA=1, RCODE=0
    let rdlen = match q.qtype {
        1 => 4,
        28 => 16,
        _ => 0,
    };
    if rdlen > 0 {
        r[6..8].copy_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&[0xC0, 0x0C]); // name: pointer to the question
        r.extend_from_slice(&q.qtype.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes()); // class IN
        r.extend_from_slice(&60u32.to_be_bytes()); // ttl
        r.extend_from_slice(&(rdlen as u16).to_be_bytes());
        r.extend(std::iter::repeat(0).take(rdlen));
    }
    r
}

fn checksum(h: &[u8]) -> u16 {
    let mut sum: u32 = h.chunks(2).map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32).sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Wrap a DNS payload into an IPv4/UDP reply to the query's sender.
pub fn wrap(q: &Query, dns: &[u8]) -> Vec<u8> {
    let total = 28 + dns.len();
    let mut o = vec![0u8; total];
    o[0] = 0x45;
    o[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    o[6] = 0x40; // don't fragment
    o[8] = 64;
    o[9] = 17;
    o[12..16].copy_from_slice(&q.dst);
    o[16..20].copy_from_slice(&q.src);
    let c = checksum(&o[..20]);
    o[10..12].copy_from_slice(&c.to_be_bytes());
    o[20..22].copy_from_slice(&q.dport.to_be_bytes());
    o[22..24].copy_from_slice(&q.sport.to_be_bytes());
    o[24..26].copy_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
    // UDP checksum 0 = "none", legal for IPv4
    o[28..].copy_from_slice(dns);
    o
}

// ---- JNI: io.github.xer0bit.nullveil.Native ----

fn query_impl(env: &mut JNIEnv, pkt: &JByteArray) -> Option<jstring> {
    let q = parse(&env.convert_byte_array(pkt).ok()?)?;
    Some(env.new_string(q.name).ok()?.into_raw())
}

/// Domain asked for by a DNS query packet, or null if the packet is not one.
#[no_mangle]
pub extern "system" fn Java_io_github_xer0bit_nullveil_Native_query(mut env: JNIEnv, _c: JClass, pkt: JByteArray) -> jstring {
    query_impl(&mut env, &pkt).unwrap_or(null_mut())
}

fn decide_impl(env: &mut JNIEnv, name: &JString, app: &JString, background: jboolean, perms: jint, strict: jboolean) -> Option<jstring> {
    let name = String::from(env.get_string(name).ok()?);
    let app = String::from(env.get_string(app).ok()?);
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_millis() as u64;
    let v = decide(&Input { name: &name, app: &app, background: background != 0, perms: perms as u8, strict: strict != 0, now_ms });
    let out = format!("{}|{}|{}", v.block as u8, v.score, v.reasons.join(" · "));
    Some(env.new_string(out).ok()?.into_raw())
}

/// "1|score|reasons" to block, "0|score|reasons" to pass; null on bad input.
#[no_mangle]
pub extern "system" fn Java_io_github_xer0bit_nullveil_Native_decide(
    mut env: JNIEnv, _c: JClass, name: JString, app: JString, background: jboolean, perms: jint, strict: jboolean,
) -> jstring {
    decide_impl(&mut env, &name, &app, background, perms, strict).unwrap_or(null_mut())
}

#[no_mangle]
pub extern "system" fn Java_io_github_xer0bit_nullveil_Native_setRules(mut env: JNIEnv, _c: JClass, allow: JString, block: JString) {
    if let (Ok(a), Ok(b)) = (env.get_string(&allow), env.get_string(&block)) {
        set_rules(&String::from(a), &String::from(b));
    }
}

fn reply_impl(env: &mut JNIEnv, pkt: &JByteArray, dns: Option<&JByteArray>) -> Option<jbyteArray> {
    let p = env.convert_byte_array(pkt).ok()?;
    let q = parse(&p)?;
    let payload = match dns {
        Some(d) => env.convert_byte_array(d).ok()?,
        None => sinkhole_dns(&p, &q),
    };
    Some(env.byte_array_from_slice(&wrap(&q, &payload)).ok()?.into_raw())
}

/// Full IP packet carrying the sinkhole answer for a blocked query.
#[no_mangle]
pub extern "system" fn Java_io_github_xer0bit_nullveil_Native_blockedReply(mut env: JNIEnv, _c: JClass, pkt: JByteArray) -> jbyteArray {
    reply_impl(&mut env, &pkt, None).unwrap_or(null_mut())
}

/// Full IP packet carrying a real upstream answer back to the asking app.
#[no_mangle]
pub extern "system" fn Java_io_github_xer0bit_nullveil_Native_wrap(mut env: JNIEnv, _c: JClass, pkt: JByteArray, dns: JByteArray) -> jbyteArray {
    reply_impl(&mut env, &pkt, Some(&dns)).unwrap_or(null_mut())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IPv4/UDP packet 10.111.0.1:40000 -> 10.111.0.2:53 asking `name` (type `qtype`).
    fn query_packet(name: &str, qtype: u16) -> Vec<u8> {
        let mut dns = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            dns.push(l.len() as u8);
            dns.extend_from_slice(l.as_bytes());
        }
        dns.extend_from_slice(&[0]);
        dns.extend_from_slice(&qtype.to_be_bytes());
        dns.extend_from_slice(&[0, 1]);
        let total = 28 + dns.len();
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 10, 111, 0, 1, 10, 111, 0, 2];
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&53u16.to_be_bytes());
        p.extend_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(&dns);
        p
    }

    #[test]
    fn parses_query_and_ignores_junk() {
        let p = query_packet("www.example.com", 1);
        let q = parse(&p).unwrap();
        assert_eq!((q.name.as_str(), q.qtype), ("www.example.com", 1));
        assert!(parse(&p[..30]).is_none());
        assert!(parse(&[0u8; 5]).is_none());
        let mut tcp = p.clone();
        tcp[9] = 6;
        assert!(parse(&tcp).is_none());
    }

    #[test]
    fn sinkhole_answers_a_with_zero_addr_and_valid_ip_header() {
        let p = query_packet("stats.example-ads.net", 1);
        let q = parse(&p).unwrap();
        let dns = sinkhole_dns(&p, &q);
        assert_eq!(&dns[..2], &[0x12, 0x34]); // same txn id
        assert_eq!(dns[2] & 0x80, 0x80); // is a response
        assert_eq!(&dns[6..8], &[0, 1]); // one answer
        assert_eq!(&dns[dns.len() - 4..], &[0, 0, 0, 0]);
        let out = wrap(&q, &dns);
        assert_eq!(checksum(&out[..20]), 0); // header checksum verifies
        assert_eq!(&out[12..16], &[10, 111, 0, 2]); // from the DNS server
        assert_eq!(&out[16..20], &[10, 111, 0, 1]); // to the asker
        assert_eq!(u16::from_be_bytes([out[22], out[23]]), 40000);
    }

    #[test]
    fn sinkhole_https_query_is_empty_noerror() {
        let p = query_packet("tracker.example-ads.net", 65);
        let dns = sinkhole_dns(&p, &parse(&p).unwrap());
        assert_eq!((&dns[6..8], dns[3] & 0x0F), (&[0u8, 0][..], 0));
    }

    fn input<'a>(name: &'a str, app: &'a str, background: bool) -> Input<'a> {
        Input { name, app, background, perms: 0, strict: false, now_ms: 1_000 }
    }

    #[test]
    fn registrable_domains() {
        assert_eq!(registrable("a.b.example.com"), "example.com");
        assert_eq!(registrable("x.example.co.uk"), "example.co.uk");
        assert_eq!(registrable("localhost"), "localhost");
    }

    #[test]
    fn background_tracker_like_name_is_blocked_foreground_is_not() {
        let bg = decide(&input("events.analytics.t1sdk.com", "com.game.one", true));
        assert!(bg.block, "{:?}", bg.reasons);
        let fg = decide(&input("events.analytics.t1sdk.com", "com.game.one", false));
        assert!(!fg.block);
    }

    #[test]
    fn strict_blocks_obvious_trackers_even_in_foreground() {
        let mut i = input("telemetry.t2sdk.com", "com.game.two", false);
        i.strict = true;
        assert!(decide(&i).block);
    }

    #[test]
    fn own_service_in_background_passes() {
        assert!(!decide(&input("api.spotify.com", "com.spotify.music", true)).block);
    }

    #[test]
    fn random_looking_hostname_in_background_is_blocked() {
        let v = decide(&input("a8f3k29dj4h1x7q0z5m2p6w9r3t8.cdn-x.com", "com.app.three", true));
        assert!(v.block && v.reasons.contains(&"random-looking name"));
        assert!(!random_looking("www.example.com"));
    }

    #[test]
    fn domain_shared_by_many_apps_in_background_is_blocked() {
        let mut last = false;
        for n in 0..7 {
            let app = format!("com.vendor{n}.app");
            last = decide(&Input { perms: 4, ..input("api.sharedcollector4.net", &app, true) }).block;
        }
        assert!(last);
    }

    #[test]
    fn steady_beacon_is_detected() {
        let steady: Vec<u64> = (0..6).map(|n| n * 30_000).collect();
        assert!(beaconing(&steady));
        assert!(!beaconing(&[0, 1_000, 9_000, 9_500, 40_000]));
    }

    #[test]
    fn your_rules_beat_the_engine() {
        set_rules("events.analytics.t5sdk.com", "quiet.example-ok.org");
        assert!(!decide(&input("events.analytics.t5sdk.com", "com.game.five", true)).block);
        assert!(decide(&input("quiet.example-ok.org", "com.game.five", false)).block);
        set_rules("", "");
    }
}

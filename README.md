# qrtc

Quantum realtime communication: a pure Rust WebRTC engine with hybrid
post-quantum key agreement.

qrtc implements the peer-connection side of WebRTC behind two traits,
[`PeerEngine`](src/lib.rs) and [`Peer`](src/lib.rs). A consumer exposes them
as the W3C `RTCPeerConnection` API. Two consumers are planned or shipping:

- [tauri-plugin-webrtc](https://github.com/crabnebula-dev/tauri-plugin-webrtc)
  gives WebRTC to Tauri webviews that lack it (WebKitGTK on Linux), through a
  JS shim over Tauri IPC.
- [formal-web](https://github.com/crabnebula-dev/formal-web) is to expose it as
  native `RTCPeerConnection` and `RTCDataChannel` bindings (in progress).

## What it does

| Area | Status |
| --- | --- |
| JSEP | Offers, answers, renegotiation, rollback, ICE restart, `setCodecPreferences` |
| ICE | Host and mDNS `.local` candidates, STUN, TURN over UDP, TCP and TLS, relay-only policy |
| DTLS | DTLS 1.2, or DTLS 1.3 with X25519MLKEM768 (see below) |
| Data channels | Reliable and unreliable, ordered and unordered, negotiated ids, buffered-amount events |
| Audio | Opus (rusty-opus), AEC3, noise suppression and AGC (sonora), jitter buffer, in-band FEC, DTMF (RFC 4733) |
| Video | VP8 and H.264 packetization; the consumer encodes and decodes |
| Encoded transforms | Hooks for `RTCRtpScriptTransform` (LiveKit E2EE) |
| Stats | Candidate pairs, `inbound-rtp`, `outbound-rtp`, transport `tlsGroup` |

With `turn-tls-rustcrypto` the build compiles no C code. Its only `-sys`
crates bind the platform's own APIs for the certificate store (Windows,
Apple's Security framework).

## Post-quantum key agreement

qrtc agrees DTLS 1.3 and TURN over TLS keys with hybrid X25519MLKEM768
(draft-ietf-tls-ecdhe-mlkem), the group browsers and TLS servers negotiate.
Only the key exchange is post-quantum: peers still authenticate with ECDSA
certificates whose fingerprints travel in the signalling.

| Feature | ML-KEM from | Groups offered, in order |
| --- | --- | --- |
| `pq-moduletto` (default) | [moduletto](https://github.com/crabnebula-dev/moduletto) | X25519MLKEM768, X25519+ML-KEM-512 (private codepoint 0xfe5c), MLKEM768, MLKEM512 |
| `pq-hybrid` | RustCrypto [ml-kem](https://crates.io/crates/ml-kem) | X25519MLKEM768, MLKEM768 |

Each connection sets `RtcConfiguration::post_quantum`:

| Policy | DTLS | TURN over TLS |
| --- | --- | --- |
| `Off` | DTLS 1.2, classical groups | classical groups |
| `Prefer` (default when a pq feature is on) | DTLS 1.3 with X25519MLKEM768 when the peer supports it, otherwise DTLS 1.2 | X25519MLKEM768 first, classical groups after |
| `Require` | DTLS 1.3 with post-quantum groups only | TLS 1.3 with post-quantum groups only |

Verified against Chromium 141 with its `WebRTC-ForceDtls13` and
`WebRTC-EnableDtlsPqc` field trials (X25519MLKEM768 negotiated both ways) and
against OpenSSL 3.5.5 for TURN over TLS.

## Features

| Feature | Effect |
| --- | --- |
| `turn-tls-ring` (default) | TURN over TLS with rustls and ring (compiles C and assembly) |
| `turn-tls-rustcrypto` | TURN over TLS with the pure Rust RustCrypto provider (pre-release) |
| `pq-moduletto` (default) | Post-quantum groups with moduletto |
| `pq-hybrid` | Post-quantum groups with RustCrypto ml-kem |

Without a TLS feature, `turns:` servers are skipped. Certificates are checked
against the platform trust store, with Mozilla's roots as the fallback.

## Use

```rust
use qrtc::{native::NativeEngine, PeerEngine, RtcConfiguration};
use std::sync::Arc;

let engine = NativeEngine::new()?;
let peer = engine.create_peer(
    &RtcConfiguration::default(),
    Arc::new(|event| println!("{event:?}")),
)?;
let offer = peer.create_offer()?;
peer.set_local_description(&offer)?;
```

All methods block; call them from a blocking pool on an async runtime.
Events arrive in order per peer connection, from engine threads.
`examples/stdio_peer.rs` drives a peer over JSON lines on stdin and stdout.

## Vendored crates

`vendor/` holds patched copies. Every reference to them is a path inside this
repository, so consumers need no `[patch]` section.

| Crate | Version | Why |
| --- | --- | --- |
| `str0m` | 0.24.0 | VP8 PictureID for SFUs, JSEP re-offers; see `vendor/str0m/PATCHES.md` |
| `str0m-rust-crypto` | 0.6.0 | DTLS certificate from RustCrypto (no AWS-LC); DTLS options for post-quantum groups |
| `dimpl` | 0.7.4 | Key encapsulation groups for DTLS 1.3; see `vendor/dimpl/PATCHES.md` |
| `str0m-proto`, `is` | 0.7.0, 0.11.1 | Unmodified, vendored so they use the patched dimpl |

The patches are meant for upstream.

## Test

```sh
cargo test --lib                                                     # defaults
cargo test --lib --no-default-features --features turn-tls-rustcrypto,pq-hybrid
node tests/pq-tls-interop.mjs pq-moduletto   # TURN TLS against OpenSSL 3.5+ (Node)
cargo build --example stdio_peer && (cd tests && npm ci) && node tests/chromium-interop.mjs
node tests/sbom-check.mjs                    # SBOM matches Cargo.lock
cargo deny --all-features check              # advisories, licences, sources
```

The unit tests cover JSEP, media, TURN framing, DTMF, and post-quantum DTLS
between engines for every policy pair. `chromium-interop.mjs` checks data
channels both ways against headless Chromium: DTLS 1.2 against default
Chromium, X25519MLKEM768 over DTLS 1.3 with Chromium's post-quantum field
trials, and `Require` failing to connect against default Chromium. LiveKit,
Matrix and TURN server suites live in tauri-plugin-webrtc.

CI (`.github/workflows/ci.yml`) runs all of the above, plus `rustfmt`,
`clippy -D warnings` and warning-free docs for four feature sets. The unit
tests run on x86_64 and aarch64 Linux and on aarch64 macOS, for three feature sets.
It also checks MSRV 1.91 and that the `turn-tls-rustcrypto` builds contain
no C code. Windows runs but does not block, as it is not yet verified. CI runs
again weekly for new advisories. `deny.toml` records why each ignored
advisory does not reach qrtc.

A signed `v*` tag triggers `.github/workflows/release.yml`. It checks the
tag against the crate version, runs the tests, then publishes a GitHub
release. The release carries the source archive, the SBOM and SHA-256 sums,
each with a build provenance attestation.

Minimum Rust: 1.91.

`sbom/qrtc.cdx.json` is the CycloneDX 1.5 SBOM of the default build (`cargo cyclonedx`).

## Licence and compliance

Licensed under either of Apache License 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
or MIT ([LICENSE-MIT](LICENSE-MIT)), at your option. Vendored crates keep their
own licences (all MIT OR Apache-2.0).

CrabNebula stewards qrtc as free and open-source software. See
[COMPLIANCE.md](COMPLIANCE.md) for its status under the Cyber Resilience Act.

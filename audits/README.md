# Security reviews

Reviews of qrtc, newest first. Each entry records scope, method, findings
with their status, and the risks the maintainer accepted. Vulnerability
reports go through the process in [SECURITY.md](../SECURITY.md), not here.

| Date | Reviewer | Scope | Findings | Open |
|---|---|---|---|---|
| 2026-10-10 | Internal (maintainer, assisted by Claude) | Engine source, vendored patches, randomness, build and release pipeline | 9 | 1 accepted risk |

## 2026-10-10: internal review

### Scope

- qrtc's own code: `src/` (JSEP, driver, STUN/TURN client, TURN streams, mDNS, post-quantum key agreement, audio), `examples/stdio_peer.rs`.
- The patched vendored crates under `vendor/`: the patch sites in dimpl (fragmented hellos, key encapsulation groups), str0m-rust-crypto (certificate generation, DTLS options) and str0m; the wiring of `is` and `str0m-proto`.
- Randomness: every generator used for keys, credentials, identifiers and nonces, including seeding of the generators the vendored crates use.
- Build, test and release: `Cargo.toml`, `deny.toml`, the GitHub workflows, the Node test and documentation scripts, the SBOM check.

Out of scope: a line-by-line review of unpatched vendored code (str0m's RTP, SCTP and SRTP, dimpl's record layer), the moduletto crate, and the consumers (tauri-plugin-webrtc, formal-web).

### Method

Manual reading of the code paths above, with the RFCs they implement (8445, 8489, 8656, 9147, 8446 section 4.1.3, 6762, FIPS 203, draft-ietf-tls-ecdhe-mlkem); `cargo deny` and `cargo audit` against the lockfile; verification of each ignored advisory's justification against the dependency graph; a check of every call into a random number generator down to its seed.

### Findings

Severity is the reviewer's judgement of impact on a deployment with TLS-protected signalling, which is the documented assumption. Status "fixed" means in the change set that added this file.

| ID | Severity | Title | Status |
|---|---|---|---|
| [QRTC-2026-001](#qrtc-2026-001) | Medium | ICE credentials and STUN transaction ids from a non-cryptographic generator seeded from the clock | Fixed |
| [QRTC-2026-002](#qrtc-2026-002) | Medium | TURN responses accepted without MESSAGE-INTEGRITY after authentication | Fixed |
| [QRTC-2026-003](#qrtc-2026-003) | Medium | Host candidates expose interface addresses | Fixed |
| [QRTC-2026-004](#qrtc-2026-004) | Medium | Default feature depends on a git branch | Accepted risk |
| [QRTC-2026-005](#qrtc-2026-005) | Low | No downgrade protection in the DTLS 1.2 fallback of `prefer` | Fixed |
| [QRTC-2026-006](#qrtc-2026-006) | Low | Non-constant-time MESSAGE-INTEGRITY comparison | Fixed |
| [QRTC-2026-007](#qrtc-2026-007) | Low | Unbounded, unvalidated mDNS resolutions driven by the remote peer | Fixed |
| [QRTC-2026-008](#qrtc-2026-008) | Low | Secret hygiene: ICE passwords in trace logs, TURN password in `Debug`, shared secrets not wiped | Fixed |
| [QRTC-2026-009](#qrtc-2026-009) | Low | No `SECURITY.md`, no dependency update automation | Fixed |

#### QRTC-2026-001

**ICE credentials and STUN transaction ids from a non-cryptographic generator seeded from the clock.** Medium. Fixed.

The vendored `is` (ICE agent) and `str0m-proto` crates generated `ice-ufrag`, `ice-pwd` (`Id::random`), STUN transaction ids (`TransId::new`) and the ICE tie-breaker from `str0m_proto::NonCryptographicRng`, which is `fastrand`. On native targets `fastrand` seeds its thread-local wyrand state from `Instant::now()` hashed with the thread id, not from the operating system, and wyrand's 64-bit state is recoverable from its outputs. Raw outputs leave the host in cleartext: the tie-breaker in every connectivity check, SSRCs in SDP and RTP. An observer could therefore predict the ICE password of later peer connections on the same engine thread and forge connectivity checks, redirecting the selected candidate pair. RFC 8445 section 5.3 requires unguessable credentials with at least 128 bits of randomness; RFC 8489 section 6 requires cryptographically random transaction ids. DTLS protects the content of media and data channels regardless, so the impact is on ICE integrity and availability.

Fix: `str0m-proto` gains `CryptographicRng` over `getrandom`; `Id::random` (with uniform rejection sampling over its alphabet), `TransId::new` and the tie-breaker use it. Every engine thread, and the thread that builds a peer connection, also reseeds `fastrand` from the OS, so the RTP identifiers that still use it do not derive from the clock. Recorded as str0m patch 7 in `vendor/str0m/PATCHES.md`; to be proposed upstream.

#### QRTC-2026-002

**TURN responses accepted without MESSAGE-INTEGRITY after authentication.** Medium. Fixed.

`TurnClient::handle` verified MESSAGE-INTEGRITY on a success response only when the attribute was present, and never on error responses. RFC 8489 section 10.2.3 requires a client holding a long-term key to discard responses that lack a valid MESSAGE-INTEGRITY, except the 400, 401 and 438 errors a server sends before authenticating. A party able to deliver a response with the right transaction id (on-path, or racing the server) could hand the client a forged relayed address, so the engine advertised a bogus relay candidate, or cancel a transaction. The transaction was also removed before the check, so a forged response with a bad MAC cancelled the real one.

Fix: with a key in hand, every response must verify, except those three error codes; verification happens before the transaction is consumed. Unit tests cover the unauthenticated 401 challenge, success and error responses without integrity, a wrong key, and anonymous allocation (`src/native/turn.rs`).

#### QRTC-2026-003

**Host candidates expose interface addresses.** Medium (privacy). Fixed.

The engine bound a socket per usable interface and emitted each address as a host candidate, in trickled candidates, in the local SDP and in stats. Browsers replace these with random `<uuid>.local` names and answer mDNS queries for them, so the page, the signalling server and a remote peer that never connects do not learn LAN or VPN addresses. qrtc only resolved the remote side's names.

Fix: one mDNS responder per engine (`src/native/mdns.rs`) registers a UUID name per host address and answers A/AAAA queries on 224.0.0.251 and ff02::fb, with the RFC 6762 rules for legacy unicast queries and a one-answer-per-second limit per name. Candidates, SDP `a=candidate` lines and the local candidate in stats carry the name. Loopback keeps its address. If no mDNS socket can be opened the engine logs a warning and falls back to addresses. A name registered by the same engine resolves without the network, which keeps two peers in one process (the unit tests) independent of multicast.

#### QRTC-2026-004

**Default feature depends on a git branch.** Medium (supply chain). Accepted risk.

`Cargo.toml` pulls moduletto, the default ML-KEM implementation, with `branch = "main"`. This repository's `Cargo.lock` pins the commit, but a downstream consumer resolves `main` at its own lock time, and `cargo update` follows the branch. Anyone able to push to that branch can change what every default build of qrtc compiles. A git dependency also prevents publishing qrtc to crates.io.

Decision (maintainer, 2026-10-10): keep `branch = "main"`. moduletto is a CrabNebula repository under the same maintainers; the weekly CI run exists to catch changes on `main`; `deny.toml` denies every other git source. Revisit when moduletto is published to crates.io, which would also unblock publishing qrtc. Mitigations for integrators: vendor qrtc, or add a `[patch]` pinning moduletto to a reviewed revision.

#### QRTC-2026-005

**No downgrade protection in the DTLS 1.2 fallback of `prefer`.** Low. Fixed.

Under `postQuantum: "prefer"` the auto-sensing client sends a hybrid ClientHello and takes the server's first response as the version. An attacker on the media path can inject a HelloVerifyRequest or a DTLS 1.2 ServerHello and force the classical fallback. The transcript-bound Finished message keeps keys safe, so the effect is denial of post-quantum key agreement, not compromise. The vendored dimpl did not implement the RFC 8446 section 4.1.3 downgrade sentinel.

Fix: dimpl patch 7. The DTLS 1.2 client fails with `SecurityError::DowngradeSentinel` when it offered 1.3 and the ServerHello random ends in `DOWNGRD\x01` or `DOWNGRD\x00`; the auto-sensing server sets the sentinel when it falls back to 1.2. A peer that only speaks DTLS 1.2 cannot set the sentinel, so against such peers `prefer` remains best effort; `require` is the guarantee. The documentation says so.

#### QRTC-2026-006

**Non-constant-time MESSAGE-INTEGRITY comparison.** Low. Fixed.

`Message::verify` compared the computed HMAC-SHA1 with `==`. The client verifies server responses, so a timing side channel is hard to exploit, but the fix is trivial: `Mac::verify_slice` (`src/native/stun.rs`).

#### QRTC-2026-007

**Unbounded, unvalidated mDNS resolutions driven by the remote peer.** Low. Fixed.

Each remote candidate whose address ended in `.local` spawned a task holding a multicast socket for up to 3 s, with no limit on concurrency and no check on the name, so a hostile peer could exhaust file descriptors or use the engine to send arbitrary multicast queries on the local network. The DNS label length was also cast to a byte without a bound.

Fix: only names of the shape browsers generate are resolved (one label of letters, digits and hyphens under `.local`, at most 63 bytes), at most eight resolutions in flight per peer connection; others are ignored, as a browser does when a name does not resolve.

#### QRTC-2026-008

**Secret hygiene.** Low. Fixed.

Trace-level logs wrote complete local and remote SDP, including `a=ice-pwd`. `IceServerAddr` derived `Debug` with the TURN password in the clear. In the post-quantum key agreement, decapsulation keys and X25519 private keys were zeroized but the KEM shared secrets and the combined secret were plain vectors.

Fix: ICE passwords are redacted from the SDP written to logs; `IceServerAddr` has a redacting `Debug`; the shared secrets and OS-random seeds are `Zeroizing` and the rustls `SharedSecret` is built from a borrowed slice so no unwiped copy outlives the exchange.

#### QRTC-2026-009

**Repository hygiene.** Low. Fixed.

There was no `SECURITY.md`, so GitHub's Security tab did not surface the reporting process described in `COMPLIANCE.md`, and no Dependabot or Renovate configuration, so pinned action SHAs and the Node test dependency received no update proposals.

Fix: `SECURITY.md`, `.github/dependabot.yml` (GitHub Actions, Cargo, npm in `tests/`), `NOTICE`, and this folder.

### Randomness

Every generator reached by the engine, after the fixes above.

| Use | Generator | Verdict |
|---|---|---|
| X25519 private keys, ML-KEM seeds `d`, `z`, `m` (`src/native/pq.rs`) | `getrandom` (OS), wrapped in `Zeroizing` | Sound. X25519 scalars are clamped inside `diffie_hellman`; the all-zero shared secret is rejected. |
| ML-KEM key generation with the `pq-hybrid` feature | RustCrypto `ml-kem` with its `getrandom` feature (`SysRng`) | Sound |
| DTLS certificate key and serial (`vendor/str0m-rust-crypto`) | `getrandom` | Sound. Fresh P-256 key and positive 128-bit serial per certificate. |
| DTLS hello randoms, cookie secrets, DTLS 1.2 explicit nonces (dimpl) | `rand::random` (ChaCha12 thread-local, OS-seeded) via `SeededRng` | Sound. The deterministic seed path is active only under str0m's `_internal_test_exports` feature, which qrtc does not enable. |
| DTLS key exchange for classical groups (dimpl RustCrypto provider) | `rand_core::OsRng` | Sound |
| STUN transaction ids of the engine's own STUN and TURN client (`src/native/stun.rs`) | `rand::random` | Sound |
| ICE ufrag and pwd, ICE STUN transaction ids, tie-breaker (`vendor/is`, `vendor/str0m-proto`) | Was `fastrand`; now `getrandom` through `CryptographicRng` | Fixed (QRTC-2026-001). The credential alphabet has 60 symbols (it omits `w` and `W`), so a 22-character password carries about 130 bits. |
| SSRC, RTP sequence numbers, VP8 and VP9 PictureID (str0m) | `fastrand`, now reseeded from the OS per engine thread and before each peer connection is built | Acceptable: these need only be unlikely to collide. |
| Remote-created transceiver track ids (`src/native/driver.rs`) | `rand::random` | Fine; identifiers only. |
| mDNS candidate names (`src/native/mdns.rs`) | `getrandom` (UUID version 4) | Sound |

### Checked and found sound

- No `unsafe` in qrtc's own code. Parsers in `stun.rs`, `mdns.rs` and `turn_stream.rs` use checked slicing; stream framing is capped at 65,555 bytes; remote Opus sample counts are clamped to 5,760 before decoding and decode errors are logged, not propagated.
- STUN and TURN responses are matched on both the server address and the transaction id. Peer-side input to str0m passes `Rtc::accepts`, which checks the ICE credentials or a known remote address.
- The hybrid key agreement follows draft-ietf-tls-ecdhe-mlkem: `ek || x25519_pub`, `ct || x25519_pub`, `ss_mlkem || ss_x25519`; share lengths are checked before splitting; encapsulation keys fail the FIPS 203 modulus check when malformed (tested).
- TURN over TLS: platform trust store with Mozilla roots as the fallback, SNI from the URL, TLS 1.3 only under `require`, no client authentication.
- DTLS fingerprint verification is enabled in str0m. The vendored dimpl patches bound the epoch-0 sequence counter and reject spoofed non-first ClientHello fragments (tests present upstream and in the vendored copy).
- The SDP munging check refuses structural edits (setup role, ICE credentials, fingerprints, m-lines, directions) and tolerates `a=fmtp` and ordering changes.
- CI: actions pinned by commit, `contents: read` by default, `--verify-tag` on release, build provenance attestations, SBOM drift check, `cargo deny` with `unknown-registry` and `unknown-git` denied. The justification for the ignored rustls-webpki 0.102.8 advisories was verified: it is reached only through `rustls-rustcrypto`, which imports only its `alg_id` constants, while path validation uses rustls-webpki 0.103.
- The Node scripts (`tests/*.mjs`, `docs/build.mjs`) spawn processes with argument arrays, not shells, and fetch nothing at run time; the npm lockfile resolves to registry.npmjs.org with integrity hashes.

### Validation

`cargo +1.95 fmt --check` and `cargo +1.95 clippy --all-targets -- -D warnings` pass for the default, pure Rust and classical feature sets, matching CI's pinned lint toolchain. All unit tests pass for the three feature sets, including the new ones for TURN integrity, mDNS packets and names, candidate rewriting and the hybrid key agreement; dimpl's 252 in-tree unit tests pass with `rust-crypto`, including the sentinel test. The four end-to-end tests between two engines in one process (data channel, media, DTMF, post-quantum DTLS) passed in one run and failed in others on the reviewer's machine, where a VPN tunnel intercepts local UDP connectivity checks; they fail the same way on the unmodified code. Their authoritative run is CI, on x86_64 and aarch64 Linux and aarch64 macOS, together with the Chromium and OpenSSL interoperability tests, which also exercise the mDNS names against a browser. The SBOM was regenerated for the Linux target; it differs from the previous one only by the two new dependency edges (`getrandom` under `str0m-proto`, `fastrand` under qrtc).

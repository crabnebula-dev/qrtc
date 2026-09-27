# Local patches to str0m 0.24.0

Source: crates.io `str0m-0.24.0` (src, Cargo.toml, license, readme only; examples,
tests and docs are dropped and their targets removed from the manifest).

1. `src/packet/vp8.rs`, `src/packet/mod.rs`: the VP8 packetizer writes a 15-bit
   PictureID in every payload descriptor, starting at a random value, like
   browsers do. Without it LiveKit's SFU logs "no vp8 pictureID" and never
   forwards our video. Adds `Vp8Packetizer::with_picture_id`. To be proposed
   upstream as a config option; drop this vendor copy once released.

2. `src/change/sdp.rs`: `SdpApi::apply_offer()` always returns an offer, also
   when nothing changed, as JSEP `createOffer()` does. LiveKit (and perfect
   negotiation in general) calls `createOffer()` on an unchanged session.

3. `Cargo.toml`: `str0m-rust-crypto` comes from `vendor/str0m-rust-crypto`
   (crates.io 0.6.0, src and manifest only) with one patch: the DTLS
   certificate (self-signed ECDSA P-256, random 128-bit serial, one year) is
   built with RustCrypto (`p256`, `x509-cert`) instead of dimpl's `rcgen`
   feature. That feature enabled `aws-lc-rs`, compiling AWS-LC (C) into an
   otherwise pure Rust stack.

4. Dev-dependencies are removed from both vendored manifests (their tests are
   not vendored), so SBOMs list only what is built.

5. `str0m-rust-crypto` (`src/lib.rs`, `src/dtls.rs`): `provider_with_dtls`
   builds the RustCrypto crypto provider with `DtlsOptions`: a dimpl crypto
   provider (for extra key exchange groups) and a key exchange group
   preference list. The engine uses it for post-quantum DTLS 1.3; see
   `vendor/dimpl/PATCHES.md`. The default provider is unchanged.

6. `Cargo.toml`: `dimpl`, `is` and `str0m-proto` are path dependencies on the
   copies in `vendor/`, so the patched dimpl applies without a `[patch]`
   section in projects that depend on qrtc. `is` and `str0m-proto` are
   vendored unmodified apart from the same path wiring.

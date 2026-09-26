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

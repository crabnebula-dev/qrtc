# Local patches to dimpl 0.7.4

Source: crates.io `dimpl-0.7.4` (src, manifest, licences and readme only; the
integration tests and dev-dependencies are dropped). The workspace uses this
copy through `[patch.crates-io]` in the root `Cargo.toml`.

The patches add post-quantum key exchange groups to DTLS 1.3. They are
needed by the engine's `pq-hybrid` and `pq-moduletto` features and change
nothing for classical groups. Every changed spot is marked
`Patched (tauri-plugin-webrtc)`. To be proposed upstream.

1. **Named groups** (`src/types.rs`). Adds `MLKEM512`, `MLKEM768`, `MLKEM1024`
   (draft-ietf-tls-mlkem), `SECP256R1MLKEM768` and `X25519MLKEM768`
   (draft-ietf-tls-ecdhe-mlkem), and `X25519MLKEM512_PRIVATE` (0xfe5c, a
   private-use codepoint). `NamedGroup::supported()` grows from 4 to 10
   entries. The group lists in the supported_groups extension and the DTLS
   1.3 client and server use that length as their capacity instead of 4, so
   a peer that offers more groups is no longer rejected.

2. **Key encapsulation** (`src/crypto/provider.rs`, `src/dtls13/server.rs`).
   A KEM server cannot produce its key share before it has the client's:
   the share is a ciphertext for the client's encapsulation key. The new
   `SupportedKxGroup::server_exchange` takes the client's share and returns
   the server's share and the secret. Its default runs the existing
   Diffie-Hellman steps, so classical groups are unchanged. The DTLS 1.3
   server calls it instead of `start_exchange` plus `complete`.

3. **DTLS 1.2 exclusion** (`src/dtls12/`). KEM groups cannot work in DTLS
   1.2, where the server sends its share first. The new
   `SupportedKxGroup::dtls12()` (default `true`) removes them from DTLS 1.2
   offers, selection and key exchange.

4. **Provider validation** (`src/crypto/validation/mod.rs`). The provider
   self-test exchanges keys as a TLS 1.3 client and server (through
   `server_exchange`), which covers both kinds of group. The provider's
   group filter admits the post-quantum groups.

5. **Fragmented hybrid ClientHello** (`src/auto.rs`, `src/dtls12/client.rs`,
   `src/dtls13/client.rs`, `src/dtls13/engine.rs`, `src/lib.rs`). A
   ClientHello with an X25519MLKEM768 share is about 1.4 kB, above the
   DTLS MTU. The auto-sensing client now splits it into MTU-sized records
   (RFC 9147 section 5.5) and tells the forked DTLS 1.2 or 1.3 handshake
   how many epoch-0 records it used.

6. **Fragmented ServerHello detection** (`src/auto.rs`). The auto-sensing
   client decides the version from the first ServerHello record. A
   ServerHello split over several records carries a large key share and is
   DTLS 1.3; a DTLS 1.2 ServerHello always fits one record. The DTLS 1.3
   client then reassembles it.

The patched crate passes its own unit tests (251 with `rust-crypto`, 301 with
the default features), run from a copy with the upstream dev-dependencies
restored.

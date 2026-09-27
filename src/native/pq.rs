//! Post-quantum and hybrid key agreement, shared by DTLS (media and data
//! channels) and TURN over TLS.
//!
//! Every group here is a key encapsulation mechanism (KEM) in the TLS 1.3
//! sense: the client sends an encapsulation key, the server answers with a
//! ciphertext, and both derive the same secret. Hybrid groups concatenate an
//! ML-KEM exchange with an X25519 exchange, following
//! draft-ietf-tls-ecdhe-mlkem: the client share is `ek || x25519_pub`, the
//! server share is `ct || x25519_pub` and the secret is `ss_mlkem || ss_x25519`.
//! The hybrid stays secure while either component does.
//!
//! Groups:
//! - `X25519MLKEM768` (0x11ec): what browsers and TLS servers negotiate.
//!   Preferred. ML-KEM-768 from moduletto (feature `pq-moduletto`) or from
//!   RustCrypto's `ml-kem` (feature `pq-hybrid`).
//! - `MLKEM768` (0x0201): ML-KEM-768 alone.
//! - `X25519MLKEM512` (0xfe5c, feature `pq-moduletto`): X25519 with
//!   ML-KEM-512 (NIST category 1, against 3 for 768), on a private-use
//!   codepoint. Only this engine knows it. It is offered after
//!   X25519MLKEM768, so it is chosen only by a peer that lacks 768.
//! - `MLKEM512` (0x0200, feature `pq-moduletto`): ML-KEM-512 alone.

use std::cell::Cell;
use x25519_dalek::{PublicKey, StaticSecret};

thread_local! {
    /// The post-quantum group of the last DTLS key exchange on this thread.
    /// str0m runs DTLS synchronously inside `Rtc::handle_input`, so the
    /// driver reads this right after each call to learn what was negotiated.
    static NEGOTIATED: Cell<Option<PqGroup>> = const { Cell::new(None) };
}

/// Take the group recorded by a DTLS key exchange on this thread, if any.
pub fn take_negotiated() -> Option<PqGroup> {
    NEGOTIATED.with(|n| n.take())
}

/// A post-quantum or hybrid key exchange group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PqGroup {
    X25519MlKem768,
    MlKem768,
    #[cfg(feature = "pq-moduletto")]
    X25519MlKem512,
    #[cfg(feature = "pq-moduletto")]
    MlKem512,
}

#[derive(Debug, thiserror::Error)]
pub enum PqError {
    #[error("{0}: key share has the wrong length")]
    Length(&'static str),
    #[error("{0}: invalid encapsulation key")]
    InvalidKey(&'static str),
    #[error("{0}: X25519 produced an all-zero secret")]
    NonContributory(&'static str),
    #[error("random number generator: {0}")]
    Rng(String),
}

const X25519_LEN: usize = 32;

impl PqGroup {
    /// Groups in preference order: the interoperable, stronger hybrid first.
    pub fn all() -> &'static [PqGroup] {
        &[
            PqGroup::X25519MlKem768,
            #[cfg(feature = "pq-moduletto")]
            PqGroup::X25519MlKem512,
            PqGroup::MlKem768,
            #[cfg(feature = "pq-moduletto")]
            PqGroup::MlKem512,
        ]
    }

    /// TLS NamedGroup codepoint.
    pub fn codepoint(self) -> u16 {
        match self {
            PqGroup::X25519MlKem768 => 0x11ec,
            PqGroup::MlKem768 => 0x0201,
            #[cfg(feature = "pq-moduletto")]
            PqGroup::X25519MlKem512 => 0xfe5c,
            #[cfg(feature = "pq-moduletto")]
            PqGroup::MlKem512 => 0x0200,
        }
    }

    #[cfg(test)]
    pub fn from_codepoint(c: u16) -> Option<PqGroup> {
        PqGroup::all().iter().copied().find(|g| g.codepoint() == c)
    }

    pub fn name(self) -> &'static str {
        match self {
            PqGroup::X25519MlKem768 => "X25519MLKEM768",
            PqGroup::MlKem768 => "MLKEM768",
            #[cfg(feature = "pq-moduletto")]
            PqGroup::X25519MlKem512 => "X25519MLKEM512",
            #[cfg(feature = "pq-moduletto")]
            PqGroup::MlKem512 => "MLKEM512",
        }
    }

    fn hybrid(self) -> bool {
        match self {
            PqGroup::X25519MlKem768 => true,
            #[cfg(feature = "pq-moduletto")]
            PqGroup::X25519MlKem512 => true,
            _ => false,
        }
    }

    fn kem(self) -> Kem {
        match self {
            PqGroup::X25519MlKem768 | PqGroup::MlKem768 => Kem::MlKem768,
            #[cfg(feature = "pq-moduletto")]
            PqGroup::X25519MlKem512 | PqGroup::MlKem512 => Kem::MlKem512,
        }
    }

    /// Client side: generate key pairs and the key share to send.
    pub fn client_start(self) -> Result<ClientKx, PqError> {
        let (kem_dk, mut share) = self.kem().keypair()?;
        let x = if self.hybrid() {
            let sk = StaticSecret::from(random32()?);
            share.extend_from_slice(PublicKey::from(&sk).as_bytes());
            Some(sk)
        } else {
            None
        };
        Ok(ClientKx { group: self, kem_dk, x, share })
    }

    /// Server side: answer a client's key share. Returns the server's key
    /// share and the shared secret.
    pub fn server_respond(self, client_share: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PqError> {
        let kem = self.kem();
        let x_len = if self.hybrid() { X25519_LEN } else { 0 };
        if client_share.len() != kem.ek_len() + x_len {
            return Err(PqError::Length(self.name()));
        }
        let (ek, x_peer) = client_share.split_at(kem.ek_len());
        let (mut share, mut secret) = kem.encapsulate(ek, self.name())?;
        if self.hybrid() {
            let sk = StaticSecret::from(random32()?);
            share.extend_from_slice(PublicKey::from(&sk).as_bytes());
            secret.extend_from_slice(&x25519(&sk, x_peer, self.name())?);
        }
        Ok((share, secret))
    }
}

/// The client's half of an exchange in progress.
pub struct ClientKx {
    group: PqGroup,
    kem_dk: KemSecret,
    x: Option<StaticSecret>,
    /// The key share to send.
    pub share: Vec<u8>,
}

impl std::fmt::Debug for ClientKx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientKx").field("group", &self.group).finish_non_exhaustive()
    }
}

impl ClientKx {
    pub fn group(&self) -> PqGroup {
        self.group
    }

    /// Combine with the server's key share into the shared secret.
    pub fn complete(self, server_share: &[u8]) -> Result<Vec<u8>, PqError> {
        let name = self.group.name();
        let kem = self.group.kem();
        let x_len = if self.x.is_some() { X25519_LEN } else { 0 };
        if server_share.len() != kem.ct_len() + x_len {
            return Err(PqError::Length(name));
        }
        let (ct, x_peer) = server_share.split_at(kem.ct_len());
        let mut secret = self.kem_dk.decapsulate(ct, name)?;
        if let Some(sk) = &self.x {
            secret.extend_from_slice(&x25519(sk, x_peer, name)?);
        }
        Ok(secret)
    }
}

fn x25519(sk: &StaticSecret, peer: &[u8], name: &'static str) -> Result<[u8; 32], PqError> {
    let peer: [u8; 32] = peer.try_into().map_err(|_| PqError::Length(name))?;
    let ss = sk.diffie_hellman(&PublicKey::from(peer));
    if !ss.was_contributory() {
        return Err(PqError::NonContributory(name));
    }
    Ok(ss.to_bytes())
}

fn random32() -> Result<[u8; 32], PqError> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|e| PqError::Rng(e.to_string()))?;
    Ok(b)
}

// ---------------------------------------------------------------------------
// ML-KEM backends
// ---------------------------------------------------------------------------
//
// ML-KEM-768 comes from moduletto when `pq-moduletto` is on, otherwise from
// RustCrypto's ml-kem (`pq-hybrid`). ML-KEM-512 is moduletto only.

#[derive(Clone, Copy)]
enum Kem {
    MlKem768,
    #[cfg(feature = "pq-moduletto")]
    MlKem512,
}

enum KemSecret {
    #[cfg(not(feature = "pq-moduletto"))]
    MlKem768(Box<ml_kem::DecapsulationKey<ml_kem::MlKem768>>),
    #[cfg(feature = "pq-moduletto")]
    MlKem768(zeroize::Zeroizing<Vec<u8>>),
    #[cfg(feature = "pq-moduletto")]
    MlKem512(zeroize::Zeroizing<Vec<u8>>),
}

impl Kem {
    fn ek_len(self) -> usize {
        match self {
            Kem::MlKem768 => 1184,
            #[cfg(feature = "pq-moduletto")]
            Kem::MlKem512 => moduletto::kem::ml_kem_512::EK_BYTES,
        }
    }

    fn ct_len(self) -> usize {
        match self {
            Kem::MlKem768 => 1088,
            #[cfg(feature = "pq-moduletto")]
            Kem::MlKem512 => moduletto::kem::ml_kem_512::CT_BYTES,
        }
    }

    fn keypair(self) -> Result<(KemSecret, Vec<u8>), PqError> {
        match self {
            #[cfg(not(feature = "pq-moduletto"))]
            Kem::MlKem768 => {
                use ml_kem::kem::Kem as _;
                use ml_kem::KeyExport;
                let (dk, ek) = ml_kem::MlKem768::generate_keypair();
                Ok((KemSecret::MlKem768(Box::new(dk)), ek.to_bytes().to_vec()))
            }
            #[cfg(feature = "pq-moduletto")]
            Kem::MlKem768 => {
                let (ek, dk) = moduletto::kem::ml_kem_768::keygen_derand(&random32()?, &random32()?);
                Ok((KemSecret::MlKem768(zeroize::Zeroizing::new(dk.to_vec())), ek.to_vec()))
            }
            #[cfg(feature = "pq-moduletto")]
            Kem::MlKem512 => {
                let (ek, dk) = moduletto::kem::ml_kem_512::keygen_derand(&random32()?, &random32()?);
                Ok((KemSecret::MlKem512(zeroize::Zeroizing::new(dk.to_vec())), ek.to_vec()))
            }
        }
    }

    /// Encapsulate to a peer's key, after the FIPS 203 encapsulation key check.
    fn encapsulate(self, ek: &[u8], name: &'static str) -> Result<(Vec<u8>, Vec<u8>), PqError> {
        match self {
            #[cfg(not(feature = "pq-moduletto"))]
            Kem::MlKem768 => {
                use ml_kem::kem::Encapsulate;
                use ml_kem::TryKeyInit;
                let ek = ml_kem::EncapsulationKey::<ml_kem::MlKem768>::new_from_slice(ek)
                    .map_err(|_| PqError::InvalidKey(name))?;
                let (ct, ss) = ek.encapsulate();
                Ok((ct.to_vec(), ss.to_vec()))
            }
            #[cfg(feature = "pq-moduletto")]
            Kem::MlKem768 => {
                let (ct, ss) = moduletto::kem::ml_kem_768::encaps_derand(ek, &random32()?)
                    .map_err(|_| PqError::InvalidKey(name))?;
                Ok((ct.to_vec(), ss.to_vec()))
            }
            #[cfg(feature = "pq-moduletto")]
            Kem::MlKem512 => {
                let (ct, ss) = moduletto::kem::ml_kem_512::encaps_derand(ek, &random32()?)
                    .map_err(|_| PqError::InvalidKey(name))?;
                Ok((ct.to_vec(), ss.to_vec()))
            }
        }
    }
}

impl KemSecret {
    fn decapsulate(&self, ct: &[u8], name: &'static str) -> Result<Vec<u8>, PqError> {
        match self {
            #[cfg(not(feature = "pq-moduletto"))]
            KemSecret::MlKem768(dk) => {
                use ml_kem::kem::Decapsulate;
                let ct: ml_kem::Ciphertext<ml_kem::MlKem768> =
                    ct.try_into().map_err(|_| PqError::Length(name))?;
                Ok(dk.decapsulate(&ct).to_vec())
            }
            #[cfg(feature = "pq-moduletto")]
            KemSecret::MlKem768(dk) => moduletto::kem::ml_kem_768::decaps(dk, ct)
                .map(|ss| ss.to_vec())
                .map_err(|_| PqError::Length(name)),
            #[cfg(feature = "pq-moduletto")]
            KemSecret::MlKem512(dk) => moduletto::kem::ml_kem_512::decaps(dk, ct)
                .map(|ss| ss.to_vec())
                .map_err(|_| PqError::Length(name)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_group_agrees() {
        for &g in PqGroup::all() {
            let c = g.client_start().unwrap();
            let (share, s_secret) = g.server_respond(&c.share).unwrap();
            let c_secret = c.complete(&share).unwrap();
            assert_eq!(c_secret, s_secret, "{}", g.name());
            assert_eq!(c_secret.len(), if g.hybrid() { 64 } else { 32 });
            assert_eq!(PqGroup::from_codepoint(g.codepoint()), Some(g));
        }
    }

    #[test]
    fn rejects_malformed_shares() {
        let g = PqGroup::X25519MlKem768;
        let c = g.client_start().unwrap();
        assert!(g.server_respond(&c.share[1..]).is_err());
        // An X25519 low-order point (all zero) must not yield a secret.
        let mut bad = c.share.clone();
        let n = bad.len();
        bad[n - 32..].fill(0);
        assert!(matches!(g.server_respond(&bad), Err(PqError::NonContributory(_))));
        // A coefficient >= q in the encapsulation key fails the modulus check.
        let mut bad = c.share.clone();
        bad[0] = 0xff;
        bad[1] |= 0x0f;
        assert!(matches!(g.server_respond(&bad), Err(PqError::InvalidKey(_))));
    }

    /// moduletto and RustCrypto implement the same FIPS 203, so each can
    /// decapsulate what the other encapsulated, for both parameter sets.
    #[cfg(all(feature = "pq-moduletto", feature = "pq-hybrid"))]
    #[test]
    fn moduletto_interoperates_with_rustcrypto() {
        use ml_kem::kem::{Decapsulate, Encapsulate, Kem as _};
        use ml_kem::{KeyExport, TryKeyInit};
        use moduletto::kem::{ml_kem_512 as m512, ml_kem_768 as m768};
        macro_rules! both_ways {
            ($rc:ty, $m:ident) => {{
                // RustCrypto key pair, moduletto encapsulates.
                let (dk, ek) = <$rc>::generate_keypair();
                let (ct, ss) = $m::encaps_derand(&ek.to_bytes(), &random32().unwrap()).unwrap();
                let ct: ml_kem::Ciphertext<$rc> = ct.as_slice().try_into().unwrap();
                assert_eq!(dk.decapsulate(&ct).as_slice(), ss.as_slice());
                // moduletto key pair, RustCrypto encapsulates.
                let (ek, dk) = $m::keygen_derand(&random32().unwrap(), &random32().unwrap());
                let ek = ml_kem::EncapsulationKey::<$rc>::new_from_slice(&ek).unwrap();
                let (ct, ss) = ek.encapsulate();
                assert_eq!($m::decaps(&dk, &ct).unwrap().as_slice(), ss.as_slice());
            }};
        }
        for _ in 0..20 {
            both_ways!(ml_kem::MlKem512, m512);
            both_ways!(ml_kem::MlKem768, m768);
        }
    }
}

// ---------------------------------------------------------------------------
// DTLS 1.3 (dimpl)
// ---------------------------------------------------------------------------

/// Post-quantum groups as dimpl key exchange groups.
pub mod dtls {
    use super::{ClientKx, PqError, PqGroup};
    use crate::PqPolicy;
    use dimpl::crypto::{ActiveKeyExchange, Buf, CryptoProvider, SupportedKxGroup};
    use dimpl::{CryptoError, NamedGroup};
    use std::sync::{Arc, OnceLock};

    #[derive(Debug)]
    struct Group(PqGroup);

    impl Group {
        fn named(&self) -> NamedGroup {
            NamedGroup::from_u16(self.0.codepoint())
        }

        fn err(&self, e: PqError) -> CryptoError {
            log::debug!("DTLS {}: {e}", self.0.name());
            match e {
                PqError::Rng(_) => CryptoError::InvalidPrivateKey,
                _ => CryptoError::InvalidPublicKey(self.named()),
            }
        }
    }

    impl SupportedKxGroup for Group {
        fn name(&self) -> NamedGroup {
            self.named()
        }

        fn start_exchange(&self, _buf: Buf) -> Result<Box<dyn ActiveKeyExchange>, CryptoError> {
            let kx = self.0.client_start().map_err(|e| self.err(e))?;
            Ok(Box::new(Active(kx)))
        }

        fn server_exchange(
            &self,
            _buf: Buf,
            peer_pub: &[u8],
            server_share: &mut Buf,
            shared_secret: &mut Buf,
        ) -> Result<(), CryptoError> {
            let (share, secret) = self.0.server_respond(peer_pub).map_err(|e| self.err(e))?;
            server_share.clear();
            server_share.extend_from_slice(&share);
            shared_secret.clear();
            shared_secret.extend_from_slice(&secret);
            log::debug!("DTLS 1.3 key exchange (server): {}", self.0.name());
            super::NEGOTIATED.with(|n| n.set(Some(self.0)));
            Ok(())
        }

        fn dtls12(&self) -> bool {
            false
        }
    }

    #[derive(Debug)]
    struct Active(ClientKx);

    impl ActiveKeyExchange for Active {
        fn pub_key(&self) -> &[u8] {
            &self.0.share
        }

        fn complete(self: Box<Self>, peer_pub: &[u8], out: &mut Buf) -> Result<(), CryptoError> {
            let g = Group(self.0.group());
            let secret = self.0.complete(peer_pub).map_err(|e| g.err(e))?;
            out.clear();
            out.extend_from_slice(&secret);
            log::debug!("DTLS 1.3 key exchange (client): {}", g.0.name());
            super::NEGOTIATED.with(|n| n.set(Some(g.0)));
            Ok(())
        }

        fn group(&self) -> NamedGroup {
            NamedGroup::from_u16(self.0.group().codepoint())
        }
    }

    /// A str0m crypto provider whose DTLS offers the groups `policy` allows,
    /// or `None` for [`PqPolicy::Off`] (str0m's default then applies).
    pub fn str0m_provider(policy: PqPolicy) -> Option<Arc<str0m::config::CryptoProvider>> {
        static PREFER: OnceLock<Arc<str0m::config::CryptoProvider>> = OnceLock::new();
        static REQUIRE: OnceLock<Arc<str0m::config::CryptoProvider>> = OnceLock::new();
        let cell = match policy {
            PqPolicy::Off => return None,
            PqPolicy::Prefer => &PREFER,
            PqPolicy::Require => &REQUIRE,
        };
        Some(cell.get_or_init(|| Arc::new(build(policy))).clone())
    }

    fn build(policy: PqPolicy) -> str0m::config::CryptoProvider {
        let base = dimpl::crypto::rust_crypto::default_provider();
        let pq: Vec<&'static dyn SupportedKxGroup> = PqGroup::all()
            .iter()
            .map(|g| &*Box::leak(Box::new(Group(*g))) as &'static dyn SupportedKxGroup)
            .collect();
        let mut groups: Vec<NamedGroup> = pq.iter().map(|g| g.name()).collect();
        let mut all = pq;
        if policy == PqPolicy::Prefer {
            // Classical groups after the post-quantum ones.
            all.extend(base.kx_groups.iter().copied());
            groups.extend(base.kx_groups.iter().map(|g| g.name()));
        }
        let provider = CryptoProvider {
            kx_groups: Box::leak(all.into_boxed_slice()),
            ..base
        };
        str0m_rust_crypto::provider_with_dtls(str0m_rust_crypto::DtlsOptions {
            provider: Some(provider),
            kx_groups: Some(groups),
        })
    }
}

// ---------------------------------------------------------------------------
// TLS 1.3 (rustls), for TURN over TLS
// ---------------------------------------------------------------------------

/// Post-quantum groups as rustls key exchange groups (client side).
#[cfg(feature = "_turn-tls")]
pub mod tls {
    use super::{ClientKx, PqError, PqGroup};
    use crate::PqPolicy;
    use rustls::crypto::{
        ActiveKeyExchange, CompletedKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup,
    };
    use rustls::{NamedGroup, ProtocolVersion};

    #[derive(Debug)]
    struct Group(PqGroup);

    fn err(g: PqGroup, e: PqError) -> rustls::Error {
        rustls::Error::General(format!("{}: {e}", g.name()))
    }

    impl SupportedKxGroup for Group {
        fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
            Ok(Box::new(Active(self.0.client_start().map_err(|e| err(self.0, e))?)))
        }

        fn start_and_complete(&self, peer: &[u8]) -> Result<CompletedKeyExchange, rustls::Error> {
            let (pub_key, secret) = self.0.server_respond(peer).map_err(|e| err(self.0, e))?;
            Ok(CompletedKeyExchange {
                group: self.name(),
                pub_key,
                secret: SharedSecret::from(secret),
            })
        }

        fn name(&self) -> NamedGroup {
            NamedGroup::from(self.0.codepoint())
        }

        fn usable_for_version(&self, version: ProtocolVersion) -> bool {
            version == ProtocolVersion::TLSv1_3
        }
    }

    #[derive(Debug)]
    struct Active(ClientKx);

    impl ActiveKeyExchange for Active {
        fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, rustls::Error> {
            let g = self.0.group();
            Ok(SharedSecret::from(self.0.complete(peer).map_err(|e| err(g, e))?))
        }

        fn pub_key(&self) -> &[u8] {
            &self.0.share
        }

        fn group(&self) -> NamedGroup {
            NamedGroup::from(self.0.group().codepoint())
        }
    }

    /// `base` with the interoperable post-quantum groups in front (`Prefer`)
    /// or instead of the classical ones (`Require`). The private-codepoint
    /// moduletto group is left out: TURN servers do not know it.
    pub fn with_pq_groups(mut base: CryptoProvider, policy: PqPolicy) -> CryptoProvider {
        let mut groups: Vec<&'static dyn SupportedKxGroup> = [PqGroup::X25519MlKem768, PqGroup::MlKem768]
            .into_iter()
            .map(|g| &*Box::leak(Box::new(Group(g))) as &'static dyn SupportedKxGroup)
            .collect();
        if policy == PqPolicy::Prefer {
            groups.extend(base.kx_groups.iter().copied());
        }
        base.kx_groups = groups;
        base
    }
}

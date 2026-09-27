//! RustCrypto implementation of cryptographic functions.
//! DTLS via dimpl with RustCrypto as crypto backend.

mod dtls;
mod sha1;
mod sha256;
mod srtp;

use dtls::RustCryptoDtlsProvider;
use sha1::RustCryptoSha1HmacProvider;
use sha256::RustCryptoSha256Provider;
use srtp::RustCryptoSrtpProvider;
use str0m_proto::crypto::CryptoProvider;

/// Create the default RustCrypto crypto provider.
///
/// This provider implements all cryptographic operations required for WebRTC:
/// - DTLS 1.2 for secure key exchange (using dimpl protocol + RustCrypto)
/// - SRTP for encrypted media
/// - SHA1-HMAC for STUN message integrity
/// - SHA-256 for certificate fingerprints
///
/// # Supported SRTP Profiles
///
/// - `SRTP_AES128_CM_SHA1_80`
/// - `SRTP_AEAD_AES_128_GCM`
/// - `SRTP_AEAD_AES_256_GCM`
pub fn default_provider() -> CryptoProvider {
    static SRTP: RustCryptoSrtpProvider = RustCryptoSrtpProvider;
    static SHA1_HMAC: RustCryptoSha1HmacProvider = RustCryptoSha1HmacProvider;
    static SHA256: RustCryptoSha256Provider = RustCryptoSha256Provider;
    static DTLS: RustCryptoDtlsProvider = RustCryptoDtlsProvider {
        options: DtlsOptions {
            provider: None,
            kx_groups: None,
        },
    };

    CryptoProvider {
        srtp_provider: &SRTP,
        sha1_hmac_provider: &SHA1_HMAC,
        sha256_provider: &SHA256,
        dtls_provider: &DTLS,
    }
}

/// Patched (tauri-plugin-webrtc): DTLS options for [`provider_with_dtls`].
#[derive(Debug, Clone, Default)]
pub struct DtlsOptions {
    /// dimpl crypto provider to use instead of dimpl's RustCrypto default,
    /// for example one with additional key exchange groups.
    pub provider: Option<dimpl::crypto::CryptoProvider>,
    /// Key exchange groups to offer and accept, in preference order.
    pub kx_groups: Option<Vec<dimpl::NamedGroup>>,
}

/// Patched (tauri-plugin-webrtc): the RustCrypto provider with DTLS options.
///
/// The DTLS provider is leaked to get the `'static` lifetime str0m expects,
/// so call this once per distinct configuration and reuse the result.
pub fn provider_with_dtls(options: DtlsOptions) -> CryptoProvider {
    let mut p = default_provider();
    p.dtls_provider = Box::leak(Box::new(RustCryptoDtlsProvider { options }));
    p
}

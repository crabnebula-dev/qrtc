//! DTLS implementation using dimpl with RustCrypto backend.

use std::sync::Arc;
use std::time::Instant;

use str0m_proto::crypto::CryptoError;
use str0m_proto::crypto::DtlsVersion;
use str0m_proto::crypto::dtls::ProtocolVersion;
use str0m_proto::crypto::dtls::{DtlsCert, DtlsImplError, DtlsInstance, DtlsOutput, DtlsProvider};

// ============================================================================
// DTLS Provider Implementation
// ============================================================================

#[derive(Debug)]
pub(super) struct RustCryptoDtlsProvider;

impl DtlsProvider for RustCryptoDtlsProvider {
    fn generate_certificate(&self) -> Option<DtlsCert> {
        // Patched (tauri-plugin-webrtc): pure RustCrypto instead of rcgen.
        self_signed_p256().ok()
    }

    fn new_dtls(
        &self,
        cert: &DtlsCert,
        now: Instant,
        dtls_version: DtlsVersion,
        mtu: Option<usize>,
    ) -> Result<Box<dyn DtlsInstance>, CryptoError> {
        let dimpl_cert = dimpl::DtlsCertificate {
            certificate: cert.certificate.clone(),
            private_key: cert.private_key.clone(),
        };

        // Create a default dimpl Config with RustCrypto crypto provider
        // ICE verifies return routability before DTLS, making server cookies redundant.
        let mut builder = dimpl::Config::builder().use_server_cookie(false);
        if let Some(mtu) = mtu {
            builder = builder.mtu(mtu);
        }
        if self.is_test() {
            // We need the DTLS impl to be deterministic for the BWE tests.
            builder = builder.dangerously_set_rng_seed(42);
        }

        let config = builder
            .build()
            .map_err(|e| CryptoError::Other(format!("dimpl config creation failed: {}", e)))?;

        let config = Arc::new(config);
        let dtls = match dtls_version {
            DtlsVersion::Dtls12 => dimpl::Dtls::new_12(config, dimpl_cert, now),
            DtlsVersion::Dtls13 => dimpl::Dtls::new_13(config, dimpl_cert, now),
            DtlsVersion::Auto => dimpl::Dtls::new_auto(config, dimpl_cert, now),
            _ => {
                return Err(CryptoError::Other(format!(
                    "Unsupported DTLS version: {dtls_version}"
                )));
            }
        };

        Ok(Box::new(RustCryptoDtlsInstance { dtls }))
    }
}

// ============================================================================
// DTLS Instance Wrapper
// ============================================================================

struct RustCryptoDtlsInstance {
    dtls: dimpl::Dtls,
}

impl std::fmt::Debug for RustCryptoDtlsInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustCryptoDtlsInstance").finish()
    }
}

impl DtlsInstance for RustCryptoDtlsInstance {
    fn set_active(&mut self, active: bool) {
        self.dtls.set_active(active);
    }

    fn handle_packet(&mut self, packet: &[u8]) -> Result<(), DtlsImplError> {
        self.dtls.handle_packet(packet)
    }

    fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> DtlsOutput<'a> {
        self.dtls.poll_output(buf)
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), DtlsImplError> {
        self.dtls.handle_timeout(now)
    }

    fn send_application_data(&mut self, data: &[u8]) -> Result<(), DtlsImplError> {
        self.dtls.send_application_data(data)
    }

    fn is_active(&self) -> bool {
        self.dtls.is_active()
    }

    fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.dtls.protocol_version()
    }

    fn is_closing(&self) -> bool {
        self.dtls.is_closing()
    }

    fn is_closed(&self) -> bool {
        self.dtls.is_closed()
    }

    fn close(&mut self) -> Result<(), DtlsImplError> {
        self.dtls.close()
    }
}

/// Self-signed ECDSA P-256 certificate for DTLS, like dimpl's rcgen path:
/// CN "DTLS Peer", O "DTLS", random 128-bit serial (unique across processes
/// for Firefox, str0m#517), one year validity. Key as PKCS#8 DER.
fn self_signed_p256() -> Result<DtlsCert, Box<dyn std::error::Error>> {
    use p256::ecdsa::{DerSignature, SigningKey};
    use p256::pkcs8::EncodePrivateKey;
    use std::str::FromStr;
    use std::time::Duration;
    use x509_cert::builder::{Builder, CertificateBuilder, Profile};
    use x509_cert::der::Encode;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;
    use x509_cert::time::Validity;

    let key = loop {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)?;
        if let Ok(k) = SigningKey::from_slice(&seed) {
            break k;
        }
    };
    let mut serial = [0u8; 16];
    getrandom::fill(&mut serial)?;
    serial[0] &= 0x7f; // positive INTEGER
    let subject = Name::from_str("CN=DTLS Peer,O=DTLS")?;
    let spki = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key())?;
    let builder = CertificateBuilder::new(
        Profile::Leaf { issuer: subject.clone(), enable_key_agreement: false, enable_key_encipherment: false },
        SerialNumber::new(&serial)?,
        Validity::from_now(Duration::from_secs(365 * 24 * 3600))?,
        subject,
        spki,
        &key,
    )?;
    let cert = builder.build::<DerSignature>()?;
    Ok(DtlsCert {
        certificate: cert.to_der()?,
        private_key: key.to_pkcs8_der()?.as_bytes().to_vec(),
    })
}

#[cfg(test)]
mod cert_tests {
    #[test]
    fn self_signed_parses_and_differs() {
        let a = super::self_signed_p256().unwrap();
        let b = super::self_signed_p256().unwrap();
        assert_ne!(a.certificate, b.certificate);
        use x509_cert::der::Decode;
        let c = x509_cert::Certificate::from_der(&a.certificate).unwrap();
        assert_eq!(c.tbs_certificate.subject.to_string(), "CN=DTLS Peer,O=DTLS");
    }
}

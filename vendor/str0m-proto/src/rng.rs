/// Patched (tauri-plugin-webrtc): randomness from the operating system, for
/// values that must be unguessable: ICE credentials (RFC 8445 section 5.3),
/// STUN transaction ids (RFC 8489 section 6) and the ICE tie-breaker.
///
/// `NonCryptographicRng` below is `fastrand`, whose thread-local state is
/// seeded from the clock and the thread id on native targets and is
/// recoverable from its outputs. It stays in use for RTP identifiers.
pub struct CryptographicRng;

impl CryptographicRng {
    /// Fill `buf` from the operating system. Panics if the OS generator is
    /// unavailable, as `rand`'s `OsRng` does: there is no safe fallback.
    pub fn fill(buf: &mut [u8]) {
        getrandom::fill(buf).expect("operating system random number generator");
    }

    pub fn u64() -> u64 {
        let mut b = [0u8; 8];
        Self::fill(&mut b);
        u64::from_ne_bytes(b)
    }
}

/// Fast, non-cryptographic randomness for identifiers that only need to be
/// unlikely to collide (SSRC, sequence numbers, PictureID).
pub struct NonCryptographicRng;

impl NonCryptographicRng {
    #[inline(always)]
    pub fn u8() -> u8 {
        fastrand::u8(..)
    }

    #[inline(always)]
    pub fn u16() -> u16 {
        fastrand::u16(..)
    }

    #[inline(always)]
    pub fn u32() -> u32 {
        fastrand::u32(..)
    }

    #[inline(always)]
    pub fn u64() -> u64 {
        fastrand::u64(..)
    }

    #[inline(always)]
    pub fn f32() -> f32 {
        fastrand::f32()
    }
}

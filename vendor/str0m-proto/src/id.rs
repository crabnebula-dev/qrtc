use std::fmt;
use std::str::from_utf8;

use crate::CryptographicRng;

// deliberate subset of ice-char, etc that are "safe"
const CHARS: &[u8] = b"abcdefghijklmnopqrstuvxyzABCDEFGHIJKLMNOPQRSTUVXYZ0123456789";

pub struct Id<const L: usize>([u8; L]);

impl<const L: usize> Id<L> {
    /// Patched (tauri-plugin-webrtc): `Id` is used for ice-ufrag and
    /// ice-pwd, which RFC 8445 section 5.3 requires to be unguessable, so
    /// the bytes come from the operating system. Rejection sampling keeps
    /// the choice uniform over `CHARS`.
    pub fn random() -> Id<L> {
        let limit = 256 - 256 % CHARS.len();
        let mut buf = [0u8; 64];
        let mut i = buf.len();
        let mut x = [0; L];
        for val in x.iter_mut() {
            loop {
                if i == buf.len() {
                    CryptographicRng::fill(&mut buf);
                    i = 0;
                }
                let b = buf[i] as usize;
                i += 1;
                if b < limit {
                    *val = CHARS[b % CHARS.len()];
                    break;
                }
            }
        }
        Id(x)
    }

    pub fn into_array(self) -> [u8; L] {
        self.0
    }
}

impl<const L: usize> Default for Id<L> {
    fn default() -> Self {
        Id::random()
    }
}

impl<const L: usize> fmt::Display for Id<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = from_utf8(&self.0).expect("ascii characters");
        write!(f, "{s}")
    }
}

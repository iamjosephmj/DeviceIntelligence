//! Fixed lab HMAC key for stateless session tokens — shared by every port.

pub const SERVER_KEY: &[u8] = b"intel-lab-session-key-v1";

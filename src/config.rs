use rand::{RngCore, rngs::OsRng};
use hex;


/// Generates a 512-bit (64-byte) secure random secret and returns it as a hex string.
pub fn generate_jwt_secret() -> String {
    let mut key = [0u8; 64];
    OsRng.fill_bytes(&mut key);
    hex::encode(key)
}
//! Rust interfaces to Ledger SDK APIs.

use crate::constants;
use aes::{
    block_cipher_trait::{
        generic_array::typenum::{U16, U32, U8},
        generic_array::GenericArray,
        BlockCipher,
    },
    Aes256,
};

use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};
use blake2s_simd::{blake2s, Hash as Blake2sHash, Params as Blake2sParams};
use core::convert::TryInto;
use core::slice;

#[cfg(any(unix, windows))]
use getrandom::getrandom;
use jubjub::AffinePoint;
use rand::{CryptoRng, RngCore};

extern "C" {
    fn bolos_cx_rng(buffer: *mut u8, len: u32);
    fn c_zcash_blake2b_expand_seed(
        input_a: *const u8,
        input_a_len: u32,
        input_b: *const u8,
        input_b_len: u32,
        out: *mut u8,
    );
    fn c_aes256_encryptblock(k: *const u8, a: *const u8, out: *mut u8);
    fn c_zcash_blake2b_expand_vec_two(
        input_a: *const u8,
        input_a_len: u32,
        input_b: *const u8,
        input_b_len: u32,
        input_c: *const u8,
        input_c_len: u32,
        out: *mut u8,
    );

    fn c_blake2b32_withpersonal(person: *const u8, input: *const u8, input_len: u32, out: *mut u8);
    fn c_blake2b64_withpersonal(person: *const u8, input: *const u8, input_len: u32, out: *mut u8);

    fn c_zcash_blake2b_expand_vec_four(
        input_a: *const u8,
        input_a_len: u32,
        input_b: *const u8,
        input_b_len: u32,
        input_c: *const u8,
        input_c_len: u32,
        input_d: *const u8,
        input_d_len: u32,
        input_e: *const u8,
        input_e_len: u32,
        out: *mut u8,
    );
    fn c_zcash_blake2b_zip32master(a: *const u8, a_len: u32, out: *mut u8);

    fn check_app_canary();
    fn zcash_blake2b_expand_seed(a: *const u8, a_len: u32, b: *const u8, b_len: u32, out: *mut u8);
    fn c_zcash_blake2b_redjubjub(a: *const u8, a_len: u32, b: *const u8, b_len: u32, out: *mut u8);
    fn c_jubjub_scalarmult(point: *mut u8, scalar: *const u8);
    fn c_jubjub_spending_base_scalarmult(point: *mut u8, scalar: *const u8);
}

pub fn sdk_jubjub_scalarmult_spending_base(point: &mut [u8], scalar: &[u8]) {
    let mut scalarbytes = [0u8; 32];
    scalarbytes.copy_from_slice(&scalar);
    let result = constants::SPENDING_KEY_BASE.multiply_bits(&scalarbytes);
    point.copy_from_slice(&AffinePoint::from(result).to_bytes());
}

pub fn sdk_jubjub_scalarmult(point: &mut [u8], scalar: &[u8]) {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&point);
    let mut scalarbytes = [0u8; 32];
    scalarbytes.copy_from_slice(&scalar);
    let result = jubjub::AffinePoint::from_bytes(bytes)
        .unwrap()
        .to_niels()
        .multiply_bits(&scalarbytes);
    point.copy_from_slice(&AffinePoint::from(result).to_bytes());
}


pub fn blake2b32_with_personalization(person: &[u8; 16], data: &[u8]) -> [u8; 32] {
    let h = Blake2bParams::new()
        .hash_length(32)
        .personal(person)
        .hash(data);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&h.as_bytes());
    hash
}

pub fn blake2b64_with_personalization(person: &[u8; 16], data: &[u8]) -> [u8; 64] {
    let h = Blake2bParams::new()
        .hash_length(64)
        .personal(person)
        .hash(data);
    let mut hash = [0u8; 64];
    hash.copy_from_slice(&h.as_bytes());
    hash
}

pub fn blake2b_redjubjub(a: &[u8], b: &[u8]) -> [u8; 64] {
    pub const REDJUBJUB_PERSONALIZATION: &[u8; 16] = b"MASP__RedJubjubH";

    let h = Blake2bParams::new()
        .hash_length(64)
        .personal(REDJUBJUB_PERSONALIZATION)
        .to_state()
        .update(a)
        .update(b)
        .finalize();

    let result: [u8; 64] = *h.as_array();
    result
}

pub fn c_check_app_canary() {}

pub fn aes256_encryptblock(k: &[u8], a: &[u8]) -> [u8; 16] {
    let cipher: Aes256 = Aes256::new(GenericArray::from_slice(k));
    //cipher.encrypt_block(block);

    let mut b = GenericArray::clone_from_slice(a);
    cipher.encrypt_block(&mut b);

    let out: [u8; 16] = b.as_slice().try_into().expect("err");
    out
}

pub fn blake2b_expand_seed(a: &[u8], b: &[u8]) -> [u8; 64] {
    pub const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"MASP__ExpandSeed";

    let h = Blake2bParams::new()
        .hash_length(64)
        .personal(PRF_EXPAND_PERSONALIZATION)
        .to_state()
        .update(a)
        .update(b)
        .finalize();

    let result: [u8; 64] = *h.as_array();
    result
}

#[inline(never)]
pub fn blake2s_diversification(tag: &[u8]) -> [u8; 32] {
    pub const KEY_DIVERSIFICATION_PERSONALIZATION: &[u8; 8] = b"MASP__gd";
    pub const GH_FIRST_BLOCK: &[u8; 64] =
        b"096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0";

    let h = Blake2sParams::new()
        .hash_length(32)
        .personal(KEY_DIVERSIFICATION_PERSONALIZATION)
        .to_state()
        .update(GH_FIRST_BLOCK)
        .update(tag)
        .finalize();

    let result: [u8; 32] = *h.as_array();
    result
}

#[no_mangle]
pub unsafe extern "C" fn rust_blake2b_expand_vec_two(
    in_sk_ptr: *const u8,
    in_sk_len: usize,
    in_b_ptr: *const u8,
    in_b_len: usize,
    in_c_ptr: *const u8,
    in_c_len: usize,
    out_hash_ptr: *mut u8,
    out_hash_len: usize,
) {

    // Convert the input pointers and lengths into slices
    let sk = slice::from_raw_parts(in_sk_ptr, in_sk_len);
    let in_b = slice::from_raw_parts(in_b_ptr, in_b_len);
    let in_c = slice::from_raw_parts(in_c_ptr, in_c_len);

    // Call the original function
    let hash = blake2b_expand_vec_two(sk, in_b, in_c);

    // Copy the result back to the C memory location
    let out_hash = slice::from_raw_parts_mut(out_hash_ptr, out_hash_len);
    out_hash.copy_from_slice(&hash);
}

pub fn blake2b_expand_vec_two(sk: &[u8], a: &[u8], b: &[u8]) -> [u8; 64] {
    pub const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"MASP__ExpandSeed";
    let mut h = Blake2bParams::new()
        .hash_length(64)
        .personal(PRF_EXPAND_PERSONALIZATION)
        .to_state();
    h.update(sk);
    h.update(a);
    h.update(b);
    let mut hash = [0u8; 64];
    hash.copy_from_slice(&h.finalize().as_bytes());
    hash
}

#[no_mangle]
pub unsafe extern "C" fn rust_blake2b_expand_vec_three(
    in_a_ptr: *const u8,
    in_a_len: usize,
    in_b_ptr: *const u8,
    in_b_len: usize,
    in_c_ptr: *const u8,
    in_c_len: usize,
    in_d_ptr: *const u8,
    in_d_len: usize,
    out_hash_ptr: *mut u8,
    out_hash_len: usize,
) {

    // Convert the input pointers and lengths into slices
    let in_a = slice::from_raw_parts(in_a_ptr, in_a_len);
    let in_b = slice::from_raw_parts(in_b_ptr, in_b_len);
    let in_c = slice::from_raw_parts(in_c_ptr, in_c_len);
    let in_d = slice::from_raw_parts(in_d_ptr, in_d_len);

    // Call the original function
    let hash = blake2b_expand_vec_three(in_a, in_b, in_c, in_d);

    // Copy the result back to the C memory location
    let out_hash = slice::from_raw_parts_mut(out_hash_ptr, out_hash_len);
    out_hash.copy_from_slice(&hash);
}


pub fn blake2b_expand_vec_three(
    in_a: &[u8],
    in_b: &[u8],
    in_c: &[u8],
    in_d: &[u8],
) -> [u8; 64] {
    pub const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"MASP__ExpandSeed";
    let mut blake2b_state = Blake2bParams::new()
        .hash_length(64)
        .personal(PRF_EXPAND_PERSONALIZATION)
        .to_state();
    blake2b_state.update(in_a);
    blake2b_state.update(in_b);
    blake2b_state.update(in_c);
    blake2b_state.update(in_d);
    let mut hash = [0u8; 64];
    hash.copy_from_slice(&blake2b_state.finalize().as_bytes());
    hash
}


#[no_mangle]
pub unsafe extern "C" fn rust_blake2b_expand_vec_four(
    in_a_ptr: *const u8,
    in_a_len: usize,
    in_b_ptr: *const u8,
    in_b_len: usize,
    in_c_ptr: *const u8,
    in_c_len: usize,
    in_d_ptr: *const u8,
    in_d_len: usize,
    in_e_ptr: *const u8,
    in_e_len: usize,
    out_hash_ptr: *mut u8,
    out_hash_len: usize,
) {

    // Convert the input pointers and lengths into slices
    let in_a = slice::from_raw_parts(in_a_ptr, in_a_len);
    let in_b = slice::from_raw_parts(in_b_ptr, in_b_len);
    let in_c = slice::from_raw_parts(in_c_ptr, in_c_len);
    let in_d = slice::from_raw_parts(in_d_ptr, in_d_len);
    let in_e = slice::from_raw_parts(in_e_ptr, in_e_len);

    // Call the original function
    let hash = blake2b_expand_vec_four(in_a, in_b, in_c, in_d, in_e);

    // Copy the result back to the C memory location
    let out_hash = slice::from_raw_parts_mut(out_hash_ptr, out_hash_len);
    out_hash.copy_from_slice(&hash);
}



pub fn blake2b_expand_vec_four(
    in_a: &[u8],
    in_b: &[u8],
    in_c: &[u8],
    in_d: &[u8],
    in_e: &[u8],
) -> [u8; 64] {
    pub const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"MASP__ExpandSeed";
    let mut blake2b_state = Blake2bParams::new()
        .hash_length(64)
        .personal(PRF_EXPAND_PERSONALIZATION)
        .to_state();
    blake2b_state.update(in_a);
    blake2b_state.update(in_b);
    blake2b_state.update(in_c);
    blake2b_state.update(in_d);
    blake2b_state.update(in_e);
    let mut hash = [0u8; 64];
    hash.copy_from_slice(&blake2b_state.finalize().as_bytes());
    hash
}

pub struct Trng;

impl RngCore for Trng {
    fn next_u32(&mut self) -> u32 {
        let mut out = [0; 4];
        self.fill_bytes(&mut out);
        u32::from_le_bytes(out)
    }

    fn next_u64(&mut self) -> u64 {
        let mut out = [0; 8];
        self.fill_bytes(&mut out);
        u64::from_le_bytes(out)
    }

    #[cfg(not(any(unix, windows)))]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        unsafe {
            bolos_cx_rng(dest.as_mut_ptr(), dest.len() as u32);
        }
    }


    #[cfg(any(unix, windows))]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom(dest).unwrap()
    }


    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for Trng {}


mod tests {
    use super::*;

    #[test]
    fn test_randomness() {
        let mut buf = [0u8; 64];
        Trng.fill_bytes(&mut buf);
        assert_ne!(buf[..], [0u8; 64][..]);
    }
}

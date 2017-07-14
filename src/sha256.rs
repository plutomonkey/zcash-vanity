use byteorder::{BigEndian, ByteOrder};
use crypto::sha2::sha256_digest_block;

static H256: [u32; 8] = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
];

pub fn sha256_compress(dst: &mut [u8; 32], src: &[u8; 64]) {
    let mut state = H256;
    sha256_digest_block(&mut state, src);
    BigEndian::write_u32_into(&state, dst);
}

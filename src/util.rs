use bs58;
use crypto::digest::Digest;
use crypto::sha2::Sha256;

pub fn bs58_encode_check(input: &[u8]) -> String {
    let mut check = [0u8; 32];
    let mut sha = Sha256::new();
    sha.input(input);
    sha.result(&mut check);
    sha.reset();
    sha.input(&check);
    sha.result(&mut check);

    let mut output = input.to_vec();
    for &b in check.iter().take(4) {
        output.push(b);
    }
    bs58::encode(output).into_string()
}

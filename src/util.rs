use bs58;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::io::Write;

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

pub fn clear_console_line_80(out: &mut Write) {
    write!(out, "\r{}\r", " ".repeat(80)).unwrap();
    out.flush().unwrap();
}

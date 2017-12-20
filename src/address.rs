use curve25519_dalek::constants::ED25519_BASEPOINT;
use curve25519_dalek::scalar::Scalar;
use sha256::sha256_compress;
use std::fmt;
use util::bs58_encode_check;

pub const PAYMENT_ADDRESS_PREFIX: [u8; 2] = [0x16, 0x9a];
pub const SPENDING_KEY_PREFIX: [u8; 2] = [0xab, 0x36];
pub const VIEWING_KEY_PREFIX: [u8; 3] = [0xa8,0xab, 0xd3];

/// A Zcash spending key.
pub struct SpendingKey {
    a_sk: [u8; 32], // 252 bits; first 4 bits are always 0
}

/// A Zcash viewing key.
pub struct ViewingKey {
    pub sk_enc: [u8; 32],
    pub pk_enc: [u8; 32],
}

/// A Zcash payment address.
pub struct PaymentAddress {
    pub a_pk: [u8; 32],
    pub pk_enc: [u8; 32],
}

impl fmt::Display for SpendingKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut data = [0u8; 2 + 32];
        data[..2].copy_from_slice(&SPENDING_KEY_PREFIX);
        data[2..34].copy_from_slice(&self.a_sk);

        f.write_str(bs58_encode_check(&data).as_str())
    }
}

impl fmt::Display for ViewingKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut data = [0u8; 3 + 32 * 2];
        data[..3].copy_from_slice(&VIEWING_KEY_PREFIX);
        data[2..34].copy_from_slice(&self.sk_enc);
        data[34..66].copy_from_slice(&self.pk_enc);

        f.write_str(bs58_encode_check(&data).as_str())
    }
}

impl fmt::Display for PaymentAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut data = [0u8; 2 + 32 * 2];
        data[..2].copy_from_slice(&PAYMENT_ADDRESS_PREFIX);
        data[2..34].copy_from_slice(&self.a_pk);
        data[34..66].copy_from_slice(&self.pk_enc);

        f.write_str(bs58_encode_check(&data).as_str())
    }
}

impl SpendingKey {
    /// Creates a new spending key instance for a given 252-bit *a_sk*.
    /// *a_sk* is represented by 32 bytes; the first four bits of the first byte are zeroed.
    pub fn new(a_sk_u256: [u8; 32]) -> SpendingKey {
        let mut a_sk_u252 = [0u8; 32];
        a_sk_u252.copy_from_slice(&a_sk_u256);
        a_sk_u252[0] &= 0x0f;

        SpendingKey { a_sk: a_sk_u252 }
    }

    /// Calculates the payment address for this spending key
    pub fn address(&self) -> PaymentAddress {
        let mut a_pk = [0u8; 32];
        pseudorandom_function_a_pk(&mut a_pk, &self.a_sk);

        PaymentAddress {
            a_pk: a_pk,
            pk_enc: self.viewing_key().pk_enc,
        }
    }

    /// Computes a viewing key for this spending key.
    pub fn viewing_key(&self) -> ViewingKey {
        let mut sk_enc = [0u8; 32];
        pseudorandom_function_sk_enc(&mut sk_enc, &self.a_sk);
        clamp_curve25519(&mut sk_enc);
        let pk = &Scalar(sk_enc) * &ED25519_BASEPOINT;
        let pk_enc = pk.compress_montgomery().unwrap().to_bytes();

        ViewingKey {
            sk_enc: sk_enc,
            pk_enc: pk_enc,
        }
    }
}

pub fn pseudorandom_function_a_pk(a_pk: &mut [u8; 32], a_sk: &[u8; 32]) {
    pseudorandom_function(a_pk, a_sk, 0)
}

pub fn pseudorandom_function_sk_enc(sk_enc: &mut [u8; 32], a_sk: &[u8; 32]) {
    pseudorandom_function(sk_enc, a_sk, 1)
}

fn pseudorandom_function(dst: &mut [u8; 32], input: &[u8; 32], t: u8) {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(input);
    data[0] = 0xc0 | (data[0] & 0x0f);
    data[32] = t;
    sha256_compress(dst, &data);
}

fn clamp_curve25519(key: &mut [u8; 32]) {
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
}

#[cfg(test)]
mod test {
    use bs58;
    use super::*;

    static ENCODED: [(&str, &str, &str); 5] = [
        (
            "SKxny894fJe2rmZjeuoE6GVfNkWoXfPp8337VrLLNWG56FfQtuS1",
            "zcbxovDeXGJJikZH5wQkcQvYx1gzsRt9mR5UnQir6NY8hhPHdgK7z7dE1vfa55Bq3JHJu7isfuWQGYrvMbLnud74z2vS4tS",
            "ZiUBSSMXjXXeFEJVTNiEh3frFcxpBwuCWHEjnobHfGS2keQNF3LTJGGaBRcfamK4rBZHve1kh4YjSCLGwtZpt35WuzHSBTvC3",
        ),
        (
            "SKxoo5QkFQgTbdc6EWRKyHPMdmtNDJhqudrAVhen9b4kjCwN6CeV",
            "zcRYvLiURno1LhXq95e8avXFcH2fKKToSFfhqaVKTy8mGH7i6SJbfuWcm4h9rEA6DvswrbxDhFGDQgpdDYV8zwUoHvwNvFX",
            "ZiTn6ZX2k5RyZ2pUZDtNMA97FK2pYNzAt2cZwMc1ZN8SwUNUKFWSbAahYakDUSWcJZYQuUBzdfDMqYdJ6VNxa8G4388qgSHFq",
        ),
        (
            "SKxsVGKsCESoVb3Gfm762psjRtGHmjmv7HVjHckud5MnESfktUuG",
            "zcWGguu2UPfNhh1ygWW9Joo3osvncsuehtz5ewvXd78vFDdnDCRNG6QeKSZpwZmYmkfEutPVf8HzCfBytqXWsEcF2iBAM1e",
            "ZiVgrhGoZJzDZQn6whow6sHZEcLMSsU6iwghsqdbbFdG7XjDppunWwGEUm4jjjffpqzNCmF9g6DcteQQk4GYwkknWP3TLdr3C",  
        ),
        (
            "SKxp72QGQ2qtovHSoVnPp8jRFQpHBhG1xF8s27iRFjPXXkYMQUA6",
            "zcWZomPYMEjJ49S4UHcvTnhjYqogfdYJuEDMURDpbkrz94bkzdTdJEZKWkkpQ8nK62eyLkZCvLZDFtLC2Cq5BmEK3WCKGMN",
            "ZiThWXyRSm1gWKLi3Z17CZPEqrqwrpbWeGeR6HT9iMzSYkGs7shmeyDypffhS3CMyRxJ6D2XaoY1gSU4MGSpzXXq9JXvPTnPS",
        ),
        (
            "SKxpmLdykLu3xxSXtw1EA7iLJnXu8hFh8hhmW1B2J2194ijh5CR4",
            "zcgjj3fJF59QGBufopx3F51jCjUpXbgEzec7YQT6jRt4Ebu5EV3AW4jHPN6ZdXhmygBvQDRJrXoZLa3Lkh5GqnsFUzt7Qok",
            "ZiVhAKxsvDeBoATdHsPwDAUuBeKYHwovTz841wNmemSnesn4PqHCYikBdFrCfdxY464yYuJZVoZs5fC3AQz9hQhSTf7q4LEb7",
        ),
    ];

    #[test]
    fn spending_keys_to_payment_addresses() {
        for &(spending_key_encoded, payment_address_encoded, _) in ENCODED.iter() {
            let mut a_sk = [0u8; 32];
            a_sk.copy_from_slice(
                &bs58::decode(spending_key_encoded).into_vec().unwrap()[2..34],
            );
            let spending_key = SpendingKey::new(a_sk);
            assert_eq!(spending_key_encoded, spending_key.to_string());
            let payment_address = spending_key.address();
            assert_eq!(payment_address_encoded, payment_address.to_string());
        }
    }

    #[test]
    fn spending_keys_to_viewing_keys() {
        for &(spending_key_encoded, _,viewing_key_encoded) in ENCODED.iter() {
            let mut a_sk = [0u8; 32];
            a_sk.copy_from_slice(
                &bs58::decode(spending_key_encoded).into_vec().unwrap()[2..34],
            );
            let spending_key = SpendingKey::new(a_sk);
            assert_eq!(spending_key_encoded, spending_key.to_string());
            let viewing_key = spending_key.viewing_key();
            assert_eq!(viewing_key_encoded, viewing_key.to_string());
        }
    }
}

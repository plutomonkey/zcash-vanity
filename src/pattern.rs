use address::PAYMENT_ADDRESS_PREFIX;
use bs58;
use byteorder::{BigEndian, ByteOrder};
use std::fmt;

#[derive(Clone)]
pub struct Pattern {
    pub prefix: String,
    pub range: (u64, u64),
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.prefix.as_str())
    }
}

impl Pattern {
    pub fn new(prefix: String) -> Result<Pattern, String> {
        match prefix_to_range_u64(prefix.as_str()) {
            Ok(range) => Ok(Pattern {
                prefix,
                range,
            }),
            Err(err) => Err(err),
        }
    }

    pub fn case_insensitive(&self) -> Vec<Pattern> {
        let prefix_bytes = self.prefix.as_bytes().to_owned();
        let mut patterns = vec![];

        let alpha = bs58::alphabet::DEFAULT;
        let mut rev = [0xff; 128];
        for (i, &c) in alpha.iter().enumerate() {
            rev[c as usize] = i;
        }
        for (i, &c) in alpha.iter().enumerate() {
            let lower = (c as char).to_lowercase().next().unwrap() as usize;
            if lower != c as usize && rev[lower] != 0xff {
                rev[c as usize] = rev[lower];
                rev[lower] = i;
            }
        }

        let mut i = 0;
        let mut max = 1;
        while i < max {
            let mut tmp = prefix_bytes.clone().to_owned();
            let mut k = 1u64;
            for c in &mut tmp {
                if alpha[rev[*c as usize]] != *c {
                    if i & k != 0 {
                        *c = alpha[rev[*c as usize]];
                    }
                    k <<= 1;
                }
            }
            max = k;

            if let Ok(pattern) = Pattern::new(String::from_utf8(tmp).unwrap()) {
                patterns.push(pattern);
            }
            i += 1;
        }
        patterns
    }
}

fn prefix_to_range_u64(prefix: &str) -> Result<(u64, u64), String> {
    // 2-byte prefix, 32-byte a_pk, 32-byte pk_enc, 4-byte check
    let mut address_data = [0u8; 2 + 32 * 2 + 4];
    address_data[..2].copy_from_slice(&PAYMENT_ADDRESS_PREFIX);
    let address_00 = bs58::encode(address_data.as_ref()).into_string();
    for d in address_data.iter_mut().skip(2) {
        *d = 0xff;
    }
    let address_ff = bs58::encode(address_data.as_ref()).into_string();

    let suffix_length = address_ff.len() - prefix.len();
    let prefix_1 = prefix.to_owned() + &"1".repeat(suffix_length);
    let prefix_z = prefix.to_owned() + &"z".repeat(suffix_length);

    if prefix_z < address_00 {
        return Err(format!(
            "Invalid z-addr: {} < {}",
            prefix,
            &address_00[..prefix.len()]
        ));
    }
    if prefix_1 > address_ff {
        return Err(format!(
            "Invalid z-addr: {} > {}",
            prefix,
            &address_ff[..prefix.len()]
        ));
    }

    let pattern_1 = if prefix_1 < address_00 {
        <u64>::min_value()
    } else {
        bs58::decode(prefix_1).into(address_data.as_mut()).unwrap();
        BigEndian::read_u64(&address_data[2..10])
    };

    let pattern_z = if prefix_z > address_ff {
        <u64>::max_value()
    } else {
        bs58::decode(prefix_z).into(address_data.as_mut()).unwrap();
        BigEndian::read_u64(&address_data[2..10])
    };

    Ok((pattern_1, pattern_z))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn case_insensitive_vanity() {
        let pattern = Pattern::new("zcVANiTY".to_string()).unwrap();
        assert_eq!(
            pattern
                .case_insensitive()
                .iter()
                .map(|p| p.prefix.as_str())
                .collect::<Vec<&str>>(),
            vec![
                "zcVANiTY",
                "zcVaNiTY",
                "zcVAniTY",
                "zcVaniTY",
                "zcVANitY",
                "zcVaNitY",
                "zcVAnitY",
                "zcVanitY",
                "zcVANiTy",
                "zcVaNiTy",
                "zcVAniTy",
                "zcVaniTy",
                "zcVANity",
                "zcVaNity",
                "zcVAnity",
                "zcVanity",
            ]
        );
    }

    #[test]
    fn case_insensitive_a() {
        let pattern = Pattern::new("zcA".to_string()).unwrap();
        assert_eq!(
            pattern
                .case_insensitive()
                .iter()
                .map(|p| p.prefix.as_str())
                .collect::<Vec<&str>>(),
            vec![
                "zcA",
                "zca",
            ]
        );
    }
}

use std::collections::HashMap;

use hex::FromHexError;

pub fn hex_to_base64(hex: &str) -> String {
    if let Ok(bytes) = hex::decode(hex) {
        return base64::encode(bytes).to_string();
    }

    String::from("")
}

pub fn fixed_xor(hex: &str) -> Result<String, FromHexError> {
    let rhs_bytes = hex::decode("686974207468652062756c6c277320657965")?;
    let lhs_bytes = hex::decode(hex)?;

    let xor: Vec<u8> = lhs_bytes
        .iter()
        .zip(rhs_bytes.iter())
        .map(|(l, r)| l ^ r)
        .collect();

    Ok(hex::encode(xor))
}

static CHAR_FREQUENCIES: [(u8, f32); 28] = [
    (b' ', 12.17),
    (b'.', 6.57),
    (b'a', 6.09),
    (b'b', 1.05),
    (b'c', 2.84),
    (b'd', 2.92),
    (b'e', 11.36),
    (b'f', 1.79),
    (b'g', 1.38),
    (b'h', 3.41),
    (b'i', 5.44),
    (b'j', 0.24),
    (b'k', 0.41),
    (b'l', 2.92),
    (b'm', 2.76),
    (b'n', 5.44),
    (b'o', 6.00),
    (b'p', 1.95),
    (b'q', 0.24),
    (b'r', 4.95),
    (b's', 5.68),
    (b't', 8.03),
    (b'u', 2.43),
    (b'v', 0.97),
    (b'w', 1.38),
    (b'x', 0.24),
    (b'y', 1.30),
    (b'z', 0.03),
];

fn score_english_cypher(cypher: &Vec<u8>) -> f32 {
    let len = cypher.len();
    let mut count_chars: HashMap<u8, f32> = HashMap::new();

    for c in cypher {
        let maybe_char = if c.is_ascii_control() || !c.is_ascii() {
            return f32::MAX;
        } else if c.is_ascii_alphabetic() {
            Some(c.to_ascii_lowercase())
        } else if c.is_ascii_whitespace() {
            Some(b' ')
        } else {
            Some(b'.')
        };

        if let Some(found_char) = maybe_char {
            *count_chars.entry(found_char).or_insert(0.0f32) += 1f32
        }
    }

    CHAR_FREQUENCIES
        .iter()
        .map(|(c, score)| {
            let s1 = score / 100f32 * len as f32;
            let s2 = count_chars.get(&c).unwrap_or(&0.0f32);
            (s1 - s2).powi(2)
        })
        .sum::<f32>()
        .sqrt()
}

pub fn single_byte_xor_cypher(hex: &str) -> Result<String, FromHexError> {
    let cypher = hex::decode(hex)?;

    let (_score, phrase) = (0u8..=255)
        .map(|i| cypher.iter().map(|l| l ^ i).collect::<Vec<u8>>())
        .map(|xored| (score_english_cypher(&xored), xored))
        .min_by(|(s1, _), (s2, _)| s1.partial_cmp(&s2).unwrap())
        .unwrap();

    let phrase_str = std::str::from_utf8(&phrase).unwrap_or("");

    Ok(phrase_str.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_to_base64_test() {
        let result = hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        assert_eq!(
            result,
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }

    #[test]
    fn fixed_xor_test() {
        let result = fixed_xor("1c0111001f010100061a024b53535009181c");
        assert_eq!(
            result,
            Ok("746865206b696420646f6e277420706c6179".to_string())
        );
    }

    #[test]
    fn single_byte_xor_cypher_test() {
        let result = single_byte_xor_cypher(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
        );

        assert_eq!(result, Ok("Cooking MC's like a pound of bacon".to_string()));
    }
}

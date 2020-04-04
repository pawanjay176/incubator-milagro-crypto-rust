use super::big::Big;
use super::dbig::DBig;
use super::fp::FP;
use super::fp2::FP2;
use super::rom::{HASH_ALGORITHM, HASH_TYPE, L, MODULUS, Z_PAD};

use errors::AmclError;
use hash256::HASH256;
use hash384::HASH384;
use hash512::HASH512;

/// Oversized DST padding
pub const OVERSIZED_DST: &[u8] = b"H2C-OVERSIZE-DST-";

#[derive(Copy, Clone)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

/// Hash a message
pub fn hash(msg: &[u8], hash_function: HashAlgorithm) -> Vec<u8> {
    match hash_function {
        HashAlgorithm::Sha256 => {
            let mut hash = HASH256::new();
            hash.init();
            hash.process_array(msg);
            hash.hash().to_vec()
        }
        HashAlgorithm::Sha384 => {
            let mut hash = HASH384::new();
            hash.init();
            hash.process_array(msg);
            hash.hash().to_vec()
        }
        HashAlgorithm::Sha512 => {
            let mut hash = HASH512::new();
            hash.init();
            hash.process_array(msg);
            hash.hash().to_vec()
        }
    }
}

// Hash To Field - Fp
//
// Take a message as bytes and convert it to a Field Point
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#section-5.3
pub fn hash_to_field_fp(msg: &[u8], count: usize, dst: &[u8]) -> Result<Vec<FP>, AmclError> {
    let m = 1;
    let p = Big::new_ints(&MODULUS);

    let len_in_bytes = count * m * L;
    let pseudo_random_bytes = expand_message_xmd(msg, len_in_bytes, dst, HASH_ALGORITHM)?;

    let mut u: Vec<FP> = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let elm_offset = L as usize * i * m as usize;
        let mut dbig = DBig::frombytes(&pseudo_random_bytes[elm_offset..elm_offset + L as usize]);
        let e: Big = dbig.dmod(&p);
        u.push(FP::new_big(&e));
    }
    Ok(u)
}

// Hash To Field - Fp2
//
// Take a message as bytes and convert it to a vector of Field Points with extension degree 2.
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-06#section-5.2
pub fn hash_to_field_fp2(msg: &[u8], count: usize, dst: &[u8]) -> Result<Vec<FP2>, AmclError> {
    let m = 2;
    let p = Big::new_ints(&MODULUS);

    let len_in_bytes = count * m * L;

    let pseudo_random_bytes = expand_message_xmd(msg, len_in_bytes, dst, HASH_ALGORITHM)?;

    let mut u: Vec<FP2> = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let mut e: Vec<Big> = Vec::with_capacity(m as usize);
        for j in 0..m as usize {
            let elm_offset = L as usize * (j + i * m as usize);
            let mut big =
                DBig::frombytes(&pseudo_random_bytes[elm_offset..elm_offset + L as usize]);
            e.push(big.dmod(&p));
        }
        u.push(FP2::new_bigs(&e[0], &e[1]));
    }
    Ok(u)
}

// Expand Message XMD
//
// Take a message and convert it to pseudo random bytes of specified length
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-06#section-5.3.1
pub fn expand_message_xmd(
    msg: &[u8],
    len_in_bytes: usize,
    dst: &[u8],
    hash_algorithm: HashAlgorithm,
) -> Result<Vec<u8>, AmclError> {
    // ell = ceiling(len_in_bytes / b_in_bytes)
    let ell = (len_in_bytes + HASH_TYPE - 1) / HASH_TYPE;

    // Error if length of output less than 255 bytes
    if ell >= 255 {
        return Err(AmclError::HashToFieldError);
    }

    // Create DST prime as (dst.len() || dst)
    let dst_prime = if dst.len() > 256 {
        // DST too long, shorten to H("H2C-OVERSIZE-DST-" || dst)
        let mut tmp = OVERSIZED_DST.to_vec();
        tmp.extend_from_slice(dst);
        let mut prime = vec![32u8; 1];
        prime.append(&mut hash(&tmp, hash_algorithm));
        prime
    } else {
        // DST correct size, prepend length as a single byte
        let mut prime = vec![dst.len() as u8; 1];
        prime.extend_from_slice(dst);
        prime
    };

    let mut pseudo_random_bytes: Vec<u8> = vec![];
    let mut b: Vec<Vec<u8>> = vec![vec![]; 2];

    // Set b[0] to H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
    let mut tmp = Z_PAD.to_vec();
    tmp.extend_from_slice(msg);
    let l_i_b_str: &[u8] = &(len_in_bytes as u16).to_be_bytes();
    tmp.extend_from_slice(l_i_b_str);
    tmp.push(0u8);
    tmp.extend_from_slice(&dst_prime);
    b[0] = hash(&tmp, hash_algorithm);

    // Set b[1] to H(b_0 || I2OSP(1, 1) || DST_prime)
    tmp = b[0].clone();
    tmp.push(1u8);
    tmp.extend_from_slice(&dst_prime);
    b[1] = hash(&tmp, hash_algorithm);

    pseudo_random_bytes.extend_from_slice(&b[1]);

    for i in 2..=ell {
        // Set b[i] to H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
        tmp = b[0]
            .iter()
            .enumerate()
            .map(|(j, b_0)| {
                // Perform strxor(b[0], b[i-1])
                b_0 ^ b[i - 1][j] // b[i].len() will all be 32 bytes as they are SHA256 output.
            })
            .collect();
        tmp.push(i as u8); // i < 256
        tmp.extend_from_slice(&dst_prime);
        b.push(hash(&tmp, hash_algorithm));

        pseudo_random_bytes.extend_from_slice(&b[i]);
    }

    // Take required length
    Ok(pseudo_random_bytes[..len_in_bytes as usize].to_vec())
}

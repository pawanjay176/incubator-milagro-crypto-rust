/*
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
*/

/// BLS12-381
///
/// An implementation of BLS12-381 as specified by the following standard:
/// https://github.com/cfrg/draft-irtf-cfrg-bls-signature
pub mod iso;
pub mod sqrt_division_chain;

use super::big;
use super::big::Big;
use super::dbig::DBig;
use super::ecp::ECP;
use super::ecp2::ECP2;
use super::fp::FP;
use super::fp2::FP2;
use super::pair;
use super::rom;
use self::iso::Iso3Fp2;
use hash256::HASH256;
use std::str;
use rand::RAND;
use sha3::SHA3;
use sha3::SHAKE256;

// BLS API Functions
pub const BFS: usize = big::MODBYTES as usize;
pub const BGS: usize = big::MODBYTES as usize;
pub const BLS_OK: isize = 0;
pub const BLS_FAIL: isize = -1;

/// L = ceil(ceil(log2(Q) + 128) / 8)
pub const L: usize = 64;
/// b_in_bytes = ceil(b / 8), where b is bits outputted from SHA256
pub const B_IN_BYTES: usize = 32;
/// H2C as bytes
pub const H2C: &[u8] = b"H2C";
/// Domain Separation Tag
pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
/// DST_PRIME[0] = DST.len() = 43 (ASCII '+')
pub const DST_PRIME: &[u8] = b"+BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
/// Z_PAD is a vector of zeros of length equal to the hash block size (64).
pub const Z_PAD: [u8; 64] = [0u8; 64];

// Hash a message to an ECP point, using SHA3
#[allow(non_snake_case)]
fn bls_hashit(m: &str) -> ECP {
    let mut sh = SHA3::new(SHAKE256);
    let mut hm: [u8; BFS] = [0; BFS];
    let t = m.as_bytes();
    for i in 0..m.len() {
        sh.process(t[i]);
    }
    sh.shake(&mut hm, BFS);
    let P = ECP::mapit(&hm);
    P
}

/// Generate key pair, private key s, public key w
pub fn key_pair_generate(mut rng: &mut RAND, s: &mut [u8], w: &mut [u8]) -> isize {
    let q = Big::new_ints(&rom::CURVE_ORDER);
    let g = ECP2::generator();
    let sc = Big::randomnum(&q, &mut rng);
    sc.tobytes(s);
    pair::g2mul(&g, &sc).tobytes(w);
    BLS_OK
}

/// Sign message m using private key s to produce signature sig.
pub fn sign(sig: &mut [u8], m: &str, s: &[u8]) -> isize {
    let d = bls_hashit(m);
    let mut sc = Big::frombytes(&s);
    pair::g1mul(&d, &mut sc).tobytes(sig, true);
    BLS_OK
}

/// Verify signature given message m, the signature sig, and the public key w
pub fn verify(sig: &[u8], m: &str, w: &[u8]) -> isize {
    let hm = bls_hashit(m);
    let mut d = ECP::frombytes(&sig);
    let g = ECP2::generator();
    let pk = ECP2::frombytes(&w);
    d.neg();

    // Use new multi-pairing mechanism
    let mut r = pair::initmp();
    pair::another(&mut r, &g, &d);
    pair::another(&mut r, &pk, &hm);
    let mut v = pair::miller(&r);

    //.. or alternatively
    //    let mut v = pair::ate2(&g, &d, &pk, &hm);

    v = pair::fexp(&v);
    if v.isunity() {
        return BLS_OK;
    }
    BLS_FAIL
}

/*************************************************************************************************
* Functions for hashing to curve when signatures are on ECP
*************************************************************************************************/
/// Hash to Curve
///
/// Takes a message as input and converts it to a Curve Point
/// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05
pub fn hash_to_curve_g1(msg: &[u8]) -> ECP {
    let u = hash_to_field_g1(msg, 2);
    // TODO: Finish function
    let mut q0 = map_to_curve_g1(u[0]);
    let q1 = map_to_curve_g1(u[1]);
    q0.add(&q1);
    //q0.clear_cofactor();
    q0
}

// Hash To Base - FP
//
// Take a message as bytes and convert it to a Field Point
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#section-5.3
fn hash_to_field_g1(msg: &[u8], count: usize) -> Vec<FP> {
    let m = 1;
    let p = Big::new_ints(&rom::MODULUS);

    let len_in_bytes = count * m * L;
    let pseudo_random_bytes = expand_message_xmd(msg, len_in_bytes);

    let mut u: Vec<FP> = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let elm_offset = L as usize * i * m as usize;
        let mut dbig = DBig::frombytes(&pseudo_random_bytes[elm_offset..elm_offset + L as usize]);
        let e: Big = dbig.dmod(&p);
        u.push(FP::new_big(&e));
    }
    u
}

// Simplified SWU for Pairing-Friendly Curves
//
// Take a field point and map it to a Curve Point.
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#section-6.6.3
fn map_to_curve_g1(_u: FP) -> ECP {
    // TODO: Implement this for G1
    assert!(false, "function not implemented");
    ECP::new()
}

/*************************************************************************************************
* Functions for hashing to curve when signatures are on ECP2
*************************************************************************************************/
/// Hash to Curve
///
/// Takes a message as input and converts it to a Curve Point
/// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05
pub fn hash_to_curve_g2(msg: &[u8]) -> ECP2 {
    let u = hash_to_field_g2(msg, 2);
    let mut q0 = map_to_curve_g2(u[0]);
    let q1 = map_to_curve_g2(u[1]);
    q0.add(&q1);
    q0.clear_cofactor();
    q0
}

// Hash To Field - Fp2
//
// Take a message as bytes and convert it to a vector of Field Points with extension degree 2.
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-06#section-5.2
fn hash_to_field_g2(msg: &[u8], count: usize) -> Vec<FP2> {
    let m = 2;
    let p = Big::new_ints(&rom::MODULUS);

    let len_in_bytes = count * m * L;
    let pseudo_random_bytes = expand_message_xmd(msg, len_in_bytes);

    let mut u: Vec<FP2> = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let mut e: Vec<Big> = Vec::with_capacity(m as usize);
        for j in 0..m as usize {
            let elm_offset = L as usize * (j + i * m as usize);
            let mut big = DBig::frombytes(&pseudo_random_bytes[elm_offset..elm_offset + L as usize]);
            e.push(big.dmod(&p));
        }
        u.push(FP2::new_bigs(&e[0], &e[1]));
    }
    u
}

// Expand Message XMD
//
// Take a message and convert it to pseudo random bytes of specified length
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-06#section-5.3.1
fn expand_message_xmd(msg: &[u8], len_in_bytes: usize) -> Vec<u8> {
    // ell = ceiling(len_in_bytes / b_in_bytes)
    let ceiling = if len_in_bytes % B_IN_BYTES == 0 {
        0
    } else {
        1
    };
    let ell = len_in_bytes / B_IN_BYTES + ceiling;


    // TODO: Confirm panic is correct behaviour
    assert!(
        ell > 255,
        "expand_message_xmd ell too large {}", ell
    );

    // Set tmp to (Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
    let mut tmp = Z_PAD.to_vec();
    tmp.extend_from_slice(msg);
    let l_i_b_str: &[u8] = &len_in_bytes.to_be_bytes()[2..];
    tmp.extend_from_slice(l_i_b_str);
    tmp.push(0u8);
    tmp.extend_from_slice(DST_PRIME);

    let mut b: Vec<Vec<u8>> = vec![vec![]];
    let mut pseudo_random_bytes: Vec<u8> = vec![];

    let mut hash256 = HASH256::new();
    hash256.init();
    hash256.process_array(&tmp);
    b[0] = hash256.hash().to_vec();

    // Set tmp to (b_0 || I2OSP(1, 1) || DST_prime)
    tmp = b[0].clone();
    tmp.push(1u8);
    tmp.extend_from_slice(DST_PRIME);

    let mut hash256 = HASH256::new();
    hash256.init();
    hash256.process_array(&tmp);
    b[1] = hash256.hash().to_vec();
    pseudo_random_bytes.extend_from_slice(&b[1]);

    for i in 2..=ell {
        // Set tmp to (strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
        tmp = b[0].iter().enumerate().map(|(j, b_0)| {
                // Perform strxor(b[0], b[i-1])
                b_0 ^ b[i-1][j] // b[i].len() will all be 32 bytes as they are SHA256 output.
            }
        ).collect();
        tmp.push(i as u8); // i < 255
        tmp.extend_from_slice(DST_PRIME);

        let mut hash256 = HASH256::new();
        hash256.init();
        hash256.process_array(&tmp);
        b.push(hash256.hash().to_vec());

        pseudo_random_bytes.extend_from_slice(&b[i]);
    }

    // Take required length
    pseudo_random_bytes[..len_in_bytes as usize].to_vec()
}

// Simplified SWU for Pairing-Friendly Curves
//
// Take a field point and map it to a Curve Point.
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#section-6.6.3
fn map_to_curve_g2(u: FP2) -> ECP2 {
    let mut iso3 = Iso3Fp2::swu_optimised(u);
    iso3.iso3_to_ecp2()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The following tests were exported from
    // https://github.com/kwantam/bls_sigs_ref/tree/master/python-impl
    // Format: [(input, output)]
    // input: [u0_a, u0_b, u1_a, u1_b]
    // output: [x_a, x_b, y_a, y_b]
    pub const TESTS: [([&str; 4], [&str; 4]); 3] =
        [
            // Test 0
            (
                // Input
                [
                    "004ad233c619209060e40059b81e4c1f92796b05aa1bc6358d65e53dc0d657dfbc713d4030b0b6d9234a6634fd1944e7",
                    "0e2386c82713441bc3b06a460bd81850f4bf376ea89c80b18c0881e855c58dc8e83b2fd23af983f4786508e30c42af01",
                    "08a6a75e0a8d32f1e096f29047ea879dd34a5504218d7ce92c32c244786822fb73fbf708d167ad86537468249ec6df48",
                    "07016d0e5e13cd65780042c6f7b4c74ae1c58da438c99582696818b5c229895b893318dcb87d2a65e557d4ebeb408b70"
                ],
                // Output
                [
                    "04861c41efcc5fc56e62273692b48da25d950d2a0aaffb34eff80e8dbdc2d41ca38555ceb8554368436aea47d16056b5",
                    "09db5217528c55d982cf05fc54242bdcd25f1ebb73372e00e16d8e0f19dc3aeabdeef2d42d693405a04c37d60961526a",
                    "177d05b95e7879a7ddbd83c15114b5a4e9846fde72b2263072dc9e60db548ccbadaacb92cc4952d4f47425fe3c5e0172",
                    "0fc82c99b928ed9df12a74f9215c3df8ae1e9a3fa54c00897889296890b23a0edcbb9653f9170bf715f882b35c0b4647"
                ]
            ),
            // Test 1
            (
                // Input
                [
                    "083c57b3ee2ecba5bbf874bb03897827f949096efceea00f002c979de7e5e9429fcf1f3323d4c8c548cd6f8ecb1a5c1d",
                    "0344fdfe8e1401867a275b3bef7e6ec52450968ab8a1293938fe3d5712dda67c85afeb91d85ab83fcdbebba4dc913e44",
                    "1361b5ee134c6bee4e287e63f852b6e48546dcf0684af7cf3e7653a3427a609f769ce4d9d99a638b6ae432130fa43104",
                    "18425b12c2ab5de136eb493b88ca950a45cab942505b5dd59a8b3ae8ec34c40ada65ff2719b1fcda9769fb22882002f9"
                ],
                // Output
                [
                    "15f7a5c1168ad5ab67ff285c80fa8dd932ca88d9f8b3803c6c7b1f525d2dd5d01f2418259ae167c17c514d55e4707ddb",
                    "04378269c7364a6cefcdafdb87b004d3ebf6853f46687e46f29f23196d47a176c6f858be34c9f9a3608c74e804f6c686",
                    "023d9d46abe82bc0ac7c104d9519c037ff72893b8371d72ab92378f60a2361d7171df6b33500828c88923ddb1aab7fa5",
                    "1015adfeece3613836bf82541ea560c701e197b3d081e2c242b217d809f4ac0ca787b402537a66c0d1f6b76e1b19e94b"
                ]
            ),
            // Test 2
            /*
            (
                // Input
                [
                    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                ],
                // Output
                [
                    "1063d10c6a6eb081e7c64df360c4b30105214e36651f1d9b96a8be06850b0271d280911027c01ba6121d3150efdf1f90",
                    "10f0c3a6591e86bbafccbc8a6f0d39cf9db340df0ca87e5454370a75dc9283cf3e4028492612ed7f15c1d7f850c73848",
                    "126d09223e5b0de4b3d848f0679d3b38a15256811e09fa35ea0cee94a6380285e2c3592424aa3c7a083129251d5d7b54",
                    "02b874326f760b68d79791620b0a8921b86a988411c80db0035588b8eb9a11f8e83bfd2502e6313ec77d074edf969874"
                ]
            ),
            */
            // Test 3
            (
                // Input
                [
                    "05495a3dfa360cb809c1904530db1986aea4bf356e634b40b51e0ee5fcb6cb75085a72a0626873a426470067627c6418",
                    "11e63b587bedb59c2140518565950bdf881d75c0cccdcedcd9f4b71f2cfede3e5fdbe0261b015562d5edeaa11b7b2b76",
                    "116c87bbeece66871eb6c2a51bc4327b10ffe470b49c28ef8eef624da766caa2cc9ff6c7042b26b2efd3404f5a81a140",
                    "010450a90c17ba2997b645ef340fb5b207d6c915b34a93d93e75ee905d6d203d4aac046e10bd4d94a215604ade7afa8e"
                ],
                // Output
                [
                    "0f1614a6e91c3e00799098fded2f2cfd72cb585cbdaec41b478509913c6772266a764f00b24a7f99607948a4b69b4d8f",
                    "13ca2148705ca7ba49c92ab8985d7babcc8afc6bf8e397fb829f5fe3f49e51c41332ba4389f5ba66667310b22bea16c9",
                    "026a743ee00eec8c7ef63351f4a3b26b2f029c10130385efc56ce53d0788db32ff5296ab77f9c389bd196cce8fc1e888",
                    "0d458d80897e922f3e7e15cfa66a0d3645d95788bddb7478af3f1b5ca662c348b0e9ffdb88fabfdb74f103fea0c2d793"
                ]
            )
        ];


    #[test]
    fn test_map_to_curve_g2() {
        for test in &TESTS {
            // Input u0 and u1
            let a = Big::frombytes(&hex::decode(test.0[0]).unwrap());
            let b = Big::frombytes(&hex::decode(test.0[1]).unwrap());
            let mut u0 = FP2::new_bigs(&a, &b);
            let a = Big::frombytes(&hex::decode(test.0[2]).unwrap());
            let b = Big::frombytes(&hex::decode(test.0[3]).unwrap());
            let mut u1 = FP2::new_bigs(&a, &b);

            // Map to Curve
            let mut iso3_0 = Iso3Fp2::swu_optimised(u0);
            let mut iso3_1 = Iso3Fp2::swu_optimised(u1);

            // 3-Isogeny Map
            let mut q0 = iso3_0.iso3_to_ecp2();
            let q1 = iso3_1.iso3_to_ecp2();
            q0.add(&q1);

            // Clear Cofactor
            q0.clear_cofactor();

            // Check expected values
            let a = Big::frombytes(&hex::decode(test.1[0]).unwrap());
            let b = Big::frombytes(&hex::decode(test.1[1]).unwrap());
            let check_x = FP2::new_bigs(&a, &b);
            let a = Big::frombytes(&hex::decode(test.1[2]).unwrap());
            let b = Big::frombytes(&hex::decode(test.1[3]).unwrap());
            let check_y = FP2::new_bigs(&a, &b);
            let mut check_e = ECP2::new_fp2s(&check_x, &check_y);

            assert!(q0.equals(&check_e));
        }
    }
}

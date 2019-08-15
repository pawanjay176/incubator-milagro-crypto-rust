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
use super::big;
use super::big::Big;
use super::dbig::DBig;
use super::ecp::ECP;
use super::ecp2::ECP2;
use super::fp::FP;
use super::fp2::FP2;
use super::pair;
use super::rom;
use super::bls381_utils::BLS381_IOS3_FP2;
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

/// L = ciel(ciel(log2(Q) + 128) / 8)
pub const L: u8 = 64;
/// H2C as bytes
pub const H2C: [u8; 3] = [104, 50, 99];

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
    let mut sc = Big::randomnum(&q, &mut rng);
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
/// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04
// TODO: Update link when standard is finalised
pub fn hash_to_curve_ecp() -> ECP {
    // TODO: Finish function
    ECP::new()
}

// Hash To Base - FP
//
// Take a message as bytes and convert it to a Field Point
// TODO: Update link when standard is finalised
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04#section-5.3
fn hash_to_base_fp(dst: &[u8], msg: &[u8], ctr: u8) -> FP {
    let m_prime = HASH256::hkdf_extract(dst, msg);

    // Concatenate ("H2C" || I2OSP(ctr, 1) || I2OSP(i, 1))
    let mut info = H2C.to_vec();
    info.push(ctr);
    info.push(1);

    // Hash and extract to t
    let t = HASH256::hkdf_extend(&m_prime, &info, L);

    // Convert t to an integer and modulate
    let mut e_1 = DBig::frombytes(&t);
    let p = Big::new_ints(&rom::MODULUS);
    let e_1 = e_1.dmod(&p);

    FP::new_big(&e_1)
}

// Simplified SWU for Pairing-Friendly Curves
//
// Take a field point and map it to a Curve Point.
// TODO: Update link when standard is finalised
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04#section-6.9.2
fn map_to_curve_ecp(u: FP) -> ECP {
    // TODO: Implement this for G1
    ECP::new()
}

/*************************************************************************************************
* Functions for hashing to curve when signatures are on ECP2
*************************************************************************************************/
/// Hash to Curve
///
/// Takes a message as input and converts it to a Curve Point
/// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04
// TODO: Update link when standard is finalised
pub fn hash_to_curve_ecp2(dst: &[u8], msg: &[u8], ctr: u8) -> ECP2 {
    let u = hash_to_base_fp2(dst, msg, ctr);
    let mut ecp2 = map_to_curve_ecp2(u);
    // TODO: clear the cofactor
    ecp2
}

// Hash To Base - FP2
//
// Take a message as bytes and convert it to a Field Point with extension degree 2.
// TODO: Update link when standard is finalised
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04#section-5.3
fn hash_to_base_fp2(dst: &[u8], msg: &[u8], ctr: u8) -> FP2 {
    let m_prime = HASH256::hkdf_extract(dst, msg);
    let mut e = [Big::new(); 2];

    for i in 1..=2 {
        // Concatenate ("H2C" || I2OSP(ctr, 1) || I2OSP(i, 1))
        let mut info = H2C.to_vec();
        info.push(ctr);
        info.push(i);

        // Hash and extract to t
        let t = HASH256::hkdf_extend(&m_prime, &info, L);

        // Convert t to an integer and modulate
        let mut e_i = DBig::frombytes(&t);
        let p = Big::new_ints(&rom::MODULUS);
        e[i as usize - 1] = e_i.dmod(&p);
    }

    FP2::new_bigs(&e[0], &e[1])
}

// Simplified SWU for Pairing-Friendly Curves
//
// Take a field point and map it to a Curve Point.
// TODO: Update link when standard is finalised
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04#section-6.9.2
fn map_to_curve_ecp2(u: FP2) -> ECP2 {
    let mut ios3 = BLS381_IOS3_FP2::map_to_ios3(u);
    ios3.ios3_to_ecp2()
}

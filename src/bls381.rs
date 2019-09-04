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
pub mod clear_cofactor;

use super::big;
use super::big::Big;
use super::dbig::DBig;
use super::ecp::ECP;
use super::ecp2::ECP2;
use super::fp::FP;
use super::fp2::FP2;
use super::pair;
use super::rom;
use self::iso::ISO3_FP2;
use self::sqrt_division_chain::sqrt_division_chain;
use self::clear_cofactor::clear_cofactor_psi;
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
pub fn hash_to_curve_g1() -> ECP {
    // TODO: Finish function
    ECP::new()
}

// Hash To Base - FP
//
// Take a message as bytes and convert it to a Field Point
// TODO: Update link when standard is finalised
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04#section-5.3
fn hash_to_base_g1(dst: &[u8], msg: &[u8], ctr: u8) -> FP {
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
fn map_to_curve_g1(u: FP) -> ECP {
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
pub fn hash_to_curve_g2(dst: &[u8], msg: &[u8], ctr: u8) -> ECP2 {
    let u0 = hash_to_base_g2(dst, msg, 0);
    let u1 = hash_to_base_g2(dst, msg, 1);
    let mut q0 = map_to_curve_g2(u0);
    let q1 = map_to_curve_g2(u1);
    q0.add(&q1);
    clear_cofactor_g2(q0)
}

// Hash To Base - FP2
//
// Take a message as bytes and convert it to a Field Point with extension degree 2.
// TODO: Update link when standard is finalised
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04#section-5.3
fn hash_to_base_g2(dst: &[u8], msg: &[u8], ctr: u8) -> FP2 {
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
fn map_to_curve_g2(u: FP2) -> ECP2 {
    let mut iso3 = ISO3_FP2::swu_optimised(u);
    iso3.iso3_to_ecp2()
}

// Clear G2 Cofactor
fn clear_cofactor_g2(point: ECP2) -> ECP2 {
    clear_cofactor_psi(point)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_to_curve_g2() {
        // Check hash to field value
        let a = Big::frombytes(&hex::decode("13ebfd9a2321c55f89c3f33517bb1dc0840fff8b2a7e8a838de75c2d54494bde9be9c96f994a70bf87b24f6d1ee01298").unwrap());
        let b = Big::frombytes(&hex::decode("17ef2367c8bc23b31cae4a04693f02e7b31080bdec0e31983d96ef3546ac43040607f89e28e73bae6427c2dfd76ffa8c").unwrap());
        let mut u0 = FP2::new_bigs(&a, &b);
        let a = Big::frombytes(&hex::decode("0645cf9379b1174f53ae8becc83a8a3dee00512068027769cae2462dc8c2a86ec5cdbfb82e143d87f95645090f574487").unwrap());
        let b = Big::frombytes(&hex::decode("18b6775520c61e688a6afe6566a3bd2279e724d3a216ccdb74ea66feac03d4460315a6d65ff5343c4a52d77f2376c74e").unwrap());
        let mut u1 = FP2::new_bigs(&a, &b);

        let mut iso3_0 = ISO3_FP2::swu_optimised(u0);

        // Prints
        let mut x = iso3_0.x.clone();
        let mut y = iso3_0.y.clone();
        let mut z_inverse = iso3_0.z.clone();
        z_inverse.inverse();
        x.mul(&z_inverse);
        y.mul(&z_inverse);
        println!("iso-3 X0: {}", x.tostring());
        println!("iso-3 Y0: {}", y.tostring());

        let mut iso3_1 = ISO3_FP2::swu_optimised(u1);

        // Prints
        let mut x = iso3_1.x.clone();
        let mut y = iso3_1.y.clone();
        let mut z_inverse = iso3_1.z.clone();
        z_inverse.inverse();
        x.mul(&z_inverse);
        y.mul(&z_inverse);
        println!("iso-3 X1: {}", x.tostring());
        println!("iso-3 Y1: {}", y.tostring());

        let mut q0 = iso3_0.iso3_to_ecp2();
        let q1 = iso3_1.iso3_to_ecp2();
        // TODO: Implement iso-3 addittion before ISO-3
        println!("q0: {}", q0.tostring());
        println!("q1: {}", q1.tostring());
        q0.add(&q1);

        // Check expected values (converted from Jacobian)
        let a = Big::frombytes(&hex::decode("07ea1e10b6956041d066bd36bcfe2431e56fab08ad145a48408550709e798c389fb8c244cc823bcb7c0023cbeecc9866").unwrap());
        let b = Big::frombytes(&hex::decode("0babcec1aa6d1328b2f9c2d2b2c2ea4b194ecbb17b92c081bb2f9a47f0dd7c5c59d30c6f237036c3f508d57acf4e3c99").unwrap());
        let mut check_x = FP2::new_bigs(&a, &b);
        let a = Big::frombytes(&hex::decode("16a3aff86fe15145def8915992824cf2c1831e237223a8bfda787c1848bf78be85a3ab0efc36fb10228fbd299e96327c").unwrap());
        let b = Big::frombytes(&hex::decode("073bc0e2808fadd6ae3d6690b3491b76c92f75fe4b36119d25fbe721c46a3a6bb241f2fd1be009ad073205c62b73f2e0").unwrap());
        let mut check_y = FP2::new_bigs(&a, &b);
        let a = Big::frombytes(&hex::decode("18ff97c4ccdbff04b899e9c17f9050ab57c9878ccd9fc310156d0ef195fb41436c07b70e1b9e5b0120691c23bbe37814").unwrap());
        let b = Big::frombytes(&hex::decode("007ec14b229394bfbe0248bbaa3cca2f8f2bb4ba8dafdca28cd8e3a6c16a2595c910ac69ac49174e9c34f039686516e9").unwrap());
        let mut check_z = FP2::new_bigs(&a, &b);
        check_z.inverse();
        check_x.mul(&check_z);
        check_x.mul(&check_z);
        check_y.mul(&check_z);
        check_y.mul(&check_z);
        check_y.mul(&check_z);
        let mut check_y2 = check_y.clone();
        check_y2.sqr();
        let mut rhs = ECP2::rhs(&mut check_x);
        assert!(check_y2.equals(&mut rhs));
        let mut check = ECP2::new_fp2s(&check_x, &check_y);

        println!("Final: {}", q0.tostring());
        println!("Final Check: {}", check.tostring());
        assert!(q0.equals(&check));
    }
}

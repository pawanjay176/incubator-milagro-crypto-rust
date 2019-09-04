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
/// Domain Separation Tag
// TODO: Set this
pub const DST: [u8; 0] = [];

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
fn hash_to_base_g1(msg: &[u8], ctr: u8) -> FP {
    let m_prime = HASH256::hkdf_extract(&DST, msg);

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
pub fn hash_to_curve_g2(msg: &[u8]) -> ECP2 {
    let u0 = hash_to_base_g2(msg, 0);
    let u1 = hash_to_base_g2(msg, 1);
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
fn hash_to_base_g2(msg: &[u8], ctr: u8) -> FP2 {
    let m_prime = HASH256::hkdf_extract(&DST, msg);
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

        // Map to Curve
        let mut iso3_0 = ISO3_FP2::swu_optimised(u0);
        let mut iso3_1 = ISO3_FP2::swu_optimised(u1);

        // 3-Isogeny Map
        let mut q0 = iso3_0.iso3_to_ecp2();
        let q1 = iso3_1.iso3_to_ecp2();
        q0.add(&q1);

        // Check expected values (converted from Jacobian)
        let a = Big::frombytes(&hex::decode("12964C5CDFC826C2F18830077E81698ED122CEC7F917122D431A12BCF48F921A36260AC3E8E9FCDC33905764FA27F706").unwrap());
        let b = Big::frombytes(&hex::decode("0EF5B46B1D6EF466C73BD24BBE12E88278267C2C5B1576F9704295924E20BE501494321D5E68856CFFA7E288A27C36C2").unwrap());
        let mut check_x = FP2::new_bigs(&a, &b);
        let a = Big::frombytes(&hex::decode("0E8F3E2A16106F3E6D22E028B8DED96AD852C777A1FAB87C82A57E73D0100713A2F71926BF6EED8DF0DE4783B25EDA5C").unwrap());
        let b = Big::frombytes(&hex::decode("0D94212B113F02CBB0A50FF04EFDDCF6837E6421A3A4106E743792170333D71290B9ED2F8D6945654757C99FAB4DE94B").unwrap());
        let mut check_y = FP2::new_bigs(&a, &b);
        let mut check = ECP2::new_fp2s(&check_x, &check_y);

        assert!(q0.equals(&check));
    }

    /**********************************************************************************************
    * The following tests were exported from
    * https://github.com/kwantam/bls_sigs_ref/tree/master/python-impl
    **********************************************************************************************/
    #[test]
    fn test_map_to_curve_g2_test_0() {
        // Input u0 and u1
        let mut u0 = FP2::new_ints(1, 2);
        let mut u1 = FP2::new_ints(3, 4);

        let mut iso3_0 = ISO3_FP2::swu_optimised(u0);
        let mut iso3_1 = ISO3_FP2::swu_optimised(u1);

        let mut q0 = iso3_0.iso3_to_ecp2();
        let q1 = iso3_1.iso3_to_ecp2();
        q0.add(&q1);

        let mut e = clear_cofactor_g2(q0);

        // Check expected values
        let a = Big::frombytes(&hex::decode("06a855c391b249ecc27d18c9a6069fb5c71b0ebb63ff11319f6a786a12fd4f71fa74c1cfdfff18408cc6f6887cc703f2").unwrap());
        let b = Big::frombytes(&hex::decode("13f8891f249f6d77949710e6a4d98e3e1023835f6cb21bf9f2510fcea5625b33aff5791c44e3b889c54950cecafe7a3f").unwrap());
        let check_x = FP2::new_bigs(&a, &b);
        let a = Big::frombytes(&hex::decode("0bb60236968291a18f9434cff2e1a258d609433511cddfe2a704370a9e61f42f92f89329b0580ddf187b633068ebc005").unwrap());
        let b = Big::frombytes(&hex::decode("0d0bc331332db07b1f79675a0c5d059cc2bcebde449f43cf138e524aa29c51c448ac7af478fd679ce7bed35bee40d26c").unwrap());
        let check_y = FP2::new_bigs(&a, &b);
        let mut check_e = ECP2::new_fp2s(&check_x, &check_y);

        assert!(e.equals(&check_e));
    }

    #[test]
    fn test_map_to_curve_g2_test_1() {
        // Input u0 and u1
        let a = Big::frombytes(&hex::decode("028615c3cb1ae6cd947ea3b6c4b318665defda72d207d19aa556098023a1879b17c5a05b19b9f93ae5bf7d7000b7c318").unwrap());
        let b = Big::frombytes(&hex::decode("00ffccc09c701edcb7a8461bdd7879e5fde5f19ab8215013dc198000c012e7ed8f87d3b840ddfc81c8358c11527d496b").unwrap());
        let mut u0 = FP2::new_bigs(&a, &b);
        let a = Big::frombytes(&hex::decode("0af98de1b831474dab37531928c0a0a72452cb8d00e2e9701ebfa3851b37d1b53d95ceccbdd6327dd178e43ce4a94015").unwrap());
        let b = Big::frombytes(&hex::decode("028bdabbbc298e66d537bf71c6360c2264ec5d34922e11b68d02dbd4ed4d3bcdedaa345aae5302ed30bb65fdd934f4f9").unwrap());
        let mut u1 = FP2::new_bigs(&a, &b);

        // Map to Curve
        let mut iso3_0 = ISO3_FP2::swu_optimised(u0);
        let mut iso3_1 = ISO3_FP2::swu_optimised(u1);

        // 3-Isogeny Map
        let mut q0 = iso3_0.iso3_to_ecp2();
        let q1 = iso3_1.iso3_to_ecp2();
        q0.add(&q1);

        // Clear Cofactor
        let mut e = clear_cofactor_g2(q0);

        // Check expected values
        let a = Big::frombytes(&hex::decode("04141ac264849654be0202be8e28d63999d4c92520b61716fd135dec3dd4ef55dde26271c7f36793ef568e98d223155f").unwrap());
        let b = Big::frombytes(&hex::decode("19862ce541608d976ec0fedb8ae74a5ca3a650fdd46c417c7234a899e2d4a47e2b06bb490d9e6327f6dbd721de82863e").unwrap());
        let check_x = FP2::new_bigs(&a, &b);
        let a = Big::frombytes(&hex::decode("0c81acdad319da6549ff7573103c517ac925bdce76f1e47559cb65a0a5e78464ad26d92f543207bd99902f851286d260").unwrap());
        let b = Big::frombytes(&hex::decode("1828707ecb4595ba679e881b9c405d9eb85bb433a872e45a4d53cfdf6eabee4b8d0e27740d5861cfd4669cdbb43b12fb").unwrap());
        let check_y = FP2::new_bigs(&a, &b);
        let mut check_e = ECP2::new_fp2s(&check_x, &check_y);

        assert!(e.equals(&check_e));
    }

    #[test]
    fn test_map_to_curve_g2_test_2() {
        // Input u0 and u1
        let a = Big::frombytes(&hex::decode("07d55c1cccdf02a96ad4b9e5cd78b2a08de2e4f76525df98032006e5230cb18ac67c8afb97dfb3f55e65050a57e5b0cd").unwrap());
        let b = Big::frombytes(&hex::decode("01d2fb3a225025d237b06982207f5ad437a6d454552dcc7b17fe550591a2d4379a7c6ee6c5d9a3426ad33b71fff79085").unwrap());
        let mut u0 = FP2::new_bigs(&a, &b);
        let a = Big::frombytes(&hex::decode("01f52da057434bc5fdee7b231562c38192be169d9126cabdb6b7032eb82fe7ef408ec73e54e72fad289cd2236f095680").unwrap());
        let b = Big::frombytes(&hex::decode("05aed6f0fa489e691cdf11a3029dc5e0275c431abefe2c9b033a6bed1dccc82e27b30465915cfd15ff4fce5e28567447").unwrap());
        let mut u1 = FP2::new_bigs(&a, &b);

        // Map to Curve
        let mut iso3_0 = ISO3_FP2::swu_optimised(u0);
        let mut iso3_1 = ISO3_FP2::swu_optimised(u1);

        // 3-Isogeny Map
        let mut q0 = iso3_0.iso3_to_ecp2();
        let q1 = iso3_1.iso3_to_ecp2();
        q0.add(&q1);

        // Clear Cofactor
        let mut e = clear_cofactor_g2(q0);

        // Check expected values
        let mut a = Big::frombytes(&hex::decode("0a1a1d330c688c30e9471db100d818f859d3d66306aa7841fbdcb18549d53d74397a74c148be19d79da59e259962e566").unwrap());
        let mut b = Big::frombytes(&hex::decode("0722ea0b90d7f5249280540557a1562af035e33a25ccb627817e94356ca3f1ddcfe76f2841c9d37b780b9dd2ddca24ed").unwrap());
        let check_x = FP2::new_bigs(&a, &b);
        let a = Big::frombytes(&hex::decode("0d8d24bee4cb6fffe836892e476cb9e35e662e28b45a703c5a52683c969cf519f68682bc33b95ab6b75bdc1e03d183f9").unwrap());
        let b = Big::frombytes(&hex::decode("18d38988640038d025b9cb858f83e15214f7aaae1a3721b3e6a52ca6c7a97fa6b73ad65bf694243069c80e225ec3d709").unwrap());
        let check_y = FP2::new_bigs(&a, &b);
        let mut check_e = ECP2::new_fp2s(&check_x, &check_y);

        assert!(e.equals(&check_e));
    }

    #[test]
    fn test_map_to_curve_g2_test_3() {
        // Input u0 and u1
        let a = Big::frombytes(&hex::decode("012b7c250629d409eec5f60930fc28d755645d7e2f3ec8f57e7a8a1159fdae4455d2bb1fcb850434d157c436d2b55118").unwrap());
        let b = Big::frombytes(&hex::decode("07f5fa4bb45ba27979b77c33684e8ddd30e2c20e6692da49841556409841e01e6d0915e1ba06298eaee39f3dc2f66377").unwrap());
        let mut u0 = FP2::new_bigs(&a, &b);
        let a = Big::frombytes(&hex::decode("07562d78b60c50fe653eaf1b034e4d9be52fdad0d0690c37defc53f51e83b9254b52d07955e5f3c74ce81520cd0e732e").unwrap());
        let b = Big::frombytes(&hex::decode("092a5e40e26c1d968cb55447ef17b6472b972f0bf7999dd5c157884abbb839456650c2f176deb38f2b8443fed17d5c7d").unwrap());
        let mut u1 = FP2::new_bigs(&a, &b);

        // Map to Curve
        let mut iso3_0 = ISO3_FP2::swu_optimised(u0);
        let mut iso3_1 = ISO3_FP2::swu_optimised(u1);

        // 3-Isogeny Map
        let mut q0 = iso3_0.iso3_to_ecp2();
        let q1 = iso3_1.iso3_to_ecp2();
        q0.add(&q1);

        // Clear Cofactor
        let mut e = clear_cofactor_g2(q0);

        // Check expected values
        let a = Big::frombytes(&hex::decode("148281b4f090bd27823489ed825c155f1d0a9005f2da4ee69ce3b2e57270512ce9e6ca7efdc03c2f3cbaae0342096eaf").unwrap());
        let b = Big::frombytes(&hex::decode("053ecb77c878f1b225e3ce2315445db0507d2b5c6b31575035230a67092f894caa21e96e3dabedf4e44d53981724b5a8").unwrap());
        let check_x = FP2::new_bigs(&a, &b);
        let a = Big::frombytes(&hex::decode("15b7008ba1368b5f643c6da18bcf64bf30b724328d3bb5a6cf4f11c2f543099dfbc55b1688fd046a0fe0261aac7a5448").unwrap());
        let b = Big::frombytes(&hex::decode("0b3fd652c283e74764950cfacf5dd472c596eba950355ac99483afd57d2feae536cd2434dccb93cad77ac36dd2317080").unwrap());
        let check_y = FP2::new_bigs(&a, &b);
        let mut check_e = ECP2::new_fp2s(&check_x, &check_y);

        assert!(e.equals(&check_e));
    }
}

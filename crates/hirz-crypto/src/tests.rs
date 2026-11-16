#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use super::*;

fn h(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(s.len().is_multiple_of(2));
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn h32(s: &str) -> [u8; 32] {
    h(s).try_into().unwrap()
}

#[test]
fn random_fill_produces_distinct_output() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    random_fill(&mut a).unwrap();
    random_fill(&mut b).unwrap();
    assert_ne!(a, b);
    assert_ne!(a, [0u8; 32]);
}

#[test]
fn ct_eq_basic() {
    assert!(ct_eq(b"abc", b"abc"));
    assert!(!ct_eq(b"abc", b"abd"));
    assert!(!ct_eq(b"abc", b"ab"));
    assert!(ct_eq(b"", b""));
}

#[test]
fn sha256_known_answers() {
    assert_eq!(
        sha256(b"abc").to_vec(),
        h("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    assert_eq!(
        sha256(b"").to_vec(),
        h("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
}

// RFC 4231 test cases 1, 2, 3, 4, 6, 7 (case 5 is a truncated output).
#[test]
fn hmac_sha256_rfc4231() {
    let cases: [(Vec<u8>, Vec<u8>, &str); 6] = [
        (
            vec![0x0b; 20],
            b"Hi There".to_vec(),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        ),
        (
            b"Jefe".to_vec(),
            b"what do ya want for nothing?".to_vec(),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        ),
        (
            vec![0xaa; 20],
            vec![0xdd; 50],
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        ),
        (
            (1u8..=25).collect(),
            vec![0xcd; 50],
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
        ),
        (
            vec![0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        ),
        (
            vec![0xaa; 131],
            b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".to_vec(),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
        ),
    ];
    for (key, data, expected) in cases {
        assert_eq!(hmac_sha256(&key, &data).to_vec(), h(expected));
    }
}

// RFC 5869 appendix A, test cases 1 to 3.
#[test]
fn hkdf_sha256_rfc5869() {
    let mut okm = [0u8; 42];
    hkdf_sha256(
        &h("000102030405060708090a0b0c"),
        &[0x0b; 22],
        &h("f0f1f2f3f4f5f6f7f8f9"),
        &mut okm,
    )
    .unwrap();
    assert_eq!(
        okm.to_vec(),
        h("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    );

    let salt: Vec<u8> = (0x60u8..=0xaf).collect();
    let ikm: Vec<u8> = (0x00u8..=0x4f).collect();
    let info: Vec<u8> = (0xb0u8..=0xff).collect();
    let mut okm = [0u8; 82];
    hkdf_sha256(&salt, &ikm, &info, &mut okm).unwrap();
    assert_eq!(
        okm.to_vec(),
        h(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c
           59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71
           cc30c58179ec3e87c14c01d5c1f3434f1d87"
        )
    );

    let mut okm = [0u8; 42];
    hkdf_sha256(&[], &[0x0b; 22], &[], &mut okm).unwrap();
    assert_eq!(
        okm.to_vec(),
        h("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
    );
}

#[test]
fn hkdf_rejects_bad_lengths() {
    let mut empty: [u8; 0] = [];
    assert_eq!(
        hkdf_sha256(b"s", b"k", b"i", &mut empty),
        Err(CryptoError::Invalid)
    );
    let mut too_long = vec![0u8; HKDF_SHA256_MAX_OUT + 1];
    assert_eq!(
        hkdf_sha256(b"s", b"k", b"i", &mut too_long),
        Err(CryptoError::Invalid)
    );
    let mut max = vec![0u8; HKDF_SHA256_MAX_OUT];
    hkdf_sha256(b"s", b"k", b"i", &mut max).unwrap();
}

#[test]
fn es256_round_trip_and_tamper() {
    let (pkcs8, x, y) = es256::generate().unwrap();
    assert_eq!(es256::public_key(&pkcs8).unwrap(), (x, y));
    let sig = es256::sign(&pkcs8, b"message").unwrap();
    es256::verify(&x, &y, b"message", &sig).unwrap();
    assert_eq!(
        es256::verify(&x, &y, b"messagf", &sig),
        Err(CryptoError::Auth)
    );
    let mut bad = sig.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert_eq!(
        es256::verify(&x, &y, b"message", &bad),
        Err(CryptoError::Auth)
    );
    let (_, x2, y2) = es256::generate().unwrap();
    assert_eq!(
        es256::verify(&x2, &y2, b"message", &sig),
        Err(CryptoError::Auth)
    );
    assert_eq!(es256::sign(b"not a key", b"m"), Err(CryptoError::Invalid));
    assert!(es256::public_key(&[]).is_err());
}

const RFC6979_X: &str = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";
const RFC6979_Y: &str = "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";

// RFC 6979 appendix A.2.5 (P-256, SHA-256), signatures DER-encoded.
#[test]
fn es256_verify_known_vectors() {
    let x = h32(RFC6979_X);
    let y = h32(RFC6979_Y);
    let sample = h(
        "3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716
                    022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
    );
    let test = h(
        "3045022100f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367
                  0220019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
    );
    es256::verify(&x, &y, b"sample", &sample).unwrap();
    es256::verify(&x, &y, b"test", &test).unwrap();
    assert!(es256::verify(&x, &y, b"test", &sample).is_err());

    // Wycheproof-style malformed encodings must be rejected.
    let mut trailing = sample.clone();
    trailing.push(0);
    assert!(es256::verify(&x, &y, b"sample", &trailing).is_err());
    let mut long_form = vec![0x30, 0x81, 0x46];
    long_form.extend_from_slice(&sample[2..]);
    assert!(es256::verify(&x, &y, b"sample", &long_form).is_err());
    let zero = h("3006020100020100");
    assert!(es256::verify(&x, &y, b"sample", &zero).is_err());
    assert!(es256::verify(&x, &y, b"sample", &[]).is_err());
    // A point that is not on the curve.
    let mut bad_y = y;
    bad_y[31] ^= 1;
    assert!(es256::verify(&x, &bad_y, b"sample", &sample).is_err());
}

#[test]
fn es256_spki_template() {
    let x = h32(RFC6979_X);
    let y = h32(RFC6979_Y);
    let expected = h(&format!(
        "3059301306072a8648ce3d020106082a8648ce3d03010703420004{RFC6979_X}{RFC6979_Y}"
    ));
    assert_eq!(es256::spki_der(&x, &y), expected);

    use aws_lc_rs::encoding::{AsDer, PublicKeyX509Der};
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
    let (pkcs8, gx, gy) = es256::generate().unwrap();
    let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8).unwrap();
    let der: PublicKeyX509Der<'static> = kp.public_key().as_der().unwrap();
    assert_eq!(es256::spki_der(&gx, &gy), der.as_ref());
}

// RFC 8032 section 7.1, tests 1 to 3.
#[test]
fn ed25519_rfc8032() {
    let vectors = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ];
    for (seed, public, msg, sig) in vectors {
        let pkcs8 = ed25519::pkcs8_from_seed(&h32(seed)).unwrap();
        let pk = ed25519::public_key(&pkcs8).unwrap();
        assert_eq!(pk.to_vec(), h(public));
        let s = ed25519::sign(&pkcs8, &h(msg)).unwrap();
        assert_eq!(s.to_vec(), h(sig));
        ed25519::verify(&pk, &h(msg), &s).unwrap();
        let mut bad = s;
        bad[0] ^= 0x80;
        assert_eq!(ed25519::verify(&pk, &h(msg), &bad), Err(CryptoError::Auth));
    }
}

#[test]
fn ed25519_round_trip_and_spki() {
    let (pkcs8, pk) = ed25519::generate().unwrap();
    assert_eq!(ed25519::public_key(&pkcs8).unwrap(), pk);
    let sig = ed25519::sign(&pkcs8, b"hello").unwrap();
    ed25519::verify(&pk, b"hello", &sig).unwrap();
    assert!(ed25519::verify(&pk, b"hellp", &sig).is_err());
    let spki = ed25519::spki_der(&pk);
    assert_eq!(spki.len(), 44);
    assert_eq!(&spki[..12], &h("302a300506032b6570032100")[..]);
    assert_eq!(&spki[12..], &pk[..]);
    assert_eq!(ed25519::sign(b"junk", b"m"), Err(CryptoError::Invalid));
}

// Test cases 13 to 16 of the GCM specification (McGrew and Viega), 256-bit keys.
#[test]
fn aead_known_answers() {
    let zero_key = [0u8; 32];
    let zero_nonce = [0u8; 12];
    let out = aead::seal_with_nonce(&zero_key, &zero_nonce, &[], &[]).unwrap();
    assert_eq!(&out[12..], &h("530f8afbc74536b9a963b4f1c4cb738b")[..]);
    let out = aead::seal_with_nonce(&zero_key, &zero_nonce, &[], &[0u8; 16]).unwrap();
    assert_eq!(
        &out[12..],
        &h("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919")[..]
    );

    let key = h32("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    let nonce: [u8; 12] = h("cafebabefacedbaddecaf888").try_into().unwrap();
    let pt = h(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72
                1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
    );
    let ct15 = h(
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa
                  8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad
                  b094dac5d93471bdec1a502270e3cc6c",
    );
    let out = aead::seal_with_nonce(&key, &nonce, &[], &pt).unwrap();
    assert_eq!(&out[..12], &nonce[..]);
    assert_eq!(&out[12..], &ct15[..]);
    assert_eq!(&aead::open(&key, &[], &out).unwrap()[..], &pt[..]);

    let aad = h("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let ct16 = h(
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa
                  8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662
                  76fc6ece0f4e1768cddf8853bb2d551b",
    );
    let out = aead::seal_with_nonce(&key, &nonce, &aad, &pt[..60]).unwrap();
    assert_eq!(&out[12..], &ct16[..]);
    assert_eq!(&aead::open(&key, &aad, &out).unwrap()[..], &pt[..60]);
}

#[test]
fn aead_round_trip_and_tamper() {
    let mut key = [0u8; 32];
    random_fill(&mut key).unwrap();
    let sealed = aead::seal(&key, b"aad", b"secret payload").unwrap();
    assert_eq!(sealed.len(), 12 + 14 + 16);
    assert_eq!(
        &aead::open(&key, b"aad", &sealed).unwrap()[..],
        b"secret payload"
    );
    assert_eq!(aead::open(&key, b"aae", &sealed), Err(CryptoError::Auth));
    for i in 0..sealed.len() {
        let mut t = sealed.clone();
        t[i] ^= 0x01;
        assert_eq!(
            aead::open(&key, b"aad", &t),
            Err(CryptoError::Auth),
            "byte {i}"
        );
    }
    assert_eq!(
        aead::open(&key, b"aad", &sealed[..27]),
        Err(CryptoError::Auth)
    );
    let mut other = key;
    other[0] ^= 1;
    assert_eq!(aead::open(&other, b"aad", &sealed), Err(CryptoError::Auth));
    let again = aead::seal(&key, b"aad", b"secret payload").unwrap();
    assert_ne!(sealed[..12], again[..12]);
    let empty = aead::seal(&key, b"", b"").unwrap();
    assert!(aead::open(&key, b"", &empty).unwrap().is_empty());
}

// RFC 7748 section 6.1.
#[test]
fn x25519_rfc7748() {
    let a = h32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let b = h32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let a_pub = x25519::public_key(&a).unwrap();
    let b_pub = x25519::public_key(&b).unwrap();
    assert_eq!(
        a_pub.to_vec(),
        h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    );
    assert_eq!(
        b_pub.to_vec(),
        h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    );
    let shared = h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert_eq!(&x25519::agree(&a, &b_pub).unwrap()[..], &shared[..]);
    assert_eq!(&x25519::agree(&b, &a_pub).unwrap()[..], &shared[..]);
    // A small-order public key gives an all-zero secret and must be refused.
    assert!(x25519::agree(&a, &[0u8; 32]).is_err());
}

#[test]
fn x25519_seal_round_trip_and_tamper() {
    let (sk, pk) = x25519::generate().unwrap();
    let sk: [u8; 32] = sk.as_slice().try_into().unwrap();
    assert_eq!(x25519::public_key(&sk).unwrap(), pk);
    let sealed = x25519::seal_to(&pk, b"ctx", b"vault key bytes").unwrap();
    assert_eq!(sealed.len(), 32 + 12 + 15 + 16);
    assert_eq!(
        &x25519::open_from(&sk, b"ctx", &sealed).unwrap()[..],
        b"vault key bytes"
    );
    assert_eq!(
        x25519::open_from(&sk, b"ctz", &sealed),
        Err(CryptoError::Auth)
    );
    for i in 0..sealed.len() {
        let mut t = sealed.clone();
        t[i] ^= 0x04;
        assert!(x25519::open_from(&sk, b"ctx", &t).is_err(), "byte {i}");
    }
    let (other, _) = x25519::generate().unwrap();
    let other: [u8; 32] = other.as_slice().try_into().unwrap();
    assert_eq!(
        x25519::open_from(&other, b"ctx", &sealed),
        Err(CryptoError::Auth)
    );
    assert_eq!(
        x25519::open_from(&sk, b"ctx", &sealed[..59]),
        Err(CryptoError::Auth)
    );
    assert!(x25519::seal_to(&[0u8; 32], b"", b"x").is_err());
}

#[test]
fn x25519_seal_matches_documented_construction() {
    let (sk, pk) = x25519::generate().unwrap();
    let sk: [u8; 32] = sk.as_slice().try_into().unwrap();
    let sealed = x25519::seal_to(&pk, b"aad", b"payload").unwrap();
    let eph: [u8; 32] = sealed[..32].try_into().unwrap();
    let shared = x25519::agree(&sk, &eph).unwrap();
    let mut info = b"hirz x25519 seal v1".to_vec();
    info.extend_from_slice(&eph);
    info.extend_from_slice(&pk);
    let mut key = [0u8; 32];
    hkdf_sha256(&[], &shared, &info, &mut key).unwrap();
    assert_eq!(
        &aead::open(&key, b"aad", &sealed[32..]).unwrap()[..],
        b"payload"
    );
}

#[test]
fn p256_ecdh_agrees() {
    let (a, ax, ay) = ctap_pin_uv::generate().unwrap();
    let (b, bx, by) = ctap_pin_uv::generate().unwrap();
    assert_eq!(a.len(), 32);
    let s1 = ctap_pin_uv::ecdh(&a, &bx, &by).unwrap();
    let s2 = ctap_pin_uv::ecdh(&b, &ax, &ay).unwrap();
    assert_eq!(s1.len(), 32);
    assert_eq!(&s1[..], &s2[..]);
    let mut bad = by;
    bad[0] ^= 1;
    assert!(ctap_pin_uv::ecdh(&a, &bx, &bad).is_err());
    assert!(ctap_pin_uv::ecdh(&[1u8; 5], &bx, &by).is_err());
}

// NIST SP 800-38A F.2.5 / F.2.6 (CBC-AES256).
#[test]
fn aes256_cbc_sp800_38a() {
    let key = h32("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    let iv: [u8; 16] = h("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
    let pt = h(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51
                30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
    );
    let ct = h(
        "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d
                39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
    );
    assert_eq!(ctap_pin_uv::aes256_cbc_encrypt(&key, &iv, &pt).unwrap(), ct);
    assert_eq!(
        &ctap_pin_uv::aes256_cbc_decrypt(&key, &iv, &ct).unwrap()[..],
        &pt[..]
    );
    assert!(ctap_pin_uv::aes256_cbc_encrypt(&key, &iv, &pt[..15]).is_err());
    assert!(ctap_pin_uv::aes256_cbc_decrypt(&key, &iv, &ct[..17]).is_err());
    assert!(
        ctap_pin_uv::aes256_cbc_encrypt(&key, &iv, &[])
            .unwrap()
            .is_empty()
    );
}

// RFC 9106 section 5.3 (Argon2id, with secret and associated data).
#[test]
fn argon2id_rfc9106() {
    let params = kdf::Argon2Params {
        m_cost_kib: 32,
        t_cost: 3,
        p_cost: 4,
    };
    let tag = kdf::argon2id_full(
        &[0x01; 32],
        &[0x02; 16],
        &[0x03; 8],
        &[0x04; 12],
        params,
        32,
    )
    .unwrap();
    assert_eq!(
        &tag[..],
        &h("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")[..]
    );
}

#[test]
fn argon2id_basic_and_limits() {
    let params = kdf::Argon2Params {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };
    let a = kdf::argon2id(b"password", b"saltsaltsalt", params).unwrap();
    let b = kdf::argon2id(b"password", b"saltsaltsalt", params).unwrap();
    let c = kdf::argon2id(b"passwore", b"saltsaltsalt", params).unwrap();
    assert_eq!(a.len(), 32);
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert!(kdf::argon2id(b"p", b"short", params).is_err());
    let huge = kdf::Argon2Params {
        m_cost_kib: u32::MAX,
        t_cost: 1,
        p_cost: 1,
    };
    assert_eq!(
        kdf::argon2id(b"p", b"saltsaltsalt", huge),
        Err(CryptoError::Invalid)
    );
    assert!(kdf::within_limits(kdf::DEFAULT));
}

#[test]
fn pbkdf2_rfc7914_vector() {
    let out = pbkdf2_hmac_sha256(b"passwd", b"salt", 1, 64).unwrap();
    assert_eq!(
        out.as_slice(),
        h(
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc
           49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
        )
    );
    assert!(pbkdf2_hmac_sha256(b"p", b"s", 0, 32).is_err());
    assert!(pbkdf2_hmac_sha256(b"p", b"s", PBKDF2_MAX_ITERATIONS + 1, 32).is_err());
    assert!(pbkdf2_hmac_sha256(b"p", b"s", 1, 0).is_err());
}

#[test]
fn hkdf_expand_rfc5869_case1() {
    let prk = h("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    let mut okm = [0u8; 42];
    hkdf_sha256_expand(&prk, &h("f0f1f2f3f4f5f6f7f8f9"), &mut okm).unwrap();
    assert_eq!(
        okm.to_vec(),
        h("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    );
    assert!(hkdf_sha256_expand(&prk, b"", &mut []).is_err());
}

#[test]
fn hmac_verify_rfc4231_case2() {
    let tag = h("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    hmac_sha256_verify(b"Jefe", b"what do ya want for nothing?", &tag).unwrap();
    let mut bad = tag.clone();
    bad[0] ^= 1;
    assert_eq!(
        hmac_sha256_verify(b"Jefe", b"what do ya want for nothing?", &bad),
        Err(CryptoError::Auth)
    );
    assert!(hmac_sha256_verify(b"Jefe", b"what do ya want for nothing?", &tag[..31]).is_err());
}

#[test]
fn aes_cbc_hmac_round_trip_and_tamper() {
    let (ek, mk) = ([7u8; 32], [9u8; 32]);
    for msg in [&b""[..], b"x", &[0x41; 16], &[0x42; 33]] {
        let (iv, ct, tag) = aes_cbc_hmac::seal(&ek, &mk, msg).unwrap();
        assert_eq!(ct.len(), (msg.len() / 16 + 1) * 16);
        let pt = aes_cbc_hmac::open(&ek, &mk, &iv, &ct, &tag).unwrap();
        assert_eq!(pt.as_slice(), msg);
        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 1;
        assert_eq!(
            aes_cbc_hmac::open(&ek, &mk, &iv, &bad_ct, &tag),
            Err(CryptoError::Auth)
        );
        let mut bad_iv = iv;
        bad_iv[15] ^= 1;
        assert_eq!(
            aes_cbc_hmac::open(&ek, &mk, &bad_iv, &ct, &tag),
            Err(CryptoError::Auth)
        );
        assert_eq!(
            aes_cbc_hmac::open(&ek, &[8u8; 32], &iv, &ct, &tag),
            Err(CryptoError::Auth)
        );
    }
}

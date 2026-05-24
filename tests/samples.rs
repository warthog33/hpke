use elliptic_curve::{consts::U32};
use hex_literal::hex;
// #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-sha2"))]
// use hpke::hpke_types::HpkeKemKdfX25519HkdfSha256;
// #[cfg(all(feature = "rustcrypto-p256"))]
// use p256::NistP256;
use kems::{Array};
use kems::Decapsulate;
//use kem2::Decapsulate;


/// openssl pkeyutl -encap -pubin -kemop DHKEM -inkey p256-pub.pem -out encap_out.bin -secret secret.bin
/// 
#[test]
#[cfg(all(feature = "rustcrypto-p256"))]
fn openssl_encap_p256 () {

//     let ecc_priv = "-----BEGIN EC PRIVATE KEY-----\
// MHcCAQEEIGvNx9z0Ks90NxEP8kGsSM24p2hpXOVp4RYcX8eoy1J+oAoGCCqGSM49\
// AwEHoUQDQgAE1v5Sf5sYMG4ziVOk5mk8RWyjYtXrtCU6nRC8v/FhniuAahtu6Qtc\
// J6u1mCbfqy+RQh9GAYba4NwipEz4TDwZ6Q==\
// -----END EC PRIVATE KEY----";

use hpke::{hpke_kdf::KdfForKemUsingHkdf};
//use kdfs::misc::PassThroughKdf;
    use kems::{Capsulator, eckem::{SeedAsScalar}, kem_with_kdf::{CombinerAllPubKeys, KemWithKdf}};

    let ecc_raw_priv = hex!("6BCDC7DCF42ACF7437110FF241AC48CDB8A768695CE569E1161C5FC7A8CB527E");

    let encapped_key = hex!("04 e5 96 7d f8 11 c9 57  b8 da 10 fd dc bb dd c8
        12 7c e7 30 8f c8 3a 1a  6d 38 40 0c f3 9a 85 9b
        50 89 19 0f a5 e8 32 01  74 94 ac b0 30 c8 6e 17
        dd 7b 05 41 1b 2b a8 f7  2e d6 dc e1 d8 8d c8 b7
        ed ");

    let key = hex!("0b 47 f9 31 fd 65 bb 67  49 12 3b d5 33 22 b0 f6
        e5 86 34 4b 78 54 28 51  27 27 5d a2 e8 01 a2 b0");

    //let ecc_priv2 = pem::parse(ecc_priv).unwrap();
    //let recipient_secret_key = elliptic_curve::SecretKey::from_sec1_der(ecc_priv2.contents()).unwrap();
    //let recipient_public_key = x25519_dalek::PublicKey::from(&recipient_secret_key);
    let recipient_secret_key = elliptic_curve::SecretKey::from_bytes(&ecc_raw_priv.into()).unwrap();
    
    //pub type HpkeEcCombinerP256HkdfSha256 = kems::eckem::EcCombinerAllPubKeys<hpke::hpke_kdf::HpkeKemKdf::<kdfs::rfc5869_hkdf::Hkdf<sha2::Sha256>, hpke::kem_id::DhKemP256HkdfSha256>>;
    
    //let c0_recv =  ::kems::eckem::EcEncapKey::<NistP256,U32,EcUncompressedEncoder<NistP256>>::from_bytes(GenericArray::from_slice(&encapped_key)).unwrap();
    //let decapsulator = ::kems::eckem::EcdhDecapsulatorUncompressed::<p256::NistP256,HpkeEcCombinerP256HkdfSha256, U32>::from_key(recipient_secret_key);
    let decapsulator = KemWithKdf::<kems::eckem::EcdhKemUncompressed::<p256::NistP256, SeedAsScalar>, CombinerAllPubKeys, KdfForKemUsingHkdf::<sha2::Sha256, hpke::kem_id::DhKemP256HkdfSha256>, U32>::new_decapsulator(recipient_secret_key);

    let k_recv = decapsulator.decapsulate(encapped_key.as_slice().try_into().unwrap()).unwrap();

    assert! ( k_recv == key);


}

/// openssl pkeyutl -encap -pubin -kemop DHKEM -inkey x25519-pub.pem -out encap_out.bin -secret secret.bin
/// 
#[test]
#[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-sha2"))]
fn openssl_encap_x25519 () 
{
    use hpke::{hpke_kdf::KdfForKemUsingHkdf};
    use kems::{Capsulator, eckem::{SeedAsScalar}, kem_with_kdf::{CombinerAllPubKeys, KemWithKdf}};

    let ec_priv = hex!("A840D3BBE697EBD0C81095B8E81F62841D929A75772D02DCA3C21FE54956BC53");
    let encapped_key = hex!("6d247204944aedf008f9bc93fa1997185513a0b3047b316db19c24e4e9243844");
    let key = hex!("1e8ae7282beaca3c2cb969ee352f322ae77bee32c32f62e9f6ee8877f4907024");
    
    let recipient_secret_key = x25519_dalek::StaticSecret::from(ec_priv);

    //let c0_recv =  ::kems::x25519kem::X25519EncapKey::<U32>::from_bytes(&encapped_key.into()).unwrap();
    //let c0_recv =  GenericArray::from(&encapped_key.into());
    //pub type HpkeCombinerX25519HkdfSha256 = kems::eckem::EcCombinerAllPubKeys<hpke::hpke_types::x2519_kems::HpkeKemKdfX25519HkdfSha256>;
    

    //let decapsulator = ::kems::x25519kem::X25519Decapsulator::<HpkeCombinerX25519HkdfSha256>::from_key(recipient_secret_key);
    let decapsulator = KemWithKdf::<kems::x25519kem::X25519Capsulator::<SeedAsScalar>, CombinerAllPubKeys, KdfForKemUsingHkdf::<sha2::Sha256, hpke::kem_id::DhKemX25519HkdfSha256>, U32>::new_decapsulator(recipient_secret_key);
    let k_recv: Array<u8, U32> = decapsulator.decapsulate(&encapped_key.into()).unwrap();

    assert! ( k_recv == key);
}

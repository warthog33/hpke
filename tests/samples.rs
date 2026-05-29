
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use elliptic_curve::{consts::U32};
use hex_literal::hex;
use hpke::HpkeIes;
use hpke::{hpke_kdf::KdfForKemUsingHkdf};
use hpke::hpke_types::{HpkeAuthIesP256Sha256Aes256Gcm, HpkeIesP256Sha256Aes256Gcm, HpkeIesP384Sha384Aes256Gcm, HpkeIesP521Sha512Aes256Gcm, HpkeIesX25519Sha256ChaCha20Poly1305};
use hpke::hpke_types::apple::HpkeIesXwingMl768X25519Sha256Aes256Gcm;
use hpke::hpke_types::draft_ietf_xwing::HpkeXwingMlKem768X25519;
use hpke::hpke_types::draft_ietf_hpke_pq::{HpkeIesMlKem1024Sha384Aes256Gcm, HpkeKemMlKem768, HpkeKemMlKem1024, HpkeIesMlKem768P256Shake256Aes128Gcm, HpkeIesKitchenSinkMl768X25519Sha256Aes128Gcm, HpkeIesMlKem768Sha256Aes128Gcm};
use hpke::hpke_types::p256_kems::{HpkeAuthKemP256HkdfSha256, HpkeKemP256HkdfSha256};
use hpke::hpke_types::p384_kems::HpkeKemP384HkdfSha384;
use hpke::hpke_types::p521_kems::HpkeKemP521HkdfSha512;
use hpke::hpke_types::sha2_kdfs::HpkeHkdfSha384;
use hpke::hpke_types::x25519_kems::HpkeKemX25519HkdfSha256;

use kems::{Array,Capsulator,GetEncapsulator,Decapsulate,EncodeSeed,EncodedSizeUser2,FromKeys, GenerateCapsulatorFromSeed, Encapsulate, OsRng};
use kems::eckem::SeedAsScalar;
use kems::draft_irtf_cfrg_hybrid_kems::HybridCapsulatorKitchenSinkMlKem768X25519;
use kems::kem_with_kdf::{CombinerAllPubKeys, KemWithKdf};
use kems::generic_array::GenericArray;

// #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-sha2"))]
// use hpke::hpke_types::HpkeKemKdfX25519HkdfSha256;
// #[cfg(all(feature = "rustcrypto-p256"))]
// use p256::NistP256;


/// openssl pkeyutl -encap -pubin -kemop DHKEM -inkey p256-pub.pem -out encap_out.bin -secret secret.bin
/// 
#[test]
fn openssl_encap_p256 () {
    //     let ecc_priv = "-----BEGIN EC PRIVATE KEY-----\
    // MHcCAQEEIGvNx9z0Ks90NxEP8kGsSM24p2hpXOVp4RYcX8eoy1J+oAoGCCqGSM49\
    // AwEHoUQDQgAE1v5Sf5sYMG4ziVOk5mk8RWyjYtXrtCU6nRC8v/FhniuAahtu6Qtc\
    // J6u1mCbfqy+RQh9GAYba4NwipEz4TDwZ6Q==\
    // -----END EC PRIVATE KEY----";
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




#[test]
fn test_apple_hpke_x25519() {
//    let seed = &BASE64_STANDARD.decode("67fs0M/OfCiCkfI6BC9Ma6K7isbVcu1KRjJkYMR65Kg=").unwrap();
    // let encapsulated_key = &BASE64_STANDARD.decode("h6J7OCmGB2ddVMiCbGC9519I7xDKP4BjA7yaMYyVgc9ODzyEdWKSz+sUADfQzENRAFJg0iqbyD11zWaXK4kSpWHX7y1oIlBsBqAVI+9RBNlMnk/T1nIRbDx0dOkqQzbHttyJbFAhQ/zVswmua4XhwtE0jiduVzljcWg8hTEN2LHuQ/plzmma5Xw8R8LMH41muuJMQAjf2NW1taaCqPz09aKD9mheC66/v6KZEEdmTuZpm4dD2hhRozsaAguE2jfJH06oK0tbwABHRcksz28twXkckk6JM1B1rcmpC9OdTX3VVax3Af+YwiVsIxBOJ1SVRUh3Q1AUCYwy8LNnPQFfB59T90TLkNtZBikxB2rJoGjLE4kflG+rCYyhkBA1Tqt5nLlf/GMxUubD7RlJU6URiO6lmUDncqo59MNonA6LK/QHI8k7RFQf29f+aSvxO4HiQ8Zkq9TzL1kEyMmP5a7lL14xJtky8adikguOa4GZlQW+tfwpFrcAxL6vC5Le2xDWi0YHxi4hY8gpNZXceEZypnBYSzUDtwA6fjht4Ativ/0nVdoywLXE3abYgbW8SR+n4q51uavEtGSi/xceQ99eg05ReuT8fivzL8r1FXFnMd+JSi/UBVOL3o7e58MGS+CyvdEY/NuoqtpWQo9KFOvfovErtvlfdWPonPbhTn18QkYR3/irD+kYpmmkm5G1xUetA/UawBeSsgrX2dPqIstPPxuwNSQooAI8WiB7Cr+X94YLk555Zfxb1319CuyX+/UXok7Z/ECXydoyBiUVUtTp2m7lAqNefz9wc3SRjKrtmBKZKEmrus+OaiKWXiyNtGYtFzScfS51B6ixEm1CD+OACsRuokHLyRzmPufKEJfwEk55d1Q4yKgIklnB3FvWR+JtK5QL3jmkJtFQ+qMKfjbTosdubPyFckm+LdLJ7aXuWcCL/ixhxTR/aAnVTazBlexxXyceZxvNwODqoWx16YVOEpLT9m0VaRRU//6lG61viCUgeJRpsGLL2Yx5XlWMpwdV+ii0SpU28WW8b8P6LQWi4mWTh5fBqzwWuULgPy7DyX6ZsLpFBbnENO2ZLt1OYF8GAxBbMQ2AUDatchkqO7mwHexmmzmFxX7mMkVy+pfl2O63YbtQJ740mK6dcJ7EpWWrAeR11k4EtTcEnYt0hAXGEGf9FmskzVCZlv+VIBM9NZZnO0DCMqx+T42c4YAcLhbA5nsTxhOmt3v7jQGxjFdLMhaRzg7hkIvdemuBTGxd6AGHk4DuRthkTms2GaB148Y6ycm3h0eLYph/NpmaO9WSyE4lir4Qjzx4MUDSMskVeVaiGOjYzBDZpv+VmGBKiXGWPk+TPYkUQjR3m2fb8scW+9rO3JE4TznJ4WzA9EmNncFAwkmfNVApWSpxFI5pDcHOkB2sGuOiA1cpDnK5PA2Y4+u3GYDQ3Z5eIv33qWpjf2ZcQ7QlOeT6eNvrqxucBrcOX1CaCCYvPqPr/FjuH9RWRg==").unwrap();
    // let ciphertext = &BASE64_STANDARD.decode("fVgZd6//P9xgLDeLAO9zcuotZsE0").unwrap();
    let info = hex!("0408");

    // let seed = &BASE64_STANDARD.decode("O3vXZJtfNsnucAnfTcEWSDt9gK6iKGiTdAf0YEz5m5M=").unwrap();
    // let public_key = &BASE64_STANDARD.decode("H2Q2eyOcJVRDtMVpReGAq/oge1w0his4+FdawodERhWmW0k1TSqK+pR2RLSAjUuHLEErGVAllyeEOmuJfMxqaiWx8xVv14xxcAOIdnKfvutCR/uBwxw9KDLLm2p2EZca6vhHffA7BfcnxJxrLCijk6ZGmhUgsGNqkAyhXfpTeLMgEYmu1dSDBYYO03ogHDGknAu1qrkqBzlwmOWUs1wLy8yFiiZzAxV7X1VCJke1xSnFNFDL7rKWyhRDxYZzFwYRkvdCrXE2QYHOB9dtZgZ9AtZ/PPaRU9wk+0iE2KnMlskdIAMqS4Bu1hcrbYR8I2RdYxt3uaJejBmBoPaAsKiS2mEpV4sy7iRZ15EViyItKYcML6qBi2qBO+keDHI2fasC1Hsd+rAoh+gRpLq9ofoi7eu230NSI0EEEZV4dVVYrERwqYwUewSUNOGld0fLOXgUrERg9fTBhDiBfNp6iGuwRcIu5tM3wPMuDgRSvtaalZArOuVyYExHxEGzsIV+LImaUkaE61WB93mU8nAog+Sf9FkonwYr6LAnAtoKf7N4CjudloCIeAMYPtePnyofk/A+jtHFe5hjXOOcrYyhdGpGuhVHnVFm1SJS1WWjHzWviicV9yQyncte26RgkIW+saAxsbyTiBscihLEl7J8JXa4ZWK+tSkuUpC44jGOHBGpVhcUncaNY4lerZICZ0pzE+DOM4WVGpHHAKegT9GH+rV+rPAHUFExLSaEIHZfnnkE9JlXQzwxSABxU8xR0yIxl3S2S8EuwtCPtWCSt+cFAPcTt1qbb5g54DrBfiikfAC5KUt7WrzFTNRJ3HB/pRlz3GS0XtkDGyOU92xqgXPBbdOo9FOdXay4DHyLpAWnMcJwFvcyLbgiJ2KAtVgH3aqE8VAH/hE5wPoQVGxYU8Y8HsQV6ZlYlcopNMvIfTwwAliiVuEHGQVaPCMgeDAmdVdIwJiStjRoFnsvU4tQ9UHCvpekGLKuo6ZHm5tUckGwfbyr+oYELYioRLCzm+uN85xO+XENKrkPGRO7CVcp+cO6QrpYmCW5D7ZmSxTKKMSYIEom07dXR0kVP6FO+Fco6NQE4PJNgAqgz+Bm3MWhxJPJuxRczLp/w0hhbPWlZgFgJYuuqoyaaccJBsq1Gqw2qRwhq0ExiYERjdmzDDWA3zMXEhFN97UVJdZ5u8YcFFBgvhmFkPwuMdBtO7RrgsO+X+qsLhVb89hXKTUDvmFvMWK8iRzDNyyVrxB/IRkfAhBkiZqnGpWeBUqrGbEpGSiW4ZMDFwuL2fcN8Pwxg6QlDnMwhGo9QCKQ6wGG2Ipre/Nr5ksQgJuEmpCf0Zal9DWrgMMWqzPOQ2EiKjt2snCuKQrQUPE1fpUNKwXBRwVFdzapmXpGIQMSSqSWVmlJqQJXd/Ve5cq20Mk3m0WXYESkVWVog/JzVvOLvPR1z+XIC+Vy8nInx3fNUTu5SEYzzNlhXmMh3CiPZtwimOCgturBZaw66CaeGCY3FIkcUoY/VohcnsyzKBdsFGJe5Cg8duvGlSJ848bH5LpBY8F6JoasrrXILPNfqSKzAS3HEuv15fcZu67MZsOIpxjhcOq7IEusLimpjxC7RMkxlnM5rDgYLJzZPjqLIg==").unwrap();
    // let encapsulated_key = &BASE64_STANDARD.decode("0q0eUx7HRDrRC/NRb1VPIZ3AL/hi+XKHSArqxtx5f39LPUgQ7nV+421wWIqctXAJiEbgsLaBMfYPiXwnkSPjdwDmdBoI3Z1kX9tK1MCmR7eXKCfwcWVTLgSKwqbmwjzqviRZ4I17yt/YMl3cJna9yJDFk7OjzYINJQUg+FmcdxxmTXECy8pr8NJQkIotGPQeGPwBlxIJE1sZrCux1drpJ5boU+yWSQtg/vio+xzBYsGaI8DWaT9G5AHxIUBteYqv0xfceHSVRBv1dmlCbtCNGlIuIZY1iBbFUWgJMMQKGUnEqxtnlFXYRRUijn+HwZ2OUc++2AhMK/JlnZmqPjEOp6g3Wbtx+RfaMQkGGjMuMur6gcSSCbrSI/X8KFwsj0lMYSMYiiIbY8C5VnJpMem6LjAjrg+um1fW/IgBdbfs/2yrRFmyxgzb1z6fwObk+dnuUkqg/MlAFfYHBdVZtn8hmPMKmn7rm1UG4Mc5GhM+k54qWQf31JYTBOVuXriAy3THcslWsTvHR9swuHOZr6+VUdoYk0UTePp+ektR+2FpBEkRbiR+nJ6bVgyjPG/74GI2j3/66+tQYu5VeF2mArbgZxOfXDAV2nZE8I4FlBcmVLsRtDQbIZHUWpVcTSwSFScN37ikqHg0zck6yq6bii8gSL1Xk/mAQQUIct4tToR1FY7cAjJ0ZXTjPJn99kd87H+TzvlMYg6h1jTFCfq6+2KvomEjKsb3G9n6vFA9xTszQy6eojSfeAHLAED+78FN2AX0YTC+H8tny847bkMzziPsgrdQB3O4yFhPPfUPTdr7W9o+UIYO6b51dfTjfGPXsbbpfZK/NFpITdCG2KMfG2eYHlHBv6RUMYUXLpxapBa0EKvMYqqK8purEn28qvOoUQOBhJhW5Fu8c1v7kAIZNhwjnD5bo1TSI0D/cl9+JemzG1RkGHANY1D9jDkv5Ua9rNpIqpCmfP7S5XD2kTln1rUWo0G5djN0mkfP6RKX/4EU6ZPESW6CD+PRnrLl4qgWAktkDiatQqpF3mwbGqabpDQyvmm1M/exOvbR/taezZMdPuwthjKxrxBEVybt632XMRcZAvc8vZ9NrnxXrBs7X28zX1L/Q4HtC1uZzAj0gcxld0v9ltBz9+t52zypyptlLEzXmJ6jmJNMrvmZ5eVVm7+w/Muy9vD9K4xk6MpGmHzORY7WcUCsonxcWqEDpXREZzPGwoQaCpfXgvQj0xXoDV3sX/l9fGH6l2G+cJjqpIfK7uVnAIvMsX4rseOYSR0uYEDr3w4eUK3qqD9zeqtKAtzoX1Rn2JVjwC4dcKMsgdJLd3KeRFC6PkAj4fY8fsXCtjYeWs9BLwFhPCssaAEL7V0JkONHFSjPXkUP2PjLrutDRJvbhFdAWrCRZBKOc1gOSJaVKbWadF09M4V9a9iB1T6XmyIxQLzOP+6ubcsi2HpiT16EdjSJkbiRzHUMzOxlVHjENKSZTeWT6WMfRMN3HSy/fA==").unwrap();
    // let ciphertext = &BASE64_STANDARD.decode("J2Rbn2MMd7q1AxOtNGqOOO0VFc4z").unwrap();

    
    //let seed_2 = &BASE64_STANDARD.decode("NqAfhJbWnDMut0NWwZjOTD4YhLmfe74jwKbY/txpfpH3MdH3E/MiEvCrWFW++iWvNfIObAZbENJviEEEsJl5lA==").unwrap();
    // let public_key = &BASE64_STANDARD.decode("9Pe9i/LE05J9kIqUDQqsQldheKiWezZoX5JJOUJYZtOmkmWfEmZx3RwHASK6bouTZhcZnINJBQp98tKjNIA1BihVMASeIcd1jwpln3WCBDDBivS7ReK+oFlUCaWcwYdOZGN4+tyKNuC5NzFrDCRXz2MGoCUV2Ulojbd/6VRnPNNbMvxCoOS94SZxKAgcSmJoGzQn+OJt5rQdHyvA7OsJn6VtLpgCtCOO+6qOFcMrz8gbiucgAAUUKBxf9uMKNKUd02c9C8U00pGqTtKiC6E8GbcihIIcrhKHMLkx/6XPOwIp5wqE8qy3nEqG1dPB2KArfmKXkFgl9iWRw4kPjKAlOzSz02EO17wDDXuWbUcIoXrFwbobomdJDAY/6zeuTfLCDNMDAmFr4ZoCHDdEsaI3dLdWCvF+x8gbiIMkdtq05yY6RBmhsBtkOVd2HloCcmSVV/wAYEdPm5l9E/NqhMccIeaCV+HAuGdzkxKCiigCyXEbAOQ8uvyil/bEaaXH7pKdz2Ro2bpAGjOQ0btvy8IfPhxUzBAM0NjNIZyyE0Bx8ssZKZelDfBWxyETkcy2a8A8vGM7t5oaHqWch4QuOzzFeLq+azIZU2Ocz3chuYVQoiZ5WjKZu7W6S8cP8nvKTFNgxplLEiCTfDesJqIi0oTDUjGgvbhEa3sFKeO4gzY57wZoLrUmbfs4psgdYmPEQqGm81J9d8WY9rLPMTlRM7TDXpVF0QSJpue8YpZnLzGdurWqWsOxj/hOswOMgMsdVTaF7gCQohV0eDh7NDBUVheFZAxodUeJvkhf86FGafC/JaGIZgtAfGa7AXCN3tzBliCrf4GDvIEwHCCzyAM8T8s3JFjP67ynWCoaGph8WiPFfYCmhPq1lCcDtQe2GVjDkUXPHCsaK3G2NXPGjUfF4oGj6IyA0YxniXuWefuE6FZw1NF1kimrmhqr21x7tRuY9xSn6nYZbegQ+xdJ/GGPkXkb38Widcoot6WpLgd7VbN1bOYyIHYd3DU4F+UrfepIQqRS83hPYVzGF+tA07FtoQorI+myVGBbKjAwaZWtDNpXOPaoSCCfqcgvSAqduwiBugwa6fa3SFghMACHcaW0/GFY6JfAdKsqC6h+ZVGLvncu/eAs6BGuWhdIhcYoPbRnrSgL/2EMhJxgRzQUTwqq4MF9QNw8EgkPP5dfMqyGHIW27mvDWrwvj3wiftoIrRR3g0gL6FFUU2kEZ8hPFBHExYIILgMYUxmAuUFRs+ezxlmyiIMcgXAGu+QK77NevSOJEOkqnZdsRZeEqSoODTqx8nCrBZMmoiKdxfXOz+sXmJGsp5RP2PIB2da1WnaKCgjL4ABvBBCQo0URpbPHROACYKSdOAGtkquxpieLu0ClGqQkWJEqXfad+SW4hSm7QGuXBJxWghiNu9q3o7aZYZF0djE6LuDHt8eMr5yTEWRCxrYoiOMTM7g15MQLn4wLEBxxMvilmZkH9gUCiWJmG7N6t9W84tl7NRJGPHp+zjZbT4jLX9Ki5ngAv2WiV6h6KJtYTObNgS2Zs91sFlBUq5rHAt3QvZ59unbkJIFmfxGblptTJQDBbuIsXbFyl6bkmb7314wjquR+pHOh0A9GxnHS8b76HQ==").unwrap();
    // let encapsulated_key = &BASE64_STANDARD.decode("bBcrMpyzvFLUFKU5vwewlxn9UXPwMFi3lJFJhCQNGpiGOWyEnhPt1nkBfQDZ3rGWCdDfM97NtWWoPkDywAUaytcUCXEXpHbxLgk5hxLmArOMK5p+8YVFBqdhVlN6Ivd+G5TKKZvn0BPElNHNALsyXXrjujVYB8IqYFaDa+WktCvS9n3IbIFZ/NPIFjcvkl3i/3QA0p+bKvJHmpu5b4ZtWEvtOwtDYTU62IWEYUi6grq611FEwE0X+TEm+XEU/QVpgi01LzpLC81M0LAa5UWxzCCel0Y6v/GkdmvVjqygXN4m7re6KeVUcpZuDzGXARKazMgpLHVExAjeD5BAM8r6BD9noOb43LQOYExjgh9kmTEFYKyFRTRj3nUkADbnqrwsu1/jkbR+fd1rGfa1MxnviQ+RcM5dUVR6TUH+eHTyGAKDz9y315YnBynrINJ0GWyZ0Na8PEDUzdzT0AKRCHU7yz90IEb6BaWlIcLbxa/cSYeUgkO/5CxoWmpJxsrVEpCF8AsS8yHjWiTKoLSos2KcsLN3PBxdDxG4Mbf0BEwdNl3TiYwM1GAngtkeQDmzYK42502H3dZkDbCjDfIWKl2V6Dt1r/k+np1Qau7eBTgRyCsXdMjN90nJCCqI9F+RKf7zjtFWye6682Tvkc2kqv2+7YCvgeoX59mdgCBxlT84M0Sz64y++WhLOFusOsSAvH8BWiQo3IMPjX5I9kLMRWGDtSZYXrd2kXi/DmVDSLU7BJr8ljrwdlrkXDcsOhGb7K1q74pWshRnFIPx4G9lUR5D6iP9tHtYgdjbMrc6EQe+oRG/+hEXIqGd+xowtPoExtSYrrxO6WpBYhH0CFeZ/PGDHNe1QDLLyCLNykUKq2ZziJkDzfeEvFU7db5bTPJ5hy0FpWdYQQ0tQuy50v0JnaYjV9UX77XzMWYFNWMbyhIrLycfJddDj78ssNApQtzaoaT98VPLmT6+AZODD1La9LXqWXwpIf8xVky6DwGFvQU4wPR8LRlM3uu4JYEmck/8L3KaenHztO7SYhzk2IL+whs3mVtUHxkPEeSAGPK+TQA0nQmTfYTwAgeR0IcLPTfpERnPf3r3OhSCIbuvry3YbtWic+xmAenlIRsxyWwUaGW7u1Bq2BshNbq9oppX4NWVA1gly1F5ag6bNS6A9UhEGpPnxe/ZhF6O5PbhZIgGF0T6Z3WnRzgGfYZ8Q4eR3hvnBE3voHtEQY938dCQOqfu5E7ca4e4YJMb5yh5Eh7kOOnH4D/7tDQVHjTBwb3f3A/GWNxu5jEXd75dH3+1i1lssKGm8PSzVVRdpa0xrj73nTVbFfVuM+zCIKgpvXFGvPAnIArOe62sj1aoFPJaQdaFozv0Buwk22sB8pxWedmJ2pXsn0kAyOdDN6M+JMbFtzwhvmzbhnc0sKLH1L69pZOmwuTjjIUUOEGgNUF9Xt+Ml1Qeiy4lgsD+VQlRDE4Gh6DaaC5CpOD5HAU+nzP0KhAFg2dbMw==").unwrap();
    // let ciphertext = &BASE64_STANDARD.decode("S/eqVx5Rm0KZzVPKSnGwYqD30dW0").unwrap();

    let private_raw = &BASE64_STANDARD.decode("qIbPMkqmG4yRRDBPtOu1B3UmtRHC8q+0GtnD3EgYrVQ=").unwrap();
    let public_key = &BASE64_STANDARD.decode("+XuJ76eRPecsg0Em1IsfPuXUmw74ozhYQ0QEMNAFtE0=").unwrap();
    let encapsulated_key = &BASE64_STANDARD.decode("o9j6f4+hAY1fxoiUUbNxp7MT9S0YEfRLC+Q+pbt7Khs=").unwrap();
    let ciphertext = &BASE64_STANDARD.decode("txcUDp1NZWVnOG9b13NCuzRhVMG5").unwrap();

    let private_array: [u8; 32] = private_raw.as_slice().try_into().unwrap();
    let private_key = x25519_dalek::StaticSecret::from(private_array);
    let decapsulator = HpkeKemX25519HkdfSha256::new_decapsulator(private_key);
    let encapsulator = decapsulator.get_encapsulator();

    //let (encapsulator, decapsulator) = HybridKemQsfX25519MlKem768::derive_from_seed(&Array::try_from(seed_2.as_slice()).unwrap());
    //let (encapsulator, decapsulator) = HpkeKemX25519HkdfSha256::derive_from_seed(&Array::try_from(private_raw.as_slice()).unwrap());

    assert_eq! ( encapsulator.as_bytes().as_slice(), public_key);
    // println! ( "pub1={:02X?}", encapsulator.as_bytes());
    // println! ( "pub2={:02X?}", public_key);

    let decryptor = HpkeIesX25519Sha256ChaCha20Poly1305::decryptor_from_decapsulator(decapsulator);

    let result = decryptor.single_shot_open(GenericArray::from_slice(encapsulated_key.as_slice()), &info, ciphertext.as_slice(), None).unwrap();

    assert_eq! ( result, b"hello");
    
}


#[test]
fn test_apple_hpke_p256() {
//    let seed = &BASE64_STANDARD.decode("67fs0M/OfCiCkfI6BC9Ma6K7isbVcu1KRjJkYMR65Kg=").unwrap();
    // let encapsulated_key = &BASE64_STANDARD.decode("h6J7OCmGB2ddVMiCbGC9519I7xDKP4BjA7yaMYyVgc9ODzyEdWKSz+sUADfQzENRAFJg0iqbyD11zWaXK4kSpWHX7y1oIlBsBqAVI+9RBNlMnk/T1nIRbDx0dOkqQzbHttyJbFAhQ/zVswmua4XhwtE0jiduVzljcWg8hTEN2LHuQ/plzmma5Xw8R8LMH41muuJMQAjf2NW1taaCqPz09aKD9mheC66/v6KZEEdmTuZpm4dD2hhRozsaAguE2jfJH06oK0tbwABHRcksz28twXkckk6JM1B1rcmpC9OdTX3VVax3Af+YwiVsIxBOJ1SVRUh3Q1AUCYwy8LNnPQFfB59T90TLkNtZBikxB2rJoGjLE4kflG+rCYyhkBA1Tqt5nLlf/GMxUubD7RlJU6URiO6lmUDncqo59MNonA6LK/QHI8k7RFQf29f+aSvxO4HiQ8Zkq9TzL1kEyMmP5a7lL14xJtky8adikguOa4GZlQW+tfwpFrcAxL6vC5Le2xDWi0YHxi4hY8gpNZXceEZypnBYSzUDtwA6fjht4Ativ/0nVdoywLXE3abYgbW8SR+n4q51uavEtGSi/xceQ99eg05ReuT8fivzL8r1FXFnMd+JSi/UBVOL3o7e58MGS+CyvdEY/NuoqtpWQo9KFOvfovErtvlfdWPonPbhTn18QkYR3/irD+kYpmmkm5G1xUetA/UawBeSsgrX2dPqIstPPxuwNSQooAI8WiB7Cr+X94YLk555Zfxb1319CuyX+/UXok7Z/ECXydoyBiUVUtTp2m7lAqNefz9wc3SRjKrtmBKZKEmrus+OaiKWXiyNtGYtFzScfS51B6ixEm1CD+OACsRuokHLyRzmPufKEJfwEk55d1Q4yKgIklnB3FvWR+JtK5QL3jmkJtFQ+qMKfjbTosdubPyFckm+LdLJ7aXuWcCL/ixhxTR/aAnVTazBlexxXyceZxvNwODqoWx16YVOEpLT9m0VaRRU//6lG61viCUgeJRpsGLL2Yx5XlWMpwdV+ii0SpU28WW8b8P6LQWi4mWTh5fBqzwWuULgPy7DyX6ZsLpFBbnENO2ZLt1OYF8GAxBbMQ2AUDatchkqO7mwHexmmzmFxX7mMkVy+pfl2O63YbtQJ740mK6dcJ7EpWWrAeR11k4EtTcEnYt0hAXGEGf9FmskzVCZlv+VIBM9NZZnO0DCMqx+T42c4YAcLhbA5nsTxhOmt3v7jQGxjFdLMhaRzg7hkIvdemuBTGxd6AGHk4DuRthkTms2GaB148Y6ycm3h0eLYph/NpmaO9WSyE4lir4Qjzx4MUDSMskVeVaiGOjYzBDZpv+VmGBKiXGWPk+TPYkUQjR3m2fb8scW+9rO3JE4TznJ4WzA9EmNncFAwkmfNVApWSpxFI5pDcHOkB2sGuOiA1cpDnK5PA2Y4+u3GYDQ3Z5eIv33qWpjf2ZcQ7QlOeT6eNvrqxucBrcOX1CaCCYvPqPr/FjuH9RWRg==").unwrap();
    // let ciphertext = &BASE64_STANDARD.decode("fVgZd6//P9xgLDeLAO9zcuotZsE0").unwrap();
    let info = hex!("0408");

    // let seed = &BASE64_STANDARD.decode("O3vXZJtfNsnucAnfTcEWSDt9gK6iKGiTdAf0YEz5m5M=").unwrap();
    // let public_key = &BASE64_STANDARD.decode("H2Q2eyOcJVRDtMVpReGAq/oge1w0his4+FdawodERhWmW0k1TSqK+pR2RLSAjUuHLEErGVAllyeEOmuJfMxqaiWx8xVv14xxcAOIdnKfvutCR/uBwxw9KDLLm2p2EZca6vhHffA7BfcnxJxrLCijk6ZGmhUgsGNqkAyhXfpTeLMgEYmu1dSDBYYO03ogHDGknAu1qrkqBzlwmOWUs1wLy8yFiiZzAxV7X1VCJke1xSnFNFDL7rKWyhRDxYZzFwYRkvdCrXE2QYHOB9dtZgZ9AtZ/PPaRU9wk+0iE2KnMlskdIAMqS4Bu1hcrbYR8I2RdYxt3uaJejBmBoPaAsKiS2mEpV4sy7iRZ15EViyItKYcML6qBi2qBO+keDHI2fasC1Hsd+rAoh+gRpLq9ofoi7eu230NSI0EEEZV4dVVYrERwqYwUewSUNOGld0fLOXgUrERg9fTBhDiBfNp6iGuwRcIu5tM3wPMuDgRSvtaalZArOuVyYExHxEGzsIV+LImaUkaE61WB93mU8nAog+Sf9FkonwYr6LAnAtoKf7N4CjudloCIeAMYPtePnyofk/A+jtHFe5hjXOOcrYyhdGpGuhVHnVFm1SJS1WWjHzWviicV9yQyncte26RgkIW+saAxsbyTiBscihLEl7J8JXa4ZWK+tSkuUpC44jGOHBGpVhcUncaNY4lerZICZ0pzE+DOM4WVGpHHAKegT9GH+rV+rPAHUFExLSaEIHZfnnkE9JlXQzwxSABxU8xR0yIxl3S2S8EuwtCPtWCSt+cFAPcTt1qbb5g54DrBfiikfAC5KUt7WrzFTNRJ3HB/pRlz3GS0XtkDGyOU92xqgXPBbdOo9FOdXay4DHyLpAWnMcJwFvcyLbgiJ2KAtVgH3aqE8VAH/hE5wPoQVGxYU8Y8HsQV6ZlYlcopNMvIfTwwAliiVuEHGQVaPCMgeDAmdVdIwJiStjRoFnsvU4tQ9UHCvpekGLKuo6ZHm5tUckGwfbyr+oYELYioRLCzm+uN85xO+XENKrkPGRO7CVcp+cO6QrpYmCW5D7ZmSxTKKMSYIEom07dXR0kVP6FO+Fco6NQE4PJNgAqgz+Bm3MWhxJPJuxRczLp/w0hhbPWlZgFgJYuuqoyaaccJBsq1Gqw2qRwhq0ExiYERjdmzDDWA3zMXEhFN97UVJdZ5u8YcFFBgvhmFkPwuMdBtO7RrgsO+X+qsLhVb89hXKTUDvmFvMWK8iRzDNyyVrxB/IRkfAhBkiZqnGpWeBUqrGbEpGSiW4ZMDFwuL2fcN8Pwxg6QlDnMwhGo9QCKQ6wGG2Ipre/Nr5ksQgJuEmpCf0Zal9DWrgMMWqzPOQ2EiKjt2snCuKQrQUPE1fpUNKwXBRwVFdzapmXpGIQMSSqSWVmlJqQJXd/Ve5cq20Mk3m0WXYESkVWVog/JzVvOLvPR1z+XIC+Vy8nInx3fNUTu5SEYzzNlhXmMh3CiPZtwimOCgturBZaw66CaeGCY3FIkcUoY/VohcnsyzKBdsFGJe5Cg8duvGlSJ848bH5LpBY8F6JoasrrXILPNfqSKzAS3HEuv15fcZu67MZsOIpxjhcOq7IEusLimpjxC7RMkxlnM5rDgYLJzZPjqLIg==").unwrap();
    // let encapsulated_key = &BASE64_STANDARD.decode("0q0eUx7HRDrRC/NRb1VPIZ3AL/hi+XKHSArqxtx5f39LPUgQ7nV+421wWIqctXAJiEbgsLaBMfYPiXwnkSPjdwDmdBoI3Z1kX9tK1MCmR7eXKCfwcWVTLgSKwqbmwjzqviRZ4I17yt/YMl3cJna9yJDFk7OjzYINJQUg+FmcdxxmTXECy8pr8NJQkIotGPQeGPwBlxIJE1sZrCux1drpJ5boU+yWSQtg/vio+xzBYsGaI8DWaT9G5AHxIUBteYqv0xfceHSVRBv1dmlCbtCNGlIuIZY1iBbFUWgJMMQKGUnEqxtnlFXYRRUijn+HwZ2OUc++2AhMK/JlnZmqPjEOp6g3Wbtx+RfaMQkGGjMuMur6gcSSCbrSI/X8KFwsj0lMYSMYiiIbY8C5VnJpMem6LjAjrg+um1fW/IgBdbfs/2yrRFmyxgzb1z6fwObk+dnuUkqg/MlAFfYHBdVZtn8hmPMKmn7rm1UG4Mc5GhM+k54qWQf31JYTBOVuXriAy3THcslWsTvHR9swuHOZr6+VUdoYk0UTePp+ektR+2FpBEkRbiR+nJ6bVgyjPG/74GI2j3/66+tQYu5VeF2mArbgZxOfXDAV2nZE8I4FlBcmVLsRtDQbIZHUWpVcTSwSFScN37ikqHg0zck6yq6bii8gSL1Xk/mAQQUIct4tToR1FY7cAjJ0ZXTjPJn99kd87H+TzvlMYg6h1jTFCfq6+2KvomEjKsb3G9n6vFA9xTszQy6eojSfeAHLAED+78FN2AX0YTC+H8tny847bkMzziPsgrdQB3O4yFhPPfUPTdr7W9o+UIYO6b51dfTjfGPXsbbpfZK/NFpITdCG2KMfG2eYHlHBv6RUMYUXLpxapBa0EKvMYqqK8purEn28qvOoUQOBhJhW5Fu8c1v7kAIZNhwjnD5bo1TSI0D/cl9+JemzG1RkGHANY1D9jDkv5Ua9rNpIqpCmfP7S5XD2kTln1rUWo0G5djN0mkfP6RKX/4EU6ZPESW6CD+PRnrLl4qgWAktkDiatQqpF3mwbGqabpDQyvmm1M/exOvbR/taezZMdPuwthjKxrxBEVybt632XMRcZAvc8vZ9NrnxXrBs7X28zX1L/Q4HtC1uZzAj0gcxld0v9ltBz9+t52zypyptlLEzXmJ6jmJNMrvmZ5eVVm7+w/Muy9vD9K4xk6MpGmHzORY7WcUCsonxcWqEDpXREZzPGwoQaCpfXgvQj0xXoDV3sX/l9fGH6l2G+cJjqpIfK7uVnAIvMsX4rseOYSR0uYEDr3w4eUK3qqD9zeqtKAtzoX1Rn2JVjwC4dcKMsgdJLd3KeRFC6PkAj4fY8fsXCtjYeWs9BLwFhPCssaAEL7V0JkONHFSjPXkUP2PjLrutDRJvbhFdAWrCRZBKOc1gOSJaVKbWadF09M4V9a9iB1T6XmyIxQLzOP+6ubcsi2HpiT16EdjSJkbiRzHUMzOxlVHjENKSZTeWT6WMfRMN3HSy/fA==").unwrap();
    // let ciphertext = &BASE64_STANDARD.decode("J2Rbn2MMd7q1AxOtNGqOOO0VFc4z").unwrap();

    
    //let seed_2 = &BASE64_STANDARD.decode("NqAfhJbWnDMut0NWwZjOTD4YhLmfe74jwKbY/txpfpH3MdH3E/MiEvCrWFW++iWvNfIObAZbENJviEEEsJl5lA==").unwrap();
    // let public_key = &BASE64_STANDARD.decode("9Pe9i/LE05J9kIqUDQqsQldheKiWezZoX5JJOUJYZtOmkmWfEmZx3RwHASK6bouTZhcZnINJBQp98tKjNIA1BihVMASeIcd1jwpln3WCBDDBivS7ReK+oFlUCaWcwYdOZGN4+tyKNuC5NzFrDCRXz2MGoCUV2Ulojbd/6VRnPNNbMvxCoOS94SZxKAgcSmJoGzQn+OJt5rQdHyvA7OsJn6VtLpgCtCOO+6qOFcMrz8gbiucgAAUUKBxf9uMKNKUd02c9C8U00pGqTtKiC6E8GbcihIIcrhKHMLkx/6XPOwIp5wqE8qy3nEqG1dPB2KArfmKXkFgl9iWRw4kPjKAlOzSz02EO17wDDXuWbUcIoXrFwbobomdJDAY/6zeuTfLCDNMDAmFr4ZoCHDdEsaI3dLdWCvF+x8gbiIMkdtq05yY6RBmhsBtkOVd2HloCcmSVV/wAYEdPm5l9E/NqhMccIeaCV+HAuGdzkxKCiigCyXEbAOQ8uvyil/bEaaXH7pKdz2Ro2bpAGjOQ0btvy8IfPhxUzBAM0NjNIZyyE0Bx8ssZKZelDfBWxyETkcy2a8A8vGM7t5oaHqWch4QuOzzFeLq+azIZU2Ocz3chuYVQoiZ5WjKZu7W6S8cP8nvKTFNgxplLEiCTfDesJqIi0oTDUjGgvbhEa3sFKeO4gzY57wZoLrUmbfs4psgdYmPEQqGm81J9d8WY9rLPMTlRM7TDXpVF0QSJpue8YpZnLzGdurWqWsOxj/hOswOMgMsdVTaF7gCQohV0eDh7NDBUVheFZAxodUeJvkhf86FGafC/JaGIZgtAfGa7AXCN3tzBliCrf4GDvIEwHCCzyAM8T8s3JFjP67ynWCoaGph8WiPFfYCmhPq1lCcDtQe2GVjDkUXPHCsaK3G2NXPGjUfF4oGj6IyA0YxniXuWefuE6FZw1NF1kimrmhqr21x7tRuY9xSn6nYZbegQ+xdJ/GGPkXkb38Widcoot6WpLgd7VbN1bOYyIHYd3DU4F+UrfepIQqRS83hPYVzGF+tA07FtoQorI+myVGBbKjAwaZWtDNpXOPaoSCCfqcgvSAqduwiBugwa6fa3SFghMACHcaW0/GFY6JfAdKsqC6h+ZVGLvncu/eAs6BGuWhdIhcYoPbRnrSgL/2EMhJxgRzQUTwqq4MF9QNw8EgkPP5dfMqyGHIW27mvDWrwvj3wiftoIrRR3g0gL6FFUU2kEZ8hPFBHExYIILgMYUxmAuUFRs+ezxlmyiIMcgXAGu+QK77NevSOJEOkqnZdsRZeEqSoODTqx8nCrBZMmoiKdxfXOz+sXmJGsp5RP2PIB2da1WnaKCgjL4ABvBBCQo0URpbPHROACYKSdOAGtkquxpieLu0ClGqQkWJEqXfad+SW4hSm7QGuXBJxWghiNu9q3o7aZYZF0djE6LuDHt8eMr5yTEWRCxrYoiOMTM7g15MQLn4wLEBxxMvilmZkH9gUCiWJmG7N6t9W84tl7NRJGPHp+zjZbT4jLX9Ki5ngAv2WiV6h6KJtYTObNgS2Zs91sFlBUq5rHAt3QvZ59unbkJIFmfxGblptTJQDBbuIsXbFyl6bkmb7314wjquR+pHOh0A9GxnHS8b76HQ==").unwrap();
    // let encapsulated_key = &BASE64_STANDARD.decode("bBcrMpyzvFLUFKU5vwewlxn9UXPwMFi3lJFJhCQNGpiGOWyEnhPt1nkBfQDZ3rGWCdDfM97NtWWoPkDywAUaytcUCXEXpHbxLgk5hxLmArOMK5p+8YVFBqdhVlN6Ivd+G5TKKZvn0BPElNHNALsyXXrjujVYB8IqYFaDa+WktCvS9n3IbIFZ/NPIFjcvkl3i/3QA0p+bKvJHmpu5b4ZtWEvtOwtDYTU62IWEYUi6grq611FEwE0X+TEm+XEU/QVpgi01LzpLC81M0LAa5UWxzCCel0Y6v/GkdmvVjqygXN4m7re6KeVUcpZuDzGXARKazMgpLHVExAjeD5BAM8r6BD9noOb43LQOYExjgh9kmTEFYKyFRTRj3nUkADbnqrwsu1/jkbR+fd1rGfa1MxnviQ+RcM5dUVR6TUH+eHTyGAKDz9y315YnBynrINJ0GWyZ0Na8PEDUzdzT0AKRCHU7yz90IEb6BaWlIcLbxa/cSYeUgkO/5CxoWmpJxsrVEpCF8AsS8yHjWiTKoLSos2KcsLN3PBxdDxG4Mbf0BEwdNl3TiYwM1GAngtkeQDmzYK42502H3dZkDbCjDfIWKl2V6Dt1r/k+np1Qau7eBTgRyCsXdMjN90nJCCqI9F+RKf7zjtFWye6682Tvkc2kqv2+7YCvgeoX59mdgCBxlT84M0Sz64y++WhLOFusOsSAvH8BWiQo3IMPjX5I9kLMRWGDtSZYXrd2kXi/DmVDSLU7BJr8ljrwdlrkXDcsOhGb7K1q74pWshRnFIPx4G9lUR5D6iP9tHtYgdjbMrc6EQe+oRG/+hEXIqGd+xowtPoExtSYrrxO6WpBYhH0CFeZ/PGDHNe1QDLLyCLNykUKq2ZziJkDzfeEvFU7db5bTPJ5hy0FpWdYQQ0tQuy50v0JnaYjV9UX77XzMWYFNWMbyhIrLycfJddDj78ssNApQtzaoaT98VPLmT6+AZODD1La9LXqWXwpIf8xVky6DwGFvQU4wPR8LRlM3uu4JYEmck/8L3KaenHztO7SYhzk2IL+whs3mVtUHxkPEeSAGPK+TQA0nQmTfYTwAgeR0IcLPTfpERnPf3r3OhSCIbuvry3YbtWic+xmAenlIRsxyWwUaGW7u1Bq2BshNbq9oppX4NWVA1gly1F5ag6bNS6A9UhEGpPnxe/ZhF6O5PbhZIgGF0T6Z3WnRzgGfYZ8Q4eR3hvnBE3voHtEQY938dCQOqfu5E7ca4e4YJMb5yh5Eh7kOOnH4D/7tDQVHjTBwb3f3A/GWNxu5jEXd75dH3+1i1lssKGm8PSzVVRdpa0xrj73nTVbFfVuM+zCIKgpvXFGvPAnIArOe62sj1aoFPJaQdaFozv0Buwk22sB8pxWedmJ2pXsn0kAyOdDN6M+JMbFtzwhvmzbhnc0sKLH1L69pZOmwuTjjIUUOEGgNUF9Xt+Ml1Qeiy4lgsD+VQlRDE4Gh6DaaC5CpOD5HAU+nzP0KhAFg2dbMw==").unwrap();
    // let ciphertext = &BASE64_STANDARD.decode("S/eqVx5Rm0KZzVPKSnGwYqD30dW0").unwrap();

    let private_raw = &BASE64_STANDARD.decode("xn3xJM+NzUBtj8i+aKrNgBxKb9n6F5XYzihWiSBNE68=").unwrap();
    let public_key = &BASE64_STANDARD.decode("7h3kwwQy4oiSiU3XTdTwY/tbMofAdWUuz04q5cYgldgeKItRQF+r1aok5RA0IxFg686IotPehzm1VQH8XQNtVw==").unwrap();
    let encapsulated_key = &BASE64_STANDARD.decode("BDmhtrp/NjNIzGi/Cuv//AWxTnVsZBzuU9R0poAiNHQZ+aQlKcMMkjGt1We2iSwKFnfZW969FflZts3YWjmB6zE=").unwrap();
    let ciphertext = &BASE64_STANDARD.decode("995tqwZZSmZbSOHuv+VBx6QOd8Fq").unwrap();

    //let private_array: [u8; 32] = private_raw.as_slice().try_into().unwrap();
    let private_key = p256::SecretKey::from_slice(private_raw).unwrap();
    let decapsulator = HpkeKemP256HkdfSha256::new_decapsulator(private_key);
    let encapsulator = decapsulator.get_encapsulator();

    //let (encapsulator, decapsulator) = HybridKemQsfX25519MlKem768::derive_from_seed(&Array::try_from(seed_2.as_slice()).unwrap());
    //let (encapsulator, decapsulator) = HpkeKemX25519HkdfSha256::derive_from_seed(&Array::try_from(private_raw.as_slice()).unwrap());

    assert_eq! ( &encapsulator.as_bytes().as_slice()[1..], public_key);
    // println! ( "pub1={:02X?}", encapsulator.as_bytes());
    // println! ( "pub2={:02X?}", public_key);

    let decryptor = HpkeIesP256Sha256Aes256Gcm::decryptor_from_decapsulator(decapsulator);

    let result = decryptor.single_shot_open(GenericArray::from_slice(encapsulated_key.as_slice()), &info, ciphertext.as_slice(), None).unwrap();

    assert_eq! ( result, b"hello");
    
}

#[test]
fn test_apple_hpke_p384() {
//    let seed = &BASE64_STANDARD.decode("67fs0M/OfCiCkfI6BC9Ma6K7isbVcu1KRjJkYMR65Kg=").unwrap();
    // let encapsulated_key = &BASE64_STANDARD.decode("h6J7OCmGB2ddVMiCbGC9519I7xDKP4BjA7yaMYyVgc9ODzyEdWKSz+sUADfQzENRAFJg0iqbyD11zWaXK4kSpWHX7y1oIlBsBqAVI+9RBNlMnk/T1nIRbDx0dOkqQzbHttyJbFAhQ/zVswmua4XhwtE0jiduVzljcWg8hTEN2LHuQ/plzmma5Xw8R8LMH41muuJMQAjf2NW1taaCqPz09aKD9mheC66/v6KZEEdmTuZpm4dD2hhRozsaAguE2jfJH06oK0tbwABHRcksz28twXkckk6JM1B1rcmpC9OdTX3VVax3Af+YwiVsIxBOJ1SVRUh3Q1AUCYwy8LNnPQFfB59T90TLkNtZBikxB2rJoGjLE4kflG+rCYyhkBA1Tqt5nLlf/GMxUubD7RlJU6URiO6lmUDncqo59MNonA6LK/QHI8k7RFQf29f+aSvxO4HiQ8Zkq9TzL1kEyMmP5a7lL14xJtky8adikguOa4GZlQW+tfwpFrcAxL6vC5Le2xDWi0YHxi4hY8gpNZXceEZypnBYSzUDtwA6fjht4Ativ/0nVdoywLXE3abYgbW8SR+n4q51uavEtGSi/xceQ99eg05ReuT8fivzL8r1FXFnMd+JSi/UBVOL3o7e58MGS+CyvdEY/NuoqtpWQo9KFOvfovErtvlfdWPonPbhTn18QkYR3/irD+kYpmmkm5G1xUetA/UawBeSsgrX2dPqIstPPxuwNSQooAI8WiB7Cr+X94YLk555Zfxb1319CuyX+/UXok7Z/ECXydoyBiUVUtTp2m7lAqNefz9wc3SRjKrtmBKZKEmrus+OaiKWXiyNtGYtFzScfS51B6ixEm1CD+OACsRuokHLyRzmPufKEJfwEk55d1Q4yKgIklnB3FvWR+JtK5QL3jmkJtFQ+qMKfjbTosdubPyFckm+LdLJ7aXuWcCL/ixhxTR/aAnVTazBlexxXyceZxvNwODqoWx16YVOEpLT9m0VaRRU//6lG61viCUgeJRpsGLL2Yx5XlWMpwdV+ii0SpU28WW8b8P6LQWi4mWTh5fBqzwWuULgPy7DyX6ZsLpFBbnENO2ZLt1OYF8GAxBbMQ2AUDatchkqO7mwHexmmzmFxX7mMkVy+pfl2O63YbtQJ740mK6dcJ7EpWWrAeR11k4EtTcEnYt0hAXGEGf9FmskzVCZlv+VIBM9NZZnO0DCMqx+T42c4YAcLhbA5nsTxhOmt3v7jQGxjFdLMhaRzg7hkIvdemuBTGxd6AGHk4DuRthkTms2GaB148Y6ycm3h0eLYph/NpmaO9WSyE4lir4Qjzx4MUDSMskVeVaiGOjYzBDZpv+VmGBKiXGWPk+TPYkUQjR3m2fb8scW+9rO3JE4TznJ4WzA9EmNncFAwkmfNVApWSpxFI5pDcHOkB2sGuOiA1cpDnK5PA2Y4+u3GYDQ3Z5eIv33qWpjf2ZcQ7QlOeT6eNvrqxucBrcOX1CaCCYvPqPr/FjuH9RWRg==").unwrap();
    // let ciphertext = &BASE64_STANDARD.decode("fVgZd6//P9xgLDeLAO9zcuotZsE0").unwrap();
    let info = hex!("0408");

    // let seed = &BASE64_STANDARD.decode("O3vXZJtfNsnucAnfTcEWSDt9gK6iKGiTdAf0YEz5m5M=").unwrap();
    // let public_key = &BASE64_STANDARD.decode("H2Q2eyOcJVRDtMVpReGAq/oge1w0his4+FdawodERhWmW0k1TSqK+pR2RLSAjUuHLEErGVAllyeEOmuJfMxqaiWx8xVv14xxcAOIdnKfvutCR/uBwxw9KDLLm2p2EZca6vhHffA7BfcnxJxrLCijk6ZGmhUgsGNqkAyhXfpTeLMgEYmu1dSDBYYO03ogHDGknAu1qrkqBzlwmOWUs1wLy8yFiiZzAxV7X1VCJke1xSnFNFDL7rKWyhRDxYZzFwYRkvdCrXE2QYHOB9dtZgZ9AtZ/PPaRU9wk+0iE2KnMlskdIAMqS4Bu1hcrbYR8I2RdYxt3uaJejBmBoPaAsKiS2mEpV4sy7iRZ15EViyItKYcML6qBi2qBO+keDHI2fasC1Hsd+rAoh+gRpLq9ofoi7eu230NSI0EEEZV4dVVYrERwqYwUewSUNOGld0fLOXgUrERg9fTBhDiBfNp6iGuwRcIu5tM3wPMuDgRSvtaalZArOuVyYExHxEGzsIV+LImaUkaE61WB93mU8nAog+Sf9FkonwYr6LAnAtoKf7N4CjudloCIeAMYPtePnyofk/A+jtHFe5hjXOOcrYyhdGpGuhVHnVFm1SJS1WWjHzWviicV9yQyncte26RgkIW+saAxsbyTiBscihLEl7J8JXa4ZWK+tSkuUpC44jGOHBGpVhcUncaNY4lerZICZ0pzE+DOM4WVGpHHAKegT9GH+rV+rPAHUFExLSaEIHZfnnkE9JlXQzwxSABxU8xR0yIxl3S2S8EuwtCPtWCSt+cFAPcTt1qbb5g54DrBfiikfAC5KUt7WrzFTNRJ3HB/pRlz3GS0XtkDGyOU92xqgXPBbdOo9FOdXay4DHyLpAWnMcJwFvcyLbgiJ2KAtVgH3aqE8VAH/hE5wPoQVGxYU8Y8HsQV6ZlYlcopNMvIfTwwAliiVuEHGQVaPCMgeDAmdVdIwJiStjRoFnsvU4tQ9UHCvpekGLKuo6ZHm5tUckGwfbyr+oYELYioRLCzm+uN85xO+XENKrkPGRO7CVcp+cO6QrpYmCW5D7ZmSxTKKMSYIEom07dXR0kVP6FO+Fco6NQE4PJNgAqgz+Bm3MWhxJPJuxRczLp/w0hhbPWlZgFgJYuuqoyaaccJBsq1Gqw2qRwhq0ExiYERjdmzDDWA3zMXEhFN97UVJdZ5u8YcFFBgvhmFkPwuMdBtO7RrgsO+X+qsLhVb89hXKTUDvmFvMWK8iRzDNyyVrxB/IRkfAhBkiZqnGpWeBUqrGbEpGSiW4ZMDFwuL2fcN8Pwxg6QlDnMwhGo9QCKQ6wGG2Ipre/Nr5ksQgJuEmpCf0Zal9DWrgMMWqzPOQ2EiKjt2snCuKQrQUPE1fpUNKwXBRwVFdzapmXpGIQMSSqSWVmlJqQJXd/Ve5cq20Mk3m0WXYESkVWVog/JzVvOLvPR1z+XIC+Vy8nInx3fNUTu5SEYzzNlhXmMh3CiPZtwimOCgturBZaw66CaeGCY3FIkcUoY/VohcnsyzKBdsFGJe5Cg8duvGlSJ848bH5LpBY8F6JoasrrXILPNfqSKzAS3HEuv15fcZu67MZsOIpxjhcOq7IEusLimpjxC7RMkxlnM5rDgYLJzZPjqLIg==").unwrap();
    // let encapsulated_key = &BASE64_STANDARD.decode("0q0eUx7HRDrRC/NRb1VPIZ3AL/hi+XKHSArqxtx5f39LPUgQ7nV+421wWIqctXAJiEbgsLaBMfYPiXwnkSPjdwDmdBoI3Z1kX9tK1MCmR7eXKCfwcWVTLgSKwqbmwjzqviRZ4I17yt/YMl3cJna9yJDFk7OjzYINJQUg+FmcdxxmTXECy8pr8NJQkIotGPQeGPwBlxIJE1sZrCux1drpJ5boU+yWSQtg/vio+xzBYsGaI8DWaT9G5AHxIUBteYqv0xfceHSVRBv1dmlCbtCNGlIuIZY1iBbFUWgJMMQKGUnEqxtnlFXYRRUijn+HwZ2OUc++2AhMK/JlnZmqPjEOp6g3Wbtx+RfaMQkGGjMuMur6gcSSCbrSI/X8KFwsj0lMYSMYiiIbY8C5VnJpMem6LjAjrg+um1fW/IgBdbfs/2yrRFmyxgzb1z6fwObk+dnuUkqg/MlAFfYHBdVZtn8hmPMKmn7rm1UG4Mc5GhM+k54qWQf31JYTBOVuXriAy3THcslWsTvHR9swuHOZr6+VUdoYk0UTePp+ektR+2FpBEkRbiR+nJ6bVgyjPG/74GI2j3/66+tQYu5VeF2mArbgZxOfXDAV2nZE8I4FlBcmVLsRtDQbIZHUWpVcTSwSFScN37ikqHg0zck6yq6bii8gSL1Xk/mAQQUIct4tToR1FY7cAjJ0ZXTjPJn99kd87H+TzvlMYg6h1jTFCfq6+2KvomEjKsb3G9n6vFA9xTszQy6eojSfeAHLAED+78FN2AX0YTC+H8tny847bkMzziPsgrdQB3O4yFhPPfUPTdr7W9o+UIYO6b51dfTjfGPXsbbpfZK/NFpITdCG2KMfG2eYHlHBv6RUMYUXLpxapBa0EKvMYqqK8purEn28qvOoUQOBhJhW5Fu8c1v7kAIZNhwjnD5bo1TSI0D/cl9+JemzG1RkGHANY1D9jDkv5Ua9rNpIqpCmfP7S5XD2kTln1rUWo0G5djN0mkfP6RKX/4EU6ZPESW6CD+PRnrLl4qgWAktkDiatQqpF3mwbGqabpDQyvmm1M/exOvbR/taezZMdPuwthjKxrxBEVybt632XMRcZAvc8vZ9NrnxXrBs7X28zX1L/Q4HtC1uZzAj0gcxld0v9ltBz9+t52zypyptlLEzXmJ6jmJNMrvmZ5eVVm7+w/Muy9vD9K4xk6MpGmHzORY7WcUCsonxcWqEDpXREZzPGwoQaCpfXgvQj0xXoDV3sX/l9fGH6l2G+cJjqpIfK7uVnAIvMsX4rseOYSR0uYEDr3w4eUK3qqD9zeqtKAtzoX1Rn2JVjwC4dcKMsgdJLd3KeRFC6PkAj4fY8fsXCtjYeWs9BLwFhPCssaAEL7V0JkONHFSjPXkUP2PjLrutDRJvbhFdAWrCRZBKOc1gOSJaVKbWadF09M4V9a9iB1T6XmyIxQLzOP+6ubcsi2HpiT16EdjSJkbiRzHUMzOxlVHjENKSZTeWT6WMfRMN3HSy/fA==").unwrap();
    // let ciphertext = &BASE64_STANDARD.decode("J2Rbn2MMd7q1AxOtNGqOOO0VFc4z").unwrap();

    
    //let seed_2 = &BASE64_STANDARD.decode("NqAfhJbWnDMut0NWwZjOTD4YhLmfe74jwKbY/txpfpH3MdH3E/MiEvCrWFW++iWvNfIObAZbENJviEEEsJl5lA==").unwrap();
    // let public_key = &BASE64_STANDARD.decode("9Pe9i/LE05J9kIqUDQqsQldheKiWezZoX5JJOUJYZtOmkmWfEmZx3RwHASK6bouTZhcZnINJBQp98tKjNIA1BihVMASeIcd1jwpln3WCBDDBivS7ReK+oFlUCaWcwYdOZGN4+tyKNuC5NzFrDCRXz2MGoCUV2Ulojbd/6VRnPNNbMvxCoOS94SZxKAgcSmJoGzQn+OJt5rQdHyvA7OsJn6VtLpgCtCOO+6qOFcMrz8gbiucgAAUUKBxf9uMKNKUd02c9C8U00pGqTtKiC6E8GbcihIIcrhKHMLkx/6XPOwIp5wqE8qy3nEqG1dPB2KArfmKXkFgl9iWRw4kPjKAlOzSz02EO17wDDXuWbUcIoXrFwbobomdJDAY/6zeuTfLCDNMDAmFr4ZoCHDdEsaI3dLdWCvF+x8gbiIMkdtq05yY6RBmhsBtkOVd2HloCcmSVV/wAYEdPm5l9E/NqhMccIeaCV+HAuGdzkxKCiigCyXEbAOQ8uvyil/bEaaXH7pKdz2Ro2bpAGjOQ0btvy8IfPhxUzBAM0NjNIZyyE0Bx8ssZKZelDfBWxyETkcy2a8A8vGM7t5oaHqWch4QuOzzFeLq+azIZU2Ocz3chuYVQoiZ5WjKZu7W6S8cP8nvKTFNgxplLEiCTfDesJqIi0oTDUjGgvbhEa3sFKeO4gzY57wZoLrUmbfs4psgdYmPEQqGm81J9d8WY9rLPMTlRM7TDXpVF0QSJpue8YpZnLzGdurWqWsOxj/hOswOMgMsdVTaF7gCQohV0eDh7NDBUVheFZAxodUeJvkhf86FGafC/JaGIZgtAfGa7AXCN3tzBliCrf4GDvIEwHCCzyAM8T8s3JFjP67ynWCoaGph8WiPFfYCmhPq1lCcDtQe2GVjDkUXPHCsaK3G2NXPGjUfF4oGj6IyA0YxniXuWefuE6FZw1NF1kimrmhqr21x7tRuY9xSn6nYZbegQ+xdJ/GGPkXkb38Widcoot6WpLgd7VbN1bOYyIHYd3DU4F+UrfepIQqRS83hPYVzGF+tA07FtoQorI+myVGBbKjAwaZWtDNpXOPaoSCCfqcgvSAqduwiBugwa6fa3SFghMACHcaW0/GFY6JfAdKsqC6h+ZVGLvncu/eAs6BGuWhdIhcYoPbRnrSgL/2EMhJxgRzQUTwqq4MF9QNw8EgkPP5dfMqyGHIW27mvDWrwvj3wiftoIrRR3g0gL6FFUU2kEZ8hPFBHExYIILgMYUxmAuUFRs+ezxlmyiIMcgXAGu+QK77NevSOJEOkqnZdsRZeEqSoODTqx8nCrBZMmoiKdxfXOz+sXmJGsp5RP2PIB2da1WnaKCgjL4ABvBBCQo0URpbPHROACYKSdOAGtkquxpieLu0ClGqQkWJEqXfad+SW4hSm7QGuXBJxWghiNu9q3o7aZYZF0djE6LuDHt8eMr5yTEWRCxrYoiOMTM7g15MQLn4wLEBxxMvilmZkH9gUCiWJmG7N6t9W84tl7NRJGPHp+zjZbT4jLX9Ki5ngAv2WiV6h6KJtYTObNgS2Zs91sFlBUq5rHAt3QvZ59unbkJIFmfxGblptTJQDBbuIsXbFyl6bkmb7314wjquR+pHOh0A9GxnHS8b76HQ==").unwrap();
    // let encapsulated_key = &BASE64_STANDARD.decode("bBcrMpyzvFLUFKU5vwewlxn9UXPwMFi3lJFJhCQNGpiGOWyEnhPt1nkBfQDZ3rGWCdDfM97NtWWoPkDywAUaytcUCXEXpHbxLgk5hxLmArOMK5p+8YVFBqdhVlN6Ivd+G5TKKZvn0BPElNHNALsyXXrjujVYB8IqYFaDa+WktCvS9n3IbIFZ/NPIFjcvkl3i/3QA0p+bKvJHmpu5b4ZtWEvtOwtDYTU62IWEYUi6grq611FEwE0X+TEm+XEU/QVpgi01LzpLC81M0LAa5UWxzCCel0Y6v/GkdmvVjqygXN4m7re6KeVUcpZuDzGXARKazMgpLHVExAjeD5BAM8r6BD9noOb43LQOYExjgh9kmTEFYKyFRTRj3nUkADbnqrwsu1/jkbR+fd1rGfa1MxnviQ+RcM5dUVR6TUH+eHTyGAKDz9y315YnBynrINJ0GWyZ0Na8PEDUzdzT0AKRCHU7yz90IEb6BaWlIcLbxa/cSYeUgkO/5CxoWmpJxsrVEpCF8AsS8yHjWiTKoLSos2KcsLN3PBxdDxG4Mbf0BEwdNl3TiYwM1GAngtkeQDmzYK42502H3dZkDbCjDfIWKl2V6Dt1r/k+np1Qau7eBTgRyCsXdMjN90nJCCqI9F+RKf7zjtFWye6682Tvkc2kqv2+7YCvgeoX59mdgCBxlT84M0Sz64y++WhLOFusOsSAvH8BWiQo3IMPjX5I9kLMRWGDtSZYXrd2kXi/DmVDSLU7BJr8ljrwdlrkXDcsOhGb7K1q74pWshRnFIPx4G9lUR5D6iP9tHtYgdjbMrc6EQe+oRG/+hEXIqGd+xowtPoExtSYrrxO6WpBYhH0CFeZ/PGDHNe1QDLLyCLNykUKq2ZziJkDzfeEvFU7db5bTPJ5hy0FpWdYQQ0tQuy50v0JnaYjV9UX77XzMWYFNWMbyhIrLycfJddDj78ssNApQtzaoaT98VPLmT6+AZODD1La9LXqWXwpIf8xVky6DwGFvQU4wPR8LRlM3uu4JYEmck/8L3KaenHztO7SYhzk2IL+whs3mVtUHxkPEeSAGPK+TQA0nQmTfYTwAgeR0IcLPTfpERnPf3r3OhSCIbuvry3YbtWic+xmAenlIRsxyWwUaGW7u1Bq2BshNbq9oppX4NWVA1gly1F5ag6bNS6A9UhEGpPnxe/ZhF6O5PbhZIgGF0T6Z3WnRzgGfYZ8Q4eR3hvnBE3voHtEQY938dCQOqfu5E7ca4e4YJMb5yh5Eh7kOOnH4D/7tDQVHjTBwb3f3A/GWNxu5jEXd75dH3+1i1lssKGm8PSzVVRdpa0xrj73nTVbFfVuM+zCIKgpvXFGvPAnIArOe62sj1aoFPJaQdaFozv0Buwk22sB8pxWedmJ2pXsn0kAyOdDN6M+JMbFtzwhvmzbhnc0sKLH1L69pZOmwuTjjIUUOEGgNUF9Xt+Ml1Qeiy4lgsD+VQlRDE4Gh6DaaC5CpOD5HAU+nzP0KhAFg2dbMw==").unwrap();
    // let ciphertext = &BASE64_STANDARD.decode("S/eqVx5Rm0KZzVPKSnGwYqD30dW0").unwrap();

    let private_raw = &BASE64_STANDARD.decode("b9axCAE6PRcHXB5NzUVQ4CIkjbAeXPQ0zaKNtNNFi/nDZwlyIrqqtHtZdZV5R0yh").unwrap();
    let public_key = &BASE64_STANDARD.decode("UGxU2udrRunriFz/ZpVigSUeJTiz4ux1qG+001OHoc6hixpuli8Ba4uglGBpElDgRxC8LVKWYSRkUCeiQV1cCllk/P2zerc3+/uLptKxxgs3kkFE5R9azMU/yBRENWZU").unwrap();
    let encapsulated_key = &BASE64_STANDARD.decode("BLAb2Q+7+yjD17+CPCwooGxwcmFELXI6xrY1/h0ijHdFLJdVA4htb+edFcNa+yMEyFZ4ks0cVQQkaaXAgrOg3RHFn7zeAis3Pq9ZnjTBcggNgLHSOlc/KjIBfYvjk25rgg==").unwrap();
    let ciphertext = &BASE64_STANDARD.decode("LHtZuQKFqCwqp4C142GFMi4GvFwt").unwrap();

    //let private_array: [u8; 32] = private_raw.as_slice().try_into().unwrap();
    let private_key = p384::SecretKey::from_slice(private_raw).unwrap();
    let decapsulator = HpkeKemP384HkdfSha384::new_decapsulator(private_key);
    let encapsulator = decapsulator.get_encapsulator();

    //let (encapsulator, decapsulator) = HybridKemQsfX25519MlKem768::derive_from_seed(&Array::try_from(seed_2.as_slice()).unwrap());
    //let (encapsulator, decapsulator) = HpkeKemX25519HkdfSha256::derive_from_seed(&Array::try_from(private_raw.as_slice()).unwrap());

    assert_eq! ( &encapsulator.as_bytes().as_slice()[1..], public_key);
    // println! ( "pub1={:02X?}", encapsulator.as_bytes());
    // println! ( "pub2={:02X?}", public_key);

    let decryptor = HpkeIesP384Sha384Aes256Gcm::decryptor_from_decapsulator(decapsulator);

    let result = decryptor.single_shot_open(GenericArray::from_slice(encapsulated_key.as_slice()), &info, ciphertext.as_slice(), None).unwrap();

    assert_eq! ( result, b"hello");
    
}







#[test]
fn test_apple_hpke_p521() {
    let info = hex!("0408");

    let private_raw = &BASE64_STANDARD.decode("AKUvuZ3qsh0j5le8Xs9tfwZLjnJf+aM014TbgXV7T9OdxeKt2fkKYFFRIRN9eLRlXgYJu3LWH4eJ8tVsXaDzDsaz").unwrap();
    let public_key = &BASE64_STANDARD.decode("AJgm/1WGDOHKnxkgjTKoPQJoowTZnoGNuSK8HVdyUp4+9o2RR4/kuiHck+55w32OKfuNoweO4gRgakunv/dFYCFeAWf/uPjIgrByi8AkaiizAcoui4IbEOGvTZkWuaVUHFpYAdMp79h0dIgylqJBW4Pxdwg7Nh/TIhLLRWTUHFGSA3WD").unwrap();
    let encapsulated_key = &BASE64_STANDARD.decode("BAGLi2Ipg/ZejdUsPajFsSBzYS3KM4o9o5auw4hz/g7+7s+tds0VQHTxUmovXDxfu6UEpAvlUEsQn2mlKTql+fdfEQFsUi3fLqTxeRdC3LjvDw2510Wy36SIp9+d6Ss+OcU6ptw2k0dzrQ3ahAF9UU5vZvyXGyb+ERAMiITNwC9xLVlGsg==").unwrap();
    let ciphertext = &BASE64_STANDARD.decode("EQwIunwifRYJ4WP33lS69OTYNvzj").unwrap();

    //let private_array: [u8; 32] = private_raw.as_slice().try_into().unwrap();
    let private_key = p521::SecretKey::from_slice(private_raw).unwrap();
    let decapsulator = HpkeKemP521HkdfSha512::new_decapsulator(private_key);
    let encapsulator = decapsulator.get_encapsulator();

    //let (encapsulator, decapsulator) = HybridKemQsfX25519MlKem768::derive_from_seed(&Array::try_from(seed_2.as_slice()).unwrap());
    //let (encapsulator, decapsulator) = HpkeKemX25519HkdfSha256::derive_from_seed(&Array::try_from(private_raw.as_slice()).unwrap());

    assert_eq! ( &encapsulator.as_bytes().as_slice()[1..], public_key);
    // println! ( "pub1={:02X?}", encapsulator.as_bytes());
    // println! ( "pub2={:02X?}", public_key);

    let decryptor = HpkeIesP521Sha512Aes256Gcm::decryptor_from_decapsulator(decapsulator);

    let result = decryptor.single_shot_open(GenericArray::from_slice(encapsulated_key.as_slice()), &info, ciphertext.as_slice(), None).unwrap();

    assert_eq! ( result, b"hello");
    
}



#[test]
fn test_apple_hpke_p256_sha384_chacha() {
    let info = hex!("0408");

    let private_raw = &BASE64_STANDARD.decode("08VOcjYMVUbAv7HsGuxQf6zuPmAILWLMXJFDF0iwRk8=").unwrap();
    let public_key = &BASE64_STANDARD.decode("vevzVCumJJ/aIXI435I3aG7zSnQoayEaYdu90jP/IE1EpcbTGPhGlmubBRQ+fz/aVw2WbTU8/M9lmjddK8kekg==").unwrap();
    let encapsulated_key = &BASE64_STANDARD.decode("BEYjWITuKyyrLiS/o+htvaymtXOv146vupKJtanscqvc/FvTNI/kXtS5leudItYWvbGocD6ACca9UPWug7Uvmtc=").unwrap();
    let ciphertext = &BASE64_STANDARD.decode("dO27R0NZuBa9sSq1HyrSAhkhJu3k").unwrap();

    //let private_array: [u8; 32] = private_raw.as_slice().try_into().unwrap();
    let private_key = p256::SecretKey::from_slice(private_raw).unwrap();
    let decapsulator = HpkeKemP256HkdfSha256::new_decapsulator(private_key);
    let encapsulator = decapsulator.get_encapsulator();

    //let (encapsulator, decapsulator) = HybridKemQsfX25519MlKem768::derive_from_seed(&Array::try_from(seed_2.as_slice()).unwrap());
    //let (encapsulator, decapsulator) = HpkeKemX25519HkdfSha256::derive_from_seed(&Array::try_from(private_raw.as_slice()).unwrap());

    assert_eq! ( &encapsulator.as_bytes().as_slice()[1..], public_key);
    // println! ( "pub1={:02X?}", encapsulator.as_bytes());
    // println! ( "pub2={:02X?}", public_key);

    //let decryptor = HpkeIes::<HpkeKemP256HkdfSha256, HpkeTwoStepKdf<Hkdf<Sha384>>, chacha20poly1305::ChaCha20Poly1305>::decryptor_from_decapsulator(decapsulator);
    //let decrypto = HpkeIesP256Sha384ChaCha20Poly1305::decryptor_from_decapsulator(decapsulator);
    let decryptor = HpkeIes::<HpkeKemP256HkdfSha256, HpkeHkdfSha384, chacha20poly1305::ChaCha20Poly1305>::decryptor_from_decapsulator(decapsulator);

    let result = decryptor.single_shot_open(GenericArray::from_slice(encapsulated_key.as_slice()), &info, ciphertext.as_slice(), None).unwrap();

    assert_eq! ( result, b"hello");
    
}


#[test]
fn test_apple_hpke_p256_auth() {
  let info = hex!("0408");
  let private_recip_raw = &BASE64_STANDARD.decode("XXA4ZZgIUZvo0wFwH1YIeCsTbWF7D+OR0JKa70MAFTQ=").unwrap();
  let public_recip_raw = &BASE64_STANDARD.decode("Yl1GNUxsWQSHXpbojwyE98RmxcTYQHJaNdGTriWOmDj3aDHowxCRcT9ElknRzdcDPFXc/vGlL8cJIpkqcIzm6w==").unwrap();
  let private_sender_raw = &BASE64_STANDARD.decode("/QGZ3aThDJO0Iz5qbrQTeXwWDnm3wS60CtgcSWcb4kA=").unwrap();
  let public_sender_raw = &BASE64_STANDARD.decode("AhYcVhNRP+UESv8VozUCMY14RF/ad7szOZEFemHRGH8Mtg1wGy4T2h3DdgHSJgJueYUbYTTXk5fT4VRNsQD8wg==").unwrap();

  let encapsulated_key = &BASE64_STANDARD.decode("BExbWv9PerHYA98He2Dmmx7vEwFvRge8CpqdsUlWu8qjf+YrPROkRhJ9hMQMJW29RkoHFoS074lC/euq0KHqAWk=").unwrap();
  let ciphertext = &BASE64_STANDARD.decode("oZgb610Y9b+oh1QZSIYO613G5W44").unwrap();

  let private_recip_key = p256::SecretKey::from_slice(private_recip_raw).unwrap();
  let private_sender_key = p256::SecretKey::from_slice(private_sender_raw).unwrap();
  let public_recip_key = private_recip_key.public_key();
  assert_eq! ( &public_recip_key.to_sec1_bytes()[1..], public_recip_raw.as_slice());
  let public_sender_key = private_sender_key.public_key();
  assert_eq! ( &public_sender_key.to_sec1_bytes()[1..], public_sender_raw.as_slice());


  //type HpkeAuthKemP256HkdfSha256 = EcdhAuthCapsulator<NistP256, EcCombinerAllPubKeys::<HpkeKemKdf::<Hkdf<Sha256>, kem_id::DhKemP256HkdfSha256>>,U32, EcRawEncoder<NistP256>>;
  //impl KemId for HpkeAuthKemP256HkdfSha256 { type KemType = kem_id::DhKemP256HkdfSha256;}

  //let decapsulator = HpkeAuthKemP256HkdfSha256::from_bytes_decap(GenericArray::from_slice(private_recip_raw), GenericArray::from_slice(public_sender_raw));
  let decapsulator = <HpkeAuthKemP256HkdfSha256 as Capsulator>::Decapsulator::from_keys(private_sender_key.public_key(), private_recip_key);

  //type HpkeAuthIesP256Sha256Aes128Gcm = HpkeIes<HpkeAuthKemP256HkdfSha256, HpkeTwoStepKdf<Hkdf<Sha256>>, aes_gcm::Aes128Gcm, true>;
  
  let decryptor = HpkeAuthIesP256Sha256Aes256Gcm::auth_decryptor_from_decapsulator(decapsulator);

  let result = decryptor.single_shot_open(GenericArray::from_slice(&encapsulated_key.as_slice()), &info, ciphertext.as_slice(), None).unwrap();

  assert_eq!( result, b"hello");
  
  //let encapsulator = decapsulator.get_encapsulator();

    //let x = concat_bytes! ( b"ABC", b"DEF");
    //println! ( "x={x}");
}

#[test]
fn test_ml_kem_512_hpke () {
    

    let (encryptor, decryptor) = HpkeIesMlKem768Sha256Aes128Gcm::derive_pair_from_seed(&[1u8;64]).unwrap();
    
    let (encapsulated_key, encrypted_payload) = encryptor.single_shot_seal(&mut OsRng, b"Hello World".as_ref(), b"info", None).unwrap();

    let decrypted = decryptor.single_shot_open(&encapsulated_key, b"info", encrypted_payload.as_slice(), None).unwrap();

    assert_eq!( decrypted, b"Hello World");
}



#[test]
fn test_ml_kem_768_hpke () {
    
    let (encapsulator, decapsulator) = HpkeKemMlKem768::derive_from_seed(&[2u8;64].into());
    let encapsulator_as_bytes = encapsulator.as_bytes();
        
    //let encryptor = hpke::hpke_types::draft_ietf_hpke_pq::HpkeIesMlKem768Sha256Aes128Gcm::encryptor_from_encapsulator(encapsulator);
    let encryptor = HpkeIesMlKem768Sha256Aes128Gcm::encryptor_from_bytes(&encapsulator_as_bytes);
    let (encapsulated_key, encrypted_payload) = encryptor.single_shot_seal(&mut OsRng, b"Hello World".as_ref(), b"info", None).unwrap();

    let decryptor = HpkeIesMlKem768Sha256Aes128Gcm::decryptor_from_decapsulator(decapsulator);
    let decrypted = decryptor.single_shot_open(&encapsulated_key, b"info", encrypted_payload.as_ref(), None).unwrap();

    assert_eq! ( decrypted, b"Hello World" );
}

#[test]
fn test_ml_kem_1024_hpke () {
    //let (priv_key, pub_key) = MlKem1024::generate(&mut OsRng);

    
    //let (encapsulator, decapsulator) = MlKemWithAddKeyDer::<MlKem1024, U32>::generate(&mut OsRng);
    let (encapsulator, decapsulator) = HpkeKemMlKem1024::generate(&mut OsRng);
    //let priv_key = decapsulator.as_ref();
    //let pub_key = encapsulator.as_ref();
    

    //let encapsulator = MlKemEncapsulator::<MlKem1024, <MlKem1024 as KemCore>::EncapsulationKey, U32>::from(pub_key.clone());
    //let (ek, ss_send) = encapsulator.try_encap(&mut OsRng, &pub_key).unwrap();
    let (ek, ss_send) = encapsulator.encapsulate(&mut OsRng).unwrap();

    //let decapsulator = MlKemDecapsulator::<MlKem1024>::new(priv_key.clone());
    //let ss_recv = decapsulator.try_decap(&ek).unwrap();
    let ss_recv = decapsulator.decapsulate(&ek).unwrap();

    assert_eq! ( ss_send, ss_recv);
    
    // pub type HpkeIesMlKem1024Sha256Aes128Gcm = HpkeIes<MlKemCapsulator<MlKemWrapper<MlKem1024>>, {kem_id::ML_KEM_768}, 
    //                                      Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, aes_gcm::Aes128Gcm, {aead_id::AES_128_GCM}>;

    //let encryptor = HpkeIesMlKem1024Sha256Aes128Gcm::new_encryptor();
    let encryptor = HpkeIesMlKem1024Sha384Aes256Gcm::encryptor_from_encapsulator(encapsulator);
    let (ek, result2) = encryptor.single_shot_seal(&mut OsRng, b"Hello World".as_ref(), b"info", None).unwrap();

    //let decryptor = HpkeIesMlKem1024Sha256Aes128Gcm::new_decryptor(priv_key.clone());
    let decryptor = HpkeIesMlKem1024Sha384Aes256Gcm::decryptor_from_decapsulator(decapsulator); //new_decryptor(priv_key.clone());
    let result3 = decryptor.single_shot_open(&ek, b"info", result2.as_ref(), None).unwrap();

    assert_eq! ( result3, b"Hello World");
}



#[test]
fn test_ml_key_p256_hpke() {
    
    let (encryptor, decryptor) = HpkeIesMlKem768P256Shake256Aes128Gcm::derive_pair_from_seed(&[2u8;32]).unwrap();

    //let encryptor = HpkeQsfP256MlKem768Shake256Aes128Gcm::encryptor_from_encapsulator(pub_key);
    //let (encryptor, decryptor) = HpkeIesQsfMl768P256Sha256Aes128Gcm::generate(&mut OsRng);
    let (encapped_key, ciphertext) = encryptor.single_shot_seal(&mut OsRng, b"Hello World".as_ref(), b"Info", None).unwrap();

    //let decryptor = HpkeQsfP256MlKem768Shake256Aes128Gcm::decryptor_from_decapsulator(priv_key);
    let plaintext = decryptor.single_shot_open(&encapped_key, b"Info", ciphertext.as_ref(), None).unwrap();

    assert!( plaintext == b"Hello World");
}


#[test]
fn test_ml_key_x25519_hpke() {
    

    let (encapsulator, decapsulator) = HybridCapsulatorKitchenSinkMlKem768X25519::generate(&mut OsRng);
    
    let encryptor = HpkeIesKitchenSinkMl768X25519Sha256Aes128Gcm::encryptor_from_encapsulator(encapsulator);
    let (encapped_key, ciphertext) = encryptor.single_shot_seal(&mut OsRng, b"Hello World".as_ref(), b"Info", None).unwrap();

    let decryptor = HpkeIesKitchenSinkMl768X25519Sha256Aes128Gcm::decryptor_from_decapsulator(decapsulator);
    let plaintext = decryptor.single_shot_open(&encapped_key, b"Info", ciphertext.as_ref(), None).unwrap();

    assert!( plaintext == b"Hello World");
}

#[test]
fn test_ml_key_1024_p384_hpke() {
    
    // let (encapsulator, decapsulator) = HybridKem::<
    //         MlKemWithAddKeyDer<MlKem1024>, 
    //         EcdhKem<NistP384, EcCombinerNoPubKeys<PassThroughKdf>, U48, EcCompressedEncoder<NistP384>, ReduceSeed>,
    //         QsfCombiner<Okdf3::<sha3::Sha3_256, u0>, QsfLabelMlKem1024P384>, 
    //         ExpandSeed<typenum::U32, kdfs::cshake::XofKdf<sha3::Shake256>>>::generate(&mut OsRng);

    use hpke::hpke_types::draft_ietf_hpke_pq::HpkeIesQsfMl1024P384Sha256Aes128Gcm;
use kems::OsRng;

    let (encapsulator, decapsulator) = kems::draft_irtf_cfrg_hybrid_kems::HybridCapsulatorQsfMlKem1024P384::generate(&mut OsRng);

    let encryptor = HpkeIesQsfMl1024P384Sha256Aes128Gcm::encryptor_from_encapsulator(encapsulator);
    let (encapped_key, ciphertext) = encryptor.single_shot_seal(&mut OsRng, b"Hello World".as_ref(), b"Info", None).unwrap();
                                                    
    let decryptor = HpkeIesQsfMl1024P384Sha256Aes128Gcm::decryptor_from_decapsulator(decapsulator);
    let plaintext = decryptor.single_shot_open(&encapped_key, b"Info", ciphertext.as_ref(), None).unwrap();

    assert!( plaintext == b"Hello World");
}

///
/// Sample using an xcode project which uses the new apple APIs for hybrid hpke
/// 
#[test]
fn test_apple_hpke_xwing() {
    let info = hex!("0408");

    let seed = &BASE64_STANDARD.decode("NqAfhJbWnDMut0NWwZjOTD4YhLmfe74jwKbY/txpfpE=").unwrap();
    let public_key = &BASE64_STANDARD.decode("9Pe9i/LE05J9kIqUDQqsQldheKiWezZoX5JJOUJYZtOmkmWfEmZx3RwHASK6bouTZhcZnINJBQp98tKjNIA1BihVMASeIcd1jwpln3WCBDDBivS7ReK+oFlUCaWcwYdOZGN4+tyKNuC5NzFrDCRXz2MGoCUV2Ulojbd/6VRnPNNbMvxCoOS94SZxKAgcSmJoGzQn+OJt5rQdHyvA7OsJn6VtLpgCtCOO+6qOFcMrz8gbiucgAAUUKBxf9uMKNKUd02c9C8U00pGqTtKiC6E8GbcihIIcrhKHMLkx/6XPOwIp5wqE8qy3nEqG1dPB2KArfmKXkFgl9iWRw4kPjKAlOzSz02EO17wDDXuWbUcIoXrFwbobomdJDAY/6zeuTfLCDNMDAmFr4ZoCHDdEsaI3dLdWCvF+x8gbiIMkdtq05yY6RBmhsBtkOVd2HloCcmSVV/wAYEdPm5l9E/NqhMccIeaCV+HAuGdzkxKCiigCyXEbAOQ8uvyil/bEaaXH7pKdz2Ro2bpAGjOQ0btvy8IfPhxUzBAM0NjNIZyyE0Bx8ssZKZelDfBWxyETkcy2a8A8vGM7t5oaHqWch4QuOzzFeLq+azIZU2Ocz3chuYVQoiZ5WjKZu7W6S8cP8nvKTFNgxplLEiCTfDesJqIi0oTDUjGgvbhEa3sFKeO4gzY57wZoLrUmbfs4psgdYmPEQqGm81J9d8WY9rLPMTlRM7TDXpVF0QSJpue8YpZnLzGdurWqWsOxj/hOswOMgMsdVTaF7gCQohV0eDh7NDBUVheFZAxodUeJvkhf86FGafC/JaGIZgtAfGa7AXCN3tzBliCrf4GDvIEwHCCzyAM8T8s3JFjP67ynWCoaGph8WiPFfYCmhPq1lCcDtQe2GVjDkUXPHCsaK3G2NXPGjUfF4oGj6IyA0YxniXuWefuE6FZw1NF1kimrmhqr21x7tRuY9xSn6nYZbegQ+xdJ/GGPkXkb38Widcoot6WpLgd7VbN1bOYyIHYd3DU4F+UrfepIQqRS83hPYVzGF+tA07FtoQorI+myVGBbKjAwaZWtDNpXOPaoSCCfqcgvSAqduwiBugwa6fa3SFghMACHcaW0/GFY6JfAdKsqC6h+ZVGLvncu/eAs6BGuWhdIhcYoPbRnrSgL/2EMhJxgRzQUTwqq4MF9QNw8EgkPP5dfMqyGHIW27mvDWrwvj3wiftoIrRR3g0gL6FFUU2kEZ8hPFBHExYIILgMYUxmAuUFRs+ezxlmyiIMcgXAGu+QK77NevSOJEOkqnZdsRZeEqSoODTqx8nCrBZMmoiKdxfXOz+sXmJGsp5RP2PIB2da1WnaKCgjL4ABvBBCQo0URpbPHROACYKSdOAGtkquxpieLu0ClGqQkWJEqXfad+SW4hSm7QGuXBJxWghiNu9q3o7aZYZF0djE6LuDHt8eMr5yTEWRCxrYoiOMTM7g15MQLn4wLEBxxMvilmZkH9gUCiWJmG7N6t9W84tl7NRJGPHp+zjZbT4jLX9Ki5ngAv2WiV6h6KJtYTObNgS2Zs91sFlBUq5rHAt3QvZ59unbkJIFmfxGblptTJQDBbuIsXbFyl6bkmb7314wjquR+pHOh0A9GxnHS8b76HQ==").unwrap();
    let encapsulated_key = &BASE64_STANDARD.decode("bBcrMpyzvFLUFKU5vwewlxn9UXPwMFi3lJFJhCQNGpiGOWyEnhPt1nkBfQDZ3rGWCdDfM97NtWWoPkDywAUaytcUCXEXpHbxLgk5hxLmArOMK5p+8YVFBqdhVlN6Ivd+G5TKKZvn0BPElNHNALsyXXrjujVYB8IqYFaDa+WktCvS9n3IbIFZ/NPIFjcvkl3i/3QA0p+bKvJHmpu5b4ZtWEvtOwtDYTU62IWEYUi6grq611FEwE0X+TEm+XEU/QVpgi01LzpLC81M0LAa5UWxzCCel0Y6v/GkdmvVjqygXN4m7re6KeVUcpZuDzGXARKazMgpLHVExAjeD5BAM8r6BD9noOb43LQOYExjgh9kmTEFYKyFRTRj3nUkADbnqrwsu1/jkbR+fd1rGfa1MxnviQ+RcM5dUVR6TUH+eHTyGAKDz9y315YnBynrINJ0GWyZ0Na8PEDUzdzT0AKRCHU7yz90IEb6BaWlIcLbxa/cSYeUgkO/5CxoWmpJxsrVEpCF8AsS8yHjWiTKoLSos2KcsLN3PBxdDxG4Mbf0BEwdNl3TiYwM1GAngtkeQDmzYK42502H3dZkDbCjDfIWKl2V6Dt1r/k+np1Qau7eBTgRyCsXdMjN90nJCCqI9F+RKf7zjtFWye6682Tvkc2kqv2+7YCvgeoX59mdgCBxlT84M0Sz64y++WhLOFusOsSAvH8BWiQo3IMPjX5I9kLMRWGDtSZYXrd2kXi/DmVDSLU7BJr8ljrwdlrkXDcsOhGb7K1q74pWshRnFIPx4G9lUR5D6iP9tHtYgdjbMrc6EQe+oRG/+hEXIqGd+xowtPoExtSYrrxO6WpBYhH0CFeZ/PGDHNe1QDLLyCLNykUKq2ZziJkDzfeEvFU7db5bTPJ5hy0FpWdYQQ0tQuy50v0JnaYjV9UX77XzMWYFNWMbyhIrLycfJddDj78ssNApQtzaoaT98VPLmT6+AZODD1La9LXqWXwpIf8xVky6DwGFvQU4wPR8LRlM3uu4JYEmck/8L3KaenHztO7SYhzk2IL+whs3mVtUHxkPEeSAGPK+TQA0nQmTfYTwAgeR0IcLPTfpERnPf3r3OhSCIbuvry3YbtWic+xmAenlIRsxyWwUaGW7u1Bq2BshNbq9oppX4NWVA1gly1F5ag6bNS6A9UhEGpPnxe/ZhF6O5PbhZIgGF0T6Z3WnRzgGfYZ8Q4eR3hvnBE3voHtEQY938dCQOqfu5E7ca4e4YJMb5yh5Eh7kOOnH4D/7tDQVHjTBwb3f3A/GWNxu5jEXd75dH3+1i1lssKGm8PSzVVRdpa0xrj73nTVbFfVuM+zCIKgpvXFGvPAnIArOe62sj1aoFPJaQdaFozv0Buwk22sB8pxWedmJ2pXsn0kAyOdDN6M+JMbFtzwhvmzbhnc0sKLH1L69pZOmwuTjjIUUOEGgNUF9Xt+Ml1Qeiy4lgsD+VQlRDE4Gh6DaaC5CpOD5HAU+nzP0KhAFg2dbMw==").unwrap();
    let ciphertext = &BASE64_STANDARD.decode("S/eqVx5Rm0KZzVPKSnGwYqD30dW0").unwrap();

    //let (encapsulator, decapsulator) = XwingMlKem768X25519::derive_from_seed(&Array::try_from(seed.as_slice()).unwrap());
    let decapsulator = <HpkeXwingMlKem768X25519 as Capsulator>::Decapsulator::from_seed_bytes(&Array::try_from(seed.as_slice()).unwrap());
    let encapsulator = decapsulator.get_encapsulator();

    assert_eq! ( encapsulator.as_bytes().as_slice(), public_key);
    
    let decryptor = HpkeIesXwingMl768X25519Sha256Aes256Gcm::decryptor_from_decapsulator(decapsulator);

    let decrypted = decryptor.single_shot_open(GenericArray::from_slice(encapsulated_key.as_slice()), &info, ciphertext.as_slice(), None).unwrap();

    assert_eq! ( decrypted, b"hello");
}

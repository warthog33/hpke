//!
//! Collection of hpke type specializations
//! Types are created using primitives from the rust crypto collection combined with generic types from this hpke module
//! 
#[allow(unused)]
use crate::hpke_kdf::*;
#[allow(unused)]
use crate::{HpkeIes, HpkeEcKeyGen, HpkeEcKeyGen2, KemId, KdfId, kdf_id, kem_id, AeadId, aead_id };
#[cfg(all(feature = "rustcrypto-hmac"))]
use hmac::HmacReset;
#[allow(unused)]
use kdfs::hybrid_array::sizes::{*};
#[allow(unused)]
use kdfs::{iso11770_6::{Kpf1, Ktf1, Tkdf}};
#[cfg(all(feature="rustcrypto-ml-kem"))]
use kems::draft_irtf_cfrg_concrete_hybrid_kems::{ConcreteMlKem768P256, ConcreteMlKem1024P384, LabelMlKem768P256, LabelMlKem1024P384};
#[allow(unused)]
use kems::eckem::{EcdhAuthCapsulatorUncompressed, EcdhKemUncompressed, SeedAsScalar};
#[allow(unused)]
use kems::hybrid::{DeriveExpandSeed, HybridKem, QsfCombiner};
use kems::kem_with_kdf::{CombinerAllPubKeys, KemAuthWithKdf, KemWithKdf};
#[cfg(all(feature="rustcrypto-ml-kem"))]
use kems::ml_kem::MlKemWrapper;
#[cfg(all(feature="rustcrypto-x25519", feature="rustcrypto-ml-kem"))]
use kems::xwing::{ LabelXWing, XwingMlKem768X25519};
#[cfg(all(feature = "rustcrypto-ml-kem"))]
use ml_kem::{MlKem512, MlKem768, MlKem1024};

#[cfg(all(feature = "rustcrypto-sha2"))]
use sha2::{Sha256, Sha384, Sha512};
#[cfg(all(feature = "rustcrypto-sha3"))]
use shake::{Shake128, Shake256};
#[cfg(all(feature = "rustcrypto-sha3"))]
use turboshake::{CTurboShake128, CTurboShake256};

/// Hpke use ECDH with uncompressed SEC1 format for public keys and a combiner which uses all public keys available
pub type HpkeEcdhKem<C,K,L,D> = KemWithKdf<EcdhKemUncompressed<C,D>, CombinerAllPubKeys, K, L>;
/// Hpke use ECDH with uncompressed SEC1 format for public keys and a combiner which uses all public keys available
pub type HpkeEcdhAuthKem<C,K,L,D> = KemAuthWithKdf<EcdhAuthCapsulatorUncompressed<C,D>, CombinerAllPubKeys, K,L>;

///
/// HPKE Key Encapsulation Mechanisms which involve X25519
/// 
#[cfg(all(feature = "rustcrypto-x25519", feature = "rustcrypto-sha2"))]
pub mod x25519_kems {
    use super::*;
    use kems::{x25519kem::{X25519AuthCapsulator, X25519Capsulator}};

    pub type HpkeKemKdfX25519HkdfSha256 = KdfForKemUsingHkdf<Sha256, kem_id::DhKemX25519HkdfSha256>;
    pub type HpkeKeyGenKdfX25519HkdfSha256 = KdfForKeyGenUsingHkdf2<Sha256, kem_id::DhKemX25519HkdfSha256>;
    
    pub type HpkeKemX25519HkdfSha256 = KemWithKdf<X25519Capsulator<KeyGenKdfWrapper<SeedAsScalar, HpkeKeyGenKdfX25519HkdfSha256>>, 
        CombinerAllPubKeys, HpkeKemKdfX25519HkdfSha256, U32>;
    impl KemId for HpkeKemX25519HkdfSha256 { type KemType = kem_id::DhKemX25519HkdfSha256; }
    
    pub type HpkeAuthKemX25519HkdfSha256 = KemAuthWithKdf<X25519AuthCapsulator<KeyGenKdfWrapper<SeedAsScalar, HpkeKeyGenKdfX25519HkdfSha256>>,
        CombinerAllPubKeys, HpkeKemKdfX25519HkdfSha256, U32>;
    impl KemId for HpkeAuthKemX25519HkdfSha256 { type KemType = kem_id::DhKemX25519HkdfSha256; }
}

///
/// HPKE Key Encapsulation Mechanisms which involve Elliptic Curve x448
/// 
#[cfg(all(feature = "rustcrypto-x448", feature="rustcrypto-sha2"))]
pub mod x448_kems {
    use super::*;
    use kems::x448kem::X448Capsulator;

    //pub type HpkeKemKdfX448HkdfSha512 = HpkeLabelledKdf<Hkdf<Sha512>, HpkeKemLabel<kem_id::DhKemX448HkdfSha512>>;
    pub type HpkeKemKdfX448HkdfSha512 = KdfForKemUsingHkdf<Sha512, kem_id::DhKemX448HkdfSha512>;
    // pub type HpkeKeyGenKdfX448HkdfSha512 = Tkdf<LabelledExtract::<Ktf1<HmacReset<Sha512>>, LabelHpkeV1, LabelKem<kem_id::DhKemX448HkdfSha512>, LabelKeyGenExtract>, 
    //                                LabelledExpand::<Kpf1<HmacReset<Sha512>,u8>, LabelHpkeV1, LabelKem<kem_id::DhKemX448HkdfSha512>, LabelKeyGenExpand>>;
    pub type HpkeKeyGenKdfX448HkdfSha512 = KdfForKeyGenUsingHkdf2<Sha512, kem_id::DhKemX448HkdfSha512>;

    pub type HpkeKemX448HkdfSha512 = KemWithKdf<X448Capsulator<KeyGenKdfWrapper<SeedAsScalar, HpkeKeyGenKdfX448HkdfSha512>>, CombinerAllPubKeys, HpkeKemKdfX448HkdfSha512, U64>;
    impl KemId for HpkeKemX448HkdfSha512 { type KemType = kem_id::DhKemX448HkdfSha512;}
}

///
/// HPKE Key Encapsulation Mechanisms which involve Elliptic Curve P256
/// 
#[cfg(all(feature = "rustcrypto-p256", feature = "rustcrypto-sha2"))]
pub mod p256_kems {
    use p256::NistP256;
    use super::*;

    /// HPKE Kem using P-256 curve and Hkdf key derivation, with a specific diversifier value
    pub type HpkeKemKdfP256HkdfSha256 = KdfForKemUsingHkdf<Sha256, kem_id::DhKemP256HkdfSha256>;
    pub type HpkeKeyGenKdfP256HkdfSha256 = KdfForKeyGenUsingHkdf<Sha256, kem_id::DhKemP256HkdfSha256>;
    
    /// Implementation of the KEM using NIST P256 key agreement and a HKDF-SHA256 key derivation function
    pub type HpkeKemP256HkdfSha256 = HpkeEcdhKem<NistP256, HpkeKemKdfP256HkdfSha256, U32, HpkeEcKeyGen2<HpkeKeyGenKdfP256HkdfSha256>>;
    //pub type HpkeKemP256HkdfSha256 = HpkeEcdhKem<NistP256, HpkeKemKdfP256HkdfSha256, U32, HpkeEcKeyGen<HmacReset<Sha256>, kem_id::DhKemP256HkdfSha256>>;
    impl KemId for HpkeKemP256HkdfSha256 { type KemType = kem_id::DhKemP256HkdfSha256;}

    /// Authenticated Hpke Kem using P-256 curve and Hkdf key derivation
    pub type HpkeAuthKemP256HkdfSha256 = HpkeEcdhAuthKem<NistP256, HpkeKemKdfP256HkdfSha256, U32, HpkeEcKeyGen2<HpkeKeyGenKdfP256HkdfSha256>>;

//    pub type HpkeEcdhAuthP256HkdfSha256Kem = KemAuthWithKdf<EcdhAuthCapsulatorUncompressed<NistP256>, CombinerAllPubKeys, KdfForKemUsingHkdf::<Sha256, kem_id::DhKemP256HkdfSha256>,U32>;

    impl KemId for HpkeAuthKemP256HkdfSha256 { type KemType = kem_id::DhKemP256HkdfSha256;}
}

///
/// HPKE Key Encapsulation Mechanisms which involve Elliptic Curve P384
/// 
#[cfg(all(feature = "rustcrypto-p384", feature="rustcrypto-sha2"))]
pub mod p384_kems {
    use super::*;
    use sha2::Sha384;

    /// Kem using HKDF, with diversification data specific to use with P-384
    pub type HpkeKemKdfP384HkdfSha384 = KdfForKemUsingHkdf::<Sha384, kem_id::DhKemP384HkdfSha384>;
    
    /// Implementation of the KEM from RFC9180 which uses Nist P384 and Hkdf-Sha384 key derivation
    pub type HpkeKemP384HkdfSha384 = HpkeEcdhKem<p384::NistP384, HpkeKemKdfP384HkdfSha384, U48, HpkeEcKeyGen<HmacReset<Sha384>, kem_id::DhKemP384HkdfSha384>>;
    impl KemId for HpkeKemP384HkdfSha384 { type KemType = kem_id::DhKemP384HkdfSha384; }
}

///
/// HPKE Key Encapsulation Mechanisms which involve Elliptic Curve P521
/// 
#[cfg(all(feature = "rustcrypto-p521", feature = "rustcrypto-sha2"))]
pub mod p521_kems {
    use super::*;
    use p521::NistP521;

    //pub type HpkeKemKdfP521HkdfSha512 = HpkeLabelledKdf::<Hkdf<Sha512>, HpkeKemLabel<kem_id::DhKemP521HkdfSha512>>;
    pub type HpkeKemKdfP521HkdfSha512 = KdfForKemUsingHkdf::<Sha512, kem_id::DhKemP521HkdfSha512>;
    
    /// Implementation of a KEM using Nist P521 key agreement with a HKDF-SHA512 key derivation function
    pub type HpkeKemP521HkdfSha512 = HpkeEcdhKem<NistP521, HpkeKemKdfP521HkdfSha512, U64, HpkeEcKeyGen<HmacReset<Sha512>, kem_id::DhKemP521HkdfSha512>>;
    impl KemId for HpkeKemP521HkdfSha512 { type KemType = kem_id::DhKemP521HkdfSha512;}
    
    /// Implementation of a KEM using Nist P521 key agreement with a HKDF-SHA512 key derivation function
    pub type HpkeAuthKemP521HkdfSha512 = HpkeEcdhAuthKem<NistP521, HpkeKemKdfP521HkdfSha512,U64, HpkeEcKeyGen<HmacReset<Sha512>, kem_id::DhKemP521HkdfSha512>>;
    impl KemId for HpkeAuthKemP521HkdfSha512 { type KemType = kem_id::DhKemP521HkdfSha512;}
}


///
/// HPKE Key Encapsulation Mechanisms which involve Elliptic Curve SecP256k1
/// 
#[cfg(all(feature = "rustcrypto-k256"))]
pub mod k256_kems {
    use super::*;
    // KDF based on HKDF with Sha256 with a diversion id
    //type HpkeKemKdfSecP256k1HkdfSha256 = HpkeLabelledKdf<Hkdf<sha2::Sha256>, HpkeKemLabel<kem_id::DhKemSecP256k1HkdfSha256>>;

    pub type HpkeKemKdfSecP256k1HkdfSha256 = KdfForKemUsingHkdf<Sha256, kem_id::DhKemSecP256k1HkdfSha256>;

    /// Implementation of a KEM using SecP256k1 curve with a HKDF-SHA256 key derivation function 
    pub type HpkeKemSecP256k1HkdfSha256 = HpkeEcdhKem<k256::Secp256k1, HpkeKemKdfSecP256k1HkdfSha256, U32, HpkeEcKeyGen<HmacReset<sha2::Sha256>, kem_id::DhKemSecP256k1HkdfSha256>>;
    impl KemId for HpkeKemSecP256k1HkdfSha256 { type KemType = kem_id::DhKemSecP256k1HkdfSha256;}

    /// Implementation of an authenticated KEM using SecP256k1 curve with a HKDF-SHA256 key derivation function 
    pub type HpkeAuthKemSecP256k1HkdfSha256 = HpkeEcdhAuthKem<k256::Secp256k1, HpkeKemKdfSecP256k1HkdfSha256, U32, HpkeEcKeyGen<HmacReset<sha2::Sha256>, kem_id::DhKemSecP256k1HkdfSha256>>;
    impl KemId for HpkeAuthKemSecP256k1HkdfSha256 { type KemType = kem_id::DhKemSecP256k1HkdfSha256;}
}

#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-p256", feature="rustcrypto-sha3"))]
impl crate::KemId for kems::draft_irtf_cfrg_hybrid_kems::HybridKemQsfMlKem768P256 { type KemType = crate::kem_id::QsfKemMlKem768P256;}
#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-x25519", feature="rustcrypto-sha3"))]
impl crate::KemId for kems::draft_irtf_cfrg_hybrid_kems::HybridCapsulatorKitchenSinkMlKem768X25519 { type KemType = crate::kem_id::KitchenSinkKemMlKem768X25519;}
#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-p384", feature="rustcrypto-sha3"))]
impl crate::KemId for kems::draft_irtf_cfrg_hybrid_kems::HybridCapsulatorQsfMlKem1024P384 { type KemType = crate::kem_id::QsfKemMlKem1024P384;}


///
/// HPKE Key Derivation Functions which use Sha2 digests
/// 
#[cfg(all(feature = "rustcrypto-sha2"))]
pub mod sha2_kdfs {
    use super::*;
    
    pub type LabelledTkdf1<M,L> = Tkdf<LabelledExtract::<Ktf1<M>,L>, LabelledExpand::<Kpf1<M,u8>,L>>;

    //pub type HpkeTwoStepHkdf<D> = crate::hpke_kdf::HpkeTwoStepKdf<kdfs::rfc5869_hkdf::Hkdf<D>>;
    pub type HpkeTwoStepHkdf<D> = crate::hpke_kdf::HpkeTwoStepKdf<LabelledTkdf1<HmacReset<D>,LabelHpkeV1>>;

    /// Two step KDF used for HPKE based upon HKDF-Sha256
    pub type HpkeHkdfSha256 = HpkeTwoStepHkdf::<Sha256>;
    impl KdfId for HpkeHkdfSha256 { type KdfType = kdf_id::HkdfSha256;}
    
    /// Two step KDF used for HPKE based upon HKDF-Sha384
    pub type HpkeHkdfSha384 = HpkeTwoStepHkdf::<Sha384>;
    impl KdfId for HpkeHkdfSha384 { type KdfType = kdf_id::HkdfSha384;}

    /// Two step KDF used for HPKE based upon HKDF-Sha512
    pub type HpkeHkdfSha512 = HpkeTwoStepHkdf::<Sha512>;
    impl KdfId for HpkeHkdfSha512 { type KdfType = kdf_id::HkdfSha512;}
}

///
/// HPKE Key Derivation Functions which use Sha3 digests
/// 
#[cfg(all(feature = "rustcrypto-sha3"))]
pub mod sha3_kdfs {
    use crate::hpke_kdf::HpkeOneStepKdf;
    use super::*;

    /// Single step KDF used for HPKE based upon Shake128
    pub type HpkeOneStepKdfShake128 = HpkeOneStepKdf<LabelledXofKdf<Shake128, LabelHpkeV1>, U32>;
    impl KdfId for HpkeOneStepKdfShake128 { type KdfType = kdf_id::Shake128;}

    /// Single step KDF used for HPKE based upon Shake256
    pub type HpkeOneStepKdfShake256 = HpkeOneStepKdf<LabelledXofKdf<Shake256, LabelHpkeV1>, U64>;
    impl KdfId for HpkeOneStepKdfShake256 { type KdfType = kdf_id::Shake256;}

    /// Single step KDF used for HPKE based upon TurboShake128
    pub type HpkeOneStepKdfTurboShake128 = HpkeOneStepKdf<LabelledXofKdf<CTurboShake128<0x1F>, LabelHpkeV1>, U32>;
    impl KdfId for HpkeOneStepKdfTurboShake128 { type KdfType = kdf_id::TurboShake128;}

    /// Single step KDF used for HPKE based upon TurboShake256
    pub type HpkeOneStepKdfTurboShake256 = HpkeOneStepKdf<LabelledXofKdf<CTurboShake256<0x1F>, LabelHpkeV1>, U64>;
    impl KdfId for HpkeOneStepKdfTurboShake256 { type KdfType = kdf_id::TurboShake256;}
}

///
/// HPKE Authenticated Encryption with Additional Data which use AES
/// 
#[cfg(all(feature = "rustcrypto-aes"))]
pub mod aes_aeads {
    use super::*;
    /// Type which can be used as the AEAD parameter in a HPKE
    impl AeadId for aes_gcm::Aes128Gcm { type AeadType = aead_id::Aes128Gcm;}
    /// Type which can be used as the AEAD parameter in a HPKE
    impl AeadId for aes_gcm::Aes256Gcm { type AeadType = aead_id::Aes256Gcm;}
    /// This type is never used as an AEAD, but by referencig AES GCM all trait bounds are met
    pub type ExportOnlyAead = aes_gcm::AesGcm<aes::Aes256,U0>;
    impl AeadId for ExportOnlyAead { type AeadType = aead_id::ExportOnly; }
}

///
/// HPKE Authenticated Encryption with Additional Data which use ChaCha20 and Poly1305
/// 
#[cfg(all(feature = "rustcrypto-chacha20poly1305"))]
impl crate::AeadId for chacha20poly1305::ChaCha20Poly1305 { type AeadType = crate::aead_id::ChaCha20Poly1305; }


/// HPKE using P256, HKDF-SHA256 and AES128GCM
#[cfg(all(feature = "rustcrypto-p256", feature = "rustcrypto-aes", feature = "rustcrypto-sha2"))]
pub type HpkeIesP256Sha256Aes128Gcm = HpkeIes<p256_kems::HpkeKemP256HkdfSha256, sha2_kdfs::HpkeHkdfSha256, aes_gcm::Aes128Gcm>;

/// HPKE using P256, HKDF-SHA512 and AES128GCM
#[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
pub type HpkeIesP256Sha512Aes128Gcm = HpkeIes<p256_kems::HpkeKemP256HkdfSha256, sha2_kdfs::HpkeHkdfSha512, aes_gcm::Aes128Gcm >;


/// HPKE using P256, HKDF-SHA256 and AES256GCM
#[cfg(all(feature = "rustcrypto-p256", feature = "rustcrypto-aes", feature = "rustcrypto-sha2"))]
pub type HpkeIesP256Sha256Aes256Gcm = HpkeIes<p256_kems::HpkeKemP256HkdfSha256, sha2_kdfs::HpkeHkdfSha256, aes_gcm::Aes256Gcm>;

/// HPKE using P256, HKDF-SHA256 and ChaCha20Poly1305
#[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-chacha20poly1305", feature="rustcrypto-sha2"))]
pub type HpkeIesP256Sha256ChaCha20Poly1305 = HpkeIes<p256_kems::HpkeKemP256HkdfSha256, sha2_kdfs::HpkeHkdfSha256, chacha20poly1305::ChaCha20Poly1305>;

/// HPKE AUTH using P256, HKDF-SHA256 and AES128GCM
#[cfg(all(feature = "rustcrypto-p256", feature = "rustcrypto-aes", feature = "rustcrypto-sha2"))]
pub type HpkeAuthIesP256Sha256Aes128Gcm = HpkeIes<p256_kems::HpkeAuthKemP256HkdfSha256, sha2_kdfs::HpkeHkdfSha256, aes_gcm::Aes128Gcm>;


/// HPKE AUTH using P256, HKDF-SHA512 and AES128GCM
#[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
pub type HpkeAuthIesP256Sha512Aes128Gcm = HpkeIes<p256_kems::HpkeAuthKemP256HkdfSha256, sha2_kdfs::HpkeHkdfSha512, aes_gcm::Aes128Gcm>;       

/// HPKE AUTH using P256, HKDF-SHA256 and AES256GCM
#[cfg(all(feature = "rustcrypto-p256", feature = "rustcrypto-aes", feature = "rustcrypto-sha2"))]
pub type HpkeAuthIesP256Sha256Aes256Gcm = HpkeIes<p256_kems::HpkeAuthKemP256HkdfSha256, sha2_kdfs::HpkeHkdfSha256, aes_gcm::Aes256Gcm>;

/// HPKE using K256, HKDF-SHA256 and AES128GCM
#[cfg(all(feature = "rustcrypto-k256", feature = "rustcrypto-aes", feature = "rustcrypto-sha2"))]
pub type HpkeIesK256Sha256Aes128Gcm = HpkeIes<k256_kems::HpkeKemSecP256k1HkdfSha256, sha2_kdfs::HpkeHkdfSha256, aes_gcm::Aes128Gcm>;

/// HPKE using K256, HKDF-SHA256 and AES128GCM
#[cfg(all(feature = "rustcrypto-k256"))]
pub type HpkeAuthIesK256Sha256Aes128Gcm = HpkeIes<k256_kems::HpkeAuthKemSecP256k1HkdfSha256, sha2_kdfs::HpkeHkdfSha256, aes_gcm::Aes128Gcm>;

/// HPKE using K256, HKDF-SHA256 and ChaCha20 with Poly1305
#[cfg(all(feature = "rustcrypto-k256"))]
pub type HpkeIesK256Sha256ChaCha20Poly1305 = HpkeIes<k256_kems::HpkeKemSecP256k1HkdfSha256, sha2_kdfs::HpkeHkdfSha256, chacha20poly1305::ChaCha20Poly1305>;

/// HPKE Auth using K256, HKDF-SHA256 and ChCha20 with Poly1305
#[cfg(all(feature = "rustcrypto-k256"))]
pub type HpkeAuthIesK256Sha256ChaCha20Poly1305 = HpkeIes<k256_kems::HpkeAuthKemSecP256k1HkdfSha256, sha2_kdfs::HpkeHkdfSha256, chacha20poly1305::ChaCha20Poly1305>;

/// HPKE using K256, HKDF-SHA256 and AES256GCM
#[cfg(all(feature = "rustcrypto-k256"))]
pub type HpkeIesK256Sha256Aes256Gcm = HpkeIes<k256_kems::HpkeKemSecP256k1HkdfSha256, sha2_kdfs::HpkeHkdfSha256, aes_gcm::Aes256Gcm>;

/// HPKE Auth using K256, HKDF-SHA256 and AES256GCM
#[cfg(all(feature = "rustcrypto-k256"))]
pub type HpkeAuthIesK256Sha256Aes256Gcm = HpkeIes<k256_kems::HpkeAuthKemSecP256k1HkdfSha256, sha2_kdfs::HpkeHkdfSha256, aes_gcm::Aes256Gcm>;



/// HPKE using P384, HKDF-SHA384 and AES256GCM
#[cfg(all(feature = "rustcrypto-p384", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
pub type HpkeIesP384Sha384Aes256Gcm = HpkeIes<p384_kems::HpkeKemP384HkdfSha384, sha2_kdfs::HpkeHkdfSha384, aes_gcm::Aes256Gcm>;

/// HPKE using P512, HKDF-SHA512 and AES256GCM
#[cfg(all(feature = "rustcrypto-p521", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
pub type HpkeIesP521Sha512Aes256Gcm = HpkeIes<p521_kems::HpkeKemP521HkdfSha512, sha2_kdfs::HpkeHkdfSha512, aes_gcm::Aes256Gcm>;

/// HPKE Auth using P521, HKDF-SHA512 and AES256GCM
#[cfg(all(feature = "rustcrypto-p521", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
pub type HpkeAuthIesP521Sha512Aes256Gcm = HpkeIes<p521_kems::HpkeAuthKemP521HkdfSha512,sha2_kdfs::HpkeHkdfSha512, aes_gcm::Aes256Gcm>;

/// HPKE using X25519, HKDF-SHA256 and ChaCha20Poly1305
#[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-chacha20poly1305", feature="rustcrypto-sha2"))]
pub type HpkeIesX25519Sha256ChaCha20Poly1305 = HpkeIes<x25519_kems::HpkeKemX25519HkdfSha256, sha2_kdfs::HpkeHkdfSha256, chacha20poly1305::ChaCha20Poly1305>;

/// HPKE using X25519, HKDF-SHA256 and Aes128GCM
#[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]                                        
pub type HpkeIesX25519Sha256Aes128Gcm = HpkeIes<x25519_kems::HpkeKemX25519HkdfSha256, sha2_kdfs::HpkeHkdfSha256, aes_gcm::Aes128Gcm>;

/// HPKE AUTH using X25519, HKDF-SHA256 and AES128GCM
#[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]   
pub type HpkeAuthIesX25519Sha256Aes128Gcm = HpkeIes<x25519_kems::HpkeAuthKemX25519HkdfSha256, sha2_kdfs::HpkeHkdfSha256, aes_gcm::Aes128Gcm>;

/// HPKE Export Only using X25519, HKDF-SHA256 and Aes128GCM
#[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
pub type HpkeIesX25519Sha256ExportOnly = HpkeIes<x25519_kems::HpkeKemX25519HkdfSha256, sha2_kdfs::HpkeHkdfSha256, aes_aeads::ExportOnlyAead >;

/// HPKE Auth Export Only using X25519, HKDF-SHA256 and Aes128GCM
#[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
pub type HpkeAuthIesX25519Sha256ExportOnly = HpkeIes<x25519_kems::HpkeAuthKemX25519HkdfSha256, sha2_kdfs::HpkeHkdfSha256, aes_aeads::ExportOnlyAead>;

/// HPKE using X448, HKDF-SHA512 and ChaCha20Poly1305
#[cfg(all(feature = "rustcrypto-x448", feature="rustcrypto-chacha20poly1305", feature="rustcrypto-sha2"))]
pub type HpkeIesX448Sha512ChaCha20Poly1305 = HpkeIes<x448_kems::HpkeKemX448HkdfSha512, sha2_kdfs::HpkeHkdfSha512, chacha20poly1305::ChaCha20Poly1305>;

/// HPKE using X448, HKDF-SHA512 and Aes256GCM
#[cfg(all(feature = "rustcrypto-x448", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
pub type HpkeIesX448Sha512Aes256Gcm = HpkeIes<x448_kems::HpkeKemX448HkdfSha512, sha2_kdfs::HpkeHkdfSha512, aes_gcm::Aes256Gcm>;




///
/// XWing is a single configuration KEM defined in <https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/>
/// 
#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-x25519", feature = "rustcrypto-aes", feature = "rustcrypto-sha2", feature = "rustcrypto-sha3"))]
pub mod draft_ietf_xwing {

    use super::*;
    use kems::{x25519kem::{X25519Capsulator}};

    type KeyGenKdf = draft_ietf_hpke_pq::HpkeKemOneStepKdfKeyDerive::<kem_id::Xwing>;
    

    /// This variation modifies default XWing by adding an additional hpke specific key derivation step during key generation from seed
    pub type HpkeXwingMlKem768X25519 = HybridKem::<
            MlKemWrapper<ml_kem::MlKem768>,
            X25519Capsulator<SeedAsScalar>,
            QsfCombiner<kdfs::iso11770_6::Okdf1::<sha3::Sha3_256>, LabelXWing>, 
            DeriveExpandSeed<U32, shake::Shake256, KeyGenKdf>>;
            //KeyGenKdfWrapper<ExpandSeed<U32, sha3::Shake256>, KeyGenKdf>>;
    impl crate::KemId for HpkeXwingMlKem768X25519 { type KemType = kem_id::Xwing; }
}

#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-aes"))]
pub mod apple {
    use crate::hpke_types::draft_ietf_xwing::HpkeXwingMlKem768X25519;

    // Implemented by apple 
    pub type HpkeIesXwingMl768X25519Sha256Aes256Gcm = crate::HpkeIes<HpkeXwingMlKem768X25519, super::sha2_kdfs::HpkeHkdfSha256, aes_gcm::Aes256Gcm>;
}

///
/// Types described in the <https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/>
/// 
#[cfg(all(feature = "rustcrypto-ml-kem"))]
pub mod draft_ietf_hpke_pq {
    use super::*;
    
    pub type HpkeKemMlKem512 = MlKemWrapper<MlKem512, HpkeKemOneStepKdfKeyDerive::<kem_id::MlKem512>>;
    impl KemId for HpkeKemMlKem512 { type KemType = kem_id::MlKem512; }

    pub type HpkeKemMlKem768 = MlKemWrapper<MlKem768, HpkeKemOneStepKdfKeyDerive::<kem_id::MlKem768>>;
    impl KemId for HpkeKemMlKem768 { type KemType = kem_id::MlKem768; }

    pub type HpkeKemMlKem1024 = MlKemWrapper<MlKem1024, HpkeKemOneStepKdfKeyDerive<kem_id::MlKem1024>>;
    impl KemId for HpkeKemMlKem1024 { type KemType = kem_id::MlKem1024; }

    impl KemId for ConcreteMlKem768P256 { type KemType = kem_id::QsfKemMlKem768P256Shake256Sha3256; }
    impl KemId for ConcreteMlKem1024P384 { type KemType = kem_id::QsfKemMlKem1024P384Shake256Sha3256; }
    

    /// HPKE using ML-KEM 768, Nist P256 and a Sha3 based combiner, similar to ConcreteMlKem768P256 except it
    /// has an additional step during the derive from seed step
    #[cfg(all(feature="rustcrypto-p256", feature="rustcrypto-sha3"))]
    pub type HpkeConcreteMlKem768P256 = HybridKem::<
            MlKemWrapper<ml_kem::MlKem768>,
            EcdhKemUncompressed<p256::NistP256,SeedAsScalar>,
            //QsfCombiner<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, LabelMlKem768P256>, 
            QsfCombiner<kdfs::iso11770_6::Okdf1::<sha3::Sha3_256>, LabelMlKem768P256>, 
            DeriveExpandSeed<U32, Shake256, HpkeKemOneStepKdfKeyDerive::<kem_id::QsfKemMlKem768P256Shake256Sha3256>>>;
    impl KemId for HpkeConcreteMlKem768P256 { type KemType = kem_id::QsfKemMlKem768P256Shake256Sha3256; }
    
    /// HPKE using ML-KEM 768, Nist P384 curve and a Sha3 based combiner
    #[cfg(all(feature="rustcrypto-p384", feature="rustcrypto-sha3"))]
    pub type HpkeConcreteMlKem1024P384 = HybridKem::<
            MlKemWrapper<ml_kem::MlKem1024>,
            EcdhKemUncompressed<p384::NistP384,SeedAsScalar>,
            //QsfCombiner<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, LabelMlKem1024P384>, 
            QsfCombiner<kdfs::iso11770_6::Okdf1::<sha3::Sha3_256>, LabelMlKem1024P384>, 
            DeriveExpandSeed<U32, Shake256, HpkeKemOneStepKdfKeyDerive::<kem_id::QsfKemMlKem1024P384Shake256Sha3256>>>;
    impl KemId for HpkeConcreteMlKem1024P384 { type KemType = kem_id::QsfKemMlKem1024P384Shake256Sha3256; }
    

    #[cfg(all(feature="rustcrypto-p384", feature="rustcrypto-sha3"))]
    pub type HpkeKemQsfMlKem1024P384 = kems::hybrid::HybridKem::<
            MlKemWrapper<ml_kem::MlKem1024>,
            HpkeEcdhKem<p384::NistP384, p384_kems::HpkeKemKdfP384HkdfSha384, U48, SeedAsScalar>,
            kems::hybrid::QsfCombiner2<kdfs::iso11770_6::Okdf1::<sha3::Sha3_256>, kems::draft_ietf_hpke_pq::QsfLabelP384MlKem1024>,
            kems::hybrid::DeriveExpandSeed<U32, shake::Shake256, HpkeKemOneStepKdfKeyDerive::<kem_id::QsfKemMlKem1024P384Shake256Sha3256>>>;
    
    impl KemId for HpkeKemQsfMlKem1024P384 { type KemType = kem_id::QsfKemMlKem1024P384Shake256Sha3256;}
    
    

    #[cfg(all(feature="rustcrypto-x25519", feature = "rustcrypto-aes", feature = "rustcrypto-sha2", feature = "rustcrypto-sha3"))]
    pub type HpkeIesKitchenSinkMl768X25519Sha256Aes128Gcm = HpkeIes<kems::draft_irtf_cfrg_hybrid_kems::HybridCapsulatorKitchenSinkMlKem768X25519, sha2_kdfs::HpkeHkdfSha256, aes_gcm::Aes128Gcm>;

    #[cfg(all(feature = "rustcrypto-p384", feature = "rustcrypto-aes", feature = "rustcrypto-sha2", feature = "rustcrypto-sha3"))]
    pub type HpkeIesQsfMl1024P384Sha256Aes128Gcm = HpkeIes<kems::draft_irtf_cfrg_hybrid_kems::HybridCapsulatorQsfMlKem1024P384, sha2_kdfs::HpkeHkdfSha256, aes_gcm::Aes128Gcm >;

    
    //pub type HpkeKemOneStepKdf2<I> = crate::hpke_kdf::HpkeKemOneStepKdf<sha3::Shake256, I>;
    //pub type HpkeKemOneStepKdfKeyDerive<I> = crate::hpke_kdf::LabelledXofKdf::<sha3::Shake256, LabelHpkeV1, HpkeKemLabelKeyDerive<I>>;
    pub type HpkeKemOneStepKdfKeyDerive<I> = crate::hpke_kdf::LabelledXofKdf::<shake::Shake256, LabelHpkeV1, LabelKem<I>, LabelKeyDerive>;
    
    // v4, A.1.  ML-KEM-512, HKDF-SHA256, AES-128-GCM
    #[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
    //pub type HpkeIesMlKem512Sha256Aes128Gcm = HpkeIes<HpkeKemMlKem512, super::sha2_kdfs::HpkeHkdfSha256, aes_gcm::Aes128Gcm, HpkeKemOneStepKdfKeyDerive::<kem_id::MlKem512>>;
    pub type HpkeIesMlKem512Sha256Aes128Gcm = HpkeIes<HpkeKemMlKem512, sha2_kdfs::HpkeHkdfSha256, aes_gcm::Aes128Gcm>;

    // v3, A.1. and v4 A.2: ML-KEM-768, HKDF-SHA256, AES-128-GCM
    #[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
    pub type HpkeIesMlKem768Sha256Aes128Gcm = HpkeIes<HpkeKemMlKem768, sha2_kdfs::HpkeHkdfSha256, aes_gcm::Aes128Gcm >;

    // v3, A.2. and v4 A.3: ML-KEM-1024, HKDF-SHA384, AES-256-GCM
    #[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
    //pub type HpkeIesMlKem1024Sha384Aes256Gcm = HpkeIes<HpkeKemMlKem1024, super::sha2_kdfs::HpkeHkdfSha384, aes_gcm::Aes256Gcm, HpkeKemOneStepKdfKeyDerive<kem_id::MlKem1024>>;
    pub type HpkeIesMlKem1024Sha384Aes256Gcm = HpkeIes<HpkeKemMlKem1024, sha2_kdfs::HpkeHkdfSha384, aes_gcm::Aes256Gcm >;

    // A.3. QSF-P256-MLKEM768, SHAKE256, AES-128-GCM
    #[cfg(all(feature = "rustcrypto-ml-kem", feature= "rustcrypto-p256", feature="rustcrypto-sha3", feature="rustcrypto-aes"))]
    //pub type HpkeIesMlKem768P256Shake256Aes128Gcm = HpkeIes::<ConcreteMlKem768P256/*HpkeKemQsfP256MlKem768*/, super::sha2_kdfs::HpkeHkdfSha256, aes_gcm::Aes128Gcm, HpkeKemOneStepKdfKeyDerive::<kem_id::QsfKemMlKem768P256Shake256Sha3256>>;
    pub type HpkeIesMlKem768P256Shake256Aes128Gcm = HpkeIes::<HpkeConcreteMlKem768P256, sha2_kdfs::HpkeHkdfSha256, aes_gcm::Aes128Gcm>;
    
    // v3 - A.4.  QSF-X25519-MLKEM768, HKDF-SHA256, AES-128-GCM
    #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-ml-kem", feature="rustcrypto-sha3", feature="rustcrypto-aes"))]
    pub type HpkeIesMlKem768X25519HkdfSha256Aes128Gcm = HpkeIes::<XwingMlKem768X25519, sha2_kdfs::HpkeHkdfSha256, aes_gcm::Aes128Gcm>;

    // v3 - A.5.  QSF-X25519-MLKEM768, Unknown KDF, AES-128-GCM
    #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-ml-kem", feature="rustcrypto-sha3", feature="rustcrypto-aes"))]
    pub type HpkeIesMlKem768X25519Shake256Aes128Gcm = HpkeIes::<XwingMlKem768X25519, sha3_kdfs::HpkeOneStepKdfShake128, aes_gcm::Aes128Gcm>;

    // v4 A.4 MLKEM768-P256, HKDF-SHA256, AES-128-GCM
    //pub type HpkeIesMlKem768P256HkdfSha256Aes256Gcm = HpkeIes::<ConcreteMlKem768P256, HpkeHkdfSha256, aes_gcm::Aes128Gcm, draft_ietf_hpke_pq::HpkeKemOneStepKdfKeyDerive::<kem_id::QsfKemMlKem768P256Shake256Sha3256>>;
    pub type HpkeIesMlKem768P256HkdfSha256Aes128Gcm = HpkeIes::<HpkeConcreteMlKem768P256, sha2_kdfs::HpkeHkdfSha256, aes_gcm::Aes128Gcm>;

    // v4, A.5. MLKEM768-X25519, HKDF-SHA256, ChaCha20Poly1305
    //pub type HpkeIesMlKem768X25519Shake128ChaCha20Poly1305 = HpkeIes::<XwingMlKem768X25519, super::sha2_kdfs::HpkeHkdfSha256, chacha20poly1305::ChaCha20Poly1305, hpke_types::draft_ietf_hpke_pq::HpkeKemOneStepKdfKeyDerive::<kem_id::Xwing>>;
    pub type HpkeIesMlKem768X25519Shake128ChaCha20Poly1305 = HpkeIes::<draft_ietf_xwing::HpkeXwingMlKem768X25519, sha2_kdfs::HpkeHkdfSha256, chacha20poly1305::ChaCha20Poly1305>;

    // v4, A.6. MLKEM1024+P384, HKDF-384, AES-256-GCM
    //pub type HpkeIesMlKem1024P384HkdfSha256Aes256Gcm = HpkeIes::<ConcreteMlKem1024P384, super::sha2_kdfs::HpkeHkdfSha384, aes_gcm::Aes256Gcm, hpke_types::draft_ietf_hpke_pq::HpkeKemOneStepKdfKeyDerive::<kem_id::QsfKemMlKem1024P384Shake256Sha3256>>;
    pub type HpkeIesMlKem1024P384HkdfSha256Aes256Gcm = HpkeIes::<HpkeConcreteMlKem1024P384, sha2_kdfs::HpkeHkdfSha384, aes_gcm::Aes256Gcm>;

    // v3 A.6.  QSF-P384-MLKEM1024, Unknown KDF, AES-256-GCM
    #[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-p384", feature="rustcrypto-sha3", feature="rustcrypto-aes"))]
    //pub type HpkeIesMlKem1024P384Shake256Aes256Gcm = HpkeIes::<HpkeKemQsfMlKem1024P384, super::sha3_kdfs::HpkeOneStepKdfShake256, aes_gcm::Aes256Gcm, HpkeKemOneStepKdfKeyDerive::<kem_id::QsfKemMlKem1024P384Shake256Sha3256>>;
    pub type HpkeIesMlKem1024P384Shake256Aes256Gcm = HpkeIes::<HpkeKemQsfMlKem1024P384, sha3_kdfs::HpkeOneStepKdfShake256, aes_gcm::Aes256Gcm>;

    // v4 A.7 DHKEM(P-256, HKDF-SHA256), SHAKE256, AES-128-GCM
    pub type HpkeIesP256Shake256Aes128Gcm = HpkeIes::<p256_kems::HpkeKemP256HkdfSha256, sha3_kdfs::HpkeOneStepKdfShake128, aes_gcm::Aes128Gcm /*HpkeKemOneStepKdf2::<kem_id::DhKemP256HkdfSha256>*/>;

    // v4 A.8 DHKEM(P-384, HKDF-SHA384), SHAKE256, AES-256-GCM
    pub type HpkeIesP384Shake256Aes256Gcm = HpkeIes::<p384_kems::HpkeKemP384HkdfSha384, sha3_kdfs::HpkeOneStepKdfShake256, aes_gcm::Aes256Gcm /*HpkeKemOneStepKdf2::<kem_id::DhKemP256HkdfSha256>*/>;

    // v4 A.9 DHKEM(X25519, HKDF-SHA256), Unknown KDF, ChaCha20Poly1305
    pub type HpkeIesX25519TurboShake128ChaCha20Poly1305 = HpkeIes::<x25519_kems::HpkeKemX25519HkdfSha256, sha3_kdfs::HpkeOneStepKdfTurboShake128, chacha20poly1305::ChaCha20Poly1305 /*HpkeKemOneStepKdf2::<kem_id::DhKemP256HkdfSha256>*/>;

    // v4 A.10 DHKEM(X448, HKDF-SHA256), TurboShake256, ChaCha20Poly1305
    pub type HpkeIesX448TurboShake256ChaCha20Poly1305 = HpkeIes::<x448_kems::HpkeKemX448HkdfSha512, sha3_kdfs::HpkeOneStepKdfTurboShake256, chacha20poly1305::ChaCha20Poly1305 /*HpkeKemOneStepKdf2::<kem_id::DhKemP256HkdfSha256>*/>;

    // v4 A.11 MLKEM768-P256, SHAKE128, AES-256-GCM
    #[cfg(all(feature = "rustcrypto-ml-kem", feature= "rustcrypto-p256", feature="rustcrypto-sha3", feature="rustcrypto-aes"))]
    //pub type HpkeIesMlKem768P256Shake128Aes256Gcm = HpkeIes::<ConcreteMlKem768P256/*HpkeKemQsfP256MlKem768*/, super::sha3_kdfs::HpkeOneStepKdfShake128, aes_gcm::Aes256Gcm, HpkeKemOneStepKdfKeyDerive::<kem_id::QsfKemMlKem768P256Shake256Sha3256>>;
    pub type HpkeIesMlKem768P256Shake128Aes256Gcm = HpkeIes::<HpkeConcreteMlKem768P256, sha3_kdfs::HpkeOneStepKdfShake128, aes_gcm::Aes256Gcm>;

    // v4 A.12  MLKEM768-X25519, Shake256, ChaCha20Poly1305
    #[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-x25519", feature="rustcrypto-sha3", feature="rustcrypto-aes"))]
    //pub type HpkeIesMlKem768X25519Shake256ShaCha20Poly1305 = HpkeIes::<XwingMlKem768X25519, super::sha3_kdfs::HpkeOneStepKdfShake256, chacha20poly1305::ChaCha20Poly1305, HpkeKemOneStepKdfKeyDerive::<kem_id::Xwing>>;
    pub type HpkeIesMlKem768X25519Shake256Cha20Poly1305 = HpkeIes::<draft_ietf_xwing::HpkeXwingMlKem768X25519, sha3_kdfs::HpkeOneStepKdfShake256, chacha20poly1305::ChaCha20Poly1305>;

    // v4 A.13  ML-KEM-1024, Unknown KDF, AES-128-GCM
    #[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-x25519", feature="rustcrypto-sha3", feature="rustcrypto-aes"))]
    //pub type HpkeIesMlKem768X25519Shake256ShaCha20Poly1305 = HpkeIes::<XwingMlKem768X25519, super::sha3_kdfs::HpkeOneStepKdfShake256, chacha20poly1305::ChaCha20Poly1305, HpkeKemOneStepKdfKeyDerive::<kem_id::Xwing>>;
    pub type HpkeIesMlKem1024TurboShake256Aes128Gcm = HpkeIes::<HpkeKemMlKem1024, sha3_kdfs::HpkeOneStepKdfTurboShake256, aes_gcm::Aes128Gcm>;
   

}

///
/// Post quantum encryption mechanisms for use within JOSE
/// <https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/11/>
pub mod draft_ietf_jose_hpke_encrypt {

    /// Cipher suite for JOSE-HPKE using the DHKEM(P-256, HKDF-SHA256) KEM, the HKDF-SHA256 KDF and the AES-128-GCM AEAD
    #[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-sha2", feature="rustcrypto-aes"))]
    pub type HPKE0P256Aes128 = crate::hpke_types::HpkeIesP256Sha256Aes128Gcm;

    /// Cipher suite for JOSE-HPKE using the DHKEM(P-384, HKDF-SHA384) KEM, the HKDF-SHA384 KDF, and the AES-256-GCM AEAD.
    #[cfg(all(feature = "rustcrypto-p384", feature="rustcrypto-sha2", feature="rustcrypto-aes"))]
    pub type HPKE1P384Aes256 = crate::hpke_types::HpkeIesP384Sha384Aes256Gcm;

    /// Cipher suite for JOSE-HPKE using the DHKEM(P-521, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the AES-256-GCM AEAD
    #[cfg(all(feature = "rustcrypto-p521", feature="rustcrypto-sha2", feature="rustcrypto-aes"))]
    pub type HPKE2P521Aes256 = crate::hpke_types::HpkeIesP521Sha512Aes256Gcm;

    /// Cipher suite for JOSE-HPKE using the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF, and the AES-128-GCM AEAD
    #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-sha2", feature="rustcrypto-aes"))]
    pub type HPKE3X25519Aes128 = crate::hpke_types::HpkeIesX25519Sha256Aes128Gcm;

    /// Cipher suite for JOSE-HPKE using the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF, and the ChaCha20Poly1305 AEAD
    #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-sha2", feature="rustcrypto-chacha20poly1305"))]
    pub type HPKE4X25519ChaCha20Poly1305 = crate::hpke_types::HpkeIesX25519Sha256ChaCha20Poly1305;

    /// Cipher suite for JOSE-HPKE using the DHKEM(X448, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the AES-256-GCM AEAD
    #[cfg(all(feature = "rustcrypto-x448", feature="rustcrypto-sha2", feature="rustcrypto-aes"))]
    pub type HPKE5X448Aes256 = crate::hpke_types::HpkeIesX448Sha512Aes256Gcm;

    /// Cipher suite for JOSE-HPKE using the DHKEM(X448, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the ChaCha20Poly1305 AEAD
    #[cfg(all(feature = "rustcrypto-x448", feature="rustcrypto-chacha20poly1305"))]
    pub type HPKE6X448ChaCha20Poly1305 = crate::hpke_types::HpkeIesX448Sha512ChaCha20Poly1305;

    /// Cipher suite for JOSE-HPKE using the DHKEM(P-256, HKDF-SHA256) KEM, the HKDF-SHA256 KDF and the AES-256-GCM AEAD
    #[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-sha2", feature="rustcrypto-aes"))]
    pub type HPKE7P256Aes256 = crate::hpke_types::HpkeIesP256Sha256Aes256Gcm;

}

///
/// Post quantum encryption mechanisms for use within JOSE
/// 
#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-sha3"))]
pub mod draft_reddy_cose_jose_pqc_hybrid_hpke {

    /// Cipher suite for JOSE-HPKE in Base Mode that uses the P-256 + ML-KEM-768 Hybrid KEM, the SHAKE256 KDF, and the AES-256-GCM AEAD.
    #[cfg(all(feature="rustcrypto-p256", feature="rustcrypto-aes"))]
    pub type HPKE7MlKem768Aes128 = crate::HpkeIes<kems::draft_irtf_cfrg_hybrid_kems::HybridKemQsfMlKem768P256, kdfs::rfc5869_hkdf::Hkdf<sha2::Sha256>, aes_gcm::Aes128Gcm>;

    /// Cipher suite for JOSE-HPKE in Base Mode that uses the P-256 + ML-KEM-768 Hybrid KEM, the SHAKE256 KDF, and the ChaCha20Poly1305 AEAD.
    #[cfg(all(feature="rustcrypto-p256", feature="rustcrypto-chacha20poly1305"))]
    pub type HPKE8MlKem768P256ChaCha20Poly1305 = crate::HpkeIes<kems::draft_irtf_cfrg_hybrid_kems::HybridKemQsfMlKem768P256, kdfs::rfc5869_hkdf::Hkdf<sha2::Sha256>, chacha20poly1305::ChaCha20Poly1305>;

    /// Cipher suite for JOSE-HPKE in Base Mode that uses the X25519 + ML-KEM-768 Hybrid KEM, the SHAKE256 KDF, and the AES-256-GCM AEAD
    #[cfg(all(feature="rustcrypto-x25519", feature="rustcrypto-aes"))]
    pub type HPKE9MlKem768X25519Aes256 = crate::HpkeIes<kems::draft_irtf_cfrg_hybrid_kems::HybridCapsulatorKitchenSinkMlKem768X25519, kdfs::rfc5869_hkdf::Hkdf<sha2::Sha256>, aes_gcm::Aes256Gcm>;

    /// Cipher suite for JOSE-HPKE in Base Mode that uses the X25519 + ML-KEM-768 Hybrid KEM, the SHAKE256 KDF, and the ChaCha20Poly1305 AEAD
    #[cfg(all(feature="rustcrypto-x25519", feature="rustcrypto-chacha20poly1305", feature="rustcrypto-hmac", feature="rustcrypto-sha2"))]
    pub type HPKE10MlKem768X25519ChaCha20Poly1305 = crate::HpkeIes<kems::draft_irtf_cfrg_hybrid_kems::HybridCapsulatorKitchenSinkMlKem768X25519, kdfs::rfc5869_hkdf::Hkdf<sha2::Sha256>, chacha20poly1305::ChaCha20Poly1305>;

    /// Cipher suite for JOSE-HPKE in Base Mode that uses the P-384 + ML-KEM-1024 Hybrid KEM, the SHAKE256 KDF, and the AES-256-GCM AEAD
    #[cfg(all(feature="rustcrypto-p384", feature="rustcrypto-aes"))]
    pub type HPKE11MlKem1024P384Aes256 = crate::HpkeIes<kems::draft_irtf_cfrg_hybrid_kems::HybridCapsulatorQsfMlKem1024P384, kdfs::rfc5869_hkdf::Hkdf<sha2::Sha256>, aes_gcm::Aes256Gcm>;

    /// Cipher suite for JOSE-HPKE in Base Mode that uses the P-384 + ML-KEM-1024 Hybrid KEM, the SHAKE256 KDF, and the ChaCha20Poly1305 AEAD
    #[cfg(all(feature="rustcrypto-p384", feature="rustcrypto-chacha20poly1305"))]
    pub type HPKE12MlKem1024P384ChaCha20Poly1305 = crate::HpkeIes<kems::draft_irtf_cfrg_hybrid_kems::HybridCapsulatorQsfMlKem1024P384, kdfs::rfc5869_hkdf::Hkdf<sha2::Sha256>, chacha20poly1305::ChaCha20Poly1305>;
}


 //impl KemId for ConcreteMlKem768P256_2 { type KemType = crate::kem_id::QsfKemMlKem768P256Shake256Sha3256; }

    // pub type HpkeKemQsfP256MlKem768XX = kems::hybrid::HybridKem::<
    //         kems::ml_kem::MlKemWrapper<ml_kem::MlKem768>,
    //         //hpke::hpke_types::HpkeEcdhKem<p256::NistP256, hpke::hpke_types::p256_kems::HpkeKemKdfP256HkdfSha256, U32, kems::eckem::SeedAsScalar<U3>>,
    //         kems::eckem::EcdhKemUncompressed<p256::NistP256,kems::eckem::SeedAsScalar<aead::consts::U3>>,
    //         //kems::hybrid::QsfCombiner2<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, kems::draft_ietf_hpke_pq::QsfLabelP256MlKem768>,
    //         kems::hybrid::QsfCombiner<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, kems::draft_irtf_cfrg_concrete_hybrid_kems::LabelMlKem768P256>,
    //         kems::hybrid::DeriveExpandSeed<p256::U32, sha3::Shake256, HpkeKemOneStepKdf2::<kem_id::QsfKemMlKem768P256Shake256Sha3256>>>;

    // impl KemId for HpkeKemQsfP256MlKem768XX { type KemType = kem_id::QsfKemMlKem768P256Shake256Sha3256; }

    //pub type HpkeIesQsfP256MlKem768Shake128Aes256GcmXX = HpkeIes::<ConcreteMlKem768P256, super::sha3_kdfs::HpkeOneStepKdfShake128, aes_gcm::Aes256Gcm, HpkeKemOneStepKdf2::<kem_id::QsfKemMlKem768P256Shake256Sha3256>>;
  
    
    

    //pub type HpkeKemQsfX25519MlKem768 = kems::xwing::XwingMlKem768X25519;
    // pub type HpkeKemQsfMlKem768X25519 = kems::hybrid::HybridKem::<
    //         //HpkeKemMlKem768,
    //         //MlKemWithAddKeyDer<ml_kem::MlKem768, kdfs::misc::PassThroughKdf, typenum::U32>,
    //         MlKemWrapper<ml_kem::MlKem768>,
    //         //super::x2519_kems::HpkeKemX25519HkdfSha256,
    //         kems::x25519kem::X25519Capsulator<kems::eckem::SeedAsScalar>,
    //         QsfCombiner<Okdf3::<sha3::Sha3_256, u0>, LabelXWing>,
    //         //DeriveExpandSeed<super::U32, sha3::Shake256, HpkeKemOneStepKdf2::<kem_id::Xwing>>>;
    //         ExpandSeed<super::U32, sha3::Shake256>>;
    
    //impl KemId for HpkeKemQsfMlKem768X25519 { type KemType = crate::kem_id::Xwing;}

    //#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
    //pub type HpkeIesMlKem512Sha256Aes128Gcm = HpkeIes<HpkeKemMlKem512, super::sha2_kdfs::HpkeHkdfSha256, aes_gcm::Aes128Gcm >;
    
    //#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
    //pub type HpkeIesMlKem768Sha256Aes128Gcm = HpkeIes<HpkeKemMlKem768, super::sha2_kdfs::HpkeHkdfSha256, aes_gcm::Aes128Gcm>;

    //#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
    //pub type HpkeIesMlKem1024Sha256Aes128Gcm = HpkeIes<HpkeKemMlKem1024, super::sha2_kdfs::HpkeHkdfSha256, aes_gcm::Aes128Gcm>;

    // #[cfg(all(feature = "rustcrypto-p256", feature = "rustcrypto-aes", feature = "rustcrypto-sha2", feature = "rustcrypto-sha3"))]
    // pub type HpkeIesQsfMl768P256Sha256Aes128Gcm = HpkeIes<kems::draft_irtf_cfrg_hybrid_kems_03::HybridKemQsfMlKem768P256, super::sha2_kdfs::HpkeHkdfSha256, aes_gcm::Aes128Gcm>;
    
    

    // #[cfg(all(feature="rustcrypto-p256", feature="rustcrypto-sha3"))]
    // pub type HpkeKemQsfP256MlKem768 = kems::hybrid::HybridKem::<
    //         //MlKemWithAddKeyDer<ml_kem::MlKem768, PassThroughKdf, typenum::U32, PassThroughKdf>,
    //         MlKemWrapper<ml_kem::MlKem768>,
    //         //HpkeKemMlKem768,
    //         //HpkeEcdhKem<p256::NistP256, EcCombinerAllPubKeys<HpkeKemKdfP256HkdfSha256>, super::U32, SeedAsScalar>,
    //         HpkeEcdhKem<p256::NistP256, HpkeKemKdfP256HkdfSha256, super::U32, SeedAsScalar>,
    //         //kems::eckem::EcdhKemUncompressed<p256::NistP256,crate::HpkeEcKeyGen<super::k256_kems::HpkeKemKdfSecP256k1HkdfSha256>>,
    //         //HpkeEcKeyGen<HpkeKemKdfP256HkdfSha256>>,
    //         //HpkeKemP256HkdfSha256,
    //         kems::hybrid::QsfCombiner2<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, kems::draft_ietf_hpke_pq::QsfLabelP256MlKem768>,
    //         //kems::hybrid::ExpandSeed<typenum::consts::U32, kdfs::cshake::XofKdf<sha3::Shake256>>>;
    //         //DeriveExpandSeed<U32, XofKdf<sha3::Shake256>, HpkeKemOneStepKdf2::<kem_id::QsfKemMlKem768P256>>>;

    //         //DeriveExpandSeed<super::U32, sha3::Shake256, HpkeKemOneStepKdf2::<kem_id::QsfKemMlKem768P256Shake256Sha3256>>>;
    //         ExpandSeed<super::U32, sha3::Shake256>>;
    

    // //impl KemId for kems::draft_ietf_hpke_pq_01::HybridKemQsfP256MlKem768 { type KemType = crate::kem_id::QsfKemP256MlKem768Shake256Sha3256;}
    // impl KemId for HpkeKemQsfP256MlKem768 { type KemType = crate::kem_id::QsfKemMlKem768P256Shake256Sha3256; }
    

                                        //HybridEncapsulator::<MlKem1024, EcdhEncapsulatorCompressed<NistP384, KemKdfEcNoPubKeys<PassThroughKdf>, U48>, LabelMlKem1024P384, EcEncapKeyCompressed<NistP384, U48>, true, EcCompressedEncoder<_>>
// #[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-chacha20poly1305", feature="rustcrypto-sha2"))]
// // pub type HpkeIesPskEncryptP256Sha256Aes128Gcm = HpkeIes<{mode_id::MODE_PSK},EcdhEncapsulatorUncompressed<NistP256,HpkeKemKdfP256HkdfSha256,U32>, {kem_id::DHKEM_P256_HKDF_SHA256}, 
// //                                         Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, aes_gcm::Aes128Gcm, {aead_id::AES_128_GCM}>;
// pub type HpkeIesPskP256Sha256Aes128Gcm = HpkeIes<EcdhCapsulatorUncompressed<NistP256, HpkeKemKdfP256HkdfSha256,U32>, {kem_id::DHKEM_X25519_HKDF_SHA256}, 
//                                         Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, aes_gcm::Aes128Gcm, {aead_id::AES_128_GCM}>;


// #[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-chacha20poly1305", feature="rustcrypto-sha2"))]
// // pub type HpkeIesPskEncryptP256Sha512Aes128Gcm = HpkeIes<{mode_id::MODE_PSK},EcdhEncapsulatorUncompressed<NistP256,HpkeKemKdfP256HkdfSha256,U32>, {kem_id::DHKEM_P256_HKDF_SHA256}, 
// //                                         Hkdf<Sha512>, {kdf_id::HKDF_SHA512}, aes_gcm::Aes128Gcm, {aead_id::AES_128_GCM}>;
// pub type HpkeIesPskP256Sha512Aes128Gcm = HpkeIes<EcdhCapsulatorUncompressed<NistP256,HpkeKemKdfP256HkdfSha256,U32>, {kem_id::DHKEM_P256_HKDF_SHA256}, 
//                                         Hkdf<Sha512>, {kdf_id::HKDF_SHA512}, aes_gcm::Aes128Gcm, {aead_id::AES_128_GCM}>;

// #[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-chacha20poly1305", feature="rustcrypto-sha2"))]
// // pub type HpkeIesPskEncryptP256Sha256ChaCha20Poly1305 = HpkeIes::<{mode_id::MODE_PSK},EcdhEncapsulatorUncompressed<NistP256,HpkeKemKdfP256HkdfSha256,U32>, {kem_id::DHKEM_P256_HKDF_SHA256}, 
// //                                        Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, chacha20poly1305::ChaCha20Poly1305, {aead_id::CHACHA20_POLY1305}>;
// pub type HpkeIesPskP256Sha256ChaCha20Poly1305 = HpkeIes<EcdhCapsulatorUncompressed<NistP256,HpkeKemKdfP256HkdfSha256,U32>, {kem_id::DHKEM_P256_HKDF_SHA256}, 
//                                         Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, chacha20poly1305::ChaCha20Poly1305, {aead_id::CHACHA20_POLY1305}>;

// #[cfg(all(feature = "rustcrypto-p521", feature="rustcrypto-chacha20poly1305", feature="rustcrypto-sha2"))]
// // pub type HpkeIesPskEncryptP521Sha512Aes256Gcm = HpkeIes::<{mode_id::MODE_PSK},EcdhEncapsulatorUncompressed<NistP521,HpkeKemKdfP521HkdfSha512,U64>, {kem_id::DHKEM_P521_HKDF_SHA512},
// //                                         Hkdf<Sha512>, {kdf_id::HKDF_SHA512}, aes_gcm::Aes256Gcm, {aead_id::AES_256_GCM}>;
// pub type HpkeIesPskP521Sha512Aes256Gcm = HpkeIes<EcdhCapsulatorUncompressed<NistP521,HpkeKemKdfP521HkdfSha512,U64>, {kem_id::DHKEM_P521_HKDF_SHA512}, 
//                                         Hkdf<Sha512>, {kdf_id::HKDF_SHA512}, aes_gcm::Aes256Gcm, {aead_id::AES_256_GCM}>;

// #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-chacha20poly1305", feature="rustcrypto-sha2"))]
// // pub type HpkeIesPskEncryptX25519Sha256ChaCha20Poly1305 = HpkeIes::<{mode_id::MODE_PSK},X25519Encapsulator<HpkeKemKdfX25519HkdfSha256,U32>, {kem_id::DHKEM_X25519_HKDF_SHA256}, 
// //                                         Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, chacha20poly1305::ChaCha20Poly1305, {aead_id::CHACHA20_POLY1305}>;
// pub type HpkeIesPskX25519Sha256ChaCha20Poly1305 = HpkeIes<X25519Capsulator<HpkeKemKdfX25519HkdfSha256,U32>, {kem_id::DHKEM_X25519_HKDF_SHA256}, 
//                                         Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, chacha20poly1305::ChaCha20Poly1305, {aead_id::CHACHA20_POLY1305}>;
        
// #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-chacha20poly1305", feature="rustcrypto-sha2"))]
// // pub type HpkeIesPskEncryptX25519Sha256Aes128Gcm = HpkeIes::<{mode_id::MODE_PSK}, X25519Encapsulator<HpkeKemKdfX25519HkdfSha256,U32>,  {kem_id::DHKEM_X25519_HKDF_SHA256}, 
// //                                         Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, aes_gcm::Aes128Gcm, {aead_id::AES_128_GCM}>;
// pub type HpkeIesPskX25519Sha256Aes128Gcm = HpkeIes<X25519Capsulator<HpkeKemKdfX25519HkdfSha256,U32>, {kem_id::DHKEM_X25519_HKDF_SHA256}, 
//                                         Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, aes_gcm::Aes128Gcm, {aead_id::AES_128_GCM}>;

// #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
// // pub type HpkeIesPskEncryptX25519Sha256ExportOnly = HpkeIes::<{mode_id::MODE_PSK},X25519Encapsulator<HpkeKemKdfX25519HkdfSha256,U32>/*,U32*/,  {kem_id::DHKEM_X25519_HKDF_SHA256}, 
// //                                         Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, aes_gcm::Aes128Gcm, {aead_id::EXPORT_ONLY}>;
// pub type HpkeIesPskX25519Sha256ExportOnly = HpkeIes<X25519Capsulator<HpkeKemKdfX25519HkdfSha256,U32>, {kem_id::DHKEM_X25519_HKDF_SHA256}, 
//                                         Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, aes_gcm::Aes128Gcm, {aead_id::EXPORT_ONLY}>;



// #[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-chacha20poly1305", feature="rustcrypto-sha2"))]
// // pub type HpkeIesAuthEncryptP256Sha512Aes128Gcm = HpkeIes::<{mode_id::MODE_AUTH},EcdhAuthEncapsulatorUncompressed<NistP256, HpkeKemKdfP256HkdfSha256,U32>, { kem_id::DHKEM_P256_HKDF_SHA256},
// //                                             Hkdf<Sha512>, {kdf_id::HKDF_SHA512}, aes_gcm::Aes128Gcm, {aead_id::AES_128_GCM}>;
// pub type HpkeIesAuthP256Sha512Aes128Gcm = HpkeIes::<EcdhAuthCapsulatorUncompressed<NistP256, HpkeKemKdfP256HkdfSha256,U32>, { kem_id::DHKEM_P256_HKDF_SHA256},
//                                             Hkdf<Sha512>, {kdf_id::HKDF_SHA512}, aes_gcm::Aes128Gcm, {aead_id::AES_128_GCM}>;

// #[cfg(all(feature = "rustcrypto-p521", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
// // pub type HpkeIesAuthEncryptP521Sha512Aes256Gcm = HpkeIes::<{mode_id::MODE_AUTH},EcdhAuthEncapsulatorUncompressed<NistP521,HpkeKemKdfP521HkdfSha512,U64>, {kem_id::DHKEM_P521_HKDF_SHA512},
// //                                             Hkdf<Sha512>, {kdf_id::HKDF_SHA512}, aes_gcm::Aes256Gcm, {aead_id::AES_256_GCM}>;
// pub type HpkeIesAuthP521Sha512Aes256Gcm = HpkeIes::<EcdhCapsulatorUncompressed<NistP521, HpkeKemKdfP521HkdfSha512,U64>, {kem_id::DHKEM_P521_HKDF_SHA512},
//                                             Hkdf<Sha512>, {kdf_id::HKDF_SHA512}, aes_gcm::Aes256Gcm, {aead_id::AES_256_GCM}>;

// #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
// // pub type HpkeIesAuthEncryptX25519Sha256Aes128Gcm = HpkeIes::<{mode_id::MODE_AUTH},X25519AuthEncapsulator<HpkeKemKdfX25519HkdfSha256,U32>, {kem_id::DHKEM_X25519_HKDF_SHA256},
// //                                             Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, aes_gcm::Aes128Gcm, {aead_id::AES_128_GCM}>;
// pub type HpkeIesAuthX25519Sha256Aes128Gcm = HpkeIes::<X25519Capsulator<HpkeKemKdfX25519HkdfSha256,U32>, {kem_id::DHKEM_X25519_HKDF_SHA256},
//                                             Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, aes_gcm::Aes128Gcm, {aead_id::AES_128_GCM}>;



// #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
// // pub type HpkeIesAuthEncryptX25519Sha256ExportOnly =  HpkeIes::<{mode_id::MODE_AUTH},X25519AuthEncapsulator<HpkeKemKdfX25519HkdfSha256,U32>, {kem_id::DHKEM_X25519_HKDF_SHA256},
// //                                             Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, aes_gcm::Aes128Gcm, {aead_id::EXPORT_ONLY}>;
// pub type HpkeIesAuthX25519Sha256ExportOnly = HpkeIes::<X25519Capsulator<HpkeKemKdfX25519HkdfSha256,U32>, {kem_id::DHKEM_X25519_HKDF_SHA256},
//                                             Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, aes_gcm::Aes128Gcm, {aead_id::EXPORT_ONLY}>;


// #[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
// // pub type HpkeIesAuthPskEncryptP256Sha512Aes128Gcm = HpkeIes::<{mode_id::MODE_AUTH_PSK},EcdhAuthEncapsulatorUncompressed<NistP256, HpkeKemKdfP256HkdfSha256,U32>, { kem_id::DHKEM_P256_HKDF_SHA256},
// //                                             Hkdf<Sha512>, {kdf_id::HKDF_SHA512}, aes_gcm::Aes128Gcm, {aead_id::AES_128_GCM}>;
// pub type HpkeIesAuthPskP256Sha512Aes128Gcm = HpkeIes::<EcdhCapsulatorUncompressed<NistP256, HpkeKemKdfP256HkdfSha256,U32>, {kem_id::DHKEM_P256_HKDF_SHA256},
//                                             Hkdf<Sha512>, {kdf_id::HKDF_SHA512}, aes_gcm::Aes128Gcm, {aead_id::AES_128_GCM}>;
                                            
// #[cfg(all(feature = "rustcrypto-p521", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
// // pub type HpkeIesAuthPskEncryptP521Sha512Aes256Gcm = HpkeIes::<{mode_id::MODE_AUTH_PSK},EcdhAuthEncapsulatorUncompressed<NistP521, HpkeKemKdfP521HkdfSha512,U64>,  {kem_id::DHKEM_P521_HKDF_SHA512},
// //                                             Hkdf<Sha512>, {kdf_id::HKDF_SHA512}, aes_gcm::Aes256Gcm, {aead_id::AES_256_GCM}>;
// pub type HpkeIesAuthPskP521Sha512Aes256Gcm = HpkeIes::<EcdhCapsulatorUncompressed<NistP521, HpkeKemKdfP521HkdfSha512,U64>, {kem_id::DHKEM_P521_HKDF_SHA512},
//                                             Hkdf<Sha512>, {kdf_id::HKDF_SHA512}, aes_gcm::Aes256Gcm, {aead_id::AES_256_GCM}>;


// #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
// // pub type HpkeIesAuthPskEncryptX25519Sha256Aes128Gcm = HpkeIes::<{mode_id::MODE_AUTH_PSK},X25519AuthEncapsulator<HpkeKemKdfX25519HkdfSha256,U32>, {kem_id::DHKEM_X25519_HKDF_SHA256},
// //                                             Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, aes_gcm::Aes128Gcm, {aead_id::AES_128_GCM}>;
// pub type HpkeIesAuthPskX25519Sha256Aes128Gcm = HpkeIes::<X25519Capsulator<HpkeKemKdfX25519HkdfSha256,U32>, {kem_id::DHKEM_X25519_HKDF_SHA256},
//                                              Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, aes_gcm::Aes128Gcm, {aead_id::AES_128_GCM}>;

// #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
// // pub type HpkeIesAuthPskEncryptX25519Sha256ExportOnly =  HpkeIes::<{mode_id::MODE_AUTH_PSK},X25519AuthEncapsulator<HpkeKemKdfX25519HkdfSha256,U32>, {kem_id::DHKEM_X25519_HKDF_SHA256},
// //                                             Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, aes_gcm::Aes128Gcm, {aead_id::EXPORT_ONLY}>;
// pub type HpkeIesAuthPskX25519Sha256ExportOnly = HpkeIes::<X25519Capsulator<HpkeKemKdfX25519HkdfSha256,U32>, {kem_id::DHKEM_X25519_HKDF_SHA256},
//                                             Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, aes_gcm::Aes128Gcm, {aead_id::EXPORT_ONLY}>;

// #[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
// pub type HpkeIesDecryptP256Sha256Aes128Gcm = HpkeIes<{mode_id::MODE_BASE}, EcdhDecapsulator<NistP256,HpkeKemKdfP256HkdfSha256,U32>, {kem_id::DHKEM_P256_HKDF_SHA256}, 
//                                         Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, aes_gcm::Aes128Gcm, {aead_id::AES_128_GCM}>;
// #[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
// pub type HpkeIesDecryptP256Sha512Aes128Gcm = HpkeIes::<{mode_id::MODE_BASE},EcdhDecapsulator::<NistP256,HpkeKemKdfP256HkdfSha256,U32>, {kem_id::DHKEM_P256_HKDF_SHA256}, 
//                                         Hkdf<Sha512>, {kdf_id::HKDF_SHA512}, aes_gcm::Aes128Gcm, {aead_id::AES_128_GCM}>;
// #[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-chacha20poly1305", feature="rustcrypto-sha2"))]
// pub type HpkeIesDecryptP256Sha256ChaCha20Poly1305 = HpkeIes::<{mode_id::MODE_BASE},EcdhDecapsulator::<NistP256,HpkeKemKdfP256HkdfSha256,U32>,  {kem_id::DHKEM_P256_HKDF_SHA256}, 
//                                         Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, chacha20poly1305::ChaCha20Poly1305, {aead_id::CHACHA20_POLY1305}>;
// #[cfg(all(feature = "rustcrypto-p521", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
// pub type HpkeIesDecryptP521Sha512Aes256Gcm = HpkeIes::<{mode_id::MODE_BASE},EcdhDecapsulator<NistP521,HpkeKemKdfP521HkdfSha512,U64>, {kem_id::DHKEM_P521_HKDF_SHA512},
//                                         Hkdf<Sha512>, {kdf_id::HKDF_SHA512}, aes_gcm::Aes256Gcm, {aead_id::AES_256_GCM}>;
// #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-chacha20poly1305", feature="rustcrypto-sha2"))]
// pub type HpkeIesDecryptX25519Sha256ChaCha20Poly1305 = HpkeIes::<{mode_id::MODE_BASE},X25519Decapsulator<HpkeKemKdfX25519HkdfSha256>, {kem_id::DHKEM_X25519_HKDF_SHA256}, 
//                                         Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, chacha20poly1305::ChaCha20Poly1305, {aead_id::CHACHA20_POLY1305}>;
// #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
// pub type HpkeIesDecryptX25519Sha256Aes128Gcm = HpkeIes::<{mode_id::MODE_BASE},X25519Decapsulator<HpkeKemKdfX25519HkdfSha256>, {kem_id::DHKEM_X25519_HKDF_SHA256}, 
//                                         Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, aes_gcm::Aes128Gcm, {aead_id::AES_128_GCM}>;
// #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-chacha20poly1305", feature="rustcrypto-sha2"))]
// pub type HpkeIesDecryptX25519Sha256ExportOnly = HpkeIes::<{mode_id::MODE_BASE},X25519Decapsulator<HpkeKemKdfX25519HkdfSha256>, {kem_id::DHKEM_X25519_HKDF_SHA256}, 
//                                         Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, aes_gcm::Aes128Gcm, {aead_id::EXPORT_ONLY}>;

// #[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-chacha20poly1305", feature="rustcrypto-sha2"))]
// pub type HpkeIesPskDecryptP256Sha256Aes128Gcm= HpkeIes<{mode_id::MODE_PSK}, EcdhDecapsulator<NistP256,HpkeKemKdfP256HkdfSha256,U32>, {kem_id::DHKEM_P256_HKDF_SHA256}, 
//     Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, aes_gcm::Aes128Gcm, {aead_id::AES_128_GCM}>;
// #[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-chacha20poly1305", feature="rustcrypto-sha2"))]
// pub type HpkeIesPskDecryptP256Sha512Aes128Gcm = HpkeIes::<{mode_id::MODE_PSK},EcdhDecapsulator::<NistP256,HpkeKemKdfP256HkdfSha256,U32>, {kem_id::DHKEM_P256_HKDF_SHA256}, 
//     Hkdf<Sha512>, {kdf_id::HKDF_SHA512}, aes_gcm::Aes128Gcm, {aead_id::AES_128_GCM}>;
// #[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-chacha20poly1305", feature="rustcrypto-sha2"))]
// pub type HpkeIesPskDecryptP256Sha256ChaCha20Poly1305 = HpkeIes::<{mode_id::MODE_PSK},EcdhDecapsulator::<NistP256,HpkeKemKdfP256HkdfSha256,U32>,  {kem_id::DHKEM_P256_HKDF_SHA256}, 
//     Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, chacha20poly1305::ChaCha20Poly1305, {aead_id::CHACHA20_POLY1305}>;
// #[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-chacha20poly1305", feature="rustcrypto-sha2"))]
// pub type HpkeIesPskDecryptP521Sha512Aes256Gcm = HpkeIes::<{mode_id::MODE_PSK},EcdhDecapsulator<NistP521,HpkeKemKdfP521HkdfSha512,U64>, {kem_id::DHKEM_P521_HKDF_SHA512},
//     Hkdf<Sha512>, {kdf_id::HKDF_SHA512}, aes_gcm::Aes256Gcm, {aead_id::AES_256_GCM}>;
// #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-chacha20poly1305", feature="rustcrypto-sha2"))]
// pub type HpkeIesPskDecryptX25519Sha256ChaCha20Poly1305 = HpkeIes::<{mode_id::MODE_PSK},X25519Decapsulator<HpkeKemKdfX25519HkdfSha256>, {kem_id::DHKEM_X25519_HKDF_SHA256}, 
//     Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, chacha20poly1305::ChaCha20Poly1305, {aead_id::CHACHA20_POLY1305}>;
// #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-chacha20poly1305", feature="rustcrypto-sha2"))]
// pub type HpkeIesPskDecryptX25519Sha256Aes128Gcm = HpkeIes::<{mode_id::MODE_PSK},X25519Decapsulator<HpkeKemKdfX25519HkdfSha256>, {kem_id::DHKEM_X25519_HKDF_SHA256}, 
//     Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, aes_gcm::Aes128Gcm, {aead_id::AES_128_GCM}>;
// #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
// pub type HpkeIesPskDecryptX25519Sha256ExportOnly = HpkeIes::<{mode_id::MODE_PSK},X25519Decapsulator<HpkeKemKdfX25519HkdfSha256/*,U32*/>, {kem_id::DHKEM_X25519_HKDF_SHA256}, 
//     Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, aes_gcm::Aes128Gcm, {aead_id::EXPORT_ONLY}>;


// #[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
// pub type HpkeIesAuthDecryptP256Sha512Aes128Gcm = HpkeIes::<{mode_id::MODE_AUTH},EcdhAuthDecapsulator<NistP256, HpkeKemKdfP256HkdfSha256, U16>, { kem_id::DHKEM_P256_HKDF_SHA256}, Hkdf<Sha512>, {kdf_id::HKDF_SHA512}, aes_gcm::Aes128Gcm, {aead_id::AES_128_GCM}>;
// #[cfg(all(feature = "rustcrypto-p521", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
// pub type HpkeIesAuthDecryptP521Sha512Aes256Gcm = HpkeIes::<{mode_id::MODE_AUTH},EcdhAuthDecapsulator<NistP521,HpkeKemKdfP521HkdfSha512, U64>, {kem_id::DHKEM_P521_HKDF_SHA512}, Hkdf<Sha512>, {kdf_id::HKDF_SHA512}, aes_gcm::Aes256Gcm, {aead_id::AES_256_GCM}>;
// #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
// pub type HpkeIesAuthDecryptX25519Sha256Aes128Gcm = HpkeIes::<{mode_id::MODE_AUTH},X25519AuthDecapsulator<HpkeKemKdfX25519HkdfSha256>, {kem_id::DHKEM_X25519_HKDF_SHA256}, Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, aes_gcm::Aes128Gcm, {aead_id::AES_128_GCM}>;
// #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
// pub type HpkeIesAuthDecryptX25519Sha256ExportOnly = HpkeIes::<{mode_id::MODE_AUTH},X25519AuthDecapsulator<HpkeKemKdfX25519HkdfSha256>, {kem_id::DHKEM_X25519_HKDF_SHA256}, 
//                                             Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, aes_gcm::Aes128Gcm, {aead_id::EXPORT_ONLY}>;

// #[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
// pub type HpkeIesAuthPskDecryptP256Sha512Aes128Gcm = HpkeIes::<{mode_id::MODE_AUTH_PSK},EcdhAuthDecapsulator<NistP256, HpkeKemKdfP256HkdfSha256, U32>, { kem_id::DHKEM_P256_HKDF_SHA256},
//                                             Hkdf<Sha512>, {kdf_id::HKDF_SHA512}, aes_gcm::Aes128Gcm, {aead_id::AES_128_GCM}>;
// #[cfg(all(feature = "rustcrypto-p521", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
// pub type HpkeIesAuthPskDecryptP521Sha512Aes256Gcm = HpkeIes::<{mode_id::MODE_AUTH_PSK},EcdhAuthDecapsulator<NistP521, HpkeKemKdfP521HkdfSha512, U64>, {kem_id::DHKEM_P521_HKDF_SHA512},
//                                              Hkdf<Sha512>, {kdf_id::HKDF_SHA512}, aes_gcm::Aes256Gcm, {aead_id::AES_256_GCM}>;
// #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
// pub type HpkeIesAuthPskDecryptX25519Sha256Aes128Gcm = HpkeIes::<{mode_id::MODE_AUTH_PSK},X25519AuthDecapsulator<HpkeKemKdfX25519HkdfSha256>, {kem_id::DHKEM_X25519_HKDF_SHA256},
//                                             Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, aes_gcm::Aes128Gcm, {aead_id::AES_128_GCM}>;
// #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
// pub type HpkeIesAuthPskDecryptX25519Sha256ExportOnly = HpkeIes::<{mode_id::MODE_AUTH_PSK},X25519AuthDecapsulator<HpkeKemKdfX25519HkdfSha256>, {kem_id::DHKEM_X25519_HKDF_SHA256},
//                                             Hkdf<Sha256>, {kdf_id::HKDF_SHA256}, aes_gcm::Aes128Gcm, {aead_id::EXPORT_ONLY}>;

                                            



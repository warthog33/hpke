//!
//! Collection of hpke type specializations
//! Types are created using primitives from the rust crypto collection combined with generic types from this hpke module
//! 
#[allow(unused)]
use crate::hpke_kdf::*;

#[allow(unused)]
use crate::{HpkeIes, KemParams, KdfId, kdf_id, kem_id, AeadId, aead_id };
#[cfg(all(feature = "rustcrypto-aes"))]
use aes_gcm::{AesGcm, Aes128Gcm, Aes256Gcm};
#[allow(unused)]
use kdfs::hybrid_array::sizes::{*};
#[allow(unused)]
use kdfs::{iso11770_6::{Kpf1, Ktf1, Tkdf}};

#[allow(unused)]
use kems::eckem::{EcdhAuthKemUncompressed, EcdhKemUncompressed};
#[allow(unused)]
use kems::hybrid::{HybridKem, QsfCombiner};
#[cfg(all(feature="rustcrypto-x25519", feature="rustcrypto-ml-kem"))]
use kems::xwing::{ XwingMlKem768X25519};
#[cfg(all(feature = "rustcrypto-ml-kem"))]
use ml_kem::{MlKem512, MlKem768, MlKem1024};

#[cfg(all(feature = "rustcrypto-sha2"))]
use sha2::{Sha256, Sha384, Sha512};
#[cfg(all(feature = "rustcrypto-sha3"))]
use shake::{Shake128, Shake256};
#[cfg(all(feature = "rustcrypto-sha3"))]
use turboshake::{CTurboShake128, CTurboShake256};
#[cfg(all(feature = "rustcrypto-sha3"))]
use sha3::Sha3_256;

use kdfs::{Label, misc::PassThroughKdf};
#[cfg(feature="rustcrypto-hmac")]
use kdfs::rfc5869_hkdf::Hkdf;
use crate::hpke_kem_wrapper::{ HpkeKemWrapper, TwoStageXKeyGen, TwoStageEcKeyGen, OneStageSeedDiversify, TwoStageEcCombiner};  

///
/// HPKE Key Encapsulation Mechanisms which involve X25519
/// 
#[cfg(all(feature = "rustcrypto-x25519", feature = "rustcrypto-sha2"))]
pub mod x25519_kems {
    use super::*;
use kems::x25519kem::{X25519AuthKem, X25519Kem};

    pub type HpkeKemX25519HkdfSha256 = HpkeKemWrapper<X25519Kem>;
    impl KemParams for HpkeKemX25519HkdfSha256 { 
        type KemId = kem_id::DhKemX25519HkdfSha256; 
        const IS_AUTH: bool = false; 
        type OutputSize = U32; 
        type KeyGenFromSeed = TwoStageXKeyGen<Hkdf<Sha256>, Self::KemId>;
        type EncapsulateFromSeed = TwoStageXKeyGen<Hkdf<Sha256>, Self::KemId>;
        type Combiner = TwoStageEcCombiner<Hkdf<Sha256>, Self::KemId>;
    }
    
    pub type HpkeAuthKemX25519HkdfSha256 = HpkeKemWrapper<X25519AuthKem>;
    impl KemParams for HpkeAuthKemX25519HkdfSha256 { 
        type KemId = kem_id::DhKemX25519HkdfSha256; 
        const IS_AUTH: bool = true; 
        type OutputSize = U32; 
        type KeyGenFromSeed = TwoStageXKeyGen<Hkdf<Sha256>, Self::KemId>;
        type EncapsulateFromSeed = TwoStageXKeyGen<Hkdf<Sha256>, Self::KemId>;
        type Combiner = TwoStageEcCombiner<Hkdf<Sha256>, Self::KemId>;    
    }
}

///
/// HPKE Key Encapsulation Mechanisms which involve Elliptic Curve x448
/// 
#[cfg(all(feature = "rustcrypto-x448", feature="rustcrypto-sha2"))]
pub mod x448_kems {
    use super::*;
    use kems::x448kem::X448Kem;

    pub type HpkeKemX448HkdfSha512 = HpkeKemWrapper<X448Kem>;

    impl KemParams for HpkeKemX448HkdfSha512 { 
        type KemId = kem_id::DhKemX448HkdfSha512; 
        const IS_AUTH: bool = false; 
        type OutputSize = U64; 
        type KeyGenFromSeed = TwoStageXKeyGen<Hkdf<Sha512>, Self::KemId>;
        type EncapsulateFromSeed = TwoStageXKeyGen<Hkdf<Sha512>, Self::KemId>;
        type Combiner = TwoStageEcCombiner<Hkdf<Sha512>, Self::KemId>;
    }
}

///
/// HPKE Key Encapsulation Mechanisms which involve Elliptic Curve P256
/// 
#[cfg(all(feature = "rustcrypto-p256", feature = "rustcrypto-sha2", feature="rustcrypto-hmac"))]
pub mod p256_kems {
    use p256::NistP256;
    use super::*;

    /// Unauthenticated Hpke Kem using P-256 curve and Hkdf key derivation
    pub type HpkeKemP256HkdfSha256 = HpkeKemWrapper<EcdhKemUncompressed<NistP256>>;
    impl KemParams for HpkeKemP256HkdfSha256 { 
        type KemId = kem_id::DhKemP256HkdfSha256; 
        const IS_AUTH: bool = false; 
        type OutputSize = U32; 
        type KeyGenFromSeed = TwoStageEcKeyGen<Hkdf<Sha256>, Self::KemId, 0xFF>;
        type EncapsulateFromSeed = TwoStageEcKeyGen<Hkdf<Sha256>, Self::KemId, 0xFF>;
        type Combiner = TwoStageEcCombiner<Hkdf<Sha256>, Self::KemId>;
        
    }

    /// Authenticated Hpke Kem using P-256 curve and Hkdf key derivation
    pub type HpkeAuthKemP256HkdfSha256 = HpkeKemWrapper<EcdhAuthKemUncompressed<NistP256>>;
    impl KemParams for HpkeAuthKemP256HkdfSha256 { 
        type KemId = kem_id::DhKemP256HkdfSha256; 
        const IS_AUTH: bool = true; 
        type OutputSize = U32; 
        type KeyGenFromSeed = TwoStageEcKeyGen<Hkdf<Sha256>, Self::KemId, 0xFF>;
        type EncapsulateFromSeed = TwoStageEcKeyGen<Hkdf<Sha256>, Self::KemId, 0xFF>;
        type Combiner = TwoStageEcCombiner<Hkdf<Sha256>, Self::KemId>;
    }
}

///
/// HPKE Key Encapsulation Mechanisms which involve Elliptic Curve P384
/// 
#[cfg(all(feature = "rustcrypto-p384", feature="rustcrypto-sha2", feature="rustcrypto-hmac"))]
pub mod p384_kems {
    use super::*;
    
    /// Implementation of the KEM from RFC9180 which uses Nist P384 and Hkdf-Sha384 key derivation
    pub type HpkeKemP384HkdfSha384 = HpkeKemWrapper<EcdhKemUncompressed<p384::NistP384>>;
    
    impl KemParams for HpkeKemP384HkdfSha384 { 
        type KemId = kem_id::DhKemP384HkdfSha384; 
        const IS_AUTH: bool = false;
        type OutputSize = U48; 
        type KeyGenFromSeed = TwoStageEcKeyGen<Hkdf<Sha384>, Self::KemId, 0xFF>;
        type EncapsulateFromSeed = TwoStageEcKeyGen<Hkdf<Sha384>, Self::KemId, 0xFF>;
        type Combiner = TwoStageEcCombiner<Hkdf<Sha384>, Self::KemId>;
    }
}

///
/// HPKE Key Encapsulation Mechanisms which involve Elliptic Curve P521
/// 
#[cfg(all(feature = "rustcrypto-p521", feature = "rustcrypto-sha2"))]
pub mod p521_kems {
    use super::*;
    use p521::NistP521;

    /// Implementation of a KEM using Nist P521 key agreement with a HKDF-SHA512 key derivation function
    pub type HpkeKemP521HkdfSha512 = HpkeKemWrapper<EcdhKemUncompressed<NistP521>>;
    impl KemParams for HpkeKemP521HkdfSha512 { 
        type KemId = kem_id::DhKemP521HkdfSha512; 
        const IS_AUTH: bool = false;
        type OutputSize = U64; 
        type KeyGenFromSeed = TwoStageEcKeyGen<Hkdf<Sha512>, Self::KemId, 0x01>;
        type EncapsulateFromSeed = TwoStageEcKeyGen<Hkdf<Sha512>, Self::KemId, 0x01>;
        type Combiner = TwoStageEcCombiner<Hkdf<Sha512>, Self::KemId>;
    }
    
    /// Implementation of a KEM using Nist P521 key agreement with a HKDF-SHA512 key derivation function
    pub type HpkeAuthKemP521HkdfSha512 = HpkeKemWrapper<EcdhAuthKemUncompressed<NistP521>>;
    impl KemParams for HpkeAuthKemP521HkdfSha512 { 
        type KemId = kem_id::DhKemP521HkdfSha512; 
        const IS_AUTH: bool = true;
        type OutputSize = U64; 
        type KeyGenFromSeed = TwoStageEcKeyGen<Hkdf<Sha512>, Self::KemId, 0x01>;
        type EncapsulateFromSeed = TwoStageEcKeyGen<Hkdf<Sha512>, Self::KemId, 0x01>;
        type Combiner = TwoStageEcCombiner<Hkdf<Sha512>, Self::KemId>;
    }
}


///
/// HPKE Key Encapsulation Mechanisms which involve Elliptic Curve SecP256k1
/// 
#[cfg(all(feature = "rustcrypto-k256"))]
pub mod k256_kems {
    use k256::Secp256k1;
    use super::*;

    /// Implementation of a KEM using SecP256k1 curve with a HKDF-SHA256 key derivation function 
    pub type HpkeKemSecP256k1HkdfSha256 = HpkeKemWrapper<EcdhKemUncompressed<Secp256k1>>;
    impl KemParams for HpkeKemSecP256k1HkdfSha256 { 
        type KemId = kem_id::DhKemSecP256k1HkdfSha256; 
        const IS_AUTH: bool = false; 
        type OutputSize = U32; 
        type KeyGenFromSeed = TwoStageEcKeyGen<Hkdf<Sha256>, Self::KemId, 0xFF>;
        type EncapsulateFromSeed = TwoStageEcKeyGen<Hkdf<Sha256>, Self::KemId, 0xFF>;
        type Combiner = TwoStageEcCombiner<Hkdf<Sha256>, Self::KemId>;
    }

    /// Implementation of an authenticated KEM using SecP256k1 curve with a HKDF-SHA256 key derivation function 
    pub type HpkeAuthKemSecP256k1HkdfSha256 = HpkeKemWrapper<EcdhAuthKemUncompressed<Secp256k1>>;
    impl KemParams for HpkeAuthKemSecP256k1HkdfSha256 { 
        type KemId = kem_id::DhKemSecP256k1HkdfSha256; 
        const IS_AUTH: bool = true; 
        type OutputSize = U32; 
        type KeyGenFromSeed = TwoStageEcKeyGen<Hkdf<Sha256>, Self::KemId, 0xFF>;
        type EncapsulateFromSeed = TwoStageEcKeyGen<Hkdf<Sha256>, Self::KemId, 0xFF>;
        type Combiner = TwoStageEcCombiner<Hkdf<Sha256>, Self::KemId>;
    }
}

#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-x25519", feature="rustcrypto-sha3"))]
impl KemParams for kems::draft_irtf_cfrg_hybrid_kems::HybridCapsulatorKitchenSinkMlKem768X25519 { 
    type KemId = kem_id::KitchenSinkKemMlKem768X25519; 
    const IS_AUTH: bool = false; 
    type OutputSize = U32; 
    type KeyGenFromSeed = PassThroughKdf;
    type EncapsulateFromSeed = PassThroughKdf;
    type Combiner = PassThroughKdf;
}


///
/// HPKE Key Derivation Functions which use Sha2 digests
/// 
#[cfg(all(feature = "rustcrypto-sha2"))]
pub mod sha2_kdfs {
    use super::*;
    
    pub type HpkeTwoStepHkdf<D> = HpkeTwoStageKdf<kdfs::rfc5869_hkdf::Hkdf<D>>;
    
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
#[cfg(all(feature = "rustcrypto-sha2"))]
use sha2_kdfs::{HpkeHkdfSha256, HpkeHkdfSha384, HpkeHkdfSha512};

///
/// HPKE Key Derivation Functions which use Sha3 digests
/// 
#[cfg(all(feature = "rustcrypto-sha3"))]
pub mod sha3_kdfs {
    use super::*;

    /// Single step KDF used for HPKE based upon Shake128
    pub type HpkeOneStepKdfShake128 = HpkeOneStageKdf<Shake128, U32>;
    impl KdfId for HpkeOneStepKdfShake128 { type KdfType = kdf_id::KdfShake128;}

    /// Single step KDF used for HPKE based upon Shake256
    pub type HpkeOneStepKdfShake256 = HpkeOneStageKdf<Shake256, U64>;
    impl KdfId for HpkeOneStepKdfShake256 { type KdfType = kdf_id::KdfShake256;}
    
    /// Single step KDF used for HPKE based upon TurboShake128
    pub type HpkeOneStepKdfTurboShake128 = HpkeOneStageKdf<CTurboShake128<0x1F>, U32>;
    impl KdfId for HpkeOneStepKdfTurboShake128 { type KdfType = kdf_id::KdfTurboShake128;}

    /// Single step KDF used for HPKE based upon TurboShake256
    pub type HpkeOneStepKdfTurboShake256 = HpkeOneStageKdf<CTurboShake256<0x1F>, U64>;
    impl KdfId for HpkeOneStepKdfTurboShake256 { type KdfType = kdf_id::KdfTurboShake256;}
}
#[cfg(all(feature = "rustcrypto-sha3"))]
use sha3_kdfs::{HpkeOneStepKdfShake128, HpkeOneStepKdfShake256, HpkeOneStepKdfTurboShake128, HpkeOneStepKdfTurboShake256};

///
/// HPKE Authenticated Encryption with Additional Data which use AES
/// 
#[cfg(all(feature = "rustcrypto-aes"))]
pub mod aes_aeads {
    use super::*;
    /// Type which can be used as the AEAD parameter in a HPKE
    impl AeadId for Aes128Gcm { type AeadType = aead_id::Aes128Gcm;}
    /// Type which can be used as the AEAD parameter in a HPKE
    impl AeadId for Aes256Gcm { type AeadType = aead_id::Aes256Gcm;}
    /// This type is never used as an AEAD, but by referencig AES GCM all trait bounds are met
    pub type ExportOnlyAead = AesGcm<aes::Aes256,U0>;
    impl AeadId for ExportOnlyAead { type AeadType = aead_id::ExportOnly; }
}

/// HPKE Authenticated Encryption with Additional Data which use ChaCha20 and Poly1305
#[cfg(all(feature = "rustcrypto-chacha20poly1305"))]
impl AeadId for chacha20poly1305::ChaCha20Poly1305 { type AeadType = aead_id::ChaCha20Poly1305; }



/// HPKE using P256, HKDF-SHA256 and AES128GCM
#[cfg(all(feature = "rustcrypto-p256", feature = "rustcrypto-aes", feature = "rustcrypto-sha2", feature = "rustcrypto-hmac"))]
pub type HpkeIesP256Sha256Aes128Gcm = HpkeIes<p256_kems::HpkeKemP256HkdfSha256, HpkeHkdfSha256, Aes128Gcm>;

/// HPKE using P256, HKDF-SHA512 and AES128GCM
#[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-aes", feature="rustcrypto-sha2", feature = "rustcrypto-hmac"))]
pub type HpkeIesP256Sha512Aes128Gcm = HpkeIes<p256_kems::HpkeKemP256HkdfSha256, HpkeHkdfSha512, Aes128Gcm >;

/// HPKE using P256, HKDF-SHA256 and AES256GCM
#[cfg(all(feature = "rustcrypto-p256", feature = "rustcrypto-aes", feature = "rustcrypto-sha2", feature = "rustcrypto-hmac"))]
pub type HpkeIesP256Sha256Aes256Gcm = HpkeIes<p256_kems::HpkeKemP256HkdfSha256, HpkeHkdfSha256, Aes256Gcm>;

/// HPKE using P256, HKDF-SHA256 and ChaCha20Poly1305
#[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-chacha20poly1305", feature="rustcrypto-sha2"))]
pub type HpkeIesP256Sha256ChaCha20Poly1305 = HpkeIes<p256_kems::HpkeKemP256HkdfSha256, HpkeHkdfSha256, chacha20poly1305::ChaCha20Poly1305>;

/// HPKE AUTH using P256, HKDF-SHA256 and AES128GCM
#[cfg(all(feature = "rustcrypto-p256", feature = "rustcrypto-aes", feature = "rustcrypto-sha2", feature = "rustcrypto-hmac"))]
pub type HpkeAuthIesP256Sha256Aes128Gcm = HpkeIes<p256_kems::HpkeAuthKemP256HkdfSha256, HpkeHkdfSha256, Aes128Gcm>;


/// HPKE AUTH using P256, HKDF-SHA512 and AES128GCM
#[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-aes", feature="rustcrypto-sha2", feature = "rustcrypto-hmac"))]
pub type HpkeAuthIesP256Sha512Aes128Gcm = HpkeIes<p256_kems::HpkeAuthKemP256HkdfSha256, HpkeHkdfSha512, Aes128Gcm>;       

/// HPKE AUTH using P256, HKDF-SHA256 and AES256GCM
#[cfg(all(feature = "rustcrypto-p256", feature = "rustcrypto-aes", feature = "rustcrypto-sha2", feature = "rustcrypto-hmac"))]
pub type HpkeAuthIesP256Sha256Aes256Gcm = HpkeIes<p256_kems::HpkeAuthKemP256HkdfSha256, HpkeHkdfSha256, Aes256Gcm>;

/// HPKE using K256, HKDF-SHA256 and AES128GCM
#[cfg(all(feature = "rustcrypto-k256", feature = "rustcrypto-aes", feature = "rustcrypto-sha2"))]
pub type HpkeIesK256Sha256Aes128Gcm = HpkeIes<k256_kems::HpkeKemSecP256k1HkdfSha256, HpkeHkdfSha256, Aes128Gcm>;

/// HPKE using K256, HKDF-SHA256 and AES128GCM
#[cfg(all(feature = "rustcrypto-k256"))]
pub type HpkeAuthIesK256Sha256Aes128Gcm = HpkeIes<k256_kems::HpkeAuthKemSecP256k1HkdfSha256, HpkeHkdfSha256, Aes128Gcm>;

/// HPKE using K256, HKDF-SHA256 and ChaCha20 with Poly1305
#[cfg(all(feature = "rustcrypto-k256"))]
pub type HpkeIesK256Sha256ChaCha20Poly1305 = HpkeIes<k256_kems::HpkeKemSecP256k1HkdfSha256, HpkeHkdfSha256, chacha20poly1305::ChaCha20Poly1305>;

/// HPKE Auth using K256, HKDF-SHA256 and ChCha20 with Poly1305
#[cfg(all(feature = "rustcrypto-k256"))]
pub type HpkeAuthIesK256Sha256ChaCha20Poly1305 = HpkeIes<k256_kems::HpkeAuthKemSecP256k1HkdfSha256, HpkeHkdfSha256, chacha20poly1305::ChaCha20Poly1305>;

/// HPKE using K256, HKDF-SHA256 and AES256GCM
#[cfg(all(feature = "rustcrypto-k256"))]
pub type HpkeIesK256Sha256Aes256Gcm = HpkeIes<k256_kems::HpkeKemSecP256k1HkdfSha256, HpkeHkdfSha256, Aes256Gcm>;

/// HPKE Auth using K256, HKDF-SHA256 and AES256GCM
#[cfg(all(feature = "rustcrypto-k256"))]
pub type HpkeAuthIesK256Sha256Aes256Gcm = HpkeIes<k256_kems::HpkeAuthKemSecP256k1HkdfSha256, HpkeHkdfSha256, Aes256Gcm>;



/// HPKE using P384, HKDF-SHA384 and AES256GCM
#[cfg(all(feature = "rustcrypto-p384", feature="rustcrypto-aes", feature="rustcrypto-sha2", feature = "rustcrypto-hmac"))]
pub type HpkeIesP384Sha384Aes256Gcm = HpkeIes<p384_kems::HpkeKemP384HkdfSha384, HpkeHkdfSha384, Aes256Gcm>;

/// HPKE using P521, HKDF-SHA512 and AES256GCM
#[cfg(all(feature = "rustcrypto-p521", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
pub type HpkeIesP521Sha512Aes256Gcm = HpkeIes<p521_kems::HpkeKemP521HkdfSha512, HpkeHkdfSha512, Aes256Gcm>;

/// HPKE Auth using P521, HKDF-SHA512 and AES256GCM
#[cfg(all(feature = "rustcrypto-p521", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
pub type HpkeAuthIesP521Sha512Aes256Gcm = HpkeIes<p521_kems::HpkeAuthKemP521HkdfSha512,HpkeHkdfSha512, Aes256Gcm>;

/// HPKE using X25519, HKDF-SHA256 and ChaCha20Poly1305
#[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-chacha20poly1305", feature="rustcrypto-sha2"))]
pub type HpkeIesX25519Sha256ChaCha20Poly1305 = HpkeIes<x25519_kems::HpkeKemX25519HkdfSha256, HpkeHkdfSha256, chacha20poly1305::ChaCha20Poly1305>;

/// HPKE using X25519, HKDF-SHA256 and Aes128GCM
#[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]                                        
pub type HpkeIesX25519Sha256Aes128Gcm = HpkeIes<x25519_kems::HpkeKemX25519HkdfSha256, HpkeHkdfSha256, Aes128Gcm>;

/// HPKE AUTH using X25519, HKDF-SHA256 and AES128GCM
#[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]   
pub type HpkeAuthIesX25519Sha256Aes128Gcm = HpkeIes<x25519_kems::HpkeAuthKemX25519HkdfSha256, HpkeHkdfSha256, Aes128Gcm>;

/// HPKE Export Only using X25519, HKDF-SHA256 and Aes128GCM
#[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
pub type HpkeIesX25519Sha256ExportOnly = HpkeIes<x25519_kems::HpkeKemX25519HkdfSha256, HpkeHkdfSha256, aes_aeads::ExportOnlyAead >;

/// HPKE Auth Export Only using X25519, HKDF-SHA256 and Aes128GCM
#[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
pub type HpkeAuthIesX25519Sha256ExportOnly = HpkeIes<x25519_kems::HpkeAuthKemX25519HkdfSha256, HpkeHkdfSha256, aes_aeads::ExportOnlyAead>;

/// HPKE using X448, HKDF-SHA512 and ChaCha20Poly1305
#[cfg(all(feature = "rustcrypto-x448", feature="rustcrypto-chacha20poly1305", feature="rustcrypto-sha2"))]
pub type HpkeIesX448Sha512ChaCha20Poly1305 = HpkeIes<x448_kems::HpkeKemX448HkdfSha512, HpkeHkdfSha512, chacha20poly1305::ChaCha20Poly1305>;

/// HPKE using X448, HKDF-SHA512 and Aes256GCM
#[cfg(all(feature = "rustcrypto-x448", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
pub type HpkeIesX448Sha512Aes256Gcm = HpkeIes<x448_kems::HpkeKemX448HkdfSha512, HpkeHkdfSha512, Aes256Gcm>;




///
/// XWing is a single configuration KEM defined in <https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/>
/// 
#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-x25519", feature = "rustcrypto-aes", feature = "rustcrypto-sha2", feature = "rustcrypto-sha3"))]
pub mod draft_ietf_xwing {
    use super::*;
    
    /// This variation modifies default XWing by adding an additional hpke specific key derivation step during key generation from seed
    pub type HpkeXwingMlKem768X25519 = HpkeKemWrapper<XwingMlKem768X25519>;

    impl KemParams for HpkeXwingMlKem768X25519 { 
        type KemId = kem_id::Xwing; 
        const IS_AUTH: bool = false; 
        type OutputSize = U32; 
        type KeyGenFromSeed = OneStageSeedDiversify<Shake256,Self::KemId>;
        type EncapsulateFromSeed = PassThroughKdf;
        type Combiner = PassThroughKdf;
    }
}

#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-aes", feature="rustcrypto-x25519", feature="rustcrypto-sha3"))]
pub mod apple {
    use crate::hpke_types::draft_ietf_xwing::HpkeXwingMlKem768X25519;
    use super::*;

    // Implemented by apple 
    pub type HpkeIesXwingMl768X25519Sha256Aes256Gcm = HpkeIes<HpkeXwingMlKem768X25519, HpkeHkdfSha256, Aes256Gcm>;
}

///
/// Types described in the <https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/>
/// 
#[cfg(all(feature = "rustcrypto-ml-kem"))]
pub mod draft_ietf_hpke_pq {
   
    use super::*;
    use kems::{LabelMlKem768P256, LabelMlKem1024P384};
    
    pub type HpkeKemMlKem512 = HpkeKemWrapper<MlKem512>;
    impl KemParams for HpkeKemMlKem512 { 
        type KemId = kem_id::MlKem512; 
        const IS_AUTH: bool = false; 
        type OutputSize = U32; 
        type KeyGenFromSeed = OneStageSeedDiversify<Shake256,Self::KemId>;
        type EncapsulateFromSeed = PassThroughKdf;
        type Combiner = PassThroughKdf;
    }

    pub type HpkeKemMlKem768 = HpkeKemWrapper<MlKem768>;
    impl KemParams for HpkeKemMlKem768 { 
        type KemId = kem_id::MlKem768; 
        const IS_AUTH: bool = false; 
        type OutputSize = U32; 
        type KeyGenFromSeed = OneStageSeedDiversify<Shake256,Self::KemId>;
        type EncapsulateFromSeed = PassThroughKdf;
        type Combiner = PassThroughKdf;
    }

    pub type HpkeKemMlKem1024 = HpkeKemWrapper<MlKem1024>;
    impl KemParams for HpkeKemMlKem1024 { 
        type KemId = kem_id::MlKem1024; 
        const IS_AUTH: bool = false; 
        type OutputSize = U32; 
        type KeyGenFromSeed = OneStageSeedDiversify<Shake256,Self::KemId>;
        type EncapsulateFromSeed = PassThroughKdf;
        type Combiner = PassThroughKdf;
    }

    /// HPKE using ML-KEM 768, Nist P256 and a Sha3 based combiner, similar to ConcreteMlKem768P256 except it
    /// has an additional step during the derive from seed step
    #[cfg(all(feature="rustcrypto-p256", feature="rustcrypto-sha3"))]
    pub type HpkeConcreteMlKem768P256 = HpkeKemWrapper<HybridKem::<
            MlKem768,
            EcdhKemUncompressed<p256::NistP256>,
            QsfCombiner<kdfs::iso11770_6::Okdf1::<Sha3_256>, LabelMlKem768P256>, 
    >>;
    
    #[cfg(all(feature="rustcrypto-p256", feature="rustcrypto-sha3"))]
    impl KemParams for HpkeConcreteMlKem768P256 { 
        type KemId = kem_id::QsfKemMlKem768P256Shake256Sha3256; 
        const IS_AUTH: bool = false; 
        type OutputSize = U32; 
        type KeyGenFromSeed = OneStageSeedDiversify<Shake256,Self::KemId>;
        type EncapsulateFromSeed = PassThroughKdf;
        type Combiner = PassThroughKdf;
    }
    
    /// HPKE using ML-KEM 768, Nist P384 curve and a Sha3 based combiner
    #[cfg(all(feature="rustcrypto-p384", feature="rustcrypto-sha3"))]
    pub type HpkeConcreteMlKem1024P384 = HpkeKemWrapper<HybridKem::<
            MlKem1024,
            EcdhKemUncompressed<p384::NistP384>,
            QsfCombiner<kdfs::iso11770_6::Okdf1::<Sha3_256>, LabelMlKem1024P384>, 
    >>;
    #[cfg(all(feature="rustcrypto-p384", feature="rustcrypto-sha3"))]
    impl KemParams for HpkeConcreteMlKem1024P384 { 
        type KemId = kem_id::QsfKemMlKem1024P384Shake256Sha3256; 
        const IS_AUTH: bool = false; 
        type OutputSize = U32; 
        type KeyGenFromSeed = OneStageSeedDiversify<Shake256,Self::KemId>;
        type EncapsulateFromSeed = PassThroughKdf;
        type Combiner = PassThroughKdf;
    }
            

    #[cfg(all(feature="rustcrypto-x25519", feature = "rustcrypto-aes", feature = "rustcrypto-sha2", feature = "rustcrypto-sha3"))]
    pub type HpkeIesKitchenSinkMl768X25519Sha256Aes128Gcm = HpkeIes<kems::draft_irtf_cfrg_hybrid_kems::HybridCapsulatorKitchenSinkMlKem768X25519, HpkeHkdfSha256, Aes128Gcm>;

    // v4, A.1.  ML-KEM-512, HKDF-SHA256, AES-128-GCM
    #[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
    pub type HpkeIesMlKem512Sha256Aes128Gcm = HpkeIes<HpkeKemMlKem512, HpkeHkdfSha256, Aes128Gcm>;

    // v3, A.1. and v4 A.2: ML-KEM-768, HKDF-SHA256, AES-128-GCM
    #[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
    pub type HpkeIesMlKem768Sha256Aes128Gcm = HpkeIes<HpkeKemMlKem768, HpkeHkdfSha256, Aes128Gcm >;

    // v3, A.2. and v4 A.3: ML-KEM-1024, HKDF-SHA384, AES-256-GCM
    #[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-aes", feature="rustcrypto-sha2"))]
    pub type HpkeIesMlKem1024Sha384Aes256Gcm = HpkeIes<HpkeKemMlKem1024, HpkeHkdfSha384, Aes256Gcm >;

    // A.3. QSF-P256-MLKEM768, SHAKE256, AES-128-GCM
    #[cfg(all(feature = "rustcrypto-ml-kem", feature= "rustcrypto-p256", feature="rustcrypto-sha3", feature="rustcrypto-aes"))]
    pub type HpkeIesMlKem768P256Shake256Aes128Gcm = HpkeIes::<HpkeConcreteMlKem768P256, HpkeHkdfSha256, Aes128Gcm>;
    
    // v3 - A.4.  QSF-X25519-MLKEM768, HKDF-SHA256, AES-128-GCM
    #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-ml-kem", feature="rustcrypto-sha3", feature="rustcrypto-aes"))]
    pub type HpkeIesMlKem768X25519HkdfSha256Aes128Gcm = HpkeIes::<XwingMlKem768X25519, HpkeHkdfSha256, Aes128Gcm>;

    // v3 - A.5.  QSF-X25519-MLKEM768, Unknown KDF, AES-128-GCM
    #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-ml-kem", feature="rustcrypto-sha3", feature="rustcrypto-aes"))]
    pub type HpkeIesMlKem768X25519Shake256Aes128Gcm = HpkeIes::<XwingMlKem768X25519, HpkeOneStepKdfShake128, Aes128Gcm>;

    // v4 A.4 MLKEM768-P256, HKDF-SHA256, AES-128-GCM
    #[cfg(all(feature="rustcrypto-p256", feature="rustcrypto-sha3"))]
    pub type HpkeIesMlKem768P256HkdfSha256Aes128Gcm = HpkeIes::<HpkeConcreteMlKem768P256, HpkeHkdfSha256, Aes128Gcm>;

    // v4, A.5. MLKEM768-X25519, HKDF-SHA256, ChaCha20Poly1305
    #[cfg(all(feature="rustcrypto-x25519", feature="rustcrypto-sha3"))]
    pub type HpkeIesMlKem768X25519Shake128ChaCha20Poly1305 = HpkeIes::<draft_ietf_xwing::HpkeXwingMlKem768X25519, HpkeHkdfSha256, chacha20poly1305::ChaCha20Poly1305>;

    // v4, A.6. MLKEM1024+P384, HKDF-384, AES-256-GCM
    #[cfg(all(feature="rustcrypto-p384", feature="rustcrypto-sha3", feature="rustcrypto-sha2"))]
    pub type HpkeIesMlKem1024P384HkdfSha256Aes256Gcm = HpkeIes::<HpkeConcreteMlKem1024P384, HpkeHkdfSha384, Aes256Gcm>;

    // v4 A.7 DHKEM(P-256, HKDF-SHA256), SHAKE256, AES-128-GCM
    #[cfg(all(feature="rustcrypto-p256", feature="rustcrypto-sha3", feature="rustcrypto-sha2", feature = "rustcrypto-hmac"))]
    pub type HpkeIesP256Shake256Aes128Gcm = HpkeIes::<p256_kems::HpkeKemP256HkdfSha256, HpkeOneStepKdfShake128, Aes128Gcm /*HpkeKemOneStepKdf2::<kem_id::DhKemP256HkdfSha256>*/>;

    // v4 A.8 DHKEM(P-384, HKDF-SHA384), SHAKE256, AES-256-GCM
    #[cfg(all(feature="rustcrypto-p384", feature="rustcrypto-sha3", feature="rustcrypto-sha2", feature = "rustcrypto-hmac"))]
    pub type HpkeIesP384Shake256Aes256Gcm<'a> = HpkeIes::<p384_kems::HpkeKemP384HkdfSha384, HpkeOneStepKdfShake256, Aes256Gcm /*HpkeKemOneStepKdf2::<kem_id::DhKemP256HkdfSha256>*/>;

    // v4 A.9 DHKEM(X25519, HKDF-SHA256), Unknown KDF, ChaCha20Poly1305
    #[cfg(all(feature="rustcrypto-x25519", feature="rustcrypto-sha3", feature="rustcrypto-sha2"))]
    pub type HpkeIesX25519TurboShake128ChaCha20Poly1305 = HpkeIes::<x25519_kems::HpkeKemX25519HkdfSha256, HpkeOneStepKdfTurboShake128, chacha20poly1305::ChaCha20Poly1305 /*HpkeKemOneStepKdf2::<kem_id::DhKemP256HkdfSha256>*/>;

    // v4 A.10 DHKEM(X448, HKDF-SHA256), TurboShake256, ChaCha20Poly1305
    #[cfg(all(feature="rustcrypto-x448", feature="rustcrypto-sha3"))]
    pub type HpkeIesX448TurboShake256ChaCha20Poly1305 = HpkeIes::<x448_kems::HpkeKemX448HkdfSha512, HpkeOneStepKdfTurboShake256, chacha20poly1305::ChaCha20Poly1305 /*HpkeKemOneStepKdf2::<kem_id::DhKemP256HkdfSha256>*/>;

    // v4 A.11 MLKEM768-P256, SHAKE128, AES-256-GCM
    #[cfg(all(feature = "rustcrypto-ml-kem", feature= "rustcrypto-p256", feature="rustcrypto-sha3", feature="rustcrypto-aes"))]
    pub type HpkeIesMlKem768P256Shake128Aes256Gcm = HpkeIes::<HpkeConcreteMlKem768P256, HpkeOneStepKdfShake128, Aes256Gcm>;

    // v4 A.12  MLKEM768-X25519, Shake256, ChaCha20Poly1305
    #[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-x25519", feature="rustcrypto-sha3", feature="rustcrypto-aes"))]
    pub type HpkeIesMlKem768X25519Shake256Cha20Poly1305<'a> = HpkeIes::<draft_ietf_xwing::HpkeXwingMlKem768X25519, HpkeOneStepKdfShake256, chacha20poly1305::ChaCha20Poly1305>;

    // v4 A.13  ML-KEM-1024, Unknown KDF, AES-128-GCM
    #[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-x25519", feature="rustcrypto-sha3", feature="rustcrypto-aes"))]
    pub type HpkeIesMlKem1024TurboShake256Aes128Gcm = HpkeIes::<HpkeKemMlKem1024, HpkeOneStepKdfTurboShake256, Aes128Gcm>;
   

}

///
/// Post quantum encryption mechanisms for use within JOSE
/// <https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/11/>
pub mod draft_ietf_jose_hpke_encrypt {
    #[cfg(all(feature="rustcrypto-p384"))]
    use kdfs::Label;


    /// Cipher suite for JOSE-HPKE using the DHKEM(P-256, HKDF-SHA256) KEM, the HKDF-SHA256 KDF and the AES-128-GCM AEAD
    #[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-sha2", feature="rustcrypto-aes", feature = "rustcrypto-hmac"))]
    pub type HPKE0P256Aes128 = crate::hpke_types::HpkeIesP256Sha256Aes128Gcm;
    #[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-sha2", feature="rustcrypto-aes", feature = "rustcrypto-hmac"))]
    impl Label for HPKE0P256Aes128{const LABEL: &'static[u8] = b"HPKE-0";}

    /// Cipher suite for JOSE-HPKE using the DHKEM(P-384, HKDF-SHA384) KEM, the HKDF-SHA384 KDF, and the AES-256-GCM AEAD.
    #[cfg(all(feature = "rustcrypto-p384", feature="rustcrypto-sha2", feature="rustcrypto-aes", feature = "rustcrypto-hmac"))]
    pub type HPKE1P384Aes256 = crate::hpke_types::HpkeIesP384Sha384Aes256Gcm;
    #[cfg(all(feature = "rustcrypto-p384", feature="rustcrypto-sha2", feature="rustcrypto-aes", feature = "rustcrypto-hmac"))]
    impl Label for HPKE1P384Aes256{const LABEL: &'static[u8] = b"HPKE-1";}

    /// Cipher suite for JOSE-HPKE using the DHKEM(P-521, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the AES-256-GCM AEAD
    #[cfg(all(feature = "rustcrypto-p521", feature="rustcrypto-sha2", feature="rustcrypto-aes"))]
    pub type HPKE2P521Aes256 = crate::hpke_types::HpkeIesP521Sha512Aes256Gcm;
    #[cfg(all(feature = "rustcrypto-p521", feature="rustcrypto-sha2", feature="rustcrypto-aes"))]
    impl Label for HPKE2P521Aes256{const LABEL: &'static[u8] = b"HPKE-2";}

    /// Cipher suite for JOSE-HPKE using the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF, and the AES-128-GCM AEAD
    #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-sha2", feature="rustcrypto-aes"))]
    pub type HPKE3X25519Aes128 = crate::hpke_types::HpkeIesX25519Sha256Aes128Gcm;
    #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-sha2", feature="rustcrypto-aes"))]
    impl Label for HPKE3X25519Aes128{const LABEL: &'static[u8] = b"HPKE-3";}

    /// Cipher suite for JOSE-HPKE using the DHKEM(X25519, HKDF-SHA256) KEM, the HKDF-SHA256 KDF, and the ChaCha20Poly1305 AEAD
    #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-sha2", feature="rustcrypto-chacha20poly1305"))]
    pub type HPKE4X25519ChaCha20Poly1305 = crate::hpke_types::HpkeIesX25519Sha256ChaCha20Poly1305;
    #[cfg(all(feature = "rustcrypto-x25519", feature="rustcrypto-sha2", feature="rustcrypto-chacha20poly1305"))]
    impl Label for HPKE4X25519ChaCha20Poly1305{const LABEL: &'static[u8] = b"HPKE-4";}

    /// Cipher suite for JOSE-HPKE using the DHKEM(X448, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the AES-256-GCM AEAD
    #[cfg(all(feature = "rustcrypto-x448", feature="rustcrypto-sha2", feature="rustcrypto-aes"))]
    pub type HPKE5X448Aes256 = crate::hpke_types::HpkeIesX448Sha512Aes256Gcm;
    #[cfg(all(feature = "rustcrypto-x448", feature="rustcrypto-sha2", feature="rustcrypto-aes"))]
    impl Label for HPKE5X448Aes256{const LABEL: &'static[u8] = b"HPKE-5";}

    /// Cipher suite for JOSE-HPKE using the DHKEM(X448, HKDF-SHA512) KEM, the HKDF-SHA512 KDF, and the ChaCha20Poly1305 AEAD
    #[cfg(all(feature = "rustcrypto-x448", feature="rustcrypto-chacha20poly1305"))]
    pub type HPKE6X448ChaCha20Poly1305 = crate::hpke_types::HpkeIesX448Sha512ChaCha20Poly1305;
    #[cfg(all(feature = "rustcrypto-x448", feature="rustcrypto-chacha20poly1305"))]
    impl Label for HPKE6X448ChaCha20Poly1305{const LABEL: &'static[u8] = b"HPKE-6";}

    /// Cipher suite for JOSE-HPKE using the DHKEM(P-256, HKDF-SHA256) KEM, the HKDF-SHA256 KDF and the AES-256-GCM AEAD
    #[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-sha2", feature="rustcrypto-aes", feature = "rustcrypto-hmac"))]
    pub type HPKE7P256Aes256 = crate::hpke_types::HpkeIesP256Sha256Aes256Gcm;
    #[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-sha2", feature="rustcrypto-aes", feature = "rustcrypto-hmac"))]
    impl Label for HPKE7P256Aes256{const LABEL: &'static[u8] = b"HPKE-7";}
}

// https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-pq-pqt/
#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-sha3", feature="rustcrypto-aes"))]
pub mod draft_ietf_jose_hpke_pq 
{
    use super::*;
    
    #[cfg(all(feature="rustcrypto-p256"))]
    use kems::draft_ietf_lamps_pq_composite_kem::HybridKemMlKem768P256Sha3_256;
    #[cfg(all(feature="rustcrypto-p384"))]
    use kems::draft_ietf_lamps_pq_composite_kem::HybridKemMlKem1024P384Sha3_256;
    #[cfg(all(feature="rustcrypto-x25519"))]
    use kems::xwing::XwingMlKem768X25519;
    use ml_kem::{MlKem768, MlKem1024};
    
    #[cfg(all(feature="rustcrypto-p256"))]
    impl KemParams for HybridKemMlKem768P256Sha3_256 { 
        type KemId = crate::kem_id::QsfKemMlKem768P256Shake256Sha3256; 
        const IS_AUTH: bool = false; 
        type OutputSize = U32; 
        type KeyGenFromSeed = OneStageSeedDiversify<Shake256,Self::KemId>;
        type EncapsulateFromSeed = PassThroughKdf;
        type Combiner = PassThroughKdf;
    }
    #[cfg(all(feature="rustcrypto-x25519"))]
    impl KemParams for XwingMlKem768X25519 { 
        type KemId = kem_id::Xwing; 
        const IS_AUTH: bool = false; 
        type OutputSize = U32; 
        type KeyGenFromSeed = OneStageSeedDiversify<Shake256,Self::KemId>;
        type EncapsulateFromSeed = PassThroughKdf;
        type Combiner = PassThroughKdf;
    }
    #[cfg(all(feature="rustcrypto-p384"))]
    impl KemParams for HybridKemMlKem1024P384Sha3_256 { 
        type KemId = crate::kem_id::QsfKemMlKem1024P384Shake256Sha3256; 
        const IS_AUTH: bool = false; 
        type OutputSize = U32; 
        type KeyGenFromSeed = OneStageSeedDiversify<Shake256,Self::KemId>;
        type EncapsulateFromSeed = PassThroughKdf;
        type Combiner = PassThroughKdf;
    }
    impl KemParams for MlKem768 { 
        type KemId = crate::kem_id::MlKem768; 
        const IS_AUTH: bool = false; 
        type OutputSize = U32; 
        type KeyGenFromSeed = OneStageSeedDiversify<Shake256,Self::KemId>;
        type EncapsulateFromSeed = PassThroughKdf;
        type Combiner = PassThroughKdf;
    }
    impl KemParams for MlKem1024 { 
        type KemId = crate::kem_id::MlKem1024; 
        const IS_AUTH: bool = false; 
        type OutputSize = U32; 
        type KeyGenFromSeed = OneStageSeedDiversify<Shake256,Self::KemId>;
        type EncapsulateFromSeed = PassThroughKdf;
        type Combiner = PassThroughKdf;
    }

    /// Cipher suite for JOSE-HPKE in Base Mode that uses the P-256 + ML-KEM-768 Hybrid KEM, the SHAKE256 KDF, and the ChaCha20Poly1305 AEAD.
    #[cfg(all(feature="rustcrypto-p256"))]
    pub type HPKE8MlKem768P256Aes256 = HpkeIes<HybridKemMlKem768P256Sha3_256, HpkeOneStepKdfShake256, Aes256Gcm>;
    #[cfg(all(feature="rustcrypto-p256"))]
    impl Label for HPKE8MlKem768P256Aes256{const LABEL: &'static[u8] = b"HPKE-8";}

    #[cfg(all(feature="rustcrypto-x25519"))]
    pub type HPKE9MlKem768X25519Aes256 = HpkeIes<XwingMlKem768X25519, HpkeOneStepKdfShake256, Aes256Gcm>;
    #[cfg(all(feature="rustcrypto-x25519"))]    
    impl Label for HPKE9MlKem768X25519Aes256{const LABEL: &'static[u8] = b"HPKE-9";}

    #[cfg(all(feature="rustcrypto-p384"))]
    pub type HPKE10MlKem768P384Aes256 = HpkeIes<HybridKemMlKem1024P384Sha3_256, HpkeOneStepKdfShake256, Aes256Gcm>;
    #[cfg(all(feature="rustcrypto-p384"))]
    impl Label for HPKE10MlKem768P384Aes256{const LABEL: &'static[u8] = b"HPKE-10";}

    pub type HPKE12MlKem768Aes256 = HpkeIes<MlKem768, HpkeOneStepKdfShake256, Aes256Gcm>;
    impl Label for HPKE12MlKem768Aes256{const LABEL: &'static[u8] = b"HPKE-12";}

    pub type HPKE13MlKem1024Aes256 = HpkeIes<MlKem1024, HpkeOneStepKdfShake256, Aes256Gcm>;
    impl Label for HPKE13MlKem1024Aes256{const LABEL: &'static[u8] = b"HPKE-13";}

}


//!
//! Hpke - Implementation of the hybrid public key encryption algorithm specified in RFC 9180. Is composed of a Key Encapsulation Mechanism (KEM), Key Derivation Function (KDF) 
//!         and an Authenticated Encryption with Associated Data (AEAD) algorithm
//! # Example using HPKE
//! The following example requires features rustcrypto-x25519, rustcrypto-sha2 and rustcrypto-aes
//! ```
//! use x25519_dalek::{StaticSecret, PublicKey};
//! use hpke::hpke_types::HpkeIesX25519Sha256Aes128Gcm;
//! use aead::Payload;
//! use rand_core::OsRng;
//! 
//! let recipient_secret_key = StaticSecret::random_from_rng(&mut OsRng);
//! let recipient_public_key = PublicKey::from(&recipient_secret_key);
//! let plaintext = b"Hello World!";
//! let aad = b"Some other data";
//! let info = b"Info";
//! 
//! let encryptor = HpkeIesX25519Sha256Aes128Gcm::encryptor_from_key(recipient_public_key);
//! let (c0_send, ct_send) = encryptor.single_shot_seal(&mut OsRng, Payload{msg: plaintext.as_ref(), aad: aad.as_ref()}, info, None   ).unwrap();
//! 
//! let decryptor = HpkeIesX25519Sha256Aes128Gcm::decryptor_from_key(recipient_secret_key);
//! let plaintext_receive = decryptor.single_shot_open(&c0_send, info, Payload{msg: ct_send.as_ref(), aad: aad.as_ref()}, None).unwrap();
//! assert! ( plaintext_receive == plaintext );
//! ```

use std::marker::PhantomData;
use std::ops::{Add, Sub};

use aead::array::typenum::{Diff, Sum};
use aead::{Aead, KeyInit, Payload, Nonce};
use elliptic_curve::{PublicKey, SecretKey, Curve, CurveArithmetic, NonZeroScalar, FieldBytesEncoding};
use digest::{Mac, FixedOutputReset};
use hpke_kdf::{HpkeKdf, Psk}; 
use kdfs::{Kdf, KdfFixed, KdfLabelled, TwoStepKdf};
use kdfs::iso11770_6::{Kpf1, Ktf1};
use kdfs::hybrid_array::{Array, ArraySize};
use kems::{Capsulator, Ciphertext, CryptoRngCore, Decapsulate, DeriveKeyPairFromSeed, Encapsulate, EncapsulateDeterministic2, EncodedSizeUser2, FromKey, FromKeys, GenerateCapsulatorFromSeed};
use kems::generic_array::GenericArray;
use kems::generic_array::typenum::{Unsigned};

use crate::hpke_kdf::{LabelHpkeV1, LabelKdf, LabelKem, LabelKeyGenCandidate, LabelKeyGenExtract, LabelledExpand, LabelledExtract};
//use crate::hpke_kdf::LabeledTwoStepKdf;


pub mod hpke_types;
pub mod hpke_kdf;

#[derive(Debug)]
pub enum Error 
{
    AeadError,
    KemError,
    KeyError,
    KdfError,
}
impl From<aead::Error> for Error {
    fn from(_err: aead::Error) -> Error {
        return Error::AeadError;
    }
}
// impl From<kem::Error> for Error {
//     fn from(_err: kem::Error) -> Error {
//         return Error::KemError;
//     }
// }
/// Defines an associated type which represents the ID of the KEM
/// HPKE functions retrieve the KemType and use it as part of the key derivation process
pub trait KemId {
    type KemType: Unsigned;
}
/// Defines an associated type which represents the ID of the AEAD
/// HPKE functions retrieve the KemType and use it as part of the key derivation process
pub trait AeadId {
    type AeadType: Unsigned;
}
/// Defines an associated type which represents the ID of the KDF
/// HPKE functions retrieve the KemType and use it as part of the key derivation process
pub trait KdfId {
    type KdfType: Unsigned;
}




/// IDs for the different modes of HPKE, defined in RFC 9180
pub mod mode_id {
    /// Regular mode which does not use sender authentication or preshared keys
    pub const MODE_BASE:u8 = 0;
    /// Mode which uses a pre-shared key, but no asymmetric sender authentication
    pub const MODE_PSK:u8 = 1;
    /// Mode which uses a key pair from the sender to authenticate both ends
    pub const MODE_AUTH:u8 = 2;
    /// Mode which uses a key pair from the sender to authenticate both ends as well as a preshared keys
    pub const MODE_AUTH_PSK:u8 = 3;
}

/// Key Encapsulation Mechanism Identifiers
/// <https://www.iana.org/assignments/hpke/hpke.xhtml>
pub mod kem_id {
    use kems::generic_array::typenum::*;
    /// ID of KEM using P256 with HKDF(Sha256) RFC 5869
    pub type DhKemP256HkdfSha256 = U16; 
    /// ID of KEM using P384 with HKDF(Sha384) RFC 5869
    pub type DhKemP384HkdfSha384 = U17;
    /// ID of KEM using P521 with HKDF(Sha512) RFC 5869
    pub type DhKemP521HkdfSha512 = U18;
    /// ID of KEM using CP256 with HKDF(Sha256) RFC 6090
    pub type DhKemCP256HkdfSha256 = U19;
    /// ID of KEM using CP384 with HKDF(Sha384) RFC 6090
    pub type DhKemCP384HkdfSha384 = U20;
    /// ID of KEM using CP521 with HKDF(Sha512) RFC 6090
    pub type DhKemCP521HkdfSha512 = U21;
    /// ID of KEM using SecP256k1 with HKDF(Sha256) from draf-wahby-cfrg-hpke-kem-secp256k1-01
    pub type DhKemSecP256k1HkdfSha256 = U22; 

    /// ID of KEM using X25519 with HKDF(Sha256) from RFC 5869 and RFC 7748
    pub type DhKemX25519HkdfSha256 = U32;
    /// ID of KEM using X448 with HKDF(Sha256) from RFC 5869 and RFC 7748
    pub type DhKemX448HkdfSha512 = U33;
    // ID of KEM using X25519 ?? with HKDF(Sha256) from [https://lsd.gnunet.org/lsd0011/][draft-schanzen-hpke-elligator-kem-01]
    pub type DhKemX25519ElligatorHkdfSha256 = U34; 

    // ID of KEM using X25519 and Kyber768 with ??? from [draft-westerbaan-cfrg-hpke-xyber768d00-02]
    pub type X25519Kyber768Draft00 = U48;

    /// ID of KEM using ML-KEM 512, // Draft, from Connoly and Barnes, draft-ietf-hpke-pq-01
    pub type MlKem512 = U64; 
    /// ID of KEM using ML-KEM 768, // Draft, from Connoly and Barnes, draft-ietf-hpke-pq-01
    pub type MlKem768 = U65; 
    /// ID of KEM using ML-KEM 1024, // Draft, from Connoly and Barnes, draft-ietf-hpke-pq-01
    pub type MlKem1024 = U66;

    /// ID of KEM using a hybrid ML-KEM 768 and P256 with a QSF combiner using Sha3-256, from Connoly and Barnes, draft-ietf-hpke-pq-01
    pub type QsfKemMlKem768P256Shake256Sha3256 = U80; // Draft, draft-ietf-hpke-pq-03
    /// ID of KEM using a hybrid ML-KEM 1024 and P384 with a QSF combiner using Sha3-256, from Connoly and Barnes, draft-ietf-hpke-pq-01
    pub type QsfKemMlKem1024P384Shake256Sha3256 = U81; // Draft, draft-ietf-hpke-pq-03

    /// ID of KEM using a hybrid ML-KEM 768 and P256 with a QSF combiner, https://datatracker.ietf.org/doc/draft-irtf-cfrg-hybrid-kems/03/
    pub type QsfKemMlKem768P256 = Sum<U32768, Sum<U16384, U510>>; // 0xc1fe = 49662 = 0x8000 + 0x4000 + ;
    /// ID of KEM using a hybrid ML-KEM 768 and X25519 with a Kitchen sink combiner, https://datatracker.ietf.org/doc/draft-irtf-cfrg-hybrid-kems/03/
    pub type KitchenSinkKemMlKem768X25519 = Sum<U32768, Diff<U16384, U952>>; // 0xc1fe = 49662 = 0x8000 + 0x4000 - 0x3B8;
    /// ID of KEM using a hybrid ML-KEM 1024 and P384 with a QSF combined, https://datatracker.ietf.org/doc/draft-irtf-cfrg-hybrid-kems/03/
    pub type QsfKemMlKem1024P384 = Sum<U2048, U549>; // 0x0a25 = 0x800 + 0x224;

    /// ID of the Xwing hybrid KEM, which uses X25519 and ML-KEM 768 with a QSF combiner,  Draft, draft-connolly-cfrg-xwing-kem-06
    pub type Xwing = Sum<U16384, Sum<U8192, Sum<U1024, U122>>>; // 0x647a=25722 = 16384+8192+1024+122,
    
}

/// Key Derivation Function Identifiers
/// <https://www.iana.org/assignments/hpke/hpke.xhtml>
pub mod kdf_id {
    use kems::generic_array::typenum::*;
    /// ID of HKDF (RFC 5869) using Sha256
    pub type HkdfSha256 = U1; // HKDF from RFC5869
    /// ID of HDKF (RFC 5869) using Sha384
    pub type HkdfSha384 = U2; 
    /// ID of HKDF (RFC 5869) using Sha512
    pub type HkdfSha512 = U3; 

    /// ID of Shake128 KDF from draft_ietf_hpke-pq-01/04
    pub type Shake128 = U16;
    /// ID of Shake256 KDF from draft_ietf_hpke_pq_01/04
    pub type Shake256 = U17; 
    /// ID of TurboShake128 from draft_ietf_hpke-pq-01/04
    pub type TurboShake128 = U18; 
    /// ID of TurboShake256 from draft_ietf_hpke-pq-01/04
    pub type TurboShake256 = U19; 
}

/// AEAD Identifiers defined in RFC 9180 and used as part of the key derivation function
/// <https://www.iana.org/assignments/hpke/hpke.xhtml>
pub mod aead_id {
    use kems::generic_array::typenum::*;
    /// AEAID ID for Aes128 GCM as defined in RFC 9180
    pub type Aes128Gcm = U1;
    /// AEAID ID for Aes256 GCM as defined in RFC 9180 
    pub type Aes256Gcm = U2; 
    /// AEAID ID defined in RFC 9180 for ChaCha20 with Poly 1305 (RFC8439)
    pub type ChaCha20Poly1305 = U3;
    /// AEAD ID defined in RFC 9180 for use without a symmetric encryption or decryption algorithm
    pub type ExportOnly = Diff<U65536,U1>;
}


/// Created during the key encapsulation process and used to 
/// implement AEAD encryption/decryption with a nonce which 
/// increments after each encryption.
pub struct HpkeCipherContext<A> 
where A: Aead + KeyInit,
    A::NonceSize: ArraySize
{
    cipher: A,
    pub base_nonce: Nonce<A>, //Array<u8, A::NonceSize>,
    sequence_number: u64,
}

impl<A> HpkeCipherContext<A>
where A: Aead + KeyInit,
    A::NonceSize: ArraySize,
{
    /// Create a new context from the shared secret, info and psk fields
    //fn new<K: HpkeKdf, KEMID: Unsigned, KDFID: Unsigned, AEADID: Unsigned> ( is_auth: bool, shared_secret: &[u8], info: &[u8], psk: Option<Psk> ) -> Self
    //fn new<K: HpkeKdf + Default> (kdf: &<K as HpkeKdf>::K, is_auth: bool, shared_secret: &[u8], info: &[u8], psk: Option<Psk> ) -> Result<Self,()>
    fn new<K: HpkeKdf> (kdf: &K, is_auth: bool, shared_secret: &[u8], info: &[u8], psk: Option<Psk> ) -> Result<Self,()>
    where A::NonceSize: Add<K::LE>,
        Sum<A::NonceSize, K::LE>: kems::ArraySize,
        A::KeySize: Add<<A::NonceSize as Add<K::LE>>::Output>,
        Sum<A::KeySize, Sum<A::NonceSize, K::LE>>: Sub<A::KeySize>,
        Sum<A::KeySize, Sum<A::NonceSize, K::LE>>: ArraySize,
        Diff<Sum<A::KeySize, Sum<A::NonceSize, K::LE>>, A::KeySize>: ArraySize,
        Diff<Sum<A::KeySize, Sum<A::NonceSize, K::LE>>, A::KeySize>: Sub<A::NonceSize, Output=K::LE>,
        Diff<Diff<Sum<A::KeySize, Sum<A::NonceSize, K::LE>>, A::KeySize>, A::NonceSize>: ArraySize,
        <K as HpkeKdf>::K: KdfLabelled,
    {
        //let (cipher_key, base_nonce, _) = K::derive::<A::KeySize, A::NonceSize, K::LE>(kdf, is_auth, shared_secret, info, psk)?;
        let (cipher_key, base_nonce, _) = kdf.derive::<A::KeySize, A::NonceSize, K::LE>(is_auth, shared_secret, info, psk)?;
        Ok(HpkeCipherContext{ cipher: A::new(&cipher_key), base_nonce, sequence_number: 0})
    }

    /// Get the current nonce and increment the counter
    fn get_and_inc_nonce ( &mut self ) -> Nonce<A>
    {
        let mut nonce = self.base_nonce.clone();
        let sn_as_bytes = self.sequence_number.to_be_bytes();
        nonce[A::NonceSize::USIZE-sn_as_bytes.len()..].iter_mut().zip(sn_as_bytes.iter()).for_each(|(x1, x2)| *x1 ^= *x2) ;
        self.sequence_number += 1;
        nonce
    }

    /// Encrypt a message using the AEAD cipher with the current nonce
    pub fn seal<'msg, 'aad> ( &mut self, pt: impl Into<Payload<'msg, 'aad>>) -> Result<Vec<u8>, Error> {
        let nonce = self.get_and_inc_nonce();
        Ok( self.cipher.encrypt (&nonce, pt)?)
    }

    /// decrypt a message using the AEAD cipher with the current nonce
    pub fn open<'msg, 'aad> ( &mut self, ct: impl Into<Payload<'msg, 'aad>>) -> Result<Vec<u8>, Error> {
        let nonce = self.get_and_inc_nonce();
        Ok( self.cipher.decrypt (&nonce, ct)?)
    }
    
}



///
/// Struct used to hold an exporter secret which is can be used to derive exporter values
/// 
//pub struct HpkeExportContext<K: HpkeKdf, IE2: Unsigned, KID2: Unsigned, A2: Unsigned> 
pub struct HpkeExportContext<K: HpkeKdf> 
{
    pub exporter_secret: Array::<u8, K::LE>,
    phantom: PhantomData<K>,
}

///
impl<K: HpkeKdf> HpkeExportContext<K> 
{
    /// Create a new HpkeExportContext from a shared secret, info and psk
    //fn new<LK: ArraySize, LN: ArraySize>(kdf: &<K as HpkeKdf>::K, is_auth: bool, shared_secret: &[u8], info: &[u8], psk: Option<Psk> ) -> Result<Self,()>
    fn new<LK: ArraySize, LN: ArraySize>(kdf: &K, is_auth: bool, shared_secret: &[u8], info: &[u8], psk: Option<Psk> ) -> Result<Self,()>
    where LN: Add<LK>,
        LN: Add<K::LE>,
        LK: Add<<LN as Add<K::LE>>::Output>, <LK as Add<<LN as Add<K::LE>>::Output>>::Output: Sub<LK>, 
        <<LK as Add<<LN as Add<K::LE>>::Output>>::Output as Sub<LK>>::Output: Sub<LN, Output=K::LE>,
        <LN as Add<K::LE>>::Output: kems::ArraySize,
        <LK as Add<<LN as Add<K::LE>>::Output>>::Output: kems::ArraySize,
        <<LK as Add<<LN as Add<K::LE>>::Output>>::Output as Sub<LK>>::Output: kems::ArraySize,
        <<<LK as Add<<LN as Add<K::LE>>::Output>>::Output as Sub<LK>>::Output as Sub<LN>>::Output: kems::ArraySize
    {
        //let (_, _, exporter_secret) = K::derive::<LK,LN,K::LE>(&kdf, is_auth, shared_secret, info, psk)?;
        let (_, _, exporter_secret) = kdf.derive::<LK,LN,K::LE>(is_auth, shared_secret, info, psk)?;
        Ok(HpkeExportContext{exporter_secret, phantom: PhantomData})
    }

    /// Derive an export value from the previously calculated export secret and the provided exporter_context
    pub fn export<'a : 'b,'b,L2: ArraySize>(&'a self, kdf: &K, exporter_context: &[u8] ) -> Result<Array<u8, L2>, ()>
    {
        K::derive_exported_value::<L2>(&kdf, &self.exporter_secret, exporter_context)
    }
}


///
/// Factory struct to create new encryptor and decryptors for Hpke
/// There are 6 generic parameters representing features from RFC 9180
/// - C is the capsulator type
/// - K is the key derivation function, currently only HKDF is supported, but with varying hash funcitons
/// - A: Authenticated Encryption with Authenticated Data algorithm to use
/// - GKDF: KDF to use for generation of keys/ciphertexts based upon seeds 
/// 
//pub struct HpkeIes <C, K, A: Aead + KeyInit, GKDF=PassThroughKdf > 
pub struct HpkeIes <C, K, A: Aead + KeyInit> 
{
    phantom: PhantomData<C>,
    phantom1: PhantomData<A>,
    phantom2: PhantomData<K>,
    //phantom3: PhantomData<GKDF>,
} 



impl <C, K, A> HpkeIes<C, K, A> 
where A: Aead + KeyInit,
    C: Capsulator,
    //GKDF: Kdf,
{
    /// Create a new decryptor using a passed in key decapsulator
    pub fn decryptor_from_decapsulator (decapsulator: C::Decapsulator) -> HpkeDecryptor<C, K, A, false>
    {
        HpkeDecryptor{ decapsulator, phantom1: PhantomData, phantom2: PhantomData }
    }

    /// Create a new decryptor using a passed in private key 
    pub fn decryptor_from_key ( private: <C::Decapsulator as FromKey>::Key) -> HpkeDecryptor<C, K, A, false>
    where C::Decapsulator: FromKey
    {
        Self::decryptor_from_decapsulator(C::Decapsulator::from_key(private))
    }

    /// Create a new decryptor from a byte representation of a key
    pub fn decryptor_from_bytes ( private_bytes: &GenericArray<u8, <C::Decapsulator as EncodedSizeUser2>::EncodedSize>) -> HpkeDecryptor<C, K, A, false>
    where <C as Capsulator>::Decapsulator: EncodedSizeUser2,
    {
        Self::decryptor_from_decapsulator(C::Decapsulator::from_bytes(private_bytes))
    }
    
    /// Create a new encryptor from a key encapsulator
    pub fn encryptor_from_encapsulator (encapsulator: C::Encapsulator) -> HpkeEncryptor<false,C, K, A>
    {
        HpkeEncryptor{ encapsulator, phantom1: PhantomData, phantom2: PhantomData }
    }

    /// Create a new encryptor from a public key
    pub fn encryptor_from_key (key: <C::Encapsulator as FromKey>::Key) -> HpkeEncryptor<false,C, K, A>
    where C::Encapsulator: FromKey
    {
        Self::encryptor_from_encapsulator(C::Encapsulator::from_key(key))
    }

    /// Create a new encryptor for a byte array representing a public key
    pub fn encryptor_from_bytes ( public_bytes: &GenericArray<u8, <C::Encapsulator as EncodedSizeUser2>::EncodedSize>) -> HpkeEncryptor<false, C, K, A, >
    where <C as Capsulator>::Encapsulator: EncodedSizeUser2,
    {
        Self::encryptor_from_encapsulator(C::Encapsulator::from_bytes(public_bytes))
    }
    
    /// Create a new authenticated encryptor from a key encapsulator    
    pub fn auth_encryptor_from_encapsulator (encapsulator: C::Encapsulator) -> HpkeEncryptor<true,C, K, A>
    {
        HpkeEncryptor{ encapsulator, phantom1: PhantomData, phantom2: PhantomData }
    }

    /// Create a new authenticated encryptor from a pair of keys
    pub fn auth_encryptor_from_keys (recipient_public: <C::Encapsulator as FromKeys>::PublicKey, 
                                sender_private: <C::Encapsulator as FromKeys>::PrivateKey) -> HpkeEncryptor<true,C, K, A >
    where C::Encapsulator: FromKeys
    {
        Self::auth_encryptor_from_encapsulator(C::Encapsulator::from_keys(recipient_public, sender_private))
    }

    /// Create a new authenticated decryptor from an existing key decapsulator
    pub fn auth_decryptor_from_decapsulator (decapsulator: C::Decapsulator) -> HpkeDecryptor<C, K, A, true>
    {
        HpkeDecryptor{ decapsulator, phantom1: PhantomData, phantom2: PhantomData }
    }
    
    /// Create a new authenticated decryptor from a pair of keys
    pub fn auth_decryptor_from_keys ( recipient_private: <C::Decapsulator as FromKeys>::PrivateKey,
                                    sender_public: <C::Decapsulator as FromKeys>::PublicKey) -> HpkeDecryptor<C, K, A, true >
    where C::Decapsulator: FromKeys
    {
        Self::auth_decryptor_from_decapsulator(C::Decapsulator::from_keys(sender_public, recipient_private))
    }

    
    /// Generate a new encryptor and decryptor using a random number generator
    pub fn generate ( rng: &mut impl CryptoRngCore )  -> ( HpkeEncryptor<false,C, K, A>, HpkeDecryptor<C, K, A>)
    where C: Capsulator
    {
        let (encapsulator, decapsulator) = C::generate(rng);
        (Self::encryptor_from_encapsulator(encapsulator), Self::decryptor_from_decapsulator(decapsulator))
    }

    // Derive a new encryptor and decryptor from a seed value
    pub fn derive_pair_from_seed ( seed: &[u8] ) -> Result<( HpkeEncryptor<false,C, K, A>, HpkeDecryptor<C, K, A>), ()>
    where C: GenerateCapsulatorFromSeed + KemId,
        //GKDF: Default
    {
        let Ok(seed_as_array) = Array::try_from(seed) else { return Err(())};
        let (encapsulator, decapsulator) = C::derive_from_seed(&seed_as_array);
        Ok((Self::encryptor_from_encapsulator(encapsulator), Self::decryptor_from_decapsulator(decapsulator)))
    }
}





///
/// Implementation of the HPKE decryption algorithm from RFC9180
/// The structure stores a key encapsulator which itself stores a private key used to decode an
/// encapsulated key and recover a shared secret. 
/// Two other types are present in the structure
/// K: A key derivation function used to derive keys and nonces used for performing the symmetric key encryption
/// A: An AEAD algorithm used to encrypt the main payload
/// 
pub struct HpkeDecryptor <C: Capsulator, K, A: Aead + KeyInit, const IS_AUTH: bool = false > 
{
    pub decapsulator: C::Decapsulator,
    phantom1: PhantomData<A>,
    phantom2: PhantomData<K>,
} 

impl <C, K, A, const IS_AUTH: bool> HpkeDecryptor <C, K, A, IS_AUTH >
where C: Capsulator + KemId,
    K: HpkeKdf + KdfId,
    A: Aead + KeyInit + AeadId,
    A::KeySize: Add<K::LE>,
    A::NonceSize: Add<K::LE>,
    A::KeySize: Add<<A::NonceSize as Add<K::LE>>::Output>,
    <A::KeySize as Add<<A::NonceSize as Add<K::LE>>::Output>>::Output: Sub<A::KeySize>,
    <<A::KeySize as Add<<A::NonceSize as Add<K::LE>>::Output>>::Output as Sub<A::KeySize>>::Output: Sub<A::NonceSize, Output=K::LE>,
    <A::KeySize as Add<<A::NonceSize as Add<K::LE>>::Output>>::Output: kems::ArraySize,
    <<A::KeySize as Add<<A::NonceSize as Add<K::LE>>::Output>>::Output as Sub<A::KeySize>>::Output: kems::ArraySize,
    <A::NonceSize as Add<K::LE>>::Output: kems::ArraySize,
    <<<A::KeySize as Add<<A::NonceSize as Add<K::LE>>::Output>>::Output as Sub<A::KeySize>>::Output as Sub<A::NonceSize>>::Output: kems::ArraySize,
    A::NonceSize: Add<A::KeySize>,
{
    /// 
    /// Function to receive an encapsulated key and recover the associated cipher struct
    /// 
    pub fn setup_receiver_cipher(
        &self, 
        ct: &Ciphertext<C>,
        info: &[u8],
        psk: Option<Psk>,
    ) -> Result<HpkeCipherContext<A>, Error>
    where <K as HpkeKdf>::K: KdfLabelled
    {
        let shared_secret = self.decapsulator.decapsulate(ct).map_err(|_|Error::KemError)?;
        let kdf = <K as HpkeKdf>::K::new_with_label::<LabelKdf::<C::KemType, K::KdfType, A::AeadType>>();
        HpkeCipherContext::new::<K>(&kdf.into(), IS_AUTH, shared_secret.as_slice(), info, psk).map_err(|_|Error::KemError)
    }

    /// 
    /// Function to receive an encapsulated key and recover the associated export secret
    /// 
    pub fn setup_receiver_export (
        &self, 
        encapsulated_key: &Ciphertext<C>,
        info: &[u8],
        psk: Option<Psk>
    ) -> Result<HpkeExportContext<K>, Error>
    where <K as HpkeKdf>::K: KdfLabelled
    {
        let shared_secret = self.decapsulator.decapsulate(encapsulated_key).map_err(|_|Error::KemError)?;
        let kdf = <K as HpkeKdf>::K::new_with_label::<LabelKdf::<C::KemType, K::KdfType, A::AeadType>>();
        HpkeExportContext::new::<A::KeySize, A::NonceSize>( &kdf.into(), IS_AUTH,shared_secret.as_slice(), info, psk).map_err(|_|Error::KemError)
    }
    
    ///
    /// Function to open (decrypt) a hpke encrypted ciphertext
    /// 
    pub fn single_shot_open<'msg, 'aad>  (
        &self, 
        encapped_key: &Ciphertext<C>,
        info: &[u8],
        ct: impl Into<Payload<'msg, 'aad>>,
        psk: Option<Psk>,
    ) -> Result<Vec<u8>, Error>
    where <K as HpkeKdf>::K: KdfLabelled
    {
        let mut context = self.setup_receiver_cipher(encapped_key, info, psk).map_err(|_|Error::KemError)?;
        context.open(ct)
    }

    /// 
    /// Function to decapsulate a received message and calculate the shared export secret
    /// 
    pub fn single_shot_recv_export<L: ArraySize>  (
        &self, 
        encapped_key: &Ciphertext<C>,
        info: &[u8],
        exporter_context: &[u8],
        psk: Option<Psk>,
    ) -> Result<Array<u8,L>, Error>
    where <K as HpkeKdf>::K: KdfLabelled
    {
        let context = self.setup_receiver_export(encapped_key, info, psk)?;
        let kdf = <K as HpkeKdf>::K::new_with_label::<LabelKdf::<C::KemType, K::KdfType, A::AeadType>>();
        context.export::<L>(&kdf.into(), exporter_context).map_err(|_|Error::KemError)
    }
}



///
/// Implementation of the encryption algorithm from HPKE, RFC9180
/// The structure stores a key encapsulator which itself stores a public key
/// Two other types are present in the structure
/// K: A kdf used to derive keys and nonces used for performing the symmetric key encryption
/// A: An AEAD algorithm used to encrypt the main payload
/// 
pub struct HpkeEncryptor <const IS_AUTH: bool, C: Capsulator, K, A: Aead + KeyInit> 
{
    pub encapsulator: C::Encapsulator,
    phantom1: PhantomData<A>,
    phantom2: PhantomData<K>,
} 

impl <const IS_AUTH: bool, C: Capsulator + KemId, K, A >  HpkeEncryptor <IS_AUTH, C, K, A >
where A: Aead + KeyInit + AeadId,
    K: HpkeKdf + KdfId,
    A: Aead + KeyInit + AeadId,
    A::KeySize: Add<K::LE>,
    A::NonceSize: Add<K::LE>,
    A::KeySize: Add<<A::NonceSize as Add<K::LE>>::Output>,
    <A::KeySize as Add<<A::NonceSize as Add<K::LE>>::Output>>::Output: Sub<A::KeySize>,
    <<A::KeySize as Add<<A::NonceSize as Add<K::LE>>::Output>>::Output as Sub<A::KeySize>>::Output: Sub<A::NonceSize, Output=K::LE>,
    <A::KeySize as Add<<A::NonceSize as Add<K::LE>>::Output>>::Output: kems::ArraySize,
    <<A::KeySize as Add<<A::NonceSize as Add<K::LE>>::Output>>::Output as Sub<A::KeySize>>::Output: kems::ArraySize,
    <A::NonceSize as Add<K::LE>>::Output: kems::ArraySize,
    <<<A::KeySize as Add<<A::NonceSize as Add<K::LE>>::Output>>::Output as Sub<A::KeySize>>::Output as Sub<A::NonceSize>>::Output: kems::ArraySize,
    A::NonceSize: Add<A::KeySize>,
{
    ///
    /// Perform the first part of the HPKE protocol, which generates a random ephemeral key
    /// and uses the encapsulator to create a shared secret key
    /// 
    pub fn setup_sender_cipher <R: CryptoRngCore> (
        &self,
        csprng: &mut R,
        info: &[u8],
        psk: Option<Psk>, 
    ) -> Result<(Ciphertext<C>, HpkeCipherContext<A>), Error> 
    where <K as HpkeKdf>::K: KdfLabelled
    {
        let (encapped_key, shared_secret) = self.encapsulator.encapsulate(csprng).map_err(|_|Error::KemError)?;
        let kdf = <K as HpkeKdf>::K::new_with_label::<LabelKdf::<C::KemType, K::KdfType, A::AeadType>>();
        Ok((encapped_key, HpkeCipherContext::new::<K>(&kdf.into(), IS_AUTH, &shared_secret, info, psk).map_err(|_|Error::KdfError)?))
    }


    ///
    /// Perform the first part of the HPKE protocol, which generates a random ephemeral key
    /// and uses the encapsulator to create a shared secret key
    /// 
    pub fn setup_sender_cipher_deterministic (
        &self,
        randomness: &[u8],
        info: &[u8],
        psk: Option<Psk>, 
    ) -> Result<(Ciphertext<C>, HpkeCipherContext<A>), Error> 
    where C::Encapsulator: EncapsulateDeterministic2<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>>,
        <K as HpkeKdf>::K: KdfLabelled
    {
        let (encapped_key, shared_secret) = self.encapsulator.encapsulate_deterministic(randomness).map_err(|_|Error::KemError)?;
        let kdf = <K as HpkeKdf>::K::new_with_label::<LabelKdf::<C::KemType, K::KdfType, A::AeadType>>();
        Ok((encapped_key, HpkeCipherContext::new::<K>(&kdf.into(), IS_AUTH, &shared_secret, info, psk).map_err(|_|Error::KdfError)?))
    }

    ///
    /// Implements the first part of HPKE which uses a key encapsulation kem and kdf to create an encapsulated
    /// key and derived shared key
    /// 
    pub fn setup_sender_export <R: CryptoRngCore> (
        &self,
        csprng: &mut R,
        info: &[u8],
        psk: Option<Psk>,
    ) -> Result<(Ciphertext<C>, HpkeExportContext<K>), Error> 
    where <K as HpkeKdf>::K: KdfLabelled
    {
        let (encapped_key, shared_secret ) = self.encapsulator.encapsulate(csprng).map_err(|_|Error::KemError)?;
        let kdf = <K as HpkeKdf>::K::new_with_label::<LabelKdf::<C::KemType, K::KdfType, A::AeadType>>();
        Ok((encapped_key, HpkeExportContext::new::<A::KeySize, A::NonceSize>(&kdf.into(), IS_AUTH, &shared_secret, info, psk).map_err(|_|Error::KdfError)?))
    }

    ///
    /// Function to encrypt (seal) a plaintext (pt) using a recipient public key
    /// 
    //pub fn single_shot_seal <'msg, 'aad, R: CryptoRng + RngCore> (
    pub fn single_shot_seal <'msg, 'aad, R: CryptoRngCore> (
        &self,
        csprng: &mut R,
        pt: impl Into<Payload<'msg, 'aad>>,
        info: &[u8],
        psk: Option<Psk>,
    ) -> Result<(Ciphertext<C>, Vec<u8>), Error> 
    where <K as HpkeKdf>::K: KdfLabelled
    {
        let (encapped_key,mut cipher_context) = self.setup_sender_cipher ( csprng, info, psk).map_err(|_|Error::KemError)?;
        Ok((encapped_key, cipher_context.seal(pt)?))
    }

    /// 
    /// Function to create an encapsulated key and associated shared export secret
    /// 
    pub fn single_shot_sender_export<'a, R: CryptoRngCore, L:ArraySize> (
        &self,
        csprng: &mut R,
        export_context: &[u8],
        info: &[u8],
        psk: Option<Psk>,
    ) -> Result<(Ciphertext<C>, Array<u8,L>), Error> 
    where <K as HpkeKdf>::K: KdfLabelled
    {
        let (encapped_key, context) = self.setup_sender_export(csprng, info, psk)?;
        let kdf = <K as HpkeKdf>::K::new_with_label::<LabelKdf::<C::KemType, K::KdfType, A::AeadType>>();
        Ok((encapped_key, context.export::<L>(&kdf.into(), export_context).map_err(|_|Error::KdfError)?))
    }
}



///
/// Implementation of the elliptic curve deterministic key generation function specified in HPKE, RFC9180
/// 
pub struct HpkeEcKeyGen<H,L> (PhantomData<H>, PhantomData<L>);
//impl<H, L, C> DeriveKeyPairFromSeed<SecretKey<C>> for HpkeEcKeyGen<H,L>
impl<H, KemId, C> DeriveKeyPairFromSeed<SecretKey<C>> for HpkeEcKeyGen<H,KemId>
where 
    H: KeyInit + Clone + FixedOutputReset + Mac,
    KemId: Unsigned,
    C: Curve + CurveArithmetic,
    C::FieldBytesSize: ArraySize
{
    type SeedSize = C::FieldBytesSize;
    type PublicKey = PublicKey<C>;
    type Error = ();

    fn derive_keypair_from_seed( ikm: &[u8]) -> Result<(SecretKey<C>, PublicKey<C>), Self::Error> {
      
        if ikm.len() != Self::SeedSize::USIZE { return Err(())}
        let dkp_prk: Array<u8, H::OutputSize> = LabelledExtract::<Ktf1<H>, LabelHpkeV1, LabelKem<KemId>, LabelKeyGenExtract>::derive_secret_other(ikm, &[]).map_err(|_|())?;
        let bitmask = C::ORDER.encode_field_bytes()[0];
                    
        for counter in 0u8..255 {
            if let Ok(mut bytes) = LabelledExpand::<Kpf1<H, u8>, LabelHpkeV1, LabelKem<KemId>, LabelKeyGenCandidate>::derive_secret_other(&dkp_prk, counter.to_be_bytes().as_ref())
            {
                bytes[0] = bytes[0] & bitmask;

                if let Some(sk) = Option::<NonZeroScalar::<C>>::from(NonZeroScalar::<C>::from_repr(bytes)) {
                    return Ok((SecretKey::from(sk), PublicKey::from_secret_scalar(&sk)))
                }
            }
        }
        Err(())
    }
}



///
/// Implementation of the elliptic curve deterministic key generation function specified in HPKE, RFC9180
/// 
pub struct HpkeEcKeyGen2<K> (PhantomData<K>);
//impl<H, L, C> DeriveKeyPairFromSeed<SecretKey<C>> for HpkeEcKeyGen<H,L>
impl<K, C> DeriveKeyPairFromSeed<SecretKey<C>> for HpkeEcKeyGen2<K>
where 
    K: TwoStepKdf, //H: KeyInit + Clone + FixedOutputReset + Mac,
    K::Extract: KdfLabelled + KdfFixed,
    K::Expand: KdfLabelled,
    C: Curve + CurveArithmetic,
    C::FieldBytesSize: ArraySize
{
    type SeedSize = C::FieldBytesSize;
    type PublicKey = PublicKey<C>;
    type Error = ();

    fn derive_keypair_from_seed( ikm: &[u8]) -> Result<(SecretKey<C>, PublicKey<C>), Self::Error> {
      
        if ikm.len() != Self::SeedSize::USIZE { return Err(())}
        //let dkp_prk: Array<u8, H::OutputSize> = LabelledExtract::<Ktf1<H>, LabelHpkeV1, LabelKem<KemId>, LabelKeyGenExtract>::derive_secret_other(ikm, &[]);
        //let extract_kdf = K::Extract::default(); //new_with_label::<LabelKeyGenExtract>();
        let dkp_prk: Array<u8, <K::Extract as KdfFixed>::OutputSize> = K::Extract::derive_secret_other(ikm, &[]).map_err(|_|())?;
        let bitmask = C::ORDER.encode_field_bytes()[0];

        let expand_kdf = K::Expand::default(); //new_with_label::<LabelKeyGenCandidate>();
        for counter in 0u8..255 {
            //let mut bytes = LabelledExpand::<Kpf1<H, u8>, LabelHpkeV1, LabelKem<KemId>, LabelKeyGenCandidate>::derive_secret_other(&dkp_prk, counter.to_be_bytes().as_ref());
            if let Ok(mut bytes) = expand_kdf.derive_self_secret_other(&dkp_prk, counter.to_be_bytes().as_ref())
            {
                bytes[0] = bytes[0] & bitmask;

                if let Some(sk) = Option::<NonZeroScalar::<C>>::from(NonZeroScalar::<C>::from_repr(bytes)) {
                    return Ok((SecretKey::from(sk), PublicKey::from_secret_scalar(&sk)))
                }
            }
        }
        Err(())
    }
}




//
// Implementation of the elliptic curve deterministic key generation function specified in HPKE, RFC9180
// 
// #[cfg(feature = "rustcrypto-x25519")] 
// pub struct HpkeX25519KeyGen<K2,L> (PhantomData<K2>, PhantomData<L>);
// #[cfg(feature = "rustcrypto-x25519")] 
// impl<K2,L> DeriveKeyPairFromSeed<x25519_dalek::StaticSecret> for HpkeX25519KeyGen<K2,L>
// where K2: TwoStepKdf, // + LabeledTwoStepKdf,
//     L: Label
// {
//     type SeedSize = U32;
//     type PublicKey = x25519_dalek::PublicKey;
//     type Error = ();
//     //fn derive_keypair_from_seed( ikm: &Array::<u8, Self::SeedSize>) -> (x25519_dalek::StaticSecret, x25519_dalek::PublicKey) {
//     fn derive_keypair_from_seed( ikm: &[u8]) -> Result<(x25519_dalek::StaticSecret, x25519_dalek::PublicKey), Self::Error> {
//         use hmac::HmacReset;
//         use kdfs::iso11770_6::Tkdf;
//         use sha2::Sha256;

//         use crate::{hpke_kdf::{LabelKem, LabelKeyGenExpand, LabelKeyGenExtract, LabelledExpand, LabelledExtract}};

//         if ikm.len() != Self::SeedSize::USIZE { return Err(())};
//         // let ik: Array<u8, U32> = LabelledExtract::<Ktf1<HmacReset<Sha256>>, LabelHpkeV1, LabelKem<kem_id::DhKemX25519HkdfSha256>, LabelKeyGenExtract>::derive_secret_other(ikm, &[]);
//         // let bytes: Array<u8, U32> = LabelledExpand::<Kpf1<HmacReset<Sha256>,u8>, LabelHpkeV1, LabelKem<kem_id::DhKemX25519HkdfSha256>, LabelKeyGenExpand>::derive_secret_other(&ik, &[]);
//         // SeedAsScalar::derive_keypair_from_seed(&bytes)

//         let kdf = Tkdf::<LabelledExtract::<Ktf1<HmacReset<Sha256>>, LabelHpkeV1, LabelKem<kem_id::DhKemX25519HkdfSha256>, LabelKeyGenExtract>,
//                                   LabelledExpand::<Kpf1<HmacReset<Sha256>,u8>, LabelHpkeV1, LabelKem<kem_id::DhKemX25519HkdfSha256>, LabelKeyGenExpand>>::default();
                        
//         let whitened_seed = kdf.derive_self_secret_other::<U32>(ikm,&[]);
//         SeedAsScalar::derive_keypair_from_seed(&whitened_seed)

//     }
// }

//
// Implementation of the elliptic curve deterministic key generation function specified in HPKE, RFC9180
// 
// #[cfg(feature = "rustcrypto-x448")] 
// pub struct HpkeX448KeyGen<K2,L> (PhantomData<K2>, PhantomData<L>);
// #[cfg(feature = "rustcrypto-x448")] 
// impl<K2,L> DeriveKeyPairFromSeed<x448::StaticSecret> for HpkeX448KeyGen<K2,L>
// where K2: TwoStepKdf, // + LabeledTwoStepKdf,
//     L: Label
// {
//     type SeedSize = U56;
//     type PublicKey = x448::PublicKey;
//     type Error = ();
//     //fn derive_keypair_from_seed( ikm: &Array::<u8, Self::SeedSize>) -> (x448::StaticSecret, x448::PublicKey) {
//     fn derive_keypair_from_seed( ikm: &[u8]) -> Result<(x448::StaticSecret, x448::PublicKey), Self::Error> {
//         use aead::consts::U64;
//         use hmac::HmacReset;
//         use sha2::Sha512;

//         use crate::hpke_kdf::{LabelKem, LabelKeyGenExpand, LabelKeyGenExtract, LabelledExpand, LabelledExtract};

//         if ikm.len() != Self::SeedSize::USIZE { return Err(())}
        
//         let ik: Array<u8, U64> = LabelledExtract::<Ktf1<HmacReset<Sha512>>, LabelHpkeV1, LabelKem<kem_id::DhKemX448HkdfSha512>, LabelKeyGenExtract>::derive_secret_other(ikm, &[]);
//         let bytes: Array<u8, U56> = LabelledExpand::<Kpf1<HmacReset<Sha512>,u8>, LabelHpkeV1, LabelKem<kem_id::DhKemX448HkdfSha512>, LabelKeyGenExpand>::derive_secret_other(&ik, &[]);

//         SeedAsScalar::derive_keypair_from_seed(&bytes)
//     }
// }



// pub struct HpkeEcKeyGen2<K2> (PhantomData<K2>);
// impl<K2, C> DerivePairFromSeed<SecretKey<C>, PublicKey<C>> for HpkeEcKeyGen2<K2>
// where K2: LabeledTwoStepKdf,
//     //IE2: Unsigned,
//     C: Curve + CurveArithmetic,
//     <C as Curve>::FieldBytesSize: ArraySize
// {
//     type SeedSize = typenum::U96; //C::FieldBytesSize;
//     fn derive_keypair_from_seed( ikm: &Array::<u8, Self::SeedSize>) -> (SecretKey<C>, PublicKey<C>) {
      
//         //let suite_id = [b'K', b'E', b'M', (IE2::U16 >> 8) as u8, (IE2::U16 &0xFF) as u8];
//         //let dkp_prk = labeled_extract2::<K2>(ikm, &suite_id, b"dkp_prk", &[] );
//         let dkp_prk = K2::labeled_extract([ikm.as_slice()], b"dkp_prk", &[] );
//         let bitmask = C::ORDER.encode_field_bytes()[0];
                    
//         for counter in 0u8..255 {
//             //let mut bytes = labeled_expand_fixed::<K2,C::FieldBytesSize>(dkp_prk.as_ref(), &suite_id, b"candidate", [counter.to_be_bytes().as_ref()]);
//             let mut bytes = K2::labeled_expand_fixed::<C::FieldBytesSize>(dkp_prk.as_ref(), b"candidate", [counter.to_be_bytes().as_ref()]);

//             bytes[0] = bytes[0] & bitmask;

//             if let Some(sk) = Option::<NonZeroScalar::<C>>::from(NonZeroScalar::<C>::from_repr(GenericArray::from_slice(&bytes).clone())) {
//                 return (SecretKey::from(sk), PublicKey::from_secret_scalar(&sk));
//             }
//         }
//         panic! ( "Exhausted counter without finding a suitable key");
//     }
// }


// pub struct HpkeEcKeyGen2<K2,IE2> (PhantomData<K2>, PhantomData<IE2>);
// impl<K2, IE2,C> DerivePairFromSeed<SecretKey<C>, PublicKey<C>> for HpkeEcKeyGen2<K2,IE2>
// where K2: TwoStepKdf,
//     IE2: Unsigned,
//     C: Curve + CurveArithmetic,
//     <C as Curve>::FieldBytesSize: ArraySize
// {
//     type SeedSize = typenum::U96; //C::FieldBytesSize;
//     fn derive_keypair_from_seed( ikm: &Array::<u8, Self::SeedSize>) -> (SecretKey<C>, PublicKey<C>) {
      
//         let suite_id = [b'K', b'E', b'M', (IE2::U16 >> 8) as u8, (IE2::U16 &0xFF) as u8];
//         let dkp_prk = labeled_extract2::<K2>(ikm, &suite_id, b"dkp_prk", &[] );

//         let dkp_prk = 
//         let bitmask = C::ORDER.encode_field_bytes()[0];
                    
//         for counter in 0u8..255 {
//             let mut bytes = labeled_expand_fixed::<K2,C::FieldBytesSize>(dkp_prk.as_ref(), &suite_id, b"candidate", [counter.to_be_bytes().as_ref()]);

//             bytes[0] = bytes[0] & bitmask;

//             if let Some(sk) = Option::<NonZeroScalar::<C>>::from(NonZeroScalar::<C>::from_repr(GenericArray::from_slice(&bytes).clone())) {
//                 return (SecretKey::from(sk), PublicKey::from_secret_scalar(&sk));
//             }
//         }
//         panic! ( "Exhausted counter without finding a suitable key");
//     }
// }








// pub struct HpkeIesAuthDecryptor <C, const KEM_ID: u16, K, const KDF_ID: u16, A: Aead + KeyInit, const AEAD_ID: u16 > 
// {
//     capsulator: C,
//     phantom1: PhantomData<A>,
//     phantom2: PhantomData<K>,
// } 
// impl <C: Capsulator, const KEM_ID: u16, K, const KDF_ID: u16, A, const AEAD_ID: u16>  HpkeIesAuthDecryptor <C, KEM_ID, K, KDF_ID, A, AEAD_ID >
// where A: Aead + KeyInit,
//     K: TwoStepKdf,
// {
//     ///
//     /// Decapsulate an encapped_key and derive the Cipher context which can be used to
//     /// decrypt one or more messages. This is the authenticated version which requires
//     /// the public key of the sender to be able to derive the correct key material
//     /// 
//     pub fn setup_receive_cipher<EK: EncappedKey> (
//         &self, 
//         //encapped_key: &EK,
//         encapped_key: &GenericArray<u8, C::CiphertextSize>,
//         info: &[u8],
//         //sender_pubkey: &EK::SenderPublicKey,
//         psk: Option<Psk>,
//     ) -> Result<HpkeCipherContext<A>, Error>
//     where C: AuthDecapsulator<EK>
//     {
//         //let shared_secret = self.capsulator.try_auth_decap(encapped_key, sender_pubkey).unwrap();
//         let shared_secret = self.capsulator.decapsulate(encapped_key).unwrap();
//         return Ok(HpkeCipherContext::new::<K, KEM_ID, KDF_ID, AEAD_ID>(true, shared_secret.as_bytes(), info, psk));
//     }


//     ///
//     /// Decapsulate an encapped_key and derive the export secret 
//     /// This is the authenticated version which requires
//     /// the public key of the sender to be able to derive the correct key material
//     /// 
//     pub fn setup_auth_receive_export<EK: EncappedKey>(
//         &self, 
//         encapped_key: &EK,
//         info: &[u8],
//         sender_pubkey: &EK::SenderPublicKey,
//         psk: Option<Psk>,
        
//     ) -> Result<HpkeExportContext::<K>, Error>
//     where C: AuthDecapsulator<EK>
//     {
//         let shared_secret = self.capsulator.try_auth_decap(encapped_key, sender_pubkey)?;
//         return Ok(HpkeExportContext::new::<KEM_ID, KDF_ID, AEAD_ID> (true, shared_secret.as_bytes(), info, psk));
//     }

//     ///
//     /// Open (decrypt) a hpke message
//     /// 
//     pub fn single_shot_open<'msg, 'aad, EK: EncappedKey>  (
//         &self, 
//         //encapped_key: &EK,
//         encapped_key: &GenericArray<u8, C::CiphertextSize>,
//         info: &[u8],
//         ct: impl Into<Payload<'msg, 'aad>>,
//         sender_key: &EK::SenderPublicKey,
//         psk: Option<Psk>,
//     ) -> Result<Vec<u8>, Error>
//     where C: AuthDecapsulator<EK> {
//         let mut cipher_context = self.setup_receive_cipher ( encapped_key, info, sender_key, psk)?;
//         return cipher_context.open(ct);
//     }

//     /// 
//     /// Derive an export secret from the encapped key and senders public key
//     ///
//     pub fn single_shot_receive_auth_export<EK: EncappedKey, L:ArrayLength<u8>>(
//         &self, 
//         encapped_key: &EK,
//         info: &[u8],
//         sender_pubkey: &EK::SenderPublicKey,
//         export_context: &[u8],
//         psk: Option<Psk>,
//     ) -> Result<GenericArray<u8,L>, Error> 
//     where C: AuthDecapsulator<EK>
//     {
//         let context = self.setup_auth_receive_export(encapped_key, info, sender_pubkey, psk)?;
//         return Ok(context.export(export_context));
//     }
// }

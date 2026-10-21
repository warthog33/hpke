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
//! let recipient_secret_key = StaticSecret::random();
//! let recipient_public_key = PublicKey::from(&recipient_secret_key);
//! let plaintext = b"Hello World!";
//! let aad = b"Some other data";
//! let info = b"Info";
//! 
//! let encryptor = HpkeIesX25519Sha256Aes128Gcm::encryptor_from_key(recipient_public_key);
//! let (c0_send, ct_send) = encryptor.single_shot_seal(&mut OsRng, Payload{msg: plaintext.as_ref(), aad: aad.as_ref()}, info, None).unwrap();
//! 
//! let decryptor = HpkeIesX25519Sha256Aes128Gcm::decryptor_from_key(recipient_secret_key);
//! let plaintext_receive = decryptor.single_shot_open(&c0_send, info, Payload{msg: ct_send.as_ref(), aad: aad.as_ref()}, None).unwrap();
//! assert! ( plaintext_receive == plaintext );
//! ```

use std::marker::PhantomData;

use crate::hpke_kdf::{Export, HpkeKdfExporter, LabelKdf};

use aead::{Aead, KeyInit, KeySizeUser, Nonce, Payload};
use digest::InvalidLength;
use digest::typenum::Unsigned;

use hpke_kdf::{HpkeKdf, Psk}; 
use kdfs::{Kdf, Label};
use kdfs::hybrid_array::{Array, ArraySize};
use kem::{Decapsulator, FromSeed, InvalidKey, TryKeyInit, Kem, Encapsulate, TryDecapsulate, Ciphertext};
use kems::{CryptoRngCore, EncapsulateDeterministic, FromKey, FromKeys};

pub mod hpke_types;
pub mod hpke_kdf;
pub mod hpke_kem_wrapper;

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

/// Defines an associated type which represents the ID of the KEM
/// HPKE functions retrieve the KemType and use it as part of the key derivation process
pub trait KemParams {
    type KemId: Unsigned;
    type OutputSize: ArraySize;
    const IS_AUTH: bool;
    type KeyGenFromSeed: Default;
    type EncapsulateFromSeed: Default;
    type Combiner: Default + Kdf<Self::OutputSize>;
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
    use digest::typenum::{Diff, Sum, consts::*};
    
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
    use kem::consts::*;

    /// ID of HKDF (RFC 5869) using Sha256
    pub type HkdfSha256 = U1; // HKDF from RFC5869
    /// ID of HDKF (RFC 5869) using Sha384
    pub type HkdfSha384 = U2; 
    /// ID of HKDF (RFC 5869) using Sha512
    pub type HkdfSha512 = U3; 

    /// ID of Shake128 KDF from draft_ietf_hpke-pq-01/04
    pub type KdfShake128 = U16;
    /// ID of Shake256 KDF from draft_ietf_hpke_pq_01/04
    pub type KdfShake256 = U17; 
    /// ID of TurboShake128 from draft_ietf_hpke-pq-01/04
    pub type KdfTurboShake128 = U18; 
    /// ID of TurboShake256 from draft_ietf_hpke-pq-01/04
    pub type KdfTurboShake256 = U19; 
}

/// AEAD Identifiers defined in RFC 9180 and used as part of the key derivation function
/// <https://www.iana.org/assignments/hpke/hpke.xhtml>
pub mod aead_id {
    use digest::typenum::{Diff, consts::*};
    
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
    fn new<K: HpkeKdf<A::KeySize, A::NonceSize>, L: Label> (is_auth: bool, shared_secret: &[u8], info: &[u8], psk: Option<Psk> ) -> Self
    {
        let (cipher_key, base_nonce, _) = K::derive::<L>(is_auth, shared_secret, info, psk);
        HpkeCipherContext{ cipher: A::new(&cipher_key), base_nonce, sequence_number: 0}
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
pub struct HpkeExportContext<K: HpkeKdf<LK, LN>, LK: ArraySize, LN: ArraySize> 
{
    pub exporter_secret: Array::<u8, K::KeySize>,
    label: &'static[u8],
    phantom1: PhantomData<LK>,
    phantom2: PhantomData<LN>
}

///
impl<K: HpkeKdf<LK, LN>, LK: ArraySize, LN: ArraySize> HpkeExportContext<K,LK,LN> 
{
    /// Create a new HpkeExportContext from a shared secret, info and psk
    fn new<LB: Label>(is_auth: bool, shared_secret: &[u8], info: &[u8], psk: Option<Psk> ) -> Self
    {
        let (_, _, exporter_secret) = K::derive::<LB>(is_auth, shared_secret, info, psk);
        HpkeExportContext{exporter_secret, label: LB::LABEL, phantom1: PhantomData, phantom2: PhantomData}
    }
}
impl<K: HpkeKdf<LK, LN>, LK: ArraySize, LN: ArraySize, L: ArraySize> Export<L> for HpkeExportContext<K,LK,LN> 
where K: HpkeKdfExporter<L>,
{
    /// Derive an export value from the previously calculated export secret and the provided exporter_context
    fn export(&self, exporter_context: &[u8] ) -> Array<u8, L>
    {
        K::derive_exported_value(&self.exporter_secret, exporter_context, self.label)
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
pub struct HpkeIes <C, K, A> 
{
    phantom: PhantomData<C>,
    phantom1: PhantomData<A>,
    phantom2: PhantomData<K>,
} 

pub trait HpkeIesTypes {
    type Decryptor;
    type Encryptor;
}
impl <C, K, A> HpkeIesTypes for HpkeIes<C, K, A> 
where A: Aead + KeyInit,
    C: Kem,
{
    type Decryptor = HpkeDecryptor<C,K,A>;
    type Encryptor = HpkeEncryptor<C,K,A>;
}

impl <C, K, A> HpkeIes<C, K, A> 
where A: Aead + KeyInit,
    C: Kem,
{
    /// Create a new decryptor using a passed in key decapsulator
    pub fn decryptor_from_decapsulator (decapsulator: C::DecapsulationKey) -> HpkeDecryptor<C, K, A>
    {
        HpkeDecryptor{ decapsulator, phantom1: PhantomData, phantom2: PhantomData }
    }

    /// Create a new decryptor using a passed in private key 
    pub fn decryptor_from_key ( private: <C::DecapsulationKey as FromKey>::Key) -> HpkeDecryptor<C, K, A>
    where C::DecapsulationKey: FromKey
    {
        Self::decryptor_from_decapsulator(C::DecapsulationKey::from_key(private))
    }

    /// Create a new decryptor from a byte representation of a key
    pub fn decryptor_from_bytes ( private_bytes: &Array<u8, <C::DecapsulationKey as KeySizeUser>::KeySize>) -> HpkeDecryptor<C, K, A>
    where C::DecapsulationKey: KeyInit,
    {
        Self::decryptor_from_decapsulator(C::DecapsulationKey::new(private_bytes))
    }

    /// Create a new decryptor from a byte representation of a key
    pub fn try_decryptor_from_slice ( private_bytes: &[u8]) -> Result<HpkeDecryptor<C, K, A>, InvalidKey>
    where C::DecapsulationKey: TryKeyInit,
    {
        Ok(Self::decryptor_from_decapsulator(C::DecapsulationKey::new_from_slice(private_bytes)?))
    }

    /// Create a new decryptor from a byte representation of a key
    pub fn decryptor_from_slice ( private_bytes: &[u8]) -> Result<HpkeDecryptor<C, K, A>, InvalidLength>
    where C::DecapsulationKey: KeyInit,
    {
        Ok(Self::decryptor_from_decapsulator(C::DecapsulationKey::new_from_slice(private_bytes)?))
    }

    /// Create a new encryptor from a key encapsulator
    pub fn encryptor_from_encapsulator (encapsulator: C::EncapsulationKey) -> HpkeEncryptor<C, K, A>
    {
        HpkeEncryptor{ encapsulator, phantom1: PhantomData, phantom2: PhantomData }
    }

    /// Create a new encryptor from a public key
    pub fn encryptor_from_key (key: <C::EncapsulationKey as FromKey>::Key) -> HpkeEncryptor<C, K, A>
    where C::EncapsulationKey: FromKey
    {
        Self::encryptor_from_encapsulator(C::EncapsulationKey::from_key(key))
    }

    /// Create a new encryptor for a byte array representing a public key
    pub fn try_encryptor_from_bytes ( public_bytes: &Array<u8, <C::EncapsulationKey as KeySizeUser>::KeySize>) -> Result<HpkeEncryptor<C, K, A>, InvalidKey>
    where <C as Kem>::EncapsulationKey: TryKeyInit,
    {
        let encapsulator = <C::EncapsulationKey as TryKeyInit>::new(public_bytes)?;
        Ok(Self::encryptor_from_encapsulator(encapsulator))

    }

    pub fn encryptor_from_slice ( public_bytes: &[u8]) -> HpkeEncryptor<C, K, A, >
    where <C as Kem>::EncapsulationKey: for<'a> TryFrom<&'a [u8]>,
    {
        let Ok(encapsulator) = C::EncapsulationKey::try_from(public_bytes) else { panic! ( "UNhandled")};
        Self::encryptor_from_encapsulator(encapsulator)
    }

    /// Create a new authenticated encryptor from a key encapsulator    
    pub fn auth_encryptor_from_encapsulator (encapsulator: C::EncapsulationKey) -> HpkeEncryptor<C, K, A>
    {
        HpkeEncryptor{ encapsulator, phantom1: PhantomData, phantom2: PhantomData }
    }

    /// Create a new authenticated encryptor from a pair of keys
    pub fn auth_encryptor_from_keys (recipient_public: <C::EncapsulationKey as FromKeys>::PublicKey, 
                                sender_private: <C::EncapsulationKey as FromKeys>::PrivateKey) -> HpkeEncryptor<C, K, A >
    where C::EncapsulationKey: FromKeys
    {
        Self::auth_encryptor_from_encapsulator(C::EncapsulationKey::from_keys(recipient_public, sender_private))
    }

    /// Create a new authenticated decryptor from an existing key decapsulator
    pub fn auth_decryptor_from_decapsulator (decapsulator: C::DecapsulationKey) -> HpkeDecryptor<C, K, A>
    {
        HpkeDecryptor{ decapsulator, phantom1: PhantomData, phantom2: PhantomData }
    }
    
    /// Create a new authenticated decryptor from a pair of keys
    pub fn auth_decryptor_from_keys ( recipient_private: <C::DecapsulationKey as FromKeys>::PrivateKey,
                                    sender_public: <C::DecapsulationKey as FromKeys>::PublicKey) -> HpkeDecryptor<C, K, A >
    where C::DecapsulationKey: FromKeys
    {
        Self::auth_decryptor_from_decapsulator(C::DecapsulationKey::from_keys(sender_public, recipient_private))
    }

    
    /// Generate a new encryptor and decryptor using a random number generator
    pub fn generate ()  -> ( HpkeEncryptor<C, K, A>, HpkeDecryptor<C, K, A>)
    where C: Kem
    {
        let (decapsulator, encapsulator) = C::generate_keypair();
        (Self::encryptor_from_encapsulator(encapsulator), Self::decryptor_from_decapsulator(decapsulator))
    }

    // Derive a new encryptor and decryptor from a seed value
    pub fn derive_pair_from_seed ( seed: &[u8] ) -> Result<( HpkeEncryptor<C, K, A>, HpkeDecryptor<C, K, A>), ()>
    where C: Kem + FromSeed,
    {
        //let Ok(seed_as_array) = Array::try_from(seed) else { return Err(())};
        let seed_as_array = Array::<u8, C::SeedSize>::slice_as_array(seed).ok_or(())?;
        
        let (decapsulator, encapsulator) = C::from_seed(seed_as_array);
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
pub struct HpkeDecryptor <C: Kem, K, A: Aead + KeyInit> 
{
    decapsulator: C::DecapsulationKey,
    phantom1: PhantomData<A>,
    phantom2: PhantomData<K>,
} 

impl <C, K, A> HpkeDecryptor <C, K, A>
where C: Kem + KemParams,
    K: HpkeKdf<A::KeySize, A::NonceSize> + KdfId,
    A: Aead + KeyInit + AeadId,
{
    pub fn get_encryptor(&self) -> HpkeEncryptor<C,K,A>
    {
        HpkeEncryptor{encapsulator: self.decapsulator.encapsulation_key().clone(), phantom1: PhantomData, phantom2: PhantomData}
    }
    /// 
    /// Function which accepts encapsulated key (ct), diversification data (inf) and optional pre-shared key (psk).
    /// The function calculates the shared secret from the encapsulated key and the private key stored in the decapsulator, 
    /// then uses the shared secret, info and psk to derive the key and base nonce for the AEAD cipher. 
    /// The derived key and base nonce are used to create a new HpkeCipherContext which is returned by the function.
    /// 
    pub fn setup_receiver_cipher(
        &self, 
        ct: &Ciphertext<C>,
        info: &[u8],
        psk: Option<Psk>,
    ) -> Result<HpkeCipherContext<A>, Error>
    {
        let shared_secret = self.decapsulator.try_decapsulate(ct).map_err(|_|Error::KemError)?;
        Ok(HpkeCipherContext::new::<K, LabelKdf::<C::KemId, K::KdfType, A::AeadType>>( C::IS_AUTH, shared_secret.as_slice(), info, psk))
    }

    /// 
    /// Function which accepts encapsulated key (ct), diversification data (inf) and optional pre-shared key (psk).
    /// The function calculates the shared secret from the encapsulated key and the private key stored in the decapsulator, 
    /// then uses the shared secret, info and psk to derive the export secret for the HPKE exporter. 
    /// The derived export secret is used to create a new HpkeExportContext which is returned by the function.
    /// 
    pub fn setup_receiver_export (
        &self, 
        encapsulated_key: &Ciphertext<C>,
        info: &[u8],
        psk: Option<Psk>
    ) -> Result<HpkeExportContext<K, A::KeySize, A::NonceSize>, Error>
    {
        let shared_secret = self.decapsulator.try_decapsulate(encapsulated_key).map_err(|_|Error::KemError)?;
        Ok(HpkeExportContext::new::<LabelKdf::<C::KemId, K::KdfType, A::AeadType>>( C::IS_AUTH,shared_secret.as_slice(), info, psk))
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
    {
        self.setup_receiver_cipher(encapped_key, info, psk).map_err(|_|Error::KemError)?.open(ct)
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
    where K: HpkeKdfExporter<L>,
    {
        let context = self.setup_receiver_export(encapped_key, info, psk)?;
        Ok(context.export(exporter_context))
    }

    /// Get a reference to the decapsulator used in this decryptor
    pub fn get_decapsulator(&self) -> &C::DecapsulationKey
    {
        &self.decapsulator
    }
}



///
/// Implementation of the encryption algorithm from HPKE, RFC9180.
/// The structure stores a key encapsulator which itself stores a public key.
/// Two other types are present in the structure
/// - K: A kdf used to derive keys and nonces used for performing the symmetric key encryption
/// - A: An AEAD algorithm used to encrypt the main payload
/// 
pub struct HpkeEncryptor <C: Kem, K, A: Aead + KeyInit> 
{
    pub(crate) encapsulator: C::EncapsulationKey,
    phantom1: PhantomData<A>,
    phantom2: PhantomData<K>,
} 

impl <C: Kem + KemParams, K, A >  HpkeEncryptor <C, K, A >
where A: Aead + KeyInit + AeadId,
    K: HpkeKdf<A::KeySize, A::NonceSize> + KdfId,
    A: Aead + KeyInit + AeadId,
{
    ///
    /// Perform the first part of the HPKE protocol, which generates a random ephemeral key
    /// and uses the encapsulator to create a shared secret key
    /// 
    pub fn setup_sender_cipher <R: CryptoRngCore> (
        &self,
        _csprng: &mut R,
        info: &[u8],
        psk: Option<Psk>, 
    ) -> Result<(Ciphertext<C>, HpkeCipherContext<A>), Error> 
    {
        let (encapped_key, shared_secret) = self.encapsulator.encapsulate();
        Ok((encapped_key, HpkeCipherContext::new::<K, LabelKdf::<C::KemId, K::KdfType, A::AeadType>>( C::IS_AUTH, &shared_secret, info, psk)))
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
    where C::EncapsulationKey: EncapsulateDeterministic
    {
        let (encapped_key, shared_secret) = self.encapsulator.encapsulate_deterministic(randomness); //.map_err(|_|Error::KemError)?;
        Ok((encapped_key.as_slice().try_into().unwrap(), HpkeCipherContext::new::<K, LabelKdf::<C::KemId, K::KdfType, A::AeadType>>( C::IS_AUTH, &shared_secret, info, psk)))
    }

    ///
    /// Implements the first part of HPKE which uses a key encapsulation kem and kdf to create an encapsulated
    /// key and derived shared key
    /// 
    pub fn setup_sender_export <R: CryptoRngCore> (
        &self,
        _csprng: &mut R,
        info: &[u8],
        psk: Option<Psk>,
    ) -> Result<(Ciphertext<C>, HpkeExportContext<K, A::KeySize, A::NonceSize>), Error> 
    {
        let (encapped_key, shared_secret ) = self.encapsulator.encapsulate();
        Ok((encapped_key, HpkeExportContext::new::<LabelKdf::<C::KemId, K::KdfType, A::AeadType>>( C::IS_AUTH, &shared_secret, info, psk)))
    }

    ///
    /// Implements the first part of HPKE which uses a key encapsulation kem and kdf to create an encapsulated
    /// key and derived shared key
    /// 
    pub fn setup_sender_export_deterministic(
        &self,
        randomness: &[u8],
        info: &[u8],
        psk: Option<Psk>,
    ) -> Result<(Ciphertext<C>, HpkeExportContext<K, A::KeySize, A::NonceSize>), Error> 
    where C::EncapsulationKey: EncapsulateDeterministic,
    {
        let (encapped_key, shared_secret ) = self.encapsulator.encapsulate_deterministic(randomness);
        Ok((encapped_key.as_slice().try_into().unwrap(), HpkeExportContext::new::<LabelKdf::<C::KemId, K::KdfType, A::AeadType>>( C::IS_AUTH, &shared_secret, info, psk)))
    }

    ///
    /// Function to encrypt (seal) a plaintext (pt) using a recipient public key
    /// 
    pub fn single_shot_seal <'msg, 'aad, R: CryptoRngCore> (
        &self,
        csprng: &mut R,
        pt: impl Into<Payload<'msg, 'aad>>,
        info: &[u8],
        psk: Option<Psk>,
    ) -> Result<(Ciphertext<C>, Vec<u8>), Error> 
    {
        let (encapped_key,mut cipher_context) = self.setup_sender_cipher ( csprng, info, psk).map_err(|_|Error::KemError)?;
        Ok((encapped_key, cipher_context.seal(pt)?))
    }

    ///
    /// Function to encrypt (seal) a plaintext (pt) using a recipient public key
    /// 
    pub fn single_shot_seal_deterministic <'msg, 'aad> (
        &self,
        randomness: &[u8],
        pt: impl Into<Payload<'msg, 'aad>>,
        info: &[u8],
        psk: Option<Psk>,
    ) -> Result<(Ciphertext<C>, Vec<u8>), Error> 
    where C::EncapsulationKey: EncapsulateDeterministic
    {
        let (encapped_key,mut cipher_context) = self.setup_sender_cipher_deterministic ( randomness, info, psk).map_err(|_|Error::KemError)?;
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
    where K: HpkeKdfExporter<L>,
    {
        let (encapped_key, context) = self.setup_sender_export(csprng, info, psk)?;
        Ok((encapped_key, context.export(export_context)))
    }

    /// 
    /// Function to create an encapsulated key and associated shared export secret
    /// 
    pub fn single_shot_sender_export_deterministic<'a, L:ArraySize> (
        &self,
        randomness: &[u8],
        export_context: &[u8],
        info: &[u8],
        psk: Option<Psk>,
    ) -> Result<(Ciphertext<C>, Array<u8,L>), Error> 
    where C::EncapsulationKey: EncapsulateDeterministic,
        K: HpkeKdfExporter<L>, 
    {
        let (encapped_key, context) = self.setup_sender_export_deterministic(randomness, info, psk)?;
        Ok((encapped_key, context.export(export_context)))
    }

    ///
    /// Get a reference to the encapsulator
    /// 
    pub fn get_encapsulator (&self) -> &C::EncapsulationKey
    {
        &self.encapsulator
    }
}

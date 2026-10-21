use std::{fmt::Debug, marker::PhantomData};

use crate::{KemParams, hpke_kdf::{LabelHpkeV1, LabelKem, LabelKeyDerive}};

use digest::typenum::Unsigned;
use kdfs::{KdfFixed, Kdf, Label, TwoStepKdf};
use kem::{Ciphertext, Decapsulator, Encapsulate, EncapsulationKey, FromSeed, Generate, InvalidKey, Kem, Key, KeyExport, KeyInit, KeySizeUser, SharedKey, TryDecapsulate, TryKeyInit};
use kems::{Array, ArraySize, EncapsulateDeterministic, FromKey, FromKeys};

///
/// A HPKE kdf designed for use in creating secret keys for P256, K256, P384, P521 and other elliptic curves from seed bytes
///  K = Two stage KDF to use, must implement TwoStepKdf trait
///  I = Kem ID from RFC 9180/etc
///  BITMASK, a byte value applied to the first byte of the generated value to try and ensure it is less than the order of the curve
/// 
#[derive(Default)]
pub struct TwoStageEcKeyGen<K,I,const BITMASK: u8> (PhantomData<K>, PhantomData<I>);

impl<K: TwoStepKdf, I: Unsigned, const BITMASK: u8, L: ArraySize> Kdf<L> for TwoStageEcKeyGen<K, I, BITMASK> 
where K::Extract: KdfFixed,
    K::Expand: Kdf<L>
{
    fn derive_self_secrets_others<'a,'b> ( &self, secret: impl IntoIterator<Item=&'a[u8]> + Clone, _other_data: impl IntoIterator<Item=&'b[u8]> + Clone) -> Array<u8, L> {
        let dkp_prk = K::Extract::default().derive_self_secrets_others_fixed( secret, [LabelHpkeV1::LABEL, LabelKem::<I>::LABEL, b"dkp_prk"]);

        let mut out = K::Expand::default().derive_self_secrets_others(std::iter::once(dkp_prk.as_ref()), [&L::U16.to_be_bytes(),LabelHpkeV1::LABEL, LabelKem::<I>::LABEL, b"candidate", &[0u8]]);
        out[0] = out[0] & BITMASK;        
        out
    }
}

///
/// A HPKE kdf designed for use in creating secret keys for X25519 and X448 from seed bytes
///  K = Two stage KDF to use, must implement TwoStepKdf trait
///  I = Kem ID from RFC 9180/etc
///  L = Output size
/// 
#[derive(Default)]
pub struct TwoStageXKeyGen<K,I> (PhantomData<K>, PhantomData<I>);

impl <K: TwoStepKdf, I:Unsigned,L: ArraySize> Kdf<L> for TwoStageXKeyGen<K,I>
where K::Extract: KdfFixed,
    K::Expand: Kdf<L>
{
    fn derive_self_secrets_others<'a,'b> ( &self, secret: impl IntoIterator<Item=&'a[u8]> + Clone, _other_data: impl IntoIterator<Item=&'b[u8]> + Clone) -> Array<u8, L> {
        let secret = K::Extract::default().derive_self_secrets_others_fixed(secret, [LabelHpkeV1::LABEL, LabelKem::<I>::LABEL, b"dkp_prk"]);
        K::Expand::default().derive_self_secret_others(secret.as_ref(), [&L::U16.to_be_bytes(), LabelHpkeV1::LABEL, LabelKem::<I>::LABEL, b"sk"])
    }
}

///
/// A HPKE combiner designed to work with two stage KDFs
///  K = Two stage KDF to use, must implement TwoStepKdf trait
///  I = Kem ID from RFC 9180/etc
///  L = Output size
/// 
#[derive(Default)]
pub struct TwoStageEcCombiner<K,I> (PhantomData<K>, PhantomData<I>);

impl <K: TwoStepKdf, I:Unsigned, L: ArraySize> Kdf<L> for TwoStageEcCombiner<K,I>
where K::Extract: KdfFixed,
    K::Expand: Kdf<L>,
{
    fn derive_self_secrets_others<'a,'b> ( &self, secret: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone) -> Array<u8, L> {
        let secret = K::Extract::derive_secrets_others_fixed( secret, [LabelHpkeV1::LABEL, LabelKem::<I>::LABEL, b"eae_prk"]);
        
        let mut other_data_iter = other_data.into_iter();
        let ct = other_data_iter.next().unwrap_or_default();
        let pk = other_data_iter.next().unwrap_or_default();
        
        K::Expand::derive_secret_others(secret.as_ref(), [&L::U16.to_be_bytes(), LabelHpkeV1::LABEL, LabelKem::<I>::LABEL, b"shared_secret", ct, pk])

    }
}

///
/// A HPKE function designed to deterministically change a seed value for use with key generation or encapsulation
///  K = One stage KDF to use
///  I = Kem ID from RFC 9180/etc
///
#[derive(Default)]
pub struct OneStageSeedDiversify<K,I> (PhantomData<K>, PhantomData<I>);

impl <K: Kdf<L> + Default, I: Unsigned, L: ArraySize> Kdf<L> for OneStageSeedDiversify<K,I>
{
    fn derive_self_secrets_others<'a,'b> ( &self, secret: impl IntoIterator<Item=&'a[u8]> + Clone, _other_data: impl IntoIterator<Item=&'b[u8]> + Clone) -> Array<u8, L> {
        K::derive_secrets_others(secret, [LabelHpkeV1::LABEL, &LabelKem::<I>::LABEL, &LabelKeyDerive::LABEL, &L::U16.to_be_bytes() ])
    }
}




///
/// A wrapper around a KEM which implements the key generation, seed transformation and output combining functions specified in HPKE
/// 
#[derive(Ord,PartialEq,PartialOrd,Eq,Default,Debug,Copy,Clone)]
pub struct HpkeKemWrapper<K> (PhantomData<K>);

impl<K> Kem for HpkeKemWrapper<K>
where K: Kem,
    Self: KemParams
{
    type DecapsulationKey = HpkeEcKemDecapsulationKey<K>;
    type EncapsulationKey = HpkeEcKemEncapsulationKey<K>;
    /// Shared key size is specified in the KemParams 
    type SharedKeySize = <Self as KemParams>::OutputSize;
    /// Same ciphertext size as underlying cipher
    type CiphertextSize = K::CiphertextSize; 
}

///
/// HPKE defines KDFs to be applied whenever a seed value is turned into a key
/// This function implements the HPKE specific KDF, the base KEM is responsible for creating a key from a byte array
/// 
impl<K> FromSeed for HpkeKemWrapper<K>
where K: Kem + FromSeed,
    Self: KemParams,
    <Self as KemParams>::KeyGenFromSeed: Kdf<K::SeedSize>,
{
    type SeedSize = K::SeedSize;

    fn from_seed(seed: &kem::Seed<Self>) -> (kem::DecapsulationKey<Self>, kem::EncapsulationKey<Self>) {
        let derived_seed = <Self as KemParams>::KeyGenFromSeed::derive_secret_others(&seed, None);
        
        let (decap, encap) = K::from_seed(&derived_seed);
        let hpke_encap = HpkeEcKemEncapsulationKey::<K>(encap);
        (HpkeEcKemDecapsulationKey::<K>{decap, hpke_encap: hpke_encap.clone()}, hpke_encap)
    }
}

///
/// Initialization functions to be used by auth KEM implmentations
/// 
impl<K> HpkeKemWrapper<K>
where K: Kem,
    Self: KemParams,
{
    pub fn encap_from_keys ( pub_key: <K::EncapsulationKey as FromKeys>::PublicKey, priv_key: <K::EncapsulationKey as FromKeys>::PrivateKey ) -> <Self as Kem>::EncapsulationKey 
    where K::EncapsulationKey: FromKeys
    {
         <Self as Kem>::EncapsulationKey::from_keys(pub_key, priv_key)
    }
    pub fn decap_from_keys ( pub_key: <K::DecapsulationKey as FromKeys>::PublicKey, priv_key: <K::DecapsulationKey as FromKeys>::PrivateKey ) -> <Self as Kem>::DecapsulationKey 
    where K::DecapsulationKey: FromKeys,
        K::EncapsulationKey: FromKeys
    {
         <Self as Kem>::DecapsulationKey::from_keys(pub_key, priv_key)
    }
}




///
/// Wrapped decapsulation (private) key 
/// Holds the decapsulation key and a copy of the encapsulation key which can be returned by reference
/// 
pub struct HpkeEcKemDecapsulationKey<K: Kem> { 
    pub decap: K::DecapsulationKey, 
    pub hpke_encap: HpkeEcKemEncapsulationKey<K>
}


impl<K> FromKey for HpkeEcKemDecapsulationKey<K>
where K:Kem,
    K::DecapsulationKey: FromKey
{
    type Key = <K::DecapsulationKey as FromKey>::Key;

    fn from_key(key: Self::Key) -> Self {
        let decap = K::DecapsulationKey::from_key(key);
        let encap = HpkeEcKemEncapsulationKey(decap.encapsulation_key().clone());
        Self{ decap, hpke_encap: encap}
    }
}

impl<K:Kem> Generate for HpkeEcKemDecapsulationKey<K>
where K::DecapsulationKey: Generate
{
    fn try_generate_from_rng<R: aead::rand_core::TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        let decap = K::DecapsulationKey::try_generate_from_rng(rng)?;
        let hpke_encap = HpkeEcKemEncapsulationKey(decap.encapsulation_key().clone());
        Ok(Self{decap, hpke_encap})
    }
}

///
/// Implement only TryDecapsulate because if we implement Decapsulate, then TryDecapsulate is implicitly implemented, and we want to avoid that because it will panic on failure.
/// 
impl<K> TryDecapsulate for HpkeEcKemDecapsulationKey<K>
where K:Kem,
    K::DecapsulationKey: TryDecapsulate,
    HpkeKemWrapper<K>: KemParams,
{
    type Error = <K::DecapsulationKey as TryDecapsulate>::Error;

    fn try_decapsulate(
        &self,
        ct: &kem::Ciphertext<Self::Kem>,
    ) -> Result<kem::SharedKey<Self::Kem>, Self::Error> {
        let raw_shared_secret = self.decap.try_decapsulate(ct)?;

        Ok(<HpkeKemWrapper<K> as KemParams>::Combiner::derive_secret_others(&raw_shared_secret, [ct.as_slice(), &self.encapsulation_key().to_bytes()]))
    }
}

impl<K> Decapsulator for HpkeEcKemDecapsulationKey<K>
where K:Kem,
    HpkeKemWrapper<K>: KemParams,
{
    type Kem = HpkeKemWrapper<K>;

    fn encapsulation_key(&self) -> &EncapsulationKey<Self::Kem> {
        &self.hpke_encap
    }
}

/// Trait to export key as a sequence of bytes
impl<K> KeyExport for HpkeEcKemDecapsulationKey<K>
where K:Kem,
    K::DecapsulationKey: KeyExport,
{
    fn to_bytes(&self) -> Key<Self> {
        self.decap.to_bytes()
    }
}

/// Number of bytes in exported or important key
impl<K> KeySizeUser for HpkeEcKemDecapsulationKey<K>
where K:Kem,
    K::DecapsulationKey: KeySizeUser,
{
    type KeySize = <K::DecapsulationKey as KeySizeUser>::KeySize;
}

/// Initialize a decapsulator from a byte sequence
impl<K> TryKeyInit for HpkeEcKemDecapsulationKey<K>
where K:Kem,
    K::DecapsulationKey: TryKeyInit,
{
    fn new(key: &kem::Key<Self>) -> Result<Self, kem::InvalidKey> {
        let decap = K::DecapsulationKey::new(key)?;
        let encap = HpkeEcKemEncapsulationKey(decap.encapsulation_key().clone());
        Ok(Self{ decap, hpke_encap: encap})
    }
}

/// Initialize a decapsulator from a pair of keys, public of the peer and private of self
impl<K> FromKeys for HpkeEcKemDecapsulationKey<K>
where K:Kem,
    K::DecapsulationKey: FromKeys,
    K::EncapsulationKey: FromKeys + TryKeyInit,
{
    type PrivateKey = <K::DecapsulationKey as FromKeys>::PrivateKey;
    type PublicKey = <K::DecapsulationKey as FromKeys>::PublicKey;

    fn from_keys ( pub_key: Self::PublicKey, priv_key: Self::PrivateKey ) -> Self {
        let decap = K::DecapsulationKey::from_keys(pub_key, priv_key);
        let encap = HpkeEcKemEncapsulationKey(decap.encapsulation_key().clone());
        Self{ decap, hpke_encap: encap}
    }
}







///
/// Struct holding the encapsulation key when used in HPKE
/// 
#[derive(Copy,Clone,Eq,PartialEq,Debug)]
pub struct HpkeEcKemEncapsulationKey<K:Kem> (pub K::EncapsulationKey);

impl<K> Encapsulate for HpkeEcKemEncapsulationKey<K>
where K:Kem,
    K::EncapsulationKey: KeyExport,
    HpkeKemWrapper<K>: KemParams,
{
    type Kem = HpkeKemWrapper<K>;

    fn encapsulate_with_rng<R>(&self, rng: &mut R) -> (kem::Ciphertext<Self::Kem>, kem::SharedKey<Self::Kem>)
    where R: aead::rand_core::CryptoRng + ?Sized 
    {
        let (ciphertext, raw_shared_secret) = self.0.encapsulate_with_rng(rng);
        let derived_shared_secret = <HpkeKemWrapper<K> as KemParams>::Combiner::derive_secret_others(&raw_shared_secret, [ciphertext.as_slice(), &self.0.to_bytes()]);
        (ciphertext, derived_shared_secret)
    }
}
impl<K> TryKeyInit for HpkeEcKemEncapsulationKey<K>
where K:Kem,
    K::EncapsulationKey: TryKeyInit
{
    fn new(key: &kem::Key<Self>) -> Result<Self, kem::InvalidKey> {
        Ok(Self(<K::EncapsulationKey as TryKeyInit>::new(key)?))
    }
}
impl<K> TryFrom<&[u8]> for HpkeEcKemEncapsulationKey<K>
where K:Kem,
    K::EncapsulationKey: TryKeyInit
{
    type Error = InvalidKey;
    
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(<K::EncapsulationKey as TryKeyInit>::new_from_slice(value)?))
    }
}
impl<K> KeyInit for HpkeEcKemEncapsulationKey<K>
where K:Kem,
    K::EncapsulationKey: KeyInit
{
    fn new(key: &kem::Key<Self>) -> Self {
        Self(<K::EncapsulationKey as KeyInit>::new(key))
    }
}
impl<K> KeySizeUser for HpkeEcKemEncapsulationKey<K>
where K:Kem,
    K::EncapsulationKey: KeySizeUser
{
    type KeySize = <K::EncapsulationKey as KeySizeUser>::KeySize;
}
impl<K> KeyExport for HpkeEcKemEncapsulationKey<K>
where K:Kem,
    K::EncapsulationKey: KeyExport
{
    fn to_bytes(&self) -> kem::Key<Self> {
        self.0.to_bytes()
    }
}

impl<K> EncapsulateDeterministic for HpkeEcKemEncapsulationKey<K>
where K: Kem,
    K::EncapsulationKey: KeyExport + EncapsulateDeterministic<Kem=K>,
    HpkeKemWrapper<K>: KemParams,
    
    <HpkeKemWrapper<K> as KemParams>::EncapsulateFromSeed: Kdf<<K::EncapsulationKey as EncapsulateDeterministic>::SeedSize>,
{
    //type Kem = HpkeKemWrapper<K>;
    type SeedSize = <K::EncapsulationKey as EncapsulateDeterministic>::SeedSize;

    fn encapsulate_deterministic(&self, seed: &[u8]) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>) {
        
        let seed_2: Array<u8, <K::EncapsulationKey as EncapsulateDeterministic>::SeedSize> = <HpkeKemWrapper::<K> as KemParams>::EncapsulateFromSeed::derive_secret_others(seed, None);

        let (ciphertext, raw_shared_secret) = self.0.encapsulate_deterministic(&seed_2);
        let derived_shared_secret = <HpkeKemWrapper<K> as KemParams>::Combiner::derive_secret_others(&raw_shared_secret, [ciphertext.as_slice(), &self.0.to_bytes()]);
        (ciphertext, derived_shared_secret)
    }
}

impl<K> FromKey for HpkeEcKemEncapsulationKey<K>
where K:Kem,
    K::EncapsulationKey: FromKey
{
    type Key = <K::EncapsulationKey as FromKey>::Key;

    fn from_key(key: Self::Key) -> Self {
        Self(K::EncapsulationKey::from_key(key))
    }
}

/// 
/// Create an encapsulator from a pair of keys, a private key owned by self and a public key corresponding to the recipient
/// 
impl<K> FromKeys for HpkeEcKemEncapsulationKey<K>
where K:Kem,
    K::EncapsulationKey: FromKeys
{
    type PrivateKey = <K::EncapsulationKey as FromKeys>::PrivateKey;

    type PublicKey = <K::EncapsulationKey as FromKeys>::PublicKey;

    fn from_keys ( pub_key: Self::PublicKey, priv_key: Self::PrivateKey ) -> Self {
        HpkeEcKemEncapsulationKey::<K> ( K::EncapsulationKey::from_keys(pub_key, priv_key))
    }
}
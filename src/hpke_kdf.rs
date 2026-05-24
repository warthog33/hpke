//!
//! KDFs used within HPKE
//! There are two main types,
//! two step kdf as described in the original RFC 9180 and
//! one step kdf introduced in draft-ietf-hpke-pq
//! 
use std::marker::PhantomData;
use std::ops::{Add, Sub};

use crate::mode_id;

use aead::array::typenum::{Diff, Sum, Unsigned};
use kdfs::hybrid_array::{Array, ArraySize};
#[allow(unused)]
use kdfs::iso11770_6::{Kpf1, Ktf1, Tkdf, iter_to_vec};
use kdfs::{GetExpand, GetExtract, InitSalt, Kdf, KdfFixed, KdfLabelled, TwoStepKdf, Label};
use kems::DeriveKeyPairFromSeed;


/// Kdf used in the KEM from RFC9180
/// It is a version of the ExtractExpand KDF with a given label/suite_id. 
/// For Kem the label is specific suite_id of 'KEM' + KEM_ID
/// For Kdf the label/suite_id is 'HPKE + KEM_ID + KDF_ID + AEAD_ID
///
/// 
/// 
/// This sample is from RFC 9180, Appendix A.1.1
///```
/// use sha2::Sha256;
/// use kdfs::Kdf;
/// use hpke::{hpke_kdf::KdfForKemUsingHkdf, kem_id::DhKemX25519HkdfSha256};
/// use hex_literal::hex;
/// use kems::generic_array::typenum::consts::U32;
/// 
/// let pkEm = hex!("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
/// let pkRm = hex!("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
/// let raw_shared_secret = hex!("B3B5C19EAB3F088AC18F23F774FF6414BA4FDE45404D10085EFC3E4DC9C72E35");
/// let shared_secret = hex!("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc");
///
/// let result = KdfForKemUsingHkdf::<Sha256,DhKemX25519HkdfSha256>::derive_secret_others::<U32>(&raw_shared_secret, [pkEm.as_ref(), pkRm.as_ref()]).unwrap();
/// assert! ( result == shared_secret);
///```
/// 

pub struct LabelledExtract<K: Kdf, L1, L2=LabelNone, L3=LabelNone> 
(&'static[u8], PhantomData<K>, PhantomData<L1>, PhantomData<L2>, PhantomData<L3>);

impl<K: Kdf + KdfFixed + InitSalt, L1: Label, L2: Label, L3: Label> KdfFixed for LabelledExtract<K, L1,L2,L3>
{
    type OutputSize = K::OutputSize;
}

impl<K: Kdf + InitSalt, L1:Label, L2:Label, L3:Label> Default for LabelledExtract<K, L1,L2,L3>
{
    fn default() -> Self {
        Self::new_with_label::<LabelNone>()
    }
}

impl<K: Kdf + InitSalt, L1: Label, L2:Label, L3:Label> Kdf for LabelledExtract<K, L1, L2, L3>
{
    fn derive_self_secrets_others_into<'a,'b> ( &self, secrets: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), kdfs::Error> {
        self.derive_self_secrets_label_others_into(secrets, &[], other_data, out)
    }
}
impl<K: Kdf + InitSalt, L1: Label, L2: Label, L3: Label> KdfLabelled for LabelledExtract<K, L1, L2, L3>
{
    fn new_with_label<L: Label>() -> Self {
        Self ( L::LABEL, PhantomData, PhantomData, PhantomData, PhantomData)
    }
    fn derive_self_secrets_label_others_into<'a, 'b, 'c> ( &self, secrets: impl IntoIterator<Item=&'a[u8]> + Clone, label: &'b[u8], others: impl IntoIterator<Item=&'c[u8]> + Clone, out: &mut[u8]) -> Result<(),kdfs::Error> {
        let kdf = K::new_with_salt(&iter_to_vec(others));
        kdf.derive_self_secrets_others_into( [ L1::LABEL, L2::LABEL, L3::LABEL, self.0, label], secrets, out)
    }
}
impl<K: Kdf, L1: Label, L2,L3> InitSalt for LabelledExtract<K, L1, L2, L3>
{
    fn new_with_salt ( _salt: &[u8] ) -> Self {
        todo!()
    }
}

///
/// Implementation of the LabelledExpand function described in RFC9180
/// Labels can be specified in multiple ways
/// - As types specified in L1-L3 fields
/// - During structure generation using the new_with_label method
/// - Passed as a parameter to a derive_xx_label_xx methods
/// All non-zero length labels are included in the key derivation according to the
pub struct LabelledExpand<K: Kdf, L1:Label, L2=LabelNone, L3=LabelNone> 
(&'static[u8], PhantomData<K>, PhantomData<L1>, PhantomData<L2>, PhantomData<L3>);

impl<K: Kdf + Default, L1: Label, L2: Label, L3: Label> Default for LabelledExpand<K, L1,L2,L3>
{
    fn default() -> Self {
        Self::new_with_label::<LabelNone>()
    }
}
impl<K: Kdf + Default, L1: Label, L2: Label, L3: Label> Kdf for LabelledExpand<K, L1,L2,L3>
{
    fn derive_self_secrets_others_into<'a,'b> ( &self, secrets: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), kdfs::Error> {
        self.derive_self_secrets_label_others_into(secrets, &[], other_data, out)
    }
}
impl<K: Kdf + Default, L1: Label, L2: Label, L3: Label> KdfLabelled for LabelledExpand<K, L1,L2,L3>
{
    fn new_with_label<L: Label>() -> Self {
        Self ( L::LABEL, PhantomData, PhantomData, PhantomData, PhantomData)
    }
    
    fn derive_self_secrets_label_others_into<'a, 'b, 'c> ( &self, secrets: impl IntoIterator<Item=&'a[u8]> + Clone, label: &'b[u8], others: impl IntoIterator<Item=&'c[u8]> + Clone, out: &mut[u8]) -> Result<(),kdfs::Error> {
        let len_in_array = (out.len() as u16).to_be_bytes();
        let mut other_data2: Vec<&[u8]> = vec! [ &len_in_array, L1::LABEL, L2::LABEL, L3::LABEL, self.0, label];

        others.into_iter().for_each( |v| other_data2.push(v));
        
        K::derive_self_secrets_others_into( &K::default(), secrets, other_data2, out)
    }

}


pub struct LabelledXofKdf<K,L1,L2=LabelNone,L3=LabelNone> (&'static[u8], PhantomData<K>, PhantomData<L1>, PhantomData<L2>, PhantomData<L3>);

impl<K: Kdf + Default, L1: Label, L2: Label, L3: Label> Default for LabelledXofKdf<K, L1, L2, L3> 
{
    fn default() -> Self {
        Self::new_with_label::<LabelNone>()
    }
}
impl<K: Kdf + Default, L1: Label, L2: Label, L3: Label> Kdf for LabelledXofKdf<K,L1,L2,L3>
{
    fn derive_self_secrets_others_into<'a,'b> ( &self, secrets: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), kdfs::Error> {
        self.derive_self_secrets_label_others_into(secrets, &[], other_data, out)
    }
}
impl<K: Kdf + Default, L1: Label, L2: Label, L3: Label> KdfLabelled for LabelledXofKdf<K,L1,L2,L3>
{
    fn new_with_label<L: Label>() -> Self { // ( label: &'static[u8]) -> Self {
        Self(L::LABEL, PhantomData, PhantomData,PhantomData,PhantomData)
    }

    fn derive_self_secrets_label_others_into<'a, 'b, 'c> ( &self, secrets: impl IntoIterator<Item=&'a[u8]> + Clone, label: &'b[u8], others: impl IntoIterator<Item=&'c[u8]> + Clone, out: &mut[u8]) -> Result<(),kdfs::Error> {
        let output_len = (out.len() as u16).to_be_bytes();
        let label3len = (L3::LABEL.len() as u16 ).to_be_bytes();
        //let selflabel = (self.0.len() as u16).to_be_bytes();
        let locallabel = (label.len() as u16).to_be_bytes();
        
        let mut other_data2: Vec<&[u8]> = vec! [ L1::LABEL, L2::LABEL];

        if L3::LABEL.len() > 0 {
            other_data2.push(&label3len);
            other_data2.push(&L3::LABEL);
        }
        if self.0.len() > 0 {
            //other_data2.push(&selflabel);
            other_data2.push(&self.0);
        }
        if label.len() > 0 {
            other_data2.push(&locallabel);
            other_data2.push(&label);
        }
        other_data2.push(&output_len);
        others.into_iter().for_each( |v| other_data2.push(v));
        K::default().derive_self_secrets_others_into ( secrets, other_data2,out)
    }
}

pub struct LabelHpkeV1 ();
impl Label for LabelHpkeV1
{
    const LABEL: &[u8] = b"HPKE-v1";
}



pub struct LabelKem<KemId: Unsigned> (PhantomData<KemId>);
impl<KemId: Unsigned> Label for LabelKem<KemId>
{
    //const LABEL: &'static[u8] = !(b'"KEM", (KEM_ID >> 8 ) as u8, (KEM_ID & 0xFF) as u8, b"eak" );
    const LABEL: &[u8] = &[b'K', b'E', b'M', (KemId::U16>>8) as u8, KemId::U16 as u8];
}

pub struct LabelKemExtract ();
impl Label for LabelKemExtract
{
    //const LABEL: &'static[u8] = !(b'"KEM", (KEM_ID >> 8 ) as u8, (KEM_ID & 0xFF) as u8, b"eak" );
    //const LABEL: &[u8] = &[b'e', b'a', b'e', b'_', b'p', b'r', b'k'];
    const LABEL: &[u8] = b"eae_prk";
}
pub struct LabelKemExpand ();
impl Label for LabelKemExpand
{
    //const LABEL: &'static[u8] = !(b'"KEM", (KEM_ID >> 8 ) as u8, (KEM_ID & 0xFF) as u8, b"eak" );
    //const LABEL: &[u8] = &[b's', b'h', b'a', b'r', b'e', b'd', b'_', b's', b'e', b'c', b'r', b'e', b't'];
    const LABEL: &[u8] = b"shared_secret";
}
pub struct LabelKeyGenExtract ();
impl Label for LabelKeyGenExtract
{
    //const LABEL: &'static[u8] = !(b'"KEM", (KEM_ID >> 8 ) as u8, (KEM_ID & 0xFF) as u8, b"eak" );
    //const LABEL: &[u8] = &[b'd', b'k', b'p', b'_', b'p', b'r', b'k'];
    const LABEL: &[u8] = b"dkp_prk";
}

pub struct LabelKeyDerive ();
impl Label for LabelKeyDerive
{
    const LABEL: &'static[u8] = b"DeriveKeyPair"; 
    //const LABEL: &[u8] = &[0u8, 13u8, b'D',b'e',b'r',b'i',b'v',b'e',b'K',b'e',b'y',b'P',b'a',b'i',b'r'];
}
// pub struct LabelKeyGenExpand<KEM_ID: Unsigned> (PhantomData<KEM_ID>);
// impl<KEM_ID: Unsigned> Label for LabelKeyGenExpand<KEM_ID>
// {
//     //const LABEL: &'static[u8] = !(b'"KEM", (KEM_ID >> 8 ) as u8, (KEM_ID & 0xFF) as u8, b"eak" );
//     const LABEL: &[u8] = &[b'K', b'E', b'M', (KEM_ID::U16>>8) as u8, KEM_ID::U16 as u8, b's', b'k'];
// }
pub struct LabelKeyGenExpand ();
impl Label for LabelKeyGenExpand
{
    //const LABEL: &'static[u8] = !(b'"KEM", (KEM_ID >> 8 ) as u8, (KEM_ID & 0xFF) as u8, b"eak" );
    //const LABEL: &[u8] = &[b's', b'k'];
    const LABEL: &[u8] = b"sk";
}


pub struct LabelKeyGenCandidate ();
impl Label for LabelKeyGenCandidate
{
    //const LABEL: &'static[u8] = !(b'"KEM", (KEM_ID >> 8 ) as u8, (KEM_ID & 0xFF) as u8, b"eak" );
    //const LABEL: &[u8] = &[b'c', b'a', b'n', b'd', b'i', b'd', b'a', b't', b'e'];
    const LABEL: &[u8] = b"candidate";
}



pub struct LabelKdf<KemId: Unsigned, KdfId: Unsigned, AeadId: Unsigned> ( PhantomData<KemId>, PhantomData<KdfId>, PhantomData<AeadId>);
impl<KemId: Unsigned, KdfId: Unsigned, AeadId: Unsigned> Label for LabelKdf <KemId, KdfId, AeadId>
{
    const LABEL: &'static[u8] = &['H' as u8, 'P' as u8, 'K' as u8, 'E' as u8, (KemId::U16>>8) as u8, KemId::U8 as u8, (KdfId::U16>>8) as u8, KdfId::U16 as u8, (AeadId::U16>>8) as u8, AeadId::U16 as u8];
}

pub struct LabelNone();
impl Label for LabelNone
{
    const LABEL: &'static[u8] = &[]; 
}

#[cfg(all(feature = "rustcrypto-hmac"))]
use hmac::{HmacReset};

/// This type specifies all labels as types, so it can be used as part of a KEM with no need to explicitly set any labels
/// This type sets the HPKE-v1 label, KEM ID and level 3 label - used by key generation functions in X25519 and X448
#[cfg(all(feature = "rustcrypto-hmac"))]
pub type KdfForKemUsingHkdf<H, KemId> = Tkdf<LabelledExtract::<Ktf1<HmacReset<H>>, LabelHpkeV1, LabelKem<KemId>, LabelKemExtract>, 
                                   LabelledExpand::<Kpf1<HmacReset<H>,u8>, LabelHpkeV1, LabelKem<KemId>, LabelKemExpand>>;

/// This type sets the HPKE-v1 label and the KEM ID, but doesn't specify the final label.
/// THe final label can be set using new_with_label or derive_xx_label_xx
#[cfg(all(feature = "rustcrypto-hmac"))]
pub type KdfForKeyGenUsingHkdf<H, KemId> = Tkdf<LabelledExtract::<Ktf1<HmacReset<H>>, LabelHpkeV1, LabelKem<KemId>, LabelKeyGenExtract>, 
                                   LabelledExpand::<Kpf1<HmacReset<H>,u8>, LabelHpkeV1, LabelKem<KemId>, LabelKeyGenCandidate>>;

/// This type sets the HPKE-v1 label, KEM ID and level 3 label - used by key generation functions in X25519 and X448
#[cfg(all(feature = "rustcrypto-hmac"))]
pub type KdfForKeyGenUsingHkdf2<H, KemId> = Tkdf<LabelledExtract::<Ktf1<HmacReset<H>>, LabelHpkeV1, LabelKem<KemId>, LabelKeyGenExtract>, 
                                   LabelledExpand::<Kpf1<HmacReset<H>,u8>, LabelHpkeV1, LabelKem<KemId>, LabelKeyGenExpand>>;

#[cfg(all(feature = "rustcrypto-hmac"))]
pub type KdfForKdfUsingHkdf<H, KemId, KdfId, AeadId> = Tkdf<LabelledExtract::<Ktf1<HmacReset<H>>, LabelHpkeV1, LabelKdf<KemId, KdfId, AeadId>>, 
                                    LabelledExpand::<Kpf1<HmacReset<H>,u8>, LabelHpkeV1, LabelKdf<KemId, KdfId, AeadId>>>;




/// Trait definition for a kdf suitable for use within Hpke
/// Only two methods are defined
///  1. derive, which returns the key, nonce and expoert_secrets from the shared_secet, info and psk
///  2. export_secret, which returns an exporter value derived from the exporter_secret
pub trait HpkeKdf: From<Self::K>
{
    type K: Default;
    type LE: ArraySize;
    
    //fn derive<'a, LK: ArraySize, LN: ArraySize, LE: ArraySize> ( lkdf: &Self::K, is_auth: bool, shared_secret: &'a[u8], info: &'a[u8], psk: Option<Psk> ) 
    fn derive<'a, LK: ArraySize, LN: ArraySize, LE: ArraySize> ( &self, is_auth: bool, shared_secret: &'a[u8], info: &'a[u8], psk: Option<Psk> ) 
        -> Result<(Array<u8,LK>, Array<u8,LN>, Array<u8,LE>),()>
    where LN: Add<LE>,
        Sum<LN, LE>: ArraySize,
        LK: Add<Sum<LN, LE>>,
        Sum<LK, Sum<LN, LE>>: ArraySize,
        Sum<LK, Sum<LN, LE>>: Sub<LK>,
        Diff<Sum<LK, Sum<LN, LE>>, LK>: ArraySize,
        Diff<Sum<LK, Sum<LN, LE>>, LK>: Sub<LN, Output=LE>,
        Diff<Diff<Sum<LK, Sum<LN, LE>>, LK>, LN>: ArraySize;

    //fn derive_exported_value<L: ArraySize>(lkdf: &Self::K, exporter_secret: &Array<u8, Self::LE>, exporter_context: &[u8]) -> Result<Array<u8,L>, ()>;
    fn derive_exported_value<L: ArraySize>(&self, exporter_secret: &Array<u8, Self::LE>, exporter_context: &[u8]) -> Result<Array<u8,L>, ()>;
}


///
/// 2 step KDF used by HPKE, RFC 9180
/// This KDF accepts a shared secret, info, psk and psk_id and internally
/// generates and stores a key schedule context and derived secret.
/// expand_key, expand_base_nonce and expand_exporter_secret functions use these internal fields in calculating the output
///
/// ```
/// use sha2::Sha512;
/// use hmac::{HmacReset};
/// use kdfs::{rfc5869_hkdf::Hkdf2};
/// use hpke::{hpke_kdf::{HpkeTwoStepKdf, HpkeKdf}, kem_id, kdf_id, aead_id};
/// use hpke::hpke_kdf::KdfForKdfUsingHkdf;
/// use hex_literal::hex;
/// use kems::generic_array::typenum::consts::{U12, U16, U32};
///
/// let shared_secret=hex!("02f584736390fc93f5b4ad039826a3fa08e9911bd1215a3db8e8791ba533cafd");
/// let info=hex!("4f6465206f6e2061204772656369616e2055726e");
/// let key=hex!("090ca96e5f8aa02b69fac360da50ddf9");
/// 
/// let kdf = HpkeTwoStepKdf::from(KdfForKdfUsingHkdf::<Sha512, kem_id::DhKemP256HkdfSha256, kdf_id::HkdfSha512, aead_id::Aes128Gcm>::default());
/// let (key_calc, base_nonce, _) = kdf.derive::<U16, U12, U32>(false, &shared_secret, &info, None).unwrap();
/// assert! ( key_calc == key );
/// ```

pub struct Psk<'id, 'val> { pub id: &'id[u8], pub val: &'val[u8] }

impl<'id, 'val> Default for Psk<'id, 'val> {
    fn default() -> Self {
        Self{id: Default::default(), val: Default::default()}
    }
}



///
/// A KDF used to derive the key, base nonce and exporter secret from the shared secret output by the KEM
/// It uses a two step kdf with extract and expand functions used to determine the output values
/// 
pub struct HpkeTwoStepKdf<K: TwoStepKdf> 
where K: TwoStepKdf,
     <K::Extract as KdfFixed>::OutputSize: ArraySize
{
    //phantom: PhantomData<K>
    kdf: K
}


impl<K: TwoStepKdf> From<K> for HpkeTwoStepKdf<K>
{
    fn from(kdf: K) -> Self {
        Self {kdf}
    }
}

impl<K> HpkeKdf for HpkeTwoStepKdf<K> 
where   K: TwoStepKdf + 'static + Default,
        <K::Extract as KdfFixed>::OutputSize: ArraySize,
        K::Extract: KdfLabelled,
        K::Expand: KdfLabelled,
        K: GetExtract<T=K::Extract>,
        K: GetExpand<T=K::Expand>,
{
    /// Exporter secret length, for TwoStepKdfs this is the length of the extracted secret
    type LE = <K::Extract as KdfFixed>::OutputSize;

    type K = K;

    fn derive<'a, LK: ArraySize, LN: ArraySize, LE: ArraySize> ( &self, is_auth: bool, shared_secret: &'a[u8], info: &'a[u8], psk: Option<Psk> ) 
        -> Result<(Array<u8, LK>, Array<u8, LN>, Array<u8, LE>),()>
    {
        let mode = match (is_auth, psk.is_some()) {
            (false, false) => mode_id::MODE_BASE,
            (false, true) => mode_id::MODE_PSK,
            (true, false) => mode_id::MODE_AUTH,
            (true, true) => mode_id::MODE_AUTH_PSK
        };

        let psk = psk.unwrap_or_default();

        let psk_id_hash: Array<u8, Self::LE> = self.kdf.get_extract().derive_self_secret_label_other(psk.id, b"psk_id_hash", &[]).map_err(|_|())?;
        let info_hash: Array<u8, Self::LE> = self.kdf.get_extract().derive_self_secret_label_other(info, b"info_hash", &[]).map_err(|_|())?;
        let secret: Array<u8, Self::LE> = self.kdf.get_extract().derive_self_secret_label_other(psk.val, b"secret",  shared_secret).map_err(|_|())?;

        let key = self.kdf.get_expand().derive_self_secret_label_others(secret.as_ref(), b"key", [&[mode], psk_id_hash.as_slice(), &info_hash]).map_err(|_|())?;
        let base_nonce = self.kdf.get_expand().derive_self_secret_label_others(secret.as_ref(), b"base_nonce", [&[mode], psk_id_hash.as_slice(), &info_hash]).map_err(|_|())?;
        let exporter_secret = self.kdf.get_expand().derive_self_secret_label_others(secret.as_ref(), b"exp", [&[mode], psk_id_hash.as_slice(), &info_hash]).map_err(|_|())?;
        Ok((key, base_nonce, exporter_secret))
    }

    fn derive_exported_value<L: ArraySize>(&self, exporter_secret: &Array<u8, Self::LE>, exporter_context: &[u8]) 
        -> Result<Array<u8,L>, ()>
    {
        self.kdf.get_expand().derive_self_secret_label_other (&exporter_secret, b"sec", exporter_context).map_err(|_|())
    }
}


///
/// Single step kdf typically based on an expandable output function
/// Defined in draft_ietf_hpke_pq
/// 
pub struct HpkeOneStepKdf<K: Kdf, E> {
    kdf: K, 
    phantom: PhantomData<E>
}

// impl<K: Kdf + Default, E: ArraySize> Default for HpkeOneStepKdf<K,E>
// {
//     fn default() -> Self {
//         Self(PhantomData, PhantomData)
//     }
// }
impl<K: Kdf + Default, E: ArraySize> From<K> for HpkeOneStepKdf<K,E>
{
    fn from(kdf: K) -> Self {
        Self { kdf, phantom: PhantomData }
    }
}

impl<K: Kdf + Default + KdfLabelled, E: ArraySize> HpkeKdf for HpkeOneStepKdf<K,E>
where  
{
    type K = K;

    /// Length of exporter secret is defined by a parameter in the struct
    type LE = E;

    fn derive<'a, LK: ArraySize, LN: ArraySize, LE: ArraySize> (&self, is_auth: bool, shared_secret: &'a[u8], info: &'a[u8], psk: Option<Psk> ) 
        -> Result<(Array<u8, LK>, Array<u8, LN>, Array<u8, LE>), ()>
    where 
        LN: Add<LE>,
        Sum<LN, LE>: ArraySize,
        LK: Add<Sum<LN,LE>>,
        Sum<LK, Sum<LN,LE>>: ArraySize,
        Sum<LK, Sum<LN, LE>>: Sub<LK>,
        Diff<Sum<LK, Sum<LN, LE>>, LK>: ArraySize,
        Diff<Sum<LK, Sum<LN, LE>>, LK>: Sub<LN, Output=LE>,
        Diff<Diff<Sum<LK, Sum<LN, LE>>, LK>, LN>: ArraySize,

    {
        let mode = match (is_auth, psk.is_some()) {
            (false, false) => mode_id::MODE_BASE,
            (false, true) => mode_id::MODE_PSK,
            (true, false) => mode_id::MODE_AUTH,
            (true, true) => mode_id::MODE_AUTH_PSK
        };

        let psk = psk.unwrap_or_default();
        
        let derivation_output: Array<u8, Sum<LK, Sum<LN, LE>>> = self.kdf.derive_self_secrets_label_others(
            [(psk.val.len() as u16).to_be_bytes().as_slice(), &psk.val, &(shared_secret.len() as u16).to_be_bytes(), shared_secret],
            b"secret",
            [ &[mode], (psk.id.len() as u16).to_be_bytes().as_slice(), psk.id, &(info.len() as u16).to_be_bytes(), info]).map_err(|_|())?;

        let (key, remainder) = derivation_output.split::<LK>();
        let (nonce, export) = remainder.split::<LN>();

        Ok((key, nonce, export))
    }
    
    fn derive_exported_value<L: ArraySize> (&self, exporter_secret: &Array<u8, Self::LE>, exporter_context: &[u8]) 
        -> Result<Array<u8,L>, ()>
    {
        self.kdf.derive_self_secret_label_others::<L>(
            exporter_secret, 
            b"sec", 
            [&L::U16.to_be_bytes(), exporter_context]
        ).map_err(|_|())
    }
    
}



pub struct KeyGenKdfWrapper<G, K> (PhantomData<K>, PhantomData<G>);

impl<G,K,SK> DeriveKeyPairFromSeed<SK> for KeyGenKdfWrapper<G,K>
where G: DeriveKeyPairFromSeed<SK, Error=()>,
    K: Kdf + Default,
{
    type SeedSize = G::SeedSize;
    type PublicKey = G::PublicKey;
    type Error = ();

    fn derive_keypair_from_seed( seed: &[u8]) -> Result<(SK, Self::PublicKey), Self::Error> {
        let whitened_seed: Array<u8, G::SeedSize> = K::derive_secret_other ( seed, &[]).map_err(|_|())?;
        G::derive_keypair_from_seed(&whitened_seed)
    }
}


// //impl<K: Kdf + Default, C: Curve + CurveArithmetic + PointCompression, const Z: bool> KdfKeyAgreement for KemKdf<K,C,Z>
// impl<K: TwoStepKdf + Default, const KEM_ID: u16, C: Curve + CurveArithmetic + PointCompression> KdfKeyAgreement for KemKdf<K,KEM_ID>
// where <C as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
//     <C as CurveArithmetic>::AffinePoint: ToEncodedPoint<C> + FromEncodedPoint<C>,
// {
//     type PublicKey = elliptic_curve::PublicKey<C>;
//     type SharedSecret = elliptic_curve::ProjectivePoint<C>;
//     fn derive<L:ArrayLength<u8>> (&self, raw_shared_secret: &Self::SharedSecret, ephemeral_pub: &Self::PublicKey, recipient_pub: &Self::PublicKey ) -> GenericArray<u8, L>
//     {
//         return K::derive_secret_others (elliptic_curve::group::Curve::to_affine(raw_shared_secret).x().as_ref(), [elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(ephemeral_pub, Z).as_bytes(), elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(recipient_pub, Z).as_bytes()]);
//     }
// }


// #[derive(Clone)]
// pub struct KemKdf2<H: TwoStepKdf, C: Curve, const KEM_ID: u16> {
//     phantom: PhantomData<H>,
//     phantom2: PhantomData<C>,
// }

// impl <const KEM_ID: u16, H: TwoStepKdf, C: Curve > KemKdf2<H, C, KEM_ID,> {
//     const SUITE_ID:[u8;5] = [ 'K' as u8, 'E' as u8, 'M' as u8, (KEM_ID>>8) as u8, (KEM_ID&0xFF) as u8];
// }

// impl <const KEM_ID: u16, H:TwoStepKdf, C: Curve > Default for KemKdf2<H, C, KEM_ID> {
//     fn default () -> Self {
//         return KemKdf2 { phantom: PhantomData, phantom2: PhantomData }
//     }
// }

// // impl <const KEM_ID: u16, H:TwoStepKdf, C: Curve > Kdf for KemKdf2<H, C, KEM_ID>
// // {
// //     fn derive_self_secrets_others_into<'a,'b>( &mut self, secret: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), digest::InvalidBufferSize>  {
// //         let eae_prk = labeled_extract::<H>(secret, &Self::SUITE_ID, b"eae_prk", &[] );
// //         return labeled_expand::<H>(eae_prk.as_ref(), &Self::SUITE_ID, b"shared_secret", other_data, out);
// //     }
// // }

// //impl<K: Kdf + Default, C: Curve + CurveArithmetic + PointCompression, const Z: bool> KdfKeyAgreement for KemKdf<K,C,Z>
// impl<K: TwoStepKdf + Default, const KEM_ID: u16, C: Curve + CurveArithmetic + PointCompression> KemKdf for KemKdf2<K,C,KEM_ID>
// where <C as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
//     <C as CurveArithmetic>::AffinePoint: ToEncodedPoint<C> + FromEncodedPoint<C>,
// {
//     type PublicKey = elliptic_curve::PublicKey<C>;
//     type SharedSecret = elliptic_curve::ProjectivePoint<C>;
//     fn derive<L:ArrayLength<u8>> (&self, raw_shared_secret: &Self::SharedSecret, ephemeral_pub: &Self::PublicKey, recipient_pub: &Self::PublicKey ) -> GenericArray<u8, L>
//     {
//         let mut out = GenericArray::default();
//         //return K::derive_secret_others (elliptic_curve::group::Curve::to_affine(raw_shared_secret).x().as_ref(), [elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(ephemeral_pub, false).as_bytes(), elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(recipient_pub, false).as_bytes()]);
//         let eae_prk = labeled_extract::<K>([elliptic_curve::group::Curve::to_affine(raw_shared_secret).x().as_ref()], &Self::SUITE_ID, b"eae_prk", &[] );
//         labeled_expand::<K>(eae_prk.as_ref(), &Self::SUITE_ID, b"shared_secret", [elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(ephemeral_pub, false).as_bytes(), elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(recipient_pub, false).as_bytes()], &mut out).unwrap();
//         return out;
//     }
// }

// impl<K: TwoStepKdf + Default, const KEM_ID: u16, C: Curve + CurveArithmetic + PointCompression> KemKdfAuth for KemKdf2<K,C,KEM_ID>
// where <C as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
//     <C as CurveArithmetic>::AffinePoint: ToEncodedPoint<C> + FromEncodedPoint<C>,
// {
//     type PublicKey = elliptic_curve::PublicKey<C>;
//     type SharedSecret = elliptic_curve::ProjectivePoint<C>;
    
//     fn derive<L: ArrayLength<u8>>(&self, raw_shared_secret_1: &Self::SharedSecret, raw_shared_secret_2: &Self::SharedSecret, ephemeral_pub: &Self::PublicKey, recipient_pub: &Self::PublicKey, sender_pub: &Self::PublicKey ) -> GenericArray<u8, L> {
//         let mut out = GenericArray::default();
//         //return K::derive_secret_others (elliptic_curve::group::Curve::to_affine(raw_shared_secret).x().as_ref(), [elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(ephemeral_pub, false).as_bytes(), elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(recipient_pub, false).as_bytes()]);
//         let eae_prk = labeled_extract::<K>([elliptic_curve::group::Curve::to_affine(raw_shared_secret_1).x().as_ref(), elliptic_curve::group::Curve::to_affine(raw_shared_secret_2).x().as_ref()], &Self::SUITE_ID, b"eae_prk", &[] );
//         labeled_expand::<K>(eae_prk.as_ref(), &Self::SUITE_ID, b"shared_secret", [elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(ephemeral_pub, false).as_bytes(), elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(recipient_pub, false).as_bytes(),
//             elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(sender_pub, false).as_bytes()], &mut out).unwrap();
//         return out;
//     }

// }


#[cfg(test)]
mod tests{
    use aead::consts::U64;
    use hex_literal::hex;
    use kems::generic_array::typenum::consts::{U12,U16,U32};
    use sha2::Sha512;
    use crate::{aead_id, kdf_id, kem_id};

    use super::*;

   
    #[test]
    #[allow(non_snake_case, unused)]
    fn test_rfc_9180_a_1_1 () {
        let mode = 0;
        const KEM_ID:u16 = 32;
        const KDF_ID:u16 = 1;
        const AEAD_ID:u16 = 1;
        
        let info = hex!("4f6465206f6e2061204772656369616e2055726e");
        // let ikmE = hex!("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");
        let pkEm = hex!("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
        // let skEm = hex!("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736");
        // let ikmR = hex!("6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037");
        let pkRm = hex!("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
        // let skRm = hex!("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
        // let enc = hex!("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
        let raw_shared_secret = hex!("B3B5C19EAB3F088AC18F23F774FF6414BA4FDE45404D10085EFC3E4DC9C72E35");
        let shared_secret = hex!("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc");
        let key_schedule_context = hex!("00725611c9d98c07c03f60095cd32d400d8347d45ed670\
            97bbad50fc56da742d07cb6cffde367bb0565ba28bb02c90744a20f5ef37f3052352\
            6106f637abb05449" );
        let secret = hex!("12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397");
        let key= hex!("4531685d41d65f03dc48f6b8302c05b0");
        let base_nonce = hex!("56d890e5accaaf011cff4b7d");
        let exporter_secret = hex!("45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8");
       
        let mut kemkdf = KdfForKemUsingHkdf::<sha2::Sha256,kem_id::DhKemX25519HkdfSha256>::default(); //new(&pkrm);
        
        let shared_secret2: Array<u8, U32> = kemkdf.derive_self_secret_others(&raw_shared_secret, [pkEm.as_ref(), pkRm.as_ref()]).unwrap();

        assert_eq! ( shared_secret2, shared_secret);

        let kdf = HpkeTwoStepKdf::from(KdfForKdfUsingHkdf::<sha2::Sha256, kem_id::DhKemX25519HkdfSha256,kdf_id::HkdfSha256,aead_id::Aes128Gcm>::default());
        let (key2, base_nonce2, exporter_secret2) = kdf.derive::<U16, U12, U32>
          (false, &shared_secret, &info, None).unwrap();      

        assert_eq! ( key2, key);
        assert_eq! ( base_nonce2, base_nonce);
        assert_eq! ( exporter_secret2, exporter_secret);

    }

    #[test]
    fn test_rfc_9180_a_4_1 () {
        //let mode= 0;
        const _KEM_ID:u16 = 16; //
        const _KDF_ID:u16 = 3;
        const _AEAD_ID:u16 = 1;

        let pkrm=hex!("04085aa5b665dc3826f9650ccbcc471be268c8ada866422f739e2d531d4a88
            18a9466bc6b449357096232919ec4fe9070ccbac4aac30f4a1a53efcf7af90610edd");
        let pkem=hex!("0493ed86735bdfb978cc055c98b45695ad7ce61ce748f4dd63c525a3b8d53a
            15565c6897888070070c1579db1f86aaa56deb8297e64db7e8924e72866f9a472580");
        let raw_shared_secret = hex!("006370637DB37EF68F3A550B9ABAB6A4B9A34A168F342926DA1425A16849A095");
       
        let info=hex!("4f6465206f6e2061204772656369616e2055726e");
        
        let shared_secret=hex!("02f584736390fc93f5b4ad039826a3fa08e9911bd1215a3db8e8791ba533cafd");
        let _key_schedule_context=hex!("005b8a3617af7789ee716e7911c7e77f84cdc4cc46e60f
            b7e19e4059f9aeadc00585e26874d1ddde76e551a7679cd47168c466f6e1f705cc93
            74c192778a34fcd5ca221d77e229a9d11b654de7942d685069c633b2362ce3b3d8ea
            4891c9a2a87a4eb7cdb289ba5e2ecbf8cd2c8498bb4a383dc021454d70d46fcbbad1
            252ef4f9");
        let _secret=hex!("0c7acdab61693f936c4c1256c78e7be30eebfe466812f9cc49f0b58dc970
            328dfc03ea359be0250a471b1635a193d2dfa8cb23c90aa2e25025b892a725353eeb");
        let key=hex!("090ca96e5f8aa02b69fac360da50ddf9");
        let base_nonce=hex!("9c995e621bf9a20c5ca45546");
        let exporter_secret = hex!("4a7abb2ac43e6553f129b2c5750a7e82d149a76ed56dc342d7b
            ca61e26d494f4855dff0d0165f27ce57756f7f16baca006539bb8e4518987ba61048
            0ac03efa8");
       
        let result: Array<u8, U32> = KdfForKemUsingHkdf::<sha2::Sha256,kem_id::DhKemP256HkdfSha256>::derive_secret_others(&raw_shared_secret, [pkem.as_ref(), pkrm.as_ref()]).unwrap();
        assert! ( result.0 == shared_secret);

        let kdf = HpkeTwoStepKdf::from(KdfForKdfUsingHkdf::<Sha512, kem_id::DhKemP256HkdfSha256,kdf_id::HkdfSha512,aead_id::Aes128Gcm>::default());
        
        let (key2, nonce, exporter_secret2) = kdf.derive::<U16, U12, U64>
            (false, &shared_secret, &info, None).unwrap();

        assert! ( key2 == key );
        assert! ( nonce == base_nonce);
        assert! ( exporter_secret2 == exporter_secret);

    }

    
    #[test]
    fn test_rfc_9180_a_5_1 () {
        //let mode= 0;
        const _KEM_ID: u16 = 16;
        const _KDF_ID: u16 = 1;
        const _AEAD_ID: u16 = 3;
       
        let pkem=hex!("04c07836a0206e04e31d8ae99bfd549380b072a1b1b82e563c935c09582782
                    4fc1559eac6fb9e3c70cd3193968994e7fe9781aa103f5b50e934b5b2f387e381291");
        let pkrm=hex!("04a697bffde9405c992883c5c439d6cc358170b51af72812333b015621dc0f
                    40bad9bb726f68a5c013806a790ec716ab8669f84f6b694596c2987cf35baba2a006");
        let raw_shared_secret=hex!("A65D78F0F0B1A25E3F63A1447A8EC2EA0CB84B9B0D2E76332C8A92253BA4ACE2");
       
        let info=hex!("4f6465206f6e2061204772656369616e2055726e");
         
        let shared_secret=hex!("806520f82ef0b03c823b7fc524b6b55a088f566b9751b89551c170f4113bd850");
        let _key_schedule_context=hex!("00b738cd703db7b4106e93b4621e9a19c89c838e559642
                40e5d3f331aaf8b0d58b2e986ea1c671b61cf45eec134dac0bae58ec6f63e790b140
                0b47c33038b0269c");
        let _secret=hex!("fe891101629aa355aad68eff3cc5170d057eca0c7573f6575e91f9783e1d4506");
        let key=hex!("a8f45490a92a3b04d1dbf6cf2c3939ad8bfc9bfcb97c04bffe116730c9dfe3fc");
        let base_nonce=hex!("726b4390ed2209809f58c693");
        let exporter_secret=hex!("4f9bd9b3a8db7d7c3a5b9d44fdc1f6e37d5d77689ade5ec44a7242016e6aa205");

        let result: Array<u8, U32> = KdfForKemUsingHkdf::<sha2::Sha256,kem_id::DhKemP256HkdfSha256>::derive_secret_others(&raw_shared_secret, [pkem.as_ref(), pkrm.as_ref()]).unwrap(); 

        assert! ( result == shared_secret);

        let labelled_kdf = HpkeTwoStepKdf::from(KdfForKdfUsingHkdf::<sha2::Sha256, kem_id::DhKemP256HkdfSha256,kdf_id::HkdfSha256,aead_id::ChaCha20Poly1305>::default());
        let (key2, nonce, exporter_secret2) = labelled_kdf.derive::<U32, U12, U32>( false, &shared_secret, &info, None).unwrap();
        
        assert! ( key2 == key );
        assert! ( nonce == base_nonce);
        assert! ( exporter_secret2 == exporter_secret);

    }


}




// pub trait LabeledTwoStepKdf: TwoStepKdf 
// {
//     type IkmLength: Unsigned + ArraySize;
//     const SUITE_ID: &[u8];
//     fn labeled_extract<'a> ( secret: impl IntoIterator<Item=&'a[u8]> + Clone, label: &'a[u8], salt: & 'a[u8]) -> Array<u8, Self::IkmLength>
//     {
//         Self::Extract::derive_secrets_salt_others([ b"HPKE-v1".as_slice(), Self::SUITE_ID, &label], salt, secret).unwrap()
//     }
//     fn labeled_expand<'a, 'b> ( secret: &Array<u8, Self::IkmLength>, label: &[u8], fields: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), kdfs::Error>
//     {
//         let len_in_array = (out.len() as u16).to_be_bytes();
//         let mut other_data: Vec<&[u8]> = vec! [ &len_in_array, b"HPKE-v1", Self::SUITE_ID, label];

//         fields.into_iter().for_each( |v| other_data.push(v));
    
//         Self::Expand::derive_self_secret_others_into(&mut Self::Expand::default(), &secret, other_data, out)
//     }
//     fn labeled_expand_fixed<'a,'b, N: ArraySize> ( secret: &Array<u8, Self::IkmLength>, label: &[u8], fields: impl IntoIterator<Item=&'b[u8]> + Clone ) -> Array<u8, N>
//     {
//         let mut out = Array::default();
//         Self::labeled_expand(secret, label, fields, &mut out).unwrap();
//         out
//     }
// }


// fn labeled_extract<'a, K: TwoStepKdf> ( secret: impl IntoIterator<Item=&'a[u8]> + Clone, label: &'a[u8], salt: & 'a[u8]) -> Array<u8, K::Extract>
// where K::Extract as 
// {
//     K::Extract::derive_secrets_salt_others([ b"HPKE-v1".as_slice(), Self::SUITE_ID, &label], salt, secret)
// }
// fn labeled_expand<'a, 'b> ( secret: &Array<u8, Self::IkmLength>, label: &[u8], fields: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), kdfs::Error>
// {
//     let len_in_array: [u8;2] = (out.len() as u16).to_be_bytes();
//     let mut other_data: Vec<&[u8]> = vec! [ &len_in_array, b"HPKE-v1", Self::SUITE_ID, label];

//     fields.into_iter().for_each( |v| other_data.push(v));

//     Self::Expand::derive_self_secret_others_into(&mut Self::Expand::default(), &secret, other_data, out)
// }




//impl<H,L1,L2> Tkdf<LabelledKtf1::<HmacReset<H>, L1>, LabelledKpf1::<HmacReset<H>, L2>>
// pub trait LabelledTkdf
// {
//     type Extract: KdfFixed;
//     type Expand: Kdf;

//     //fn labeled_extract<'a> ( secret: impl IntoIterator<Item=&'a[u8]> + Clone, label: &'a[u8], salt: & 'a[u8]) -> Array<u8, <Self::Extract as KdfFixed>::OutputSize>;
//     // {
//     //     H::Extract::derive_secrets_salt_others([ b"HPKE-v1".as_slice(), L::LABEL, &label], salt, secret).unwrap()
//     // }
//     //fn labeled_expand<'a, 'b> ( secret: &Array<u8, <Self::Extract as KdfFixed>::OutputSize>, label: &[u8], fields: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), kdfs::Error>;
//     // {
//     //     let len_in_array = (out.len() as u16).to_be_bytes();
//     //     let mut other_data: Vec<&[u8]> = vec! [ &len_in_array, b"HPKE-v1", L::LABEL, label];

//     //     fields.into_iter().for_each( |v| other_data.push(v));
    
//     //     H::Expand::derive_self_secret_others_into(&mut H::Expand::default(), &secret, other_data, out)
//     // }
//     //fn labeled_expand_fixed<'a,'b, N: ArraySize> ( secret: &Array<u8, <Self::Extract as KdfFixed>::OutputSize>, label: &[u8], fields: impl IntoIterator<Item=&'b[u8]> + Clone ) -> Array<u8, N>;
//     // {
//     //     let mut out = Array::default();
//     //     Self::labeled_expand(secret, label, fields, &mut out).unwrap();
//     //     out
//     // }
// }
// impl<M,L1,L2> LabelledTkdf for Tkdf<LabelledKtf1::<M, L1>, LabelledKpf1::<M, L2>>
// where M: Mac + FixedOutputReset + Default + Clone + KeyInit,
//     L1: Label,
//     L2: Label,
// {
//     type Extract = Ktf1::<M>;
//     type Expand = Kpf1::<M, u8>;

//     // fn labeled_extract<'a> ( secret: impl IntoIterator<Item=&'a[u8]> + Clone, label: &'a[u8], salt: & 'a[u8]) -> Array<u8, <Self::Extract as KdfFixed>::OutputSize>
//     // {
//     //     Self::Extract::derive_secrets_salt_others([ b"HPKE-v1".as_slice(), L1::LABEL, &label], salt, secret).unwrap()
//     //     //LabelledKtf1::<M,L1>::derive_self_secrets_label_others(&self, secrets, label, others)//Self::Extract::derive_self_secrets_label_others(&self, secrets, label, others)
//     // }

//     // fn labeled_expand<'a, 'b> ( secret: &Array<u8, <Self::Extract as KdfFixed>::OutputSize>, label: &[u8], fields: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), kdfs::Error>
//     // {
//     //     // let len_in_array = (out.len() as u16).to_be_bytes();
//     //     // let mut other_data: Vec<&[u8]> = vec! [ &len_in_array, b"HPKE-v1", L2::LABEL, label];

//     //     // fields.into_iter().for_each( |v| other_data.push(v));
    
//     //     // Self::Expand::derive_self_secret_others_into(&mut Self::Expand::default(), &secret, other_data, out)

//     //     let kdf = LabelledKpf1::<M,L2>::default();
//     //     kdf.derive_self_secrets_label_others_into( once(secret.as_slice()), label, fields, out)
//     // }
//     // fn labeled_expand_fixed<'a,'b, N: ArraySize> ( secret: &Array<u8, <Self::Extract as KdfFixed>::OutputSize>, label: &[u8], fields: impl IntoIterator<Item=&'b[u8]> + Clone ) -> Array<u8, N>
//     // {
//     //     let mut out = Array::default();
//     //     Self::labeled_expand(secret, label, fields, &mut out).unwrap();
//     //     out
//     // }

// }




// #[derive(Clone)]
//pub struct HpkeKemKdf<H: TwoStepKdf, I: Unsigned> {
// pub struct HpkeLabelledKdf<H: TwoStepKdf, L: Label> {
//     phantom: PhantomData<H>,
//     phantom2: PhantomData<L>
// }

// impl <I: Unsigned, H: TwoStepKdf > HpkeKemKdf<H, I> {
//     const SUITE_ID:[u8;5] = [ 'K' as u8, 'E' as u8, 'M' as u8, (I::U16>>8) as u8, (I::U16&0xFF) as u8];
// }

// impl <H:TwoStepKdf, L:Label > Default for HpkeLabelledKdf<H, L> {
//     fn default () -> Self {
//         return HpkeLabelledKdf { phantom: PhantomData, phantom2: PhantomData }
//     }
// }

// impl <H:TwoStepKdf, L: Label> LabeledTwoStepKdf for HpkeLabelledKdf<H, L>
// where <<H as TwoStepKdf>::Extract as KdfFixed>::OutputSize: ArraySize
// {
//     type IkmLength = <H::Extract as KdfFixed>::OutputSize;
//     //const SUITE_ID:&[u8] = &[ 'K' as u8, 'E' as u8, 'M' as u8, (I::U16>>8) as u8, (I::U16&0xFF) as u8];
//     const SUITE_ID:&[u8]= L::LABEL;
// }


// impl <H:TwoStepKdf, L:Label> HpkeLabelledKdf<H,L> 
// where <<H as TwoStepKdf>::Extract as KdfFixed>::OutputSize: ArraySize
// {
    // pub fn labeled_extract<'a> ( secret: impl IntoIterator<Item=&'a[u8]> + Clone, label: &'a[u8], salt: & 'a[u8]) -> Array<u8, <H::Extract as KdfFixed>::OutputSize>
    // {
    //     H::Extract::derive_secrets_salt_others([ b"HPKE-v1".as_slice(), L::LABEL, &label], salt, secret).unwrap()
    // }
    // pub fn labeled_expand<'a, 'b> ( secret: &Array<u8, <H::Extract as KdfFixed>::OutputSize>, label: &[u8], fields: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), kdfs::Error>
    // {
    //     let len_in_array = (out.len() as u16).to_be_bytes();
    //     let mut other_data: Vec<&[u8]> = vec! [ &len_in_array, b"HPKE-v1", L::LABEL, label];

    //     fields.into_iter().for_each( |v| other_data.push(v));
    
    //     H::Expand::derive_self_secret_others_into(&mut H::Expand::default(), &secret, other_data, out)
    // }
    // pub fn labeled_expand_fixed<'a,'b, N: ArraySize> ( secret: &Array<u8, <H::Extract as KdfFixed>::OutputSize>, label: &[u8], fields: impl IntoIterator<Item=&'b[u8]> + Clone ) -> Array<u8, N>
    // {
    //     let mut out = Array::default();
    //     Self::labeled_expand(secret, label, fields, &mut out).unwrap();
    //     out
    // }
// }

// This is an implementation of the default kdf interface such that is can be used as part of a KEM
// The HPKE requires the KEM KDF to extract the 'eak_prk' secret, and then derive a shared secret
// Kdf described in RFC 9180 - Hybrid Public Key Encryption (HPKE), section 4.1 Encap, where the shared_secret is 
// derived from the dh output, ephemeral public key, recipient public key and label "eae_prk"
// This KDF is used for ECDH key derivation and forms the other input as a concatenation
// of the takes an input the two public keys
// impl <H:TwoStepKdf, L: Label> Kdf for HpkeLabelledKdf<H, L>
// where <<H as TwoStepKdf>::Extract as KdfFixed>::OutputSize: ArraySize,
// {
//     fn derive_self_secrets_others_into<'a,'b>( &self, secret: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), kdfs::Error>  {
//         //let eae_prk = labeled_extract::<H>(secret, &Self::SUITE_ID, b"eae_prk", &[] );
//         let eae_prk = Self::labeled_extract(secret, b"eae_prk", &[]);
//         //return labeled_expand::<H>(eae_prk.as_slice(), &Self::SUITE_ID, b"shared_secret", other_data, out);
//         Self::labeled_expand(&eae_prk, b"shared_secret", other_data, out)
//     }
// }

// impl<H:TwoStepKdf, L:Label> TwoStepKdf for HpkeLabelledKdf<H,L>
// {
//     type Expand = H::Expand;
//     type Extract = H::Extract;
// }




// ///
// /// KDF used within RFC 9180 to derive the symmetric encyption/decryption key, nonce and exporter secret
// /// It uses a Two Step KDF with derivation values of the KEM ID, KDF ID and AEAD ID
// /// 
// //pub struct HpkeLabeledTwoStepKdf<H: TwoStepKdf, IE: Unsigned, KID: Unsigned, A: Unsigned> (
// pub struct HpkeLabeledTwoStepKdf<H: TwoStepKdf, L: Label> (
//     PhantomData<H>,
//     PhantomData<L>,
//     // PhantomData<IE>,
//     // PhantomData<KID>,
//     // PhantomData<A>,
// );

// //impl <H:TwoStepKdf, IE: Unsigned, KID: Unsigned, A: Unsigned > Default for HpkeLabeledTwoStepKdf<H, IE, KID, A> {
// impl <H:TwoStepKdf, L:Label> Default for HpkeLabeledTwoStepKdf<H, L> {
//     fn default () -> Self {
//         //HpkeLabeledTwoStepKdf (PhantomData::<H>, PhantomData::<IE>, PhantomData::<KID>, PhantomData::<A> )
//         HpkeLabeledTwoStepKdf (PhantomData::<H>, PhantomData::<L> )
//     }
// }
// //impl<H:TwoStepKdf, IE: Unsigned, KID: Unsigned, A: Unsigned> TwoStepKdf for HpkeLabeledTwoStepKdf<H, IE, KID, A>
// impl<H:TwoStepKdf, L:Label> TwoStepKdf for HpkeLabeledTwoStepKdf<H, L>
// {
//     type Expand = H::Expand;
//     type Extract = H::Extract;
// }

// //impl <H:TwoStepKdf, IE: Unsigned, KID: Unsigned, A: Unsigned > LabeledTwoStepKdf for HpkeLabeledTwoStepKdf<H, IE, KID, A>
// impl <H:TwoStepKdf, L:Label> LabeledTwoStepKdf for HpkeLabeledTwoStepKdf<H, L>
// where <<H as TwoStepKdf>::Extract as KdfFixed>::OutputSize: ArraySize
// {
//     type IkmLength = <H::Extract as KdfFixed>::OutputSize;
//     //const SUITE_ID: &[u8] = &['H' as u8, 'P' as u8, 'K' as u8, 'E' as u8, (IE::U16>>8) as u8, IE::U8 as u8, (KID::U16>>8) as u8, KID::U16 as u8, (A::U16>>8) as u8, A::U16 as u8];
//     const SUITE_ID: &[u8] = L::LABEL; //&['H' as u8, 'P' as u8, 'K' as u8, 'E' as u8, (IE::U16>>8) as u8, IE::U8 as u8, (KID::U16>>8) as u8, KID::U16 as u8, (A::U16>>8) as u8, A::U16 as u8];
        
// }






//
// Implementation of the one step Kdf designed for use with Kems
// The H generic parameter is the underlying kdf to use, typically an Xof function
// The I generic parameter is the Kem identifer
// 
// #[derive(Clone)]
// //pub struct HpkeKemOneStepKdf<K: Kdf, I: Unsigned> {
// pub struct HpkeKemOneStepKdf<K: Kdf, L: Label> {
//     phantom: PhantomData<K>,
//     phantom2: PhantomData<L>
// }

// impl <K: Kdf, L: Label> HpkeKemOneStepKdf<K, L> {
//     const SUITE_ID:&[u8] = L::LABEL; //[ 'K' as u8, 'E' as u8, 'M' as u8, (I::U16>>8) as u8, (I::U16&0xFF) as u8];
// }

// impl <K:Kdf, L:Label> Default for HpkeKemOneStepKdf<K, L> {
//     fn default () -> Self {
//         return HpkeKemOneStepKdf { phantom: PhantomData, phantom2: PhantomData }
//     }
// }

// impl <K:Kdf+Default, L:Label > Kdf for HpkeKemOneStepKdf<K, L>
// {
//     fn derive_self_secrets_others_into<'a,'b>( &self, secrets: impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), kdfs::Error> {
//         let label = b"DeriveKeyPair";
//         let secret = secrets.into_iter().next().unwrap();
//         let output_len = out.len();
//         let kdf = K::default();

//         kdf.derive_self_secrets_others_into(
//                 [secret,
//                 b"HPKE-v1",
//                 &L::LABEL,
//                 &(label.len() as u16).to_be_bytes(), label.as_slice(),
//                 &(output_len as u16).to_be_bytes()], 
//             other_data, out)
//     }
// }

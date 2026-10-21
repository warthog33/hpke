//!
//! KDFs used within HPKE
//! There are two main types,
//! two step kdf as described in the original RFC 9180 and
//! one step kdf introduced in draft-ietf-hpke-pq
//! 
use std::marker::PhantomData;
use std::ops::{Add, Sub};

use crate::{mode_id};

use aead::array::typenum::{Diff, Sum, Unsigned};
use kdfs::{Kdf, KdfFixed, SaltedKdfFixed, Label, TwoStepKdf};
use kdfs::hybrid_array::{Array, ArraySize};
use kem::KeySizeUser;



/// Label used for the HPKE version, used to derive the shared secret from the shared secret and other inputs
#[derive(Clone)]
pub struct LabelHpkeV1 ();
impl Label for LabelHpkeV1
{
    const LABEL: &[u8] = b"HPKE-v1";
}

/// Label used for the KEM, used to derive the shared secret from the shared secret and other inputs
#[derive(Clone)]
pub struct LabelKem<KemId: Unsigned> (PhantomData<KemId>);
impl<KemId: Unsigned> Label for LabelKem<KemId>
{
    const LABEL: &[u8] = &[b'K', b'E', b'M', (KemId::U16>>8) as u8, KemId::U16 as u8];
}

/// Label used for the extract function in the KEM, used to derive the extracted secret from the shared secret and other inputs
// #[derive(Clone)]
// pub struct LabelKemExtract ();
// impl Label for LabelKemExtract
// {
//     const LABEL: &[u8] = b"eae_prk";
// }

/// Label used for the expand function in the KEM, used to derive the shared secret from the extracted secret
// #[derive(Clone)]
// pub struct LabelKemExpand ();
// impl Label for LabelKemExpand
// {
//     const LABEL: &[u8] = b"shared_secret";
// }

/// Label used for the extract function in the key generation functions, used to derive a secret from the shared secret and other inputs which is then used to generate candidate keys
// #[derive(Clone)]
// pub struct LabelKeyGenExtract ();
// impl Label for LabelKeyGenExtract
// {
//     const LABEL: &[u8] = b"dkp_prk";
// }

/// Label used for the expand function in the key generation functions, used to derive a secret from the shared secret and other inputs which is then used to generate candidate keys
pub struct LabelKeyDerive ();
impl Label for LabelKeyDerive
{
    const LABEL: &'static[u8] = &[0u8, 13u8, b'D', b'e', b'r', b'i', b'v', b'e', b'K', b'e', b'y', b'P', b'a', b'i', b'r']; 
}

/// Label used for the expand function in the key generation functions, used to derive a secret from the shared secret and other inputs which is then used to generate candidate keys
// #[derive(Clone)]
// pub struct LabelKeyGenExpand ();
// impl Label for LabelKeyGenExpand
// {
//     const LABEL: &[u8] = b"sk";
// }

/// Label used for the expand function in the key generation functions, used to derive a secret from the shared secret and other inputs which is then used to generate candidate keys
// pub struct LabelSec ();
// impl Label for LabelSec
// {
//     const LABEL: &[u8] = b"sec";
// }

// pub struct LabelSecret ();
// impl Label for LabelSecret
// {
//     const LABEL: &[u8] = b"secret";
// }

/// Label used for the KDF in the key generation functions, used to derive a secret from the shared secret and other inputs which is then used to generate candidate keys
// pub struct LabelKeyGenCandidate ();
// impl Label for LabelKeyGenCandidate
// {
//     const LABEL: &[u8] = b"candidate";
// }

// pub struct LabelPskIdHash ();
// impl Label for LabelPskIdHash
// {
//     const LABEL: &[u8] = b"psk_id_hash";
// }

/// Label used for the KDF in the key generation functions, used to derive a secret from the shared secret and other inputs which is then used to generate candidate keys
pub struct LabelKdf<KemId: Unsigned, KdfId: Unsigned, AeadId: Unsigned> ( PhantomData<KemId>, PhantomData<KdfId>, PhantomData<AeadId>);

impl<KemId: Unsigned, KdfId: Unsigned, AeadId: Unsigned> Label for LabelKdf <KemId, KdfId, AeadId>
{
    const LABEL: &'static[u8] = &[b'H', b'P', b'K', b'E', (KemId::U16>>8) as u8, KemId::U8 as u8, (KdfId::U16>>8) as u8, KdfId::U16 as u8, (AeadId::U16>>8) as u8, AeadId::U16 as u8];
}

/// Empty label, used where no label is required, or where the label is specified in other ways
// #[derive(Clone)]
// pub struct LabelNone();
// impl Label for LabelNone
// {
//     const LABEL: &'static[u8] = &[]; 
// }



// pub trait KeySizeUser {
//     type KeySize: ArraySize;
// }
/// Trait definition for a kdf suitable for use within Hpke
/// Only two methods are defined
///  1. derive, which returns the key, nonce and expoert_secrets from the shared_secet, info and psk
///  2. export_secret, which returns an exporter value derived from the exporter_secret
pub trait HpkeKdf<LK: ArraySize, LN: ArraySize> : KeySizeUser
{
    fn derive<'a, LB: Label> ( is_auth: bool, shared_secret: &'a[u8], info: &'a[u8], psk: Option<Psk> ) 
        -> (Array<u8,LK>, Array<u8,LN>, Array<u8,Self::KeySize>);
}

pub trait HpkeKdfExporter<L>  : KeySizeUser//: From<Self::K>
where L: ArraySize
{
    fn derive_exported_value(exporter_secret: &Array<u8, Self::KeySize>, exporter_context: &[u8], label: &'static [u8]) -> Array<u8,L>;
}

pub trait Export<L: ArraySize>
{
    fn export(&self, exporter_context: &[u8] ) -> Array<u8, L>;
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
/// use kdfs::{rfc5869_hkdf::Hkdf};
/// use hpke::{hpke_kdf::{HpkeTwoStageKdf, HpkeKdf, LabelKdf}, kem_id, kdf_id, aead_id};
/// use hex_literal::hex;
/// use kdfs::hybrid_array::{Array, typenum::consts::{U12, U16, U32}};
///
/// let shared_secret=hex!("02f584736390fc93f5b4ad039826a3fa08e9911bd1215a3db8e8791ba533cafd");
/// let info=hex!("4f6465206f6e2061204772656369616e2055726e");
/// let key=hex!("090ca96e5f8aa02b69fac360da50ddf9");
/// 
/// let (key_calc, nonce, exporter_secret2): (Array<u8, U16>, Array<u8, U12>, _) = HpkeTwoStageKdf::<Hkdf<Sha512>>::derive::<LabelKdf::<kem_id::DhKemP256HkdfSha256,kdf_id::HkdfSha512,aead_id::Aes128Gcm>>
///            (false, &shared_secret, &info, None);
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
pub struct HpkeTwoStageKdf<K: TwoStepKdf> 
where <K::Extract as KdfFixed>::OutputSize: ArraySize
{
    phantom: PhantomData<K>
}


impl<K: TwoStepKdf + Default> Default for HpkeTwoStageKdf<K>
{
    fn default() -> Self {
        Self{phantom: PhantomData}
    }
}

impl<K: TwoStepKdf> KeySizeUser for HpkeTwoStageKdf<K>
{
    type KeySize = <K::Extract as KdfFixed>::OutputSize;
}
impl<K,LK,LN> HpkeKdf<LK,LN> for HpkeTwoStageKdf<K> 
where   K: TwoStepKdf + 'static + Default,
        <K::Extract as KdfFixed>::OutputSize: ArraySize,
        K::Expand: Kdf<LK> + Kdf<LN> + Kdf<<K::Extract as KdfFixed>::OutputSize>,
        LN: ArraySize + Add<<K::Extract as KdfFixed>::OutputSize>,
        LK: ArraySize + Add<Sum<LN,<K::Extract as KdfFixed>::OutputSize>>,
{
    fn derive<'a, SuiteId: Label> ( is_auth: bool, shared_secret: &'a[u8], info: &'a[u8], psk: Option<Psk> ) 
        -> (Array<u8,LK>, Array<u8,LN>, Array<u8,Self::KeySize>)
    {
        let mode = match (is_auth, psk.is_some()) {
            (false, false) => mode_id::MODE_BASE,
            (false, true) => mode_id::MODE_PSK,
            (true, false) => mode_id::MODE_AUTH,
            (true, true) => mode_id::MODE_AUTH_PSK
        };
        let psk = psk.unwrap_or_default();

        let psk_id_hash: Array<u8, Self::KeySize> = K::Extract::derive_secret_others_fixed( psk.id, [LabelHpkeV1::LABEL, SuiteId::LABEL, b"psk_id_hash"] );
        let info_hash: Array<u8, Self::KeySize> = K::Extract::derive_secret_others_fixed( info, [LabelHpkeV1::LABEL, SuiteId::LABEL, b"info_hash"]);
        let secret: Array<u8, Self::KeySize> = K::Extract::derive_secrets_salt_others_fixed( Some(psk.val), shared_secret, [LabelHpkeV1::LABEL, SuiteId::LABEL, b"secret"]);

        let key = K::Expand::derive_secret_others(secret.as_ref(), [&LK::U16.to_be_bytes(), LabelHpkeV1::LABEL, SuiteId::LABEL, b"key", &[mode], psk_id_hash.as_slice(), &info_hash]);
        let base_nonce = K::Expand::derive_secret_others(secret.as_ref(), [&LN::U16.to_be_bytes(), LabelHpkeV1::LABEL, SuiteId::LABEL, b"base_nonce", &[mode], psk_id_hash.as_slice(), &info_hash]);
        let exporter_secret = K::Expand::derive_secret_others(secret.as_ref(), [&Self::KeySize::U16.to_be_bytes(),LabelHpkeV1::LABEL, SuiteId::LABEL, b"exp", &[mode], psk_id_hash.as_slice(), &info_hash]);
        (key, base_nonce, exporter_secret)
    }

}


impl<K,L> HpkeKdfExporter<L> for HpkeTwoStageKdf<K> 
where   K: TwoStepKdf + 'static + Default,
        <K::Extract as KdfFixed>::OutputSize: ArraySize,
        L: ArraySize,
        K::Expand: Kdf<L>,
{
    fn derive_exported_value(exporter_secret: &Array<u8, Self::KeySize>, exporter_context: &[u8], label: &'static [u8]) -> Array<u8,L>
    {
        K::Expand::derive_secret_others(exporter_secret.as_ref(), [&L::U16.to_be_bytes(), LabelHpkeV1::LABEL, label, b"sec", exporter_context])
    }
}

///
/// Single step kdf typically based on an expandable output function
/// Defined in draft_ietf_hpke_pq
/// 
pub struct HpkeOneStageKdf<K, E> {
    phantom: PhantomData<K>,
    phantom2: PhantomData<E>
}

impl<K: Default, E: ArraySize> Default for HpkeOneStageKdf<K,E>
{
    fn default() -> Self {
        Self { phantom: PhantomData, phantom2: PhantomData }
    }
}

/// This KDF is used in the one stage KDF mode defined in draft-ietf-hpke-pq
impl<K: Default, E: ArraySize> KeySizeUser for HpkeOneStageKdf<K,E>
{
    type KeySize = E;
}


impl<K: Default + Clone, E: ArraySize, LK: ArraySize, LN: ArraySize> HpkeKdf<LK, LN> for HpkeOneStageKdf<K,E>
where LN: Add<E>,
    LK: Add<Sum<LN,E>>,
    Sum<LK, Sum<LN, E>>: ArraySize + Sub<LK>,
    Diff<Sum<LK, Sum<LN, E>>, LK>: ArraySize + Sub<LN, Output=E>,
    K: Kdf<Sum<LK, Sum<LN, E>>>,
{
    fn derive<'a, LB: Label> ( is_auth: bool, shared_secret: &'a[u8], info: &'a[u8], psk: Option<Psk> ) 
        -> (Array<u8,LK>, Array<u8,LN>, Array<u8,Self::KeySize>)
    {
        let mode = match (is_auth, psk.is_some()) {
            (false, false) => mode_id::MODE_BASE,
            (false, true) => mode_id::MODE_PSK,
            (true, false) => mode_id::MODE_AUTH,
            (true, true) => mode_id::MODE_AUTH_PSK
        };

        let psk = psk.unwrap_or_default();
        
        let derivation_output: Array<u8, Sum<LK, Sum<LN, Self::KeySize>>> = K::derive_secrets_others(
            [(psk.val.len() as u16).to_be_bytes().as_slice(), &psk.val, &(shared_secret.len() as u16).to_be_bytes(), shared_secret],
            [LabelHpkeV1::LABEL, LB::LABEL, &[0, 6], b"secret", 
            &Sum::<LK, Sum<LN, Self::KeySize>>::U16.to_be_bytes(),
            &[mode], 
            (psk.id.len() as u16).to_be_bytes().as_slice(), psk.id, 
            &(info.len() as u16).to_be_bytes(), info]);

        let (key, remainder) = derivation_output.split::<LK>();
        let (nonce, export) = remainder.split::<LN>();

        (key, nonce, export)
    }
}


impl<K,E,L> HpkeKdfExporter<L> for HpkeOneStageKdf<K,E> 
where K: Default + Kdf<L>,  
    E: ArraySize,
    L: ArraySize,
{
    fn derive_exported_value(exporter_secret: &Array<u8, Self::KeySize>, exporter_context: &[u8], label: &'static [u8]) -> Array<u8,L> {
        K::derive_secret_others(exporter_secret.as_ref(), [&LabelHpkeV1::LABEL, label, &[0,3], b"sec", &L::U16.to_be_bytes(), exporter_context])
    }
}



#[cfg(test)]
mod tests{
    use kdfs::iso11770_6::{Kpf1, Ktf1, Tkdf};
    use hex_literal::hex;
    use kem::consts::*;
    use sha2::{Sha256,Sha512};
    use crate::{aead_id, kdf_id, kem_id};
    use super::*;
    use hmac::HmacReset;
   
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
       
        let secret: Array<u8, U32> = <Ktf1::<hmac::HmacReset<sha2::Sha256>> as KdfFixed>
                ::derive_secret_others_fixed( &raw_shared_secret, [LabelHpkeV1::LABEL, LabelKem::<kem_id::DhKemX25519HkdfSha256>::LABEL, b"eae_prk"]);
            
        let shared_secret2 = <Kpf1::<hmac::HmacReset<sha2::Sha256>,u8> as kdfs::Kdf<U32>>
                ::derive_secret_others(secret.as_ref(), [&U32::U16.to_be_bytes(), LabelHpkeV1::LABEL, LabelKem::<kem_id::DhKemX25519HkdfSha256>::LABEL, b"shared_secret", &pkEm, &pkRm]);

        assert_eq! ( shared_secret2, shared_secret);

        
        let (key2, base_nonce2, exporter_secret2): (Array<u8, U16>,Array<u8, U12>,_) = HpkeTwoStageKdf::<Tkdf<Ktf1<HmacReset<Sha256>>, Kpf1<HmacReset<sha2::Sha256>,u8>>>::
            derive::<LabelKdf::<kem_id::DhKemX25519HkdfSha256,kdf_id::HkdfSha256,aead_id::Aes128Gcm>> (false, &shared_secret, &info, None);

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
       
        let secret: Array<u8, U32> = <Ktf1::<hmac::HmacReset<sha2::Sha256>> as KdfFixed>
                ::derive_secret_others_fixed( &raw_shared_secret, [LabelHpkeV1::LABEL, LabelKem::<kem_id::DhKemP256HkdfSha256>::LABEL, b"eae_prk"]);
        
        let result = <Kpf1::<hmac::HmacReset<sha2::Sha256>,u8> as kdfs::Kdf<U32>>
                ::derive_secret_others(secret.as_ref(), [&U32::U16.to_be_bytes(), LabelHpkeV1::LABEL, LabelKem::<kem_id::DhKemP256HkdfSha256>::LABEL, b"shared_secret", &pkem, &pkrm]);

        assert! ( result == shared_secret);
       
        let (key2, nonce, exporter_secret2): (Array<u8, U16>,Array<u8,U12>,_) = HpkeTwoStageKdf::<Tkdf<Ktf1<HmacReset<Sha512>>, Kpf1<HmacReset<Sha512>,u8>>>::derive::</*U16, U12, U64,*/ LabelKdf::<kem_id::DhKemP256HkdfSha256,kdf_id::HkdfSha512,aead_id::Aes128Gcm>>
            (false, &shared_secret, &info, None);

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

     
        let secret = <Ktf1::<HmacReset<Sha256>> as KdfFixed>
                ::derive_secret_others_fixed( &raw_shared_secret, [LabelHpkeV1::LABEL, LabelKem::<kem_id::DhKemP256HkdfSha256>::LABEL, b"eae_prk"]);
        
        let result = <Kpf1::<HmacReset<Sha256>,u8> as kdfs::Kdf<U32>>
                ::derive_secret_others(secret.as_ref(), [&U32::U16.to_be_bytes(), LabelHpkeV1::LABEL, LabelKem::<kem_id::DhKemP256HkdfSha256>::LABEL, b"shared_secret", &pkem, &pkrm]);


        assert! ( result == shared_secret);

        let (key2, nonce, exporter_secret2): (Array<u8, U32>,Array<u8, U12>,_) = HpkeTwoStageKdf::<Tkdf<Ktf1<HmacReset<Sha256>>, Kpf1<HmacReset<Sha256>,u8>>>::derive::</*U32, U12, U32,*/ LabelKdf::<kem_id::DhKemP256HkdfSha256,kdf_id::HkdfSha256,aead_id::ChaCha20Poly1305>>
            (false, &shared_secret, &info, None);

        assert! ( key2 == key );
        assert! ( nonce == base_nonce);
        assert! ( exporter_secret2 == exporter_secret);

    }


}



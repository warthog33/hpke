
use aead::{Aead, Payload};
use elliptic_curve::{consts::*};
use elliptic_curve::SecretKey;
use hex_literal::hex;

use hpke::{kem_id, kdf_id, aead_id, HpkeEcKeyGen};
use hpke::hpke_kdf::{Psk, HpkeKdf, LabelKdf,KeyGenKdfWrapper};
use hpke::hpke_types::k256_kems::{HpkeAuthKemSecP256k1HkdfSha256, HpkeKemSecP256k1HkdfSha256};
use hpke::hpke_types::p256_kems::{HpkeKemP256HkdfSha256, HpkeKemKdfP256HkdfSha256, HpkeKeyGenKdfP256HkdfSha256,HpkeAuthKemP256HkdfSha256};
use hpke::hpke_types::p521_kems::{HpkeKemP521HkdfSha512, HpkeAuthKemP521HkdfSha512 };
use hpke::hpke_types::sha2_kdfs::{HpkeHkdfSha256,HpkeHkdfSha512};
use hpke::hpke_types::x25519_kems::{HpkeKeyGenKdfX25519HkdfSha256, HpkeKemX25519HkdfSha256,HpkeKemKdfX25519HkdfSha256};
use hpke::hpke_types::{HpkeAuthIesK256Sha256Aes128Gcm, HpkeAuthIesK256Sha256Aes256Gcm, HpkeAuthIesK256Sha256ChaCha20Poly1305, HpkeIesK256Sha256Aes128Gcm, HpkeIesK256Sha256Aes256Gcm, HpkeIesP256Sha512Aes128Gcm};
use hpke::hpke_types::{HpkeIesP521Sha512Aes256Gcm,HpkeAuthIesX25519Sha256ExportOnly,HpkeAuthIesP256Sha512Aes128Gcm,HpkeAuthIesP521Sha512Aes256Gcm,HpkeIesX25519Sha256ExportOnly,HpkeIesP256Sha256ChaCha20Poly1305};
use hpke::hpke_types::{HpkeEcdhKem, HpkeIesP256Sha256Aes128Gcm, HpkeAuthIesX25519Sha256Aes128Gcm, HpkeIesX25519Sha256Aes128Gcm,HpkeIesK256Sha256ChaCha20Poly1305, HpkeIesX25519Sha256ChaCha20Poly1305};
use kdfs::hybrid_array::Array;

use kems::{Decapsulate,FromKeys, EncodedSizeUser2,Capsulator, DeriveKeyPairFromSeed,GenerateCapsulatorFromSeed, EncapsulateDeterministic2};
use kems::eckem::{SeedAsScalar,EcUncompressedEncoder, EcdhAuthCapsulator, EcdhAuthCapsulatorUncompressed};
use kems::generic_array::GenericArray;
use kems::kem_with_kdf::{KemAuthWithKdfDecapsulator, KemAuthWithKdfEncapsulator, CombinerAllPubKeys, KemAuthWithKdf};
use kems::x25519kem::X25519AuthCapsulator;

use p256::NistP256;
use p521::NistP521;


#[test]
#[allow(non_snake_case)]
fn test_rfc_9180_a_1_1 () {
    //mode: 0
    //kem_id: 32
    //kdf_id: 1
    //aead_id: 1
    let info = hex!("4f6465206f6e2061204772656369616e2055726e");
    let ikmE = hex!("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");
    let _pkEm = hex!("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
    let _skEm = hex!("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736");
    let ikmR = hex!("6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037");
    let pkRm = hex!("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
    let skRm = hex!("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
    let enc = hex!("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
    let shared_secret = hex!("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc");
    let _key_schedule_context = hex!("00725611c9d98c07c03f60095cd32d400d8347d45ed670\
            97bbad50fc56da742d07cb6cffde367bb0565ba28bb02c90744a20f5ef37f3052352\
            6106f637abb05449" );
    let _secret = hex!("12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397");
    let key= hex!("4531685d41d65f03dc48f6b8302c05b0");
    let base_nonce = hex!("56d890e5accaaf011cff4b7d");
    let exporter_secret = hex!("45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8");

    let (encapsulator, decapsulator) = HpkeKemX25519HkdfSha256::derive_from_seed(&ikmR.into());
    assert_eq! ( encapsulator.as_bytes(), pkRm.into());
    assert_eq! ( decapsulator.as_bytes(), skRm.into());
    
    let encapsulator = HpkeKemX25519HkdfSha256::from_bytes_encap(&pkRm.into());
    let decapsulator = HpkeKemX25519HkdfSha256::from_bytes_decap(&skRm.into());

    let (c0_send, k_send) = encapsulator.encapsulate_deterministic(&ikmE).unwrap();
    assert_eq! ( c0_send, enc.into() );
    assert_eq! ( k_send, shared_secret );
    
    let k_recv: Array<u8, U32> = decapsulator.decapsulate(&c0_send).unwrap();
    assert_eq!( k_recv, shared_secret );

    // Derive the keys
//     let kdf = LabelledTkdf1::<HmacReset<Sha256>,LabelHpkeV1>::new_with_label::<LabelKdf::<kem_id::DhKemX25519HkdfSha256,kdf_id::HkdfSha256,aead_id::Aes128Gcm>>().into();
//     let (key2, base_nonce2, exporter_secret2) = HpkeHkdfSha256::derive::<U16, U12, U32>( &kdf, false, &shared_secret, &info, None).unwrap();
    let (key2, base_nonce2, exporter_secret2) = HpkeHkdfSha256::derive::<U16, U12, U32, LabelKdf::<kem_id::DhKemX25519HkdfSha256,kdf_id::HkdfSha256,aead_id::Aes128Gcm>>( false, &shared_secret, &info, None).unwrap();
    assert! ( key2 == key);
    assert! ( base_nonce2 == base_nonce);
    assert! ( exporter_secret2 == exporter_secret);

    // Repeat using all inclusive struct
    let (encryptor, decryptor) = HpkeIesX25519Sha256Aes128Gcm::derive_pair_from_seed(&ikmR).unwrap();
    assert_eq! ( encryptor.get_encapsulator().as_bytes(), pkRm.into());
    assert_eq! ( decryptor.get_decapsulator().as_bytes(), skRm.into());
    
    //sequence number: 0
    let pt = hex!("4265617574792069732074727574682c20747275746820626561757479");
    let aad = hex!("436f756e742d30");
    let _nonce = hex!("56d890e5accaaf011cff4b7d");
    let ct = hex!("f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9 6d8770ac83d07bea87e13c512a");

    //let mut pred_rng = PredictableRng::new(&skEm);

    // Single shot
    let (c0_send, ct_send) = encryptor.single_shot_seal_deterministic(&ikmE, Payload{msg: &pt, aad: &aad}, &info, None).unwrap();
    assert! ( c0_send == enc.into());
    assert! ( ct_send == &ct );
    let pt_2 = decryptor.single_shot_open(&c0_send, &info, Payload{msg:&ct, aad:&aad}, None ).unwrap();
    assert! ( pt_2 == pt);
    
    // Dual calls
    let (c0_send2, mut context_send) = encryptor.setup_sender_cipher_deterministic(&ikmE, &info, None).unwrap();
    let ct2 = context_send.seal(Payload{msg: &pt, aad: &aad}).unwrap();
    assert! ( c0_send2 == enc.into());
    assert! ( ct2 == &ct );
    let mut context_recv = decryptor.setup_receiver_cipher(&c0_send, &info, None).unwrap();
    let pt4 = context_recv.open(Payload{msg:&ct, aad:&aad}).unwrap();
    assert! ( pt4 == pt );

    //sequence number: 1
    let pt=hex!("4265617574792069732074727574682c20747275746820626561757479");
    let aad=hex!("436f756e742d31");
    let _nonce=hex!("56d890e5accaaf011cff4b7c");
    let ct=hex!("af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab25 1c03d0c22a56b8ca42c2063b84");

    // Dual call, as it is the only method that supports multiple messages
    let ct3 = context_send.seal(Payload{msg:&pt, aad:&aad}).unwrap();
    assert! ( ct3 == &ct);
    let pt3 = context_recv.open(Payload{msg:&ct, aad:&aad}).unwrap();
    assert! ( pt3 == &pt);
}



//
// Test from A.1.4 in RFC 9180
// Authenticated encryption using X25519 and AES GCM
//
#[test]
#[allow(non_snake_case)]
fn test_rfc_9180_a_1_4 () {
    //mode: 3
    //kem_id: 32
    //kdf_id: 1
    //aead_id: 1
    let info = hex!("4f6465206f6e2061204772656369616e2055726e");
    let ikmE = hex!("4303619085a20ebcf18edd22782952b8a7161e1dbae6e46e143a52a96127cf84");
    let pkEm = hex!("820818d3c23993492cc5623ab437a48a0a7ca3e9639c140fe1e33811eb844b7c");
    let skEm = hex!("14de82a5897b613616a00c39b87429df35bc2b426bcfd73febcb45e903490768");
    let ikmR = hex!("4b16221f3b269a88e207270b5e1de28cb01f847841b344b8314d6a622fe5ee90");
    let pkRm = hex!("1d11a3cd247ae48e901939659bd4d79b6b959e1f3e7d66663fbc9412dd4e0976");
    let skRm = hex!("cb29a95649dc5656c2d054c1aa0d3df0493155e9d5da6d7e344ed8b6a64a9423");
    let ikmS = hex!("62f77dcf5df0dd7eac54eac9f654f426d4161ec850cc65c54f8b65d2e0b4e345");
    let pkSm = hex!("2bfb2eb18fcad1af0e4f99142a1c474ae74e21b9425fc5c589382c69b50cc57e");
    let skSm = hex!("fc1c87d2f3832adb178b431fce2ac77c7ca2fd680f3406c77b5ecdf818b119f4");
    let psk = hex!("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82");
    let psk_id = hex!("456e6e796e20447572696e206172616e204d6f726961");

    let enc = hex!("820818d3c23993492cc5623ab437a48a0a7ca3e9639c140fe1e33811eb844b7c");
    let shared_secret = hex!("f9d0e870aba28d04709b2680cb8185466c6a6ff1d6e9d1091d5bf5e10ce3a577");
    let _key_schedule_context = hex!("03 e78d5cf6190d275863411ff5edd0dece5d39fa48e04eec1ed9b71be34729d18c cb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449" );
    let _secret = hex!("5f96c55e4108c6691829aaabaa7d539c0b41d7c72aae94ae289752f056b6cec4");
    let key= hex!("1364ead92c47aa7becfa95203037b19a");
    let base_nonce = hex!("99d8b5c54669807e9fc70df1");
    let exporter_secret = hex!("f048d55eacbf60f9c6154bd4021774d1075ebf963c6adc71fa846f183ab2dde6");

    let (skRm1, pkRm1):(x25519_dalek::StaticSecret, x25519_dalek::PublicKey) = KeyGenKdfWrapper::<SeedAsScalar, HpkeKeyGenKdfX25519HkdfSha256>::derive_keypair_from_seed(&ikmR).unwrap();
    assert_eq! ( skRm1.as_bytes(), &skRm);
    assert_eq! ( pkRm1.as_bytes(), &pkRm);

    let (skSm1, pkSm1):(x25519_dalek::StaticSecret, x25519_dalek::PublicKey) = KeyGenKdfWrapper::<SeedAsScalar, HpkeKeyGenKdfX25519HkdfSha256>::derive_keypair_from_seed(&ikmS).unwrap();
    assert_eq! ( skSm1.as_bytes(), &skSm);
    assert_eq! ( pkSm1.as_bytes(), &pkSm);

    let (skEm1, pkEm1):(x25519_dalek::StaticSecret, x25519_dalek::PublicKey) = KeyGenKdfWrapper::<SeedAsScalar, HpkeKeyGenKdfX25519HkdfSha256>::derive_keypair_from_seed(&ikmE).unwrap();
    assert_eq! ( skEm1.as_bytes(), &skEm);
    assert_eq! ( pkEm1.as_bytes(), &pkEm);

    //let mut pred_rng = PredictableRng::new(&skEm);

    // Perform asymmetric key encapsulation and decapsulation
    let encapsulator = KemAuthWithKdf::<X25519AuthCapsulator<KeyGenKdfWrapper<SeedAsScalar, HpkeKeyGenKdfX25519HkdfSha256>>, CombinerAllPubKeys, HpkeKemKdfX25519HkdfSha256, U32 >::encap_from_keys(pkRm.into(), skSm.into());
    //let (c0_send, k_send) = encapsulator.encapsulate(&mut pred_rng).unwrap();
    let (c0_send, k_send) = encapsulator.encapsulate_deterministic(&ikmE).unwrap();
    assert_eq! ( c0_send, enc.into() );
    assert_eq! ( k_send, shared_secret );
    
    let decapsulator = KemAuthWithKdf::<X25519AuthCapsulator<KeyGenKdfWrapper<SeedAsScalar, HpkeKeyGenKdfX25519HkdfSha256>>, CombinerAllPubKeys, HpkeKemKdfX25519HkdfSha256, U32 >::decap_from_keys(pkSm.into(), skRm.into());
    let k_recv: Array<u8, U32> = decapsulator.decapsulate(&c0_send).unwrap();
    assert_eq!( k_recv, shared_secret );

    // Derive working keys
    //let kdf = LabelledTkdf1::<HmacReset<Sha256>,LabelHpkeV1>::new_with_label::<LabelKdf::<kem_id::DhKemX25519HkdfSha256,kdf_id::HkdfSha256,aead_id::Aes128Gcm>>().into();
    
    let (key2, nonce2, exporter_secret2) = HpkeHkdfSha256::derive::<U16, U12, U32,LabelKdf::<kem_id::DhKemX25519HkdfSha256,kdf_id::HkdfSha256,aead_id::Aes128Gcm>> ( true, &shared_secret, &info, Some(Psk{id: &psk_id, val: &psk})).unwrap();
    assert! ( key2 == key);
    assert! ( nonce2 == base_nonce);
    assert! ( exporter_secret2 == exporter_secret);

    //sequence number: 0
    let pt = hex!("4265617574792069732074727574682c20747275746820626561757479");
    let aad = hex!("436f756e742d30");
    let _nonce = hex!("99d8b5c54669807e9fc70df1");
    let ct = hex!("a84c64df1e11d8fd11450039d4fe64ff0c8a99fca0bd72c2d4c3e0400bc14a40 f27e45e141a24001697737533e");

    let encryptor = HpkeAuthIesX25519Sha256Aes128Gcm::auth_encryptor_from_keys(pkRm.into(), skSm.into());
    let decryptor = HpkeAuthIesX25519Sha256Aes128Gcm::auth_decryptor_from_keys(skRm.into(), pkSm.into());

    // Single shot technique
    //let mut pred_rng = PredictableRng::new(&skEm);
    let (c0_send, ct_send) = encryptor.single_shot_seal_deterministic(&ikmE, Payload{msg: &pt, aad:&aad}, &info, Some(Psk{val:&psk, id: &psk_id})).unwrap();
    assert! ( c0_send == enc.into() );
    assert! ( ct_send == ct );

    let pt_2 = decryptor.single_shot_open(&c0_send, &info, Payload{msg:&ct, aad:&aad}, Some(Psk{val:&psk, id:&psk_id}) ).unwrap();
    assert! (pt_2 == pt);

    // Double call technique
    let (c0_send2, mut ctx_send) = encryptor.setup_sender_cipher_deterministic(&ikmE, &info, Some(Psk{val:&psk, id:&psk_id})).unwrap();
    let ct_send2 = ctx_send.seal ( Payload{msg: &pt, aad:&aad} ).unwrap();
    assert! ( c0_send2 == enc.into());
    assert! ( ct_send2 == ct);
    
    let mut ctx_recv = decryptor.setup_receiver_cipher(&c0_send, &info, Some(Psk{val:&psk, id:&psk_id})).unwrap();
    let pt_recv = ctx_recv.open ( Payload{msg:&ct, aad:&aad} ).unwrap();
    assert_eq!(pt_recv, pt);

    //sequence number: 1
    let pt = hex!("4265617574792069732074727574682c20747275746820626561757479");
    let aad = hex!("436f756e742d31");
    let _nonce = hex!("99d8b5c54669807e9fc70df0");
    let ct = hex!("4d19303b848f424fc3c3beca249b2c6de0a34083b8e909b6aa4c3688505c05ff e0c8f57a0a4c5ab9da127435d9");

    // Second message reques the context (multi-call) method
    let ct3 = ctx_send.seal(Payload{msg:&pt, aad:&aad}).unwrap();
    assert! ( ct3 == ct);
    let pt3 = ctx_recv.open(Payload{msg:&ct, aad:&aad}).unwrap();
    assert! ( pt3 == pt);
}



#[test]
#[allow(non_snake_case)]
fn test_rfc_9180_a_2_1 () {
    //mode: 0
    //kem_id: 32
    //kdf_id: 1
    //aead_id: 3
    let info = hex!("4f6465206f6e2061204772656369616e2055726e");
    let ikmE = hex!("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b");
    let pkEm = hex!("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
    let skEm = hex!("f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600");
    let ikmR = hex!("1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df");
    let pkRm = hex!("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a");
    let skRm = hex!("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
    let enc = hex!("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
    let shared_secret = hex!("0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7");
    let _key_schedule_context = hex!("00431df6cd95e11ff49d7013563baf7f11588c75a6611e
        e2a4404a49306ae4cfc5b69c5718a60cc5876c358d3f7fc31ddb598503f67be58ea1
        e798c0bb19eb9796");
    let _secret = hex!("5b9cd775e64b437a2335cf499361b2e0d5e444d5cb41a8a53336d8fe402282c6");
    let key = hex!("ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91");
    let base_nonce = hex!(" 5c4d98150661b848853b547f");
    let exporter_secret = hex!("a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922");

    let (encapsulator, decapsulator) = HpkeKemX25519HkdfSha256::derive_from_seed(&ikmR.into());
    assert_eq!( encapsulator.as_bytes(), pkRm.into());
    assert_eq!( decapsulator.as_bytes(), skRm.into());

    let (encapsulatorE, decapsulatorE) = HpkeKemX25519HkdfSha256::derive_from_seed(&ikmE.into());
    assert_eq!( encapsulatorE.as_bytes(), pkEm.into());
    assert_eq!( decapsulatorE.as_bytes(), skEm.into());

    let encapsulator = HpkeKemX25519HkdfSha256::from_bytes_encap(&pkRm.into());
    let decapsulator = HpkeKemX25519HkdfSha256::from_bytes_decap(&skRm.into());
    
    //let mut pred_rng = PredictableRng::new(&skEm);

    let (c0_send, k_send) = encapsulator.encapsulate_deterministic(&ikmE).unwrap();
    assert_eq! ( c0_send, enc.into() );
    assert_eq! ( k_send, shared_secret );

    let k_recv: Array<u8, U32> = decapsulator.decapsulate(&c0_send).unwrap();
    assert!( k_recv == shared_secret );

    // Derive keys
    //let kdf = LabelledTkdf1::<HmacReset<Sha256>,LabelHpkeV1>::new_with_label::<LabelKdf::<kem_id::DhKemX25519HkdfSha256,kdf_id::HkdfSha256,aead_id::ChaCha20Poly1305>>().into();
    
    let (key2, base_nonce2, exporter_secret2) = HpkeHkdfSha256::derive::<U32, U12, U32,LabelKdf::<kem_id::DhKemX25519HkdfSha256,kdf_id::HkdfSha256,aead_id::ChaCha20Poly1305>> ( false, &shared_secret, &info, None).unwrap();
    assert! ( key2 == key);
    assert! ( base_nonce2 == base_nonce);
    assert! ( exporter_secret2 == exporter_secret);

    // Use hpke structures
    let (encryptor, decryptor) = HpkeIesX25519Sha256ChaCha20Poly1305::derive_pair_from_seed(&ikmR).unwrap();
    assert_eq!( encryptor.get_encapsulator().as_bytes(), pkRm.into());
    assert_eq!( decryptor.get_decapsulator().as_bytes(), skRm.into());

    let encryptor = HpkeIesX25519Sha256ChaCha20Poly1305::encryptor_from_key(pkRm.into());
    let decryptor = HpkeIesX25519Sha256ChaCha20Poly1305::decryptor_from_key(skRm.into());
    
    //let sequence number: 0
    let pt = hex!("4265617574792069732074727574682c20747275746820626561757479");
    let aad = hex!("436f756e742d30");
    let _nonce = hex!("5c4d98150661b848853b547f");
    let ct = hex!("1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db 21993c62ce81883d2dd1b51a28");

    //let mut pred_rng = PredictableRng::new(&skEm);

    let (c0_send, ct_send ) = encryptor.single_shot_seal_deterministic(&ikmE, Payload{msg: &pt, aad: &aad}, &info, None).unwrap();
    assert! ( c0_send == enc.into());
    assert! ( ct_send == &ct );

    let pt_2 = decryptor.single_shot_open(&c0_send, &info, Payload{msg: &ct, aad: &aad}, None).unwrap();
    assert! ( pt_2 == pt );
}



// A.3. DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
#[test]
fn test_rfc_9180_a_3_1 () {
    const _KEM_ID: u16 = 16;  // DHKEM(P-256, HKDF-SHA256)
    const _KDF_ID: u16 = 1;   // HKDF-SHA256
    const _AEAD_ID: u16 =  1; // AES-128-GCM

    let info = hex!( "4f6465206f6e2061204772656369616e2055726e");
    let ikme = hex!( "4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e" );
    let pkem = hex!( "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b32
                5ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4");
    let skem = hex! ("4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb" );
    let ikmr = hex! ("668b37171f1072f3cf12ea8a236a45df23fc13b82af3609ad1e354f6ef817550" );
    let pkrm = hex! ("04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f70
                6a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0");
    let skrm = hex! ( "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2");
    let enc = hex! ("04 a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac9
                                  8536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4");
    let shared_secret = hex! ( "c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8" );
    let _key_schedule_context = hex! ("00 
                b88d4e6d91759e65e87c470e8b9141113e9ad5f0c8ceefc1e088c82e69805007
                98e486f9c9c09c9b5c753ac72d6005de254c607d1b534ed11d493ae1c1d9ac85");
    let _secret = hex! ("2eb7b6bf138f6b5aff857414a058a3f1750054a9ba1f72c2cf0684a6f20b10e1");
    let key = hex! ("868c066ef58aae6dc589b6cfdd18f97e");
    let base_nonce = hex! ("4e0bc5018beba4bf004cca59");
    let exporter_secret = hex! ("14ad94af484a7ad3ef40e9f3be99ecc6fa9036df9d4920548424df127ee0d99f");

    let (pkrm3, skrm3) = HpkeEcdhKem::<NistP256, HpkeKemKdfP256HkdfSha256, U32, /*SeedAsScalar*/HpkeEcKeyGen<HpkeKeyGenKdfP256HkdfSha256>>::derive_from_seed(&Array::from(ikmr));
    assert_eq!(pkrm3.as_bytes().as_slice(), &pkrm );
    assert_eq!(skrm3.as_bytes().as_slice(), &skrm );

    let (pkem3, skem3) = HpkeKemP256HkdfSha256::derive_from_seed(&Array::from(ikme));
    assert_eq!(pkem3.as_bytes().as_slice(), &pkem );
    assert_eq!(skem3.as_bytes().as_slice(), &skem );


    //let mut pred_rng = PredictableRng::new(&skem);

    let encapsulator = <HpkeKemP256HkdfSha256 as Capsulator>::Encapsulator::from_bytes(&GenericArray::from_slice(&pkrm));
    
    let (c0_calc, k_calc ) = encapsulator.encapsulate_deterministic(&ikme).unwrap();
    assert! ( c0_calc.as_ref() == enc );
    assert! ( k_calc == shared_secret );
    
    //let kdf = LabelledTkdf1::<HmacReset<Sha256>,LabelHpkeV1>::new_with_label::<LabelKdf::<kem_id::DhKemP256HkdfSha256,kdf_id::HkdfSha256,aead_id::Aes128Gcm>>().into();
    let (key2, base_nonce2, exporter_secret2) = HpkeHkdfSha256::derive::<U16, U12, U32,LabelKdf::<kem_id::DhKemP256HkdfSha256,kdf_id::HkdfSha256,aead_id::Aes128Gcm>> ( false, &shared_secret, &info, None).unwrap();
    assert! ( key2 == key);
    assert! ( base_nonce2 == base_nonce);
    assert! ( exporter_secret2 == exporter_secret);
    
    //let _sequence_number = 0;
    let pt = hex!("4265617574792069732074727574682c20747275746820626561757479");
    let aad = hex!("436f756e742d30");
    let nonce = hex!("4e0bc5018beba4bf004cca59");
    let ct = hex! ( "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f 9076ac232e3ab2523f39513434");

    let cipher = <aes_gcm::Aes128Gcm as aes_gcm::KeyInit>::new(&key.into() );
    let payload = Payload {msg:&pt, aad: &aad};
    let ciphertext = cipher.encrypt(&nonce.into(), payload).unwrap();
    assert! ( ciphertext == ct);
    
    
    let he_encryptor = HpkeIesP256Sha256Aes128Gcm::encryptor_from_encapsulator(pkrm3); //::new();
    let recipient_secret_key = SecretKey::<NistP256>::from_bytes(&skrm.into()).unwrap();
    let he_decryptor = HpkeIesP256Sha256Aes128Gcm::decryptor_from_key(recipient_secret_key);
    
    //let mut pred_rng = PredictableRng::new(&skem);

    let (c0_send, ct_send) = he_encryptor.single_shot_seal_deterministic(&ikme, Payload{msg: &pt, aad: &aad}, &info, None).unwrap();
    assert! ( c0_send.as_ref() == enc);
    assert! ( ct_send == &ct );

    let (c0_send2, mut ctx_send) = he_encryptor.setup_sender_cipher_deterministic(&ikme, &info, None).unwrap();
    assert_eq!(c0_send2, enc.into());
    let ct5 = ctx_send.seal(Payload{msg: &pt, aad: &aad}).unwrap();
    assert_eq!(ct5, ct);

    let pt_2 = he_decryptor.single_shot_open(&c0_send, &info, Payload{msg:&ct, aad:&aad}, None).unwrap();
    assert!( pt_2 == pt);

    let mut ctx_recv = he_decryptor.setup_receiver_cipher(&c0_send, &info, None).unwrap();
    let pt_recv = ctx_recv.open ( Payload{msg:&ct, aad:&aad} ).unwrap();
    assert_eq! ( pt_recv, pt);

    // Second decryption
    //let sequence_number = 1;
    let pt = hex!("4265617574792069732074727574682c20747275746820626561757479");
    let aad = hex!("436f756e742d31");
    let _nonce = hex!("4e0bc5018beba4bf004cca58");
    let ct = hex!("fa6f037b47fc21826b610172ca9637e82d6e5801eb31cbd3748271affd4ecb06 646e0329cbdf3c3cd655b28e82");

    // Second message reques the context (multi-call) method
    let ct3 = ctx_send.seal(Payload{msg:&pt, aad:&aad}).unwrap();
    assert! ( ct3 == ct);
    let pt3 = ctx_recv.open(Payload{msg:&ct, aad:&aad}).unwrap();
    assert! ( pt3 == pt);
}





// A.4. DHKEM(P-256, HKDF-SHA256), HKDF-SHA512, AES-128-GCM
#[test]
fn test_rfc_9180_a_4_1 () {
    
    let _mode= 0;
    const _KEM_ID:u16 = 16;
    const _KDF_ID:u16 = 3;
    const _AEAD_ID:u16 = 1;
    let info=hex!("4f6465206f6e2061204772656369616e2055726e");
    let ikme=hex!("4ab11a9dd78c39668f7038f921ffc0993b368171d3ddde8031501ee1e08c4c9a");
    let pkem=hex!("0493ed86735bdfb978cc055c98b45695ad7ce61ce748f4dd63c525a3b8d53a
            15565c6897888070070c1579db1f86aaa56deb8297e64db7e8924e72866f9a472580");
    let skem=hex!("2292bf14bb6e15b8c81a0f45b7a6e93e32d830e48cca702e0affcfb4d07e1b5c");
    let ikmr=hex!("ea9ff7cc5b2705b188841c7ace169290ff312a9cb31467784ca92d7a2e6e1be8");
    let pkrm=hex!("04085aa5b665dc3826f9650ccbcc471be268c8ada866422f739e2d531d4a88
            18a9466bc6b449357096232919ec4fe9070ccbac4aac30f4a1a53efcf7af90610edd");
    let skrm=hex!("3ac8530ad1b01885960fab38cf3cdc4f7aef121eaa239f222623614b4079fb38");
    let enc=hex!("0493ed86735bdfb978cc055c98b45695ad7ce61ce748f4dd63c525a3b8d53a1
            5565c6897888070070c1579db1f86aaa56deb8297e64db7e8924e72866f9a472580");
    let shared_secret=hex!("02f584736390fc93f5b4ad039826a3fa08e9911bd1215a3db8e8791ba533cafd");
    let _key_schedule_context=hex!("005b8a3617af7789ee716e7911c7e77f84cdc4cc46e60f
            b7e19e4059f9aeadc00585e26874d1ddde76e551a7679cd47168c466f6e1f705cc93
            74c192778a34fcd5ca221d77e229a9d11b654de7942d685069c633b2362ce3b3d8ea
            4891c9a2a87a4eb7cdb289ba5e2ecbf8cd2c8498bb4a383dc021454d70d46fcbbad1
            252ef4f9");
    let _secret=hex!(" 0c7acdab61693f936c4c1256c78e7be30eebfe466812f9cc49f0b58dc970
            328dfc03ea359be0250a471b1635a193d2dfa8cb23c90aa2e25025b892a725353eeb");
    let key=hex!("090ca96e5f8aa02b69fac360da50ddf9");
    let base_nonce=hex!("9c995e621bf9a20c5ca45546");
    let exporter_secret = hex!("4a7abb2ac43e6553f129b2c5750a7e82d149a76ed56dc342d7b
            ca61e26d494f4855dff0d0165f27ce57756f7f16baca006539bb8e4518987ba61048
            0ac03efa8");

    let (pkrm3, skrm3) = HpkeKemP256HkdfSha256::derive_from_seed(&Array::from(ikmr));
    assert_eq!(pkrm3.as_bytes().as_slice(), &pkrm );
    assert_eq!(skrm3.as_bytes().as_slice(), &skrm );

    let (pkem3, skem3) = HpkeKemP256HkdfSha256::derive_from_seed(&Array::from(ikme));
    assert_eq!(pkem3.as_bytes().as_slice(), &pkem );
    assert_eq!(skem3.as_bytes().as_slice(), &skem );
    
    //let mut pred_rng = PredictableRng::new(&skem);

    let encapsulator = HpkeKemP256HkdfSha256::from_bytes_encap(&GenericArray::from_slice(&pkrm));

    let (c0_calc, k_calc) = encapsulator.encapsulate_deterministic(&ikme).unwrap();
    assert! ( c0_calc == enc.into() );
    assert! ( k_calc == shared_secret );

    // Derive keys
    //let kdf = LabelledTkdf1::<HmacReset<Sha512>,LabelHpkeV1>::new_with_label::<LabelKdf::<kem_id::DhKemP256HkdfSha256,kdf_id::HkdfSha512,aead_id::Aes128Gcm>>().into();
    
    let (key2, base_nonce2, exporter_secret2) = HpkeHkdfSha512::derive::<U16, U12, U64,LabelKdf::<kem_id::DhKemP256HkdfSha256,kdf_id::HkdfSha512,aead_id::Aes128Gcm>> ( false, &shared_secret, &info, None).unwrap();
    assert! ( key2 == key);
    assert! ( base_nonce2 == base_nonce);
    assert! ( exporter_secret2 == exporter_secret);

    //sequence number: 0
    let pt = hex!("4265617574792069732074727574682c20747275746820626561757479");
    let aad = hex!("436f756e742d30");
    let _nonce = hex!("9c995e621bf9a20c5ca45546");
    let ct = hex!("d3cf4984931484a080f74c1bb2a6782700dc1fef9abe8442e44a6f09044c8890 7200b332003543754eb51917ba");

    let he_encryptor = HpkeIesP256Sha512Aes128Gcm::encryptor_from_encapsulator(pkrm3);
    let recipient_secret_key = SecretKey::<NistP256>::from_bytes(&skrm.into()).unwrap();
    let he_decryptor = HpkeIesP256Sha512Aes128Gcm::decryptor_from_key(recipient_secret_key);
    
    //let mut pred_rng = PredictableRng::new(&skem);

    let (c0_send, ct_send) = he_encryptor.single_shot_seal_deterministic(&ikme, Payload{msg: &pt, aad: &aad}, &info, None).unwrap();
    assert! ( c0_send.as_ref() == enc);
    assert! ( ct_send == &ct );
    
    let pt_2 = he_decryptor.single_shot_open(&c0_send, &info, Payload{msg:&ct, aad:&aad}, None ).unwrap();
    assert!( pt_2 == pt);
}


// DHKEM(P-256, HKDF-SHA256), HKDF-SHA512, AES-128-GCM
// With PSK
#[test]
#[allow(non_snake_case)]
fn test_rfc_9180_a_4_2 () {
    // let mode:u8 = 1;
    // const KEM_ID:u16 = 16; // DHKEM(P-256, HKDF-SHA256)
    // const KDF_ID:u16 = 3;  // HKDF-SHA512
    // const AEAD_ID:u16 = 1; // HKDF-SHA512
    let info = hex!("4f6465206f6e2061204772656369616e2055726e");
    let ikmE = hex!("c11d883d6587f911d2ddbc2a0859d5b42fb13bf2c8e89ef408a25564893856f5");
    let pkEm = hex!("04a307934180ad5287f95525fe5bc6244285d7273c15e061f0f2efb211c350
            57f3079f6e0abae200992610b25f48b63aacfcb669106ddee8aa023feed301901371");
    let skEm = hex!("a5901ff7d6931959c2755382ea40a4869b1dec3694ed3b009dda2d77dd488f18");
    let ikmR = hex!("75bfc2a3a3541170a54c0b06444e358d0ee2b4fb78a401fd399a47a33723b700");
    let pkRm = hex!("043f5266fba0742db649e1043102b8a5afd114465156719cea90373229aabd
                    d84d7f45dabfc1f55664b888a7e86d594853a6cccdc9b189b57839cbbe3b90b55873");
    let skRm = hex!("bc6f0b5e22429e5ff47d5969003f3cae0f4fec50e23602e880038364f33b8522");
    let psk = hex!("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82");
    let psk_id = hex!("456e6e796e20447572696e206172616e204d6f726961");
    let enc = hex!("04a307934180ad5287f95525fe5bc6244285d7273c15e061f0f2efb211c3505
                7f3079f6e0abae200992610b25f48b63aacfcb669106ddee8aa023feed301901371");
    let shared_secret = hex!("2912aacc6eaebd71ff715ea50f6ef3a6637856b2a4c58ea61e0c3fc159e3bc16");
    let _key_schedule_context = hex!("01713f73042575cebfd132f0cc4338523f8eae95c80a74
                9f7cf3eb9436ff1c612ca62c37df27ca46d2cc162445a92c5f5fdc57bcde129ca7b1
                f284b0c12297c037ca221d77e229a9d11b654de7942d685069c633b2362ce3b3d8ea
                4891c9a2a87a4eb7cdb289ba5e2ecbf8cd2c8498bb4a383dc021454d70d46fcbbad1
                252ef4f9");
    let _secret = hex!("ff2051d2128d5f3078de867143e076262ce1d0aecafc3fff3d607f1eaff0
                5345c7d5ffcb3202cdecb3d1a2f7da20592a237747b6e855390cbe2109d3e6ac70c2");
    let key = hex!("0b910ba8d9cfa17e5f50c211cb32839a");
    let base_nonce = hex!("0c29e714eb52de5b7415a1b7");
    let exporter_secret = hex!("50c0a182b6f94b4c0bd955c4aa20df01f282cc12c43065a0812
                fe4d4352790171ed2b2c4756ad7f5a730ba336c8f1edd0089d8331192058c385bae3
                9c7cc8b57");

    let (pkrm3, skrm3) = HpkeKemP256HkdfSha256::derive_from_seed(&Array::from(ikmR));
    assert_eq!(pkrm3.as_bytes().as_slice(), &pkRm );
    assert_eq!(skrm3.as_bytes().as_slice(), &skRm );

    let (pkem3, skem3) = HpkeKemP256HkdfSha256::derive_from_seed(&Array::from(ikmE));
    assert_eq!(pkem3.as_bytes().as_slice(), &pkEm );
    assert_eq!(skem3.as_bytes().as_slice(), &skEm );

    //let mut pred_rng = PredictableRng::new(&skEm);

    let encapsulator = HpkeKemP256HkdfSha256::from_bytes_encap(GenericArray::from_slice(&pkRm));
    let (c0_calc, k_calc) = encapsulator.encapsulate_deterministic(&ikmE).unwrap();
    assert! ( c0_calc == enc.into() );
    assert! ( k_calc == shared_secret );

    let decapsulator = HpkeKemP256HkdfSha256::from_bytes_decap(GenericArray::from_slice(&skRm));
    let k_calc2 = decapsulator.decapsulate(&c0_calc).unwrap();
    assert! ( k_calc2 == shared_secret );

    // Derive keys
    //let kdf = LabelledTkdf1::<HmacReset<Sha512>,LabelHpkeV1>::new_with_label::<LabelKdf::<kem_id::DhKemP256HkdfSha256,kdf_id::HkdfSha512,aead_id::Aes128Gcm>>().into();

    let (key2, base_nonce2, exporter_secret2) = HpkeHkdfSha512::derive::<U16, U12, U64,LabelKdf::<kem_id::DhKemP256HkdfSha256,kdf_id::HkdfSha512,aead_id::Aes128Gcm>> ( false, &shared_secret, &info, Some(Psk{id: &psk_id, val: &psk})).unwrap();
    assert! ( key2 == key );
    assert! ( base_nonce2 == base_nonce);
    assert! ( exporter_secret2 == exporter_secret);

    //sequence number: 0
    let pt = hex!("4265617574792069732074727574682c20747275746820626561757479");
    let aad = hex!("436f756e742d30");
    let _nonce = hex!("0c29e714eb52de5b7415a1b7");
    let ct = hex!("57624b6e320d4aba0afd11f548780772932f502e2ba2a8068676b2a0d3b5129a 45b9faa88de39e8306da41d4cc");

    let he_encryptor = HpkeIesP256Sha512Aes128Gcm::encryptor_from_encapsulator(pkrm3);
    let recipient_secret_key = SecretKey::<NistP256>::from_bytes(&skRm.into()).unwrap();
    let he_decryptor = HpkeIesP256Sha512Aes128Gcm::decryptor_from_key(recipient_secret_key);
    
    //let mut pred_rng = PredictableRng::new(&skEm);

    let (c0_send, ct_send) = he_encryptor.single_shot_seal_deterministic(&ikmE, Payload{msg: &pt, aad: &aad}, &info, Some(Psk{id: &psk_id, val: &psk})).unwrap();
    assert! ( c0_send.as_ref() == enc);
    assert! ( ct_send == &ct );
    
    let pt_2 = he_decryptor.single_shot_open(&c0_send, &info, Payload{msg:&ct, aad:&aad}, Some(Psk{id: &psk_id, val: &psk}) ).unwrap();
    assert!( pt_2 == pt);

}

// DHKEM(P-256, HKDF-SHA256), HKDF-SHA512, AES-128-GCM
// Authenticated

#[test]
#[allow(non_snake_case)]
fn test_rfc_9180_a_4_3 () {
    // let mode = 2; // - mode_auth
    // const KEM_ID:u16 = 16; //- DHKEM(P-256, HKDF-SHA256)
    // const KDF_ID:u16 = 3; //- HKDF-SHA512
    // const AEAD_ID:u16 = 1; //- AES-128-GCM
    let info = hex!("4f6465206f6e2061204772656369616e2055726e"); 
    let ikmE = hex!("6bb031aa9197562da0b44e737db2b9e61f6c3ea1138c37de28fc37ac29bc7350");
    let pkEm = hex!("04fec59fa9f76f5d0f6c1660bb179cb314ed97953c53a60ab38f8e6ace60fd"
                    "59178084d0dd66e0f79172992d4ddb2e91172ce24949bcebfff158dcc417f2c6e9c6");
    let skEm = hex!("93cddd5288e7ef4884c8fe321d075df01501b993ff49ffab8184116f39b3c655");

    let ikmR = hex!("649a3f92edbb7a2516a0ade0b7dccc58a37240c4ba06f9726a952227b4adf6ff");
    let pkRm = hex!("04378bad519aab406e04d0e5608bcca809c02d6afd2272d4dd03e9357bd0ee
                    e8adf84c8deba3155c9cf9506d1d4c8bfefe3cf033a75716cc3cc07295100ec96276");
    let skRm = hex!("1ea4484be482bf25fdb2ed39e6a02ed9156b3e57dfb18dff82e4a048de990236");

    let ikmS = hex!("4d79b8691aab55a7265e8490a04bb3860ed64dece90953ad0dc43a6ea59b4bf2");
    let pkSm = hex!("0404d3c1f9fca22eb4a6d326125f0814c35593b1da8ea0d11a640730b215a2
                    59b9b98a34ad17e21617d19fe1d4fa39a4828bfdb306b729ec51c543caca3b2d9529");
    let skSm = hex!("02b266d66919f7b08f42ae0e7d97af4ca98b2dae3043bb7e0740ccadc1957579");
    let enc = hex!("04fec59fa9f76f5d0f6c1660bb179cb314ed97953c53a60ab38f8e6ace60fd591
                    78084d0dd66e0f79172992d4ddb2e91172ce24949bcebfff158dcc417f2c6e9c6");
    let shared_secret = hex!("1ed49f6d7ada333d171cd63861a1cb700a1ec4236755a9cd5f9f8f67a2f8e7b3");
    let _key_schedule_context = hex!("025b8a3617af7789ee716e7911c7e77f84cdc4cc46e60f
                b7e19e4059f9aeadc00585e26874d1ddde76e551a7679cd47168c466f6e1f705cc93
                74c192778a34fcd5ca221d77e229a9d11b654de7942d685069c633b2362ce3b3d8ea
                4891c9a2a87a4eb7cdb289ba5e2ecbf8cd2c8498bb4a383dc021454d70d46fcbbad1
                252ef4f9");
    let _secret = hex!("9c846ba81ddbbd57bc26d99da6cf7ab956bb735ecd47fe21ed14241c70791b74
                       84c1d06663d21a5d97bf1be70d56ab727f650c4f859c5ed3f71f8928b3c082dd");
    let key = hex!(" 9d4b1c83129f3de6db95faf3d539dcf1");
    let base_nonce = hex!("ea4fd7a485ee5f1f4b62c1b7");
    let exporter_secret = hex!("ca2410672369aae1afd6c2639f4fe34ca36d35410c090608d2924f60def17f91
                                0d7928575434d7f991b1f19d3e8358b8278ff59ced0d5eed4774cec72e12766e");

    let (pkRm3, skRm3) = HpkeKemP256HkdfSha256::derive_from_seed(&ikmR.into());
    assert_eq!( pkRm3.as_bytes(), pkRm.into());
    assert_eq!( skRm3.as_bytes(), skRm.into());
    let (pkSm3, skSm3) = HpkeKemP256HkdfSha256::derive_from_seed(&ikmS.into());
    assert_eq!( pkSm3.as_bytes(), pkSm.into());
    assert_eq!( skSm3.as_bytes(), skSm.into());
    let (pkEm3, skEm3) = HpkeKemP256HkdfSha256::derive_from_seed(&ikmE.into());
    assert_eq!( pkEm3.as_bytes(), pkEm.into());
    assert_eq!( skEm3.as_bytes(), skEm.into());
        
    let encapsulator = KemAuthWithKdfEncapsulator::<EcdhAuthCapsulatorUncompressed::<_,HpkeEcKeyGen<HpkeKeyGenKdfP256HkdfSha256>>, CombinerAllPubKeys, HpkeKemKdfP256HkdfSha256, U32>::from_keys(pkRm3.encapsulator.recipient_public, skSm3.decapsulator.recipient_private);
    let (c0_calc, k_calc) = encapsulator.encapsulate_deterministic(&ikmE).unwrap();
    assert! ( c0_calc.as_ref() == enc );
    assert! ( k_calc == shared_secret );

    let decapsulator = KemAuthWithKdfDecapsulator::<EcdhAuthCapsulator::<_, EcUncompressedEncoder<NistP256>,HpkeEcKeyGen<HpkeKeyGenKdfP256HkdfSha256>>, CombinerAllPubKeys, HpkeKemKdfP256HkdfSha256, U32>::from_keys(pkSm3.encapsulator.recipient_public, skRm3.decapsulator.recipient_private);
    let k_calc2 = decapsulator.decapsulate(&c0_calc).unwrap();
    assert! ( k_calc2 == shared_secret );

    // Derive keys
    //let kdf = LabelledTkdf1::<HmacReset<Sha512>,LabelHpkeV1>::new_with_label::<LabelKdf::<kem_id::DhKemP256HkdfSha256,kdf_id::HkdfSha512,aead_id::Aes128Gcm>>().into();

    let (key2, base_nonce2, exporter_secret2) = HpkeHkdfSha512::derive::<U16, U12, U64,LabelKdf::<kem_id::DhKemP256HkdfSha256,kdf_id::HkdfSha512,aead_id::Aes128Gcm>> (true, &shared_secret, &info, None).unwrap();
    assert! ( key2 == key );
    assert! ( base_nonce2 == base_nonce);
    assert! ( exporter_secret2 == exporter_secret);

    //sequence number: 0
    let pt = hex!("4265617574792069732074727574682c20747275746820626561757479");
    let aad = hex!("436f756e742d30");
    let _nonce = hex!("ea4fd7a485ee5f1f4b62c1b7");
    let ct = hex!("2480179d880b5f458154b8bfe3c7e8732332de84aabf06fc440f6b31f169e154 157fa9eb44f2fa4d7b38a9236e");

    let encryptor = HpkeAuthIesP256Sha512Aes128Gcm::auth_encryptor_from_encapsulator(encapsulator);
    let decryptor = HpkeAuthIesP256Sha512Aes128Gcm::auth_decryptor_from_decapsulator(decapsulator);
    
    //let mut pred_rng = PredictableRng::new(&skEm);

    let (c0_send, ct_send) = encryptor.single_shot_seal_deterministic(&ikmE, Payload{msg: &pt, aad: &aad}, &info, None).unwrap();
    assert! ( c0_send.as_ref() == enc);
    assert! ( ct_send == &ct );
    
    let pt_2 = decryptor.single_shot_open(&c0_send, &info, Payload{msg:&ct, aad:&aad}, None ).unwrap();
    assert!( pt_2 == pt);
}


#[test]
#[allow(non_snake_case)]
fn test_rfc_9180_a_4_4 () {
    // let mode = 3;
    // let kem_id = 16;
    // let kdf_id = 3;
    // let aead_id = 1;
    let info = hex!("4f6465206f6e2061204772656369616e2055726e");
    let ikmE = hex!("37ae06a521cd555648c928d7af58ad2aa4a85e34b8cabd069e94ad55ab872cc8");
    let pkEm = hex!("04801740f4b1b35823f7fb2930eac2efc8c4893f34ba111c0bb976e3c7d5dc
                0aef5a7ef0bf4057949a140285f774f1efc53b3860936b92279a11b68395d898d138");
    let skEm = hex!("778f2254ae5d661d5c7fca8c4a7495a25bd13f26258e459159f3899df0de76c1");
    let ikmR = hex!("7466024b7e2d2366c3914d7833718f13afb9e3e45bcfbb510594d614ddd9b4e7");
    let pkRm = hex!("04a4ca7af2fc2cce48edbf2f1700983e927743a4e85bb5035ad562043e25d9
                a111cbf6f7385fac55edc5c9d2ca6ed351a5643de95c36748e11dbec98730f4d43e9");
    let skRm = hex!("00510a70fde67af487c093234fc4215c1cdec09579c4b30cc8e48cb530414d0e");
    let ikmS = hex!("ee27aaf99bf5cd8398e9de88ac09a82ac22cdb8d0905ab05c0f5fa12ba1709f3");
    let pkSm = hex!("04b59a4157a9720eb749c95f842a5e3e8acdccbe834426d405509ac3191e23
                f2165b5bb1f07a6240dd567703ae75e13182ee0f69fc102145cdb5abf681ff126d60");
    let skSm = hex!("d743b20821e6326f7a26684a4beed7088b35e392114480ca9f6c325079dcf10b");
    let psk = hex!("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82");
    let psk_id = hex!("456e6e796e20447572696e206172616e204d6f726961");
    let enc = hex!("04801740f4b1b35823f7fb2930eac2efc8c4893f34ba111c0bb976e3c7d5dc0
                aef5a7ef0bf4057949a140285f774f1efc53b3860936b92279a11b68395d898d138");
    let shared_secret = hex!("02bee8be0dda755846115db45071c0cf59c25722e015bde1c124de849c0fea52");
    let _key_schedule_context = hex!("03713f73042575cebfd132f0cc4338523f8eae95c80a74
                9f7cf3eb9436ff1c612ca62c37df27ca46d2cc162445a92c5f5fdc57bcde129ca7b1
                f284b0c12297c037ca221d77e229a9d11b654de7942d685069c633b2362ce3b3d8ea
                4891c9a2a87a4eb7cdb289ba5e2ecbf8cd2c8498bb4a383dc021454d70d46fcbbad1
                252ef4f9");
    let _secret = hex!("0f9df08908a6a3d06c8e934cd3f5313f9ebccd0986e316c0198bb48bed30
                dc3db2f3baab94fd40c2c285c7288c77e2255401ee2d5884306addf4296b93c238b3");
    let key = hex!("b68bb0e2fbf7431cedb46cc3b6f1fe9e");
    let base_nonce = hex!("76af62719d33d39a1cb6be9f");
    let exporter_secret = hex!("7f72308ae68c9a2b3862e686cb547b16d33d00fe482c770c471
                7d8b54e9b1e547244c3602bdd86d5a788a8443befea0a7658002b23f1c96a62a6498
                6fffc511a");

    let (pkRm3, skRm3) = HpkeKemP256HkdfSha256::derive_from_seed(&ikmR.into());
    assert_eq!(pkRm3.as_bytes(), pkRm.into());
    assert_eq!(skRm3.as_bytes(), skRm.into());
    let (pkSm3, skSm3) = HpkeKemP256HkdfSha256::derive_from_seed(&ikmS.into());
    assert_eq!(pkSm3.as_bytes(), pkSm.into());
    assert_eq!(skSm3.as_bytes(), skSm.into());
    let (pkEm3, skEm3) = HpkeKemP256HkdfSha256::derive_from_seed(&ikmE.into());
    assert_eq!(pkEm3.as_bytes(), pkEm.into());
    assert_eq!(skEm3.as_bytes(), skEm.into());

    let encapsulator = HpkeAuthKemP256HkdfSha256::encap_from_keys(pkRm3.encapsulator.recipient_public, skSm3.decapsulator.recipient_private.clone());
    let decapsulator = HpkeAuthKemP256HkdfSha256::decap_from_keys(pkSm3.encapsulator.recipient_public, skRm3.decapsulator.recipient_private.clone());

    //let mut pred_rng = PredictableRng::new(&skEm);

    let (c0_calc, k_calc) = encapsulator.encapsulate_deterministic(&ikmE).unwrap();
    assert! ( c0_calc.as_ref() == enc );
    assert! ( k_calc == shared_secret );

    let k_calc2 = decapsulator.decapsulate(&c0_calc).unwrap();
    assert! ( k_calc2 == shared_secret );

    // Derive keys
    //let kdf = LabelledTkdf1::<HmacReset<Sha512>,LabelHpkeV1>::new_with_label::<LabelKdf::<kem_id::DhKemP256HkdfSha256,kdf_id::HkdfSha512,aead_id::Aes128Gcm>>().into();

    let (key2, base_nonce2, exporter_secret2) = HpkeHkdfSha512::derive::<U16, U12, U64,LabelKdf::<kem_id::DhKemP256HkdfSha256,kdf_id::HkdfSha512,aead_id::Aes128Gcm>> (true, &shared_secret, &info, Some(Psk{val: &psk, id: &psk_id})).unwrap();
    assert! ( key2 == key );
    assert! ( base_nonce2 == base_nonce);
    assert! ( exporter_secret2 == exporter_secret);

    // sequence number: 0
    let pt = hex!("4265617574792069732074727574682c20747275746820626561757479");
    let aad = hex!("436f756e742d30");
    let _nonce = hex!("76af62719d33d39a1cb6be9f");
    let ct = hex!("840669634db51e28df54f189329c1b727fd303ae413f003020aff5e26276aaa9 10fc4296828cb9d862c2fd7d16");

    // Repeat using full hpke functions
    let he_encryptor = HpkeAuthIesP256Sha512Aes128Gcm::auth_encryptor_from_keys(pkRm3.encapsulator.recipient_public, skSm3.decapsulator.recipient_private.clone());
    let he_decryptor = HpkeAuthIesP256Sha512Aes128Gcm::auth_decryptor_from_keys(skRm3.decapsulator.recipient_private, pkSm3.encapsulator.recipient_public);    
    
    let (c0_send, ct_send) = he_encryptor.single_shot_seal_deterministic(&ikmE, Payload{msg: &pt, aad: &aad}, &info, Some(Psk{val:&psk, id:&psk_id})).unwrap();
    assert! ( ct_send == ct );

    let pt_2 = he_decryptor.single_shot_open(&c0_send, &info, Payload{msg:&ct, aad:&aad}, Some(Psk{val:&psk, id:&psk_id}) ).unwrap();
    assert! (pt_2 == pt);
}



// A.5. DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305
#[test]
fn test_rfc_9180_a_5_1 () {
    //     let _mode= 0;
    // const _KEM_ID: u16 = 16;
    // const _KDF_ID: u16 = 1;
    // const _AEAD_ID: u16 = 3;
    let info=hex!("4f6465206f6e2061204772656369616e2055726e");
    let ikme=hex!("f1f1a3bc95416871539ecb51c3a8f0cf608afb40fbbe305c0a72819d35c33f1f");
    let pkem=hex!("04c07836a0206e04e31d8ae99bfd549380b072a1b1b82e563c935c09582782
            4fc1559eac6fb9e3c70cd3193968994e7fe9781aa103f5b50e934b5b2f387e381291");
    let skem=hex!("7550253e1147aae48839c1f8af80d2770fb7a4c763afe7d0afa7e0f42a5b3689");
    let ikmr=hex!("61092f3f56994dd424405899154a9918353e3e008171517ad576b900ddb275e7");
    let pkrm=hex!("04a697bffde9405c992883c5c439d6cc358170b51af72812333b015621dc0f
            40bad9bb726f68a5c013806a790ec716ab8669f84f6b694596c2987cf35baba2a006");
    let skrm=hex!("a4d1c55836aa30f9b3fbb6ac98d338c877c2867dd3a77396d13f68d3ab150d3b");
    let enc=hex!("04c07836a0206e04e31d8ae99bfd549380b072a1b1b82e563c935c095827824
            fc1559eac6fb9e3c70cd3193968994e7fe9781aa103f5b50e934b5b2f387e381291");
    let shared_secret=hex!("806520f82ef0b03c823b7fc524b6b55a088f566b9751b89551c170f4113bd850");
    let _key_schedule_context=hex!("00b738cd703db7b4106e93b4621e9a19c89c838e559642
            40e5d3f331aaf8b0d58b2e986ea1c671b61cf45eec134dac0bae58ec6f63e790b140
            0b47c33038b0269c");
    let _secret=hex!("fe891101629aa355aad68eff3cc5170d057eca0c7573f6575e91f9783e1d4506");
    let key=hex!("a8f45490a92a3b04d1dbf6cf2c3939ad8bfc9bfcb97c04bffe116730c9dfe3fc");
    let base_nonce=hex!("726b4390ed2209809f58c693");
    let exporter_secret=hex!("4f9bd9b3a8db7d7c3a5b9d44fdc1f6e37d5d77689ade5ec44a7242016e6aa205");

    let encapsulator = HpkeKemP256HkdfSha256::from_bytes_encap(GenericArray::from_slice(&pkrm));
    let decapsulator = HpkeKemP256HkdfSha256::from_bytes_decap(GenericArray::from_slice(&skrm));

    //let mut pred_rng = PredictableRng::new(&skem);

    let (c0_calc, k_calc) = encapsulator.encapsulate_deterministic(&ikme).unwrap();
    assert! ( c0_calc.as_ref() == enc );
    assert! ( k_calc == shared_secret );

    let k_calc3 = decapsulator.decapsulate(&c0_calc).unwrap();
    assert_eq! ( k_calc3, shared_secret);

    // Derive keys
    //let kdf = LabelledTkdf1::<HmacReset<Sha256>,LabelHpkeV1>::new_with_label::<LabelKdf::<kem_id::DhKemP256HkdfSha256,kdf_id::HkdfSha256,aead_id::ChaCha20Poly1305>>().into();

    let (key2, base_nonce2, exporter_secret2) = HpkeHkdfSha256::derive::<U32, U12, U32, LabelKdf::<kem_id::DhKemP256HkdfSha256,kdf_id::HkdfSha256,aead_id::ChaCha20Poly1305>>( false, &shared_secret, &info, None).unwrap();
    assert! ( key2 == key);
    assert! ( base_nonce2 == base_nonce);
    assert! ( exporter_secret2 == exporter_secret);

    // Use HPKE functions
    let (encryptor, decryptor) = HpkeIesP256Sha256ChaCha20Poly1305::derive_pair_from_seed(&ikmr).unwrap();
    assert_eq!(encryptor.get_encapsulator().as_bytes().as_slice(), &pkrm);
    assert_eq!(decryptor.get_decapsulator().as_bytes().as_slice(), &skrm);

    let (encryptor2, decryptor2) = HpkeIesP256Sha256ChaCha20Poly1305::derive_pair_from_seed(&ikme).unwrap();
    assert_eq!(encryptor2.get_encapsulator().as_bytes().as_slice(), &pkem);
    assert_eq!(decryptor2.get_decapsulator().as_bytes().as_slice(), &skem);

    //sequence number: 0
    let pt = hex!("4265617574792069732074727574682c20747275746820626561757479");
    let aad= hex!("436f756e742d30");
    let _nonce= hex!("726b4390ed2209809f58c693");
    let ct= hex!("6469c41c5c81d3aa85432531ecf6460ec945bde1eb428cb2fedf7a29f5a685b4 ccb0d057f03ea2952a27bb458b");

    let he_encryptor = HpkeIesP256Sha256ChaCha20Poly1305::encryptor_from_bytes(&pkrm.into());
    let he_decryptor = HpkeIesP256Sha256ChaCha20Poly1305::decryptor_from_bytes(&skrm.into());
    
    let (c0_send, ct_send) = he_encryptor.single_shot_seal_deterministic(&ikme, aead::Payload{msg:&pt, aad:&aad}, &info, None).unwrap();
    assert! ( c0_send.as_ref() == enc);
    assert! ( ct_send == &ct );

    let pt_2 = he_decryptor.single_shot_open(&c0_send, &info, Payload{msg:&ct, aad:&aad}, None ).unwrap();
    assert!( pt_2 == pt);
}


#[test]
#[allow(non_snake_case)]
fn test_rfc_9180_a_6_1 () {
    // mode: 0
    // kem_id: 18
    // kdf_id: 3
    // aead_id: 2

    let info = hex!("4f6465206f6e2061204772656369616e2055726e");
    let ikmE = hex!("7f06ab8215105fc46aceeb2e3dc5028b44364f960426eb0d8e4026c2f8b5d7
            e7a986688f1591abf5ab753c357a5d6f0440414b4ed4ede71317772ac98d9239f709
            04");
    let pkEm = hex!("040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8
            900aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731
            ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed0
            692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0");
    let skEm = hex!("014784c692da35df6ecde98ee43ac425dbdd0969c0c72b42f2e708ab9d5354
            15a8569bdacfcc0a114c85b8e3f26acf4d68115f8c91a66178cdbd03b7bcc5291e37
            4b");
    let ikmR = hex!("2ad954bbe39b7122529f7dde780bff626cd97f850d0784a432784e69d86ecc
            aade43b6c10a8ffdb94bf943c6da479db137914ec835a7e715e36e45e29b587bab3b
            f1");
    let pkRm = hex!("0401b45498c1714e2dce167d3caf162e45e0642afc7ed435df7902ccae0e84
            ba0f7d373f646b7738bbbdca11ed91bdeae3cdcba3301f2457be452f271fa6837580
            e661012af49583a62e48d44bed350c7118c0d8dc861c238c72a2bda17f64704f464b
            57338e7f40b60959480c0e58e6559b190d81663ed816e523b6b6a418f66d2451ec64");

    let skRm = hex!("01462680369ae375e4b3791070a7458ed527842f6a98a79ff5e0d4cbde83c2
            7196a3916956655523a6a2556a7af62c5cadabe2ef9da3760bb21e005202f7b24628
            47");
    let enc = hex!("040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab89
            00aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731e
            ce2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed06
            92237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0");
    let shared_secret = hex!("776ab421302f6eff7d7cb5cb1adaea0cd50872c71c2d63c30c4f1
            d5e43653336fef33b103c67e7a98add2d3b66e2fda95b5b2a667aa9dac7e59cc1d46
            d30e818");
    let _key_schedule_context = hex!("0083a27c5b2358ab4dae1b2f5d8f57f10ccccc822a4733
            26f543f239a70aee46347324e84e02d7651a10d08fb3dda739d22d50c53fbfa8122b
            aacd0f9ae5913072ef45baa1f3a4b169e141feb957e48d03f28c837d8904c3d67753
            08c3d3faa75dd64adfa44e1a1141edf9349959b8f8e5291cbdc56f62b0ed6527d692
            e85b09a4");
    let _secret = hex!("49fd9f53b0f93732555b2054edfdc0e3101000d75df714b98ce5aa295a37
            f1b18dfa86a1c37286d805d3ea09a20b72f93c21e83955a1f01eb7c5eead563d21e7");
    let key = hex!( "751e346ce8f0ddb2305c8a2a85c70d5cf559c53093656be636b9406d4d7d1b70");
    let base_nonce = hex!("55ff7a7d739c69f44b25447b");
    let exporter_secret = hex!("e4ff9dfbc732a2b9c75823763c5ccc954a2c0648fc6de80a585
            81252d0ee3215388a4455e69086b50b87eb28c169a52f42e71de4ca61c920e7bd24c
            95cc3f992");

    let (encapsulator, decapsulator) = HpkeKemP521HkdfSha512::derive_from_seed(&ikmR.into());
    assert_eq! ( decapsulator.as_bytes(), skRm.into());
    assert_eq! ( encapsulator.as_bytes(), pkRm.into());
    let (encapsulatorE, decapsulatorE) = HpkeKemP521HkdfSha512::derive_from_seed(&ikmE.into());
    assert_eq! ( decapsulatorE.as_bytes(), skEm.into());
    assert_eq! ( encapsulatorE.as_bytes(), pkEm.into());

    let encapsulator = HpkeKemP521HkdfSha512::from_bytes_encap(&pkRm.into());
    let decapsulator = HpkeKemP521HkdfSha512::from_bytes_decap(&skRm.into());

    //let mut pred_rng = PredictableRng::new(&skEm);

    let (c0_calc, k_calc) = encapsulator.encapsulate_deterministic(&ikmE).unwrap();
    assert! ( c0_calc.as_ref() == enc );
    assert! ( k_calc == shared_secret );

    let k_calc2 = decapsulator.decapsulate(&c0_calc).unwrap();
    assert! ( k_calc2 == shared_secret );

    // derive keys
    //let hkdf = LabelledTkdf1::<HmacReset<Sha512>,LabelHpkeV1>::new_with_label::<LabelKdf::<kem_id::DhKemP521HkdfSha512,kdf_id::HkdfSha512,aead_id::Aes256Gcm>>().into();
    let (key2, base_nonce2, exporter_secret2) = HpkeHkdfSha512::derive::<U32, U12, U64, LabelKdf::<kem_id::DhKemP521HkdfSha512,kdf_id::HkdfSha512,aead_id::Aes256Gcm>>(false, &shared_secret, &info, None).unwrap();
    assert! ( key2 == key);
    assert! ( base_nonce2 == base_nonce);
    assert! ( exporter_secret2 == exporter_secret);

    //sequence number: 0
    let pt = hex!("4265617574792069732074727574682c20747275746820626561757479");
    let aad = hex!("436f756e742d30");
    let _nonce = hex!("55ff7a7d739c69f44b25447b");
    let ct = hex!("170f8beddfe949b75ef9c387e201baf4132fa7374593dfafa90768788b7b2b20 0aafcc6d80ea4c795a7c5b841a");

    let he_encryptor = HpkeIesP521Sha512Aes256Gcm::encryptor_from_bytes(&pkRm.into());
    let he_decryptor = HpkeIesP521Sha512Aes256Gcm::decryptor_from_bytes(&skRm.into());

    //let mut pred_rng = PredictableRng::new(&skEm);

    let (c0_send, ct_send) = he_encryptor.single_shot_seal_deterministic(&ikmE, Payload{msg: &pt, aad: &aad}, &info, None).unwrap();
    assert! ( c0_send.as_ref() == enc);
    assert! ( ct_send == &ct );

    let pt_2 = he_decryptor.single_shot_open(&c0_send, &info, Payload{msg:&ct, aad:&aad}, None ).unwrap();
    assert_eq! ( pt_2, &pt);
}




#[test]
#[allow(non_snake_case)]
fn test_rfc_9180_a_6_3 () {
    //mode: 2  // Auth
    //kem_id: 18   // P-521, SHA-512, HKDF-SHA512
    //kdf_id: 3     // HKDF-SHA512
    //aead_id: 2    // AES 256 - GCM
    let info = hex!("4f6465206f6e2061204772656369616e2055726e");
    let ikmE = hex!("fe1c589c2a05893895a537f38c7cb4300b5a7e8fef3d6ccb8f07a498029c61
        e90262e009dc254c7f6235f9c6b2fd6aeff0a714db131b09258c16e217b7bd2aa619
        b0");
    let pkEm = hex!("04017de12ede7f72cb101dab36a111265c97b3654816dcd6183f809d4b3d11
        1fe759497f8aefdc5dbb40d3e6d21db15bdc60f15f2a420761bcaeef73b891c2b117
        e9cf01e29320b799bbc86afdc5ea97d941ea1c5bd5ebeeac7a784b3bab524746f3e6
        40ec26ee1bd91255f9330d974f845084637ee0e6fe9f505c5b87c86a4e1a6c3096dd");
    let _skEm = hex!("0185f03560de87bb2c543ef03607f3c33ac09980000de25eabe3b224312946
        330d2e65d192d3b4aa46ca92fc5ca50736b624402d95f6a80dc04d1f10ae95171372
        61");
    let ikmR = hex!("8feea0438481fc0ecd470d6adfcda334a759c6b8650452c5a5dd9b2dd2cc9b
        e33d2bb7ee64605fc07ab4664a58bb9a8de80defe510b6c97d2daf85b92cd4bb0a66
        bf");
    let pkRm = hex!("04007d419b8834e7513d0e7cc66424a136ec5e11395ab353da324e3586673e
        e73d53ab34f30a0b42a92d054d0db321b80f6217e655e304f72793767c4231785c4a
        4a6e008f31b93b7a4f2b8cd12e5fe5a0523dc71353c66cbdad51c86b9e0bdfcd9a45
        698f2dab1809ab1b0f88f54227232c858accc44d9a8d41775ac026341564a2d749f4");
   let skRm = hex!("013ef326940998544a899e15e1726548ff43bbdb23a8587aa3bef9d1b85733
        8d87287df5667037b519d6a14661e9503cfc95a154d93566d8c84e95ce93ad05293a
        0b");
   let ikmS = hex!("2f66a68b85ef04822b054ef521838c00c64f8b6226935593b69e13a1a2461a
        4f1a74c10c836e87eed150c0db85d4e4f506cbb746149befac6f5c07dc48a615ef92
        db");
   let pkSm = hex!("04015cc3636632ea9a3879e43240beae5d15a44fba819282fac26a19c989fa
        fdd0f330b8521dff7dc393101b018c1e65b07be9f5fc9a28a1f450d6a541ee0d7622
        1133001e8f0f6a05ab79f9b9bb9ccce142a453d59c5abebb5674839d935a3ca1a3fb
        c328539a60b3bc3c05fed22838584a726b9c176796cad0169ba4093332cbd2dc3a9f");
   let skSm = hex!("001018584599625ff9953b9305849850d5e34bd789d4b81101139662fbea8b
        6508ddb9d019b0d692e737f66beae3f1f783e744202aaf6fea01506c27287e359fe7
        76");
   let enc = hex!("04017de12ede7f72cb101dab36a111265c97b3654816dcd6183f809d4b3d111
        fe759497f8aefdc5dbb40d3e6d21db15bdc60f15f2a420761bcaeef73b891c2b117e
        9cf01e29320b799bbc86afdc5ea97d941ea1c5bd5ebeeac7a784b3bab524746f3e64
        0ec26ee1bd91255f9330d974f845084637ee0e6fe9f505c5b87c86a4e1a6c3096dd");
   let shared_secret = hex!("26648fa2a2deb0bfc56349a590fd4cb7108a51797b634694fc020
        61e8d91b3576ac736a68bf848fe2a58dfb1956d266e68209a4d631e513badf8f4dcf
        c00f30a");
   let _key_schedule_context = hex!("0283a27c5b2358ab4dae1b2f5d8f57f10ccccc822a4733
        26f543f239a70aee46347324e84e02d7651a10d08fb3dda739d22d50c53fbfa8122b
        aacd0f9ae5913072ef45baa1f3a4b169e141feb957e48d03f28c837d8904c3d67753
        08c3d3faa75dd64adfa44e1a1141edf9349959b8f8e5291cbdc56f62b0ed6527d692
        e85b09a4");
   let _secret = hex!("56b7acb7355d080922d2ddc227829c2276a0b456087654b3ac4b53828bd3
        4af8cf54626f85af858a15a86eba73011665cc922bc59fd07d2975f356d2674db554");
   let key = hex!("01fced239845e53f0ec616e71777883a1f9fcab22a50f701bdeee17ad040e44d");
   let base_nonce = hex!("9752b85fe8c73eda183f9e80");
   let exporter_secret = hex!("80466a9d9cc5112ddad297e817e038801e15fa18152bc4dc010
        a35d7f534089c87c98b4bacd7bbc6276c4002a74085adcd9019fca6139826b529256
        9cfb7fe47");

    let (encapsulator_recv, decapsulator_recv) = HpkeKemP521HkdfSha512::derive_from_seed(&ikmR.into());
    assert_eq! (encapsulator_recv.as_bytes().as_slice(), pkRm.as_slice());
    assert_eq! (decapsulator_recv.as_bytes().as_slice(), skRm.as_slice());

    let (encapsulator_send, decapsulator_send) = HpkeKemP521HkdfSha512::derive_from_seed(&ikmS.into());
    assert_eq! (encapsulator_send.as_bytes().as_slice(), pkSm.as_slice());
    assert_eq! (decapsulator_send.as_bytes().as_slice(), skSm.as_slice());

    let skRm3 = elliptic_curve::SecretKey::<NistP521>::from_slice(&skRm).unwrap();
    let pkRm3 = elliptic_curve::PublicKey::<NistP521>::from_sec1_bytes(pkRm.as_ref()).unwrap();
    let skSm3 = elliptic_curve::SecretKey::<NistP521>::from_slice(&skSm).unwrap();
    let pkSm3 = elliptic_curve::PublicKey::<NistP521>::from_sec1_bytes(pkSm.as_ref()).unwrap();

    //let mut pred_rng = PredictableRng::new(&skEm);

    let encapsulator = HpkeAuthKemP521HkdfSha512::encap_from_keys(pkRm3, skSm3.clone());
    let decapsulator = HpkeAuthKemP521HkdfSha512::decap_from_keys(pkSm3, skRm3.clone());

    let (c0_calc, k_calc) = encapsulator.encapsulate_deterministic(&ikmE).unwrap();
    assert! ( c0_calc.as_ref() == enc );
    assert! ( c0_calc.as_ref() == pkEm );
    assert! ( k_calc == shared_secret );
    
    let k_calc2 = decapsulator.decapsulate(&c0_calc).unwrap();
    assert! ( k_calc2 == shared_secret );

    //let kdf = LabelledTkdf1::<HmacReset<Sha512>,LabelHpkeV1>::new_with_label::<LabelKdf::<kem_id::DhKemP521HkdfSha512,kdf_id::HkdfSha512,aead_id::Aes256Gcm>>().into();
    let (key2, base_nonce2, exporter_secret2) = HpkeHkdfSha512::derive::<U32, U12, U64, LabelKdf::<kem_id::DhKemP521HkdfSha512,kdf_id::HkdfSha512,aead_id::Aes256Gcm>>(true, &shared_secret, &info, None).unwrap();
    assert! ( key2 == key);
    assert! ( base_nonce2 == base_nonce);
    assert! ( exporter_secret2 == exporter_secret);

    //sequence number: 0
    let pt = hex!("4265617574792069732074727574682c20747275746820626561757479");
    let aad = hex!("436f756e742d30");
    let _nonce = hex!("9752b85fe8c73eda183f9e80");
    let ct = hex!("0116aeb3a1c405c61b1ce47600b7ecd11d89b9c08c408b7e2d1e00a4d64696d1 2e6881dc61688209a8207427f9");

    let he_encryptor = HpkeAuthIesP521Sha512Aes256Gcm::auth_encryptor_from_keys(pkRm3, skSm3);
    let he_decryptor = HpkeAuthIesP521Sha512Aes256Gcm::auth_decryptor_from_keys(skRm3, pkSm3);
    
    let (c0_send, ct_send) = he_encryptor.single_shot_seal_deterministic(&ikmE, Payload{ msg: &pt, aad: &aad}, &info, None).unwrap();
    assert! ( ct_send == ct );

    let pt_2 = he_decryptor.single_shot_open(&c0_send, &info, Payload{msg:&ct, aad:&aad},  None ).unwrap();
    assert! (pt_2 == pt);
}




#[test]
#[allow(non_snake_case)]
fn test_rfc_9180_a_6_4 () {
    //let mode = 3; // auth with PSK
    // kem_id: 18
    // kdf_id: 3
    // aead_id: 2
    let info = hex!("4f6465206f6e2061204772656369616e2055726e");
    let ikmE = hex!("54272797b1fbc128a6967ff1fd606e0c67868f7762ce1421439cbc9e90ce1b
            28d566e6c2acbce712e48eebf236696eb680849d6873e9959395b2931975d61d38bd
            6c");
    let pkEm = hex!("04000a5096a6e6e002c83517b494bfc2e36bfb8632fae8068362852b70d0ff
            71e560b15aff96741ecffb63d8ac3090c3769679009ac59a99a1feb4713c5f090fc0
            dbed01ad73c45d29d369e36744e9ed37d12f80700c16d816485655169a5dd66e4ddf
            27f2acffe0f56f7f77ea2b473b4bf0518b975d9527009a3d14e5a4957e3e8a9074f8");
    let skEm = hex!("003430af19716084efeced1241bb1a5625b6c826f11ef31649095eb2795261
            9e36f62a79ea28001ac452fb20ddfbb66e62c6c0b1be03c0d28c97794a1fb638207a
            83");
    let ikmR = hex!("3db434a8bc25b27eb0c590dc64997ab1378a99f52b2cb5a5a5b2fa540888f6
            c0f09794c654f4468524e040e6b4eca2c9dcf229f908b9d318f960cc9e9baa92c5ee
            e6");
    let pkRm = hex!("0401655b5d3b7cfafaba30851d25edc44c6dd17d99410efbed8591303b4dbe
            ea8cb1045d5255f9a60384c3bbd4a3386ae6e6fab341dc1f8db0eed5f0ab1aaac6d7
            838e00dadf8a1c2c64b48f89c633721e88369e54104b31368f26e35d04a442b0b428
            510fb23caada686add16492f333b0f7ba74c391d779b788df2c38d7a7f4778009d91");
    let skRm = hex!("0053c0bc8c1db4e9e5c3e3158bfdd7fc716aef12db13c8515adf821dd692ba
            3ca53041029128ee19c8556e345c4bcb840bb7fd789f97fe10f17f0e2c6c25280728
            43");
    let ikmS = hex!("65d523d9b37e1273eb25ad0527d3a7bd33f67208dd1666d9904c6bc04969ae
            5831a8b849e7ff642581f2c3e56be84609600d3c6bbdaded3f6989c37d2892b1e978
            d5");
    let pkSm = hex!("040013761e97007293d57de70962876b4926f69a52680b4714bee1d4236aa9
            6c19b840c57e80b14e91258f0a350e3f7ba59f3f091633aede4c7ec4fa8918323aa4
            5d5901076dec8eeb22899fda9ab9e1960003ff0535f53c02c40f2ae4cdc6070a3870
            b85b4bdd0bb77f1f889e7ee51f465a308f08c666ad3407f75dc046b2ff5a24dbe2ed");
    let skSm = hex!("003f64675fc8914ec9e2b3ecf13585b26dbaf3d5d805042ba487a5070b8c5a
            c1d39b17e2161771cc1b4d0a3ba6e866f4ea4808684b56af2a49b5e5111146d45d93
            26");
    let psk = hex!("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82");
    let psk_id = hex!("456e6e796e20447572696e206172616e204d6f726961");
    let enc = hex!("04000a5096a6e6e002c83517b494bfc2e36bfb8632fae8068362852b70d0ff7
            1e560b15aff96741ecffb63d8ac3090c3769679009ac59a99a1feb4713c5f090fc0d
            bed01ad73c45d29d369e36744e9ed37d12f80700c16d816485655169a5dd66e4ddf2
            7f2acffe0f56f7f77ea2b473b4bf0518b975d9527009a3d14e5a4957e3e8a9074f8");
    let shared_secret = hex!("9e1d5f62cb38229f57f68948a0fbc1264499910cce50ec62cb241
            88c5b0a98868f3c1cfa8c5baa97b3f24db3cdd30df6e04eae83dc4347be8a981066c
            3b5b945");
    let _key_schedule_context = hex!("0324497637cf18d6fbcc16e9f652f00244c981726f293b
            b7819861e85e50c94f0be30e022ab081e18e6f299fd3d3d976a4bc590f85bc7711bf
            ce32ee1a7fb1c154ef45baa1f3a4b169e141feb957e48d03f28c837d8904c3d67753
            08c3d3faa75dd64adfa44e1a1141edf9349959b8f8e5291cbdc56f62b0ed6527d692
            e85b09a4");
    let _secret = hex!("50a57775958037a04098e0054576cd3bc084d0d08d29548ba4befa5676b9
            1eb4dcd0752813a052c9a930d0aba6ca10b89dd690b64032dc635dece35d1bf4645c");
    let key = hex!("1316ed34bd52374854ed0e5cb0394ca0a79b2d8ce7f15d5104f21acdfb594286");
    let base_nonce = hex!("d9c64ec8deb8a0647fafe8ff");
    let exporter_secret = hex!("6cb00ff99aebb2e4a05042ce0d048326dd2c03acd61a601b103
            8a65398406a96ab8b5da3187412b2324089ea16ba4ff7e6f4fe55d281fc8ae5f2049
            032b69ebd");

    let (pkRm2, skRm2) = HpkeKemP521HkdfSha512::derive_from_seed(&ikmR.into());
    assert_eq!(pkRm2.as_bytes(), pkRm.into());
    assert_eq!(skRm2.as_bytes(), skRm.into());
    let (pkSm2, skSm2) = HpkeKemP521HkdfSha512::derive_from_seed(&ikmS.into());
    assert_eq!(pkSm2.as_bytes(), pkSm.into());
    assert_eq!(skSm2.as_bytes(), skSm.into());
    let (pkEm2, skEm2) = HpkeKemP521HkdfSha512::derive_from_seed(&ikmE.into());
    assert_eq!(pkEm2.as_bytes(), pkEm.into());
    assert_eq!(skEm2.as_bytes(), skEm.into());

    let skRm3 = elliptic_curve::SecretKey::<NistP521>::from_bytes(&skRm.into()).unwrap();
    let pkRm3 = elliptic_curve::PublicKey::<NistP521>::from_sec1_bytes(pkRm.as_ref()).unwrap();
    let skSm3 = elliptic_curve::SecretKey::<NistP521>::from_bytes(&skSm.into()).unwrap();
    let pkSm3 = elliptic_curve::PublicKey::<NistP521>::from_sec1_bytes(pkSm.as_ref()).unwrap();

    let encapsulator = HpkeAuthKemP521HkdfSha512::encap_from_keys(pkRm3, skSm3.clone());
    let decapsulator = HpkeAuthKemP521HkdfSha512::decap_from_keys(pkSm3, skRm3.clone());

    //let mut pred_rng = PredictableRng::new(&skEm);

    let (c0_calc, k_calc) = encapsulator.encapsulate_deterministic(&ikmE).unwrap();
    assert! ( c0_calc.as_ref() == enc );
    assert_eq! ( k_calc, shared_secret);
    
    let k_calc2 = decapsulator.decapsulate(&c0_calc).unwrap();
    assert! ( k_calc2 == shared_secret );

    //let kdf = LabelledTkdf1::<HmacReset<Sha512>,LabelHpkeV1>::new_with_label::<LabelKdf::<kem_id::DhKemP521HkdfSha512,kdf_id::HkdfSha512,aead_id::Aes256Gcm>>().into();

    let (key2, base_nonce2, exporter_secret2) = HpkeHkdfSha512::derive::<U32, U12, U64, LabelKdf::<kem_id::DhKemP521HkdfSha512,kdf_id::HkdfSha512,aead_id::Aes256Gcm>>(true, &shared_secret, &info, Some(Psk{val: &psk, id: &psk_id})).unwrap();
    assert! ( key2 == key );
    assert! ( base_nonce2 == base_nonce);
    assert! ( exporter_secret2 == exporter_secret);

    //sequence number: 0
    let pt=hex!("4265617574792069732074727574682c20747275746820626561757479");
    let aad=hex!("436f756e742d30");
    let _nonce=hex!(" d9c64ec8deb8a0647fafe8ff");
    let ct=hex!(" 942a2a92e0817cf032ce61abccf4f3a7c5d21b794ed943227e07b7df2d6dd92c 9b8a9371949e65cca262448ab7");

    let he_encryptor = HpkeAuthIesP521Sha512Aes256Gcm::auth_encryptor_from_keys(pkRm3, skSm3 );
    let he_decryptor = HpkeAuthIesP521Sha512Aes256Gcm::auth_decryptor_from_keys(skRm3, pkSm3);
    
    //let mut pred_rng = PredictableRng::new(&skEm);

    let (c0_send, ct_send) = he_encryptor.single_shot_seal_deterministic(&ikmE, Payload{ msg: &pt, aad: &aad}, &info, Some(Psk{val:&psk, id:&psk_id})).unwrap();
    assert! ( ct_send == ct );
    assert! ( c0_send.as_slice() == enc.as_slice() );

    let pt_2 = he_decryptor.single_shot_open(&c0_send, &info, Payload{msg:&ct, aad:&aad},Some(Psk{val:&psk, id:&psk_id}) ).unwrap();
    assert! (pt_2 == pt);
}




#[test]
#[allow(non_snake_case)]
fn test_rfc_9180_a_7_1 () {
    // mode: 0
    // kem_id: 32
    // kdf_id: 1
    // aead_id: 65535
    let info=hex!("4f6465206f6e2061204772656369616e2055726e");
    let ikmE=hex!("55bc245ee4efda25d38f2d54d5bb6665291b99f8108a8c4b686c2b14893ea5d9");
    let pkEm=hex!("e5e8f9bfff6c2f29791fc351d2c25ce1299aa5eaca78a757c0b4fb4bcd830918");
    let skEm=hex!("095182b502f1f91f63ba584c7c3ec473d617b8b4c2cec3fad5af7fa6748165ed");
    let ikmR=hex!("683ae0da1d22181e74ed2e503ebf82840deb1d5e872cade20f4b458d99783e31");
    let pkRm=hex!("194141ca6c3c3beb4792cd97ba0ea1faff09d98435012345766ee33aae2d7664");
    let skRm=hex!("33d196c830a12f9ac65d6e565a590d80f04ee9b19c83c87f2c170d972a812848");
    let enc=hex!("e5e8f9bfff6c2f29791fc351d2c25ce1299aa5eaca78a757c0b4fb4bcd830918");
    let _shared_secret=hex!("e81716ce8f73141d4f25ee9098efc968c91e5b8ce52ffff59d64039e82918b66");
    let _key_schedule_context=hex!("009bd09219212a8cf27c6bb5d54998c5240793a70ca0a8
            92234bd5e082bc619b6a3f4c22aa6d9a0424c2b4292fdf43b8257df93c2f6adbf6dd
            c9c64fee26bdd292");
    let _secret=hex!("04d64e0620aa047e9ab833b0ebcd4ff026cefbe44338fd7d1a93548102ee01af");
    let _exporter_secret=hex!("79dc8e0509cf4a3364ca027e5a0138235281611ca910e435e8ed58167c72f79b");

    let (encapsulatorR, decapsulatorR) = HpkeKemX25519HkdfSha256::derive_from_seed(&ikmR.into());
    assert_eq! ( encapsulatorR.as_bytes(), pkRm.into());
    assert_eq! ( decapsulatorR.as_bytes(), skRm.into());
    let (encapsulatorE, decapsulatorE) = HpkeKemX25519HkdfSha256::derive_from_seed(&ikmE.into());
    assert_eq! ( encapsulatorE.as_bytes(), pkEm.into());
    assert_eq! ( decapsulatorE.as_bytes(), skEm.into());

    let he_encryptor = HpkeIesX25519Sha256ExportOnly::encryptor_from_bytes(&pkRm.into());

    //let mut pred_rng = PredictableRng::new(&skEm);
    
    let exporter_context=hex!("");
    let exported_value=hex!("7a36221bd56d50fb51ee65edfd98d06a23c4dc87085aa5866cb7087244bd2a36");
    let (enc_calc, calc_exported_value) = he_encryptor.single_shot_sender_export_deterministic::<U32>(&ikmE, &exporter_context, &info, None).unwrap();
    assert! ( calc_exported_value == exported_value);
    assert_eq!( enc_calc, enc.into());
    
    let exporter_context=hex!("00");
    let exported_value=hex!("d5535b87099c6c3ce80dc112a2671c6ec8e811a2f284f948cec6dd1708ee33f0");
    let (enc_calc, calc_exported_value) = he_encryptor.single_shot_sender_export_deterministic::<U32>(&ikmE, &exporter_context, &info, None).unwrap();
    assert! ( calc_exported_value == exported_value);
    assert_eq!( enc_calc, enc.into());

    let exporter_context=hex!("54657374436f6e74657874");
    let exported_value=hex!("ffaabc85a776136ca0c378e5d084c9140ab552b78f039d2e8775f26efff4c70e");
    let (enc_calc, calc_exported_value) = he_encryptor.single_shot_sender_export_deterministic::<U32>(&ikmE, &exporter_context, &info, None).unwrap();
    assert! ( calc_exported_value == exported_value);
    assert_eq!( enc_calc, enc.into());
}



#[test]
#[allow(non_snake_case)]
fn test_rfc_9180_a_7_2 () {
    //mode: 1
    //kem_id: 32
    //kdf_id: 1
    //aead_id: 65535

   let info = hex!("4f6465206f6e2061204772656369616e2055726e");
    let ikmE = hex!("c51211a8799f6b8a0021fcba673d9c4067a98ebc6794232e5b06cb9febcbbdf5");
    let _pkEm = hex!("d3805a97cbcd5f08babd21221d3e6b362a700572d14f9bbeb94ec078d051ae3d");
    let _skEm = hex!("1d72396121a6a826549776ef1a9d2f3a2907fc6a38902fa4e401afdb0392e627");
    let ikmR = hex!("5e0516b1b29c0e13386529da16525210c796f7d647c37eac118023a6aa9eb89a");
    let pkRm = hex!("d53af36ea5f58f8868bb4a1333ed4cc47e7a63b0040eb54c77b9c8ec456da824");
    let skRm = hex!("98f304d4ecb312689690b113973c61ffe0aa7c13f2fbe365e48f3ed09e5a6a0c");
    let psk = hex!("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82");
    let psk_id = hex!("456e6e796e20447572696e206172616e204d6f726961");
    let enc = hex!("d3805a97cbcd5f08babd21221d3e6b362a700572d14f9bbeb94ec078d051ae3d");
    let _shared_secret = hex!("024573db58c887decb4c57b6ed39f2c9a09c85600a8a0ecb11cac24c6aaec195");
    let _key_schedule_context = hex!("01446fb1fe2632a0a338f0a85ed1f3a0ac475bdea2cd72
            f8c713b3a46ee737379a3f4c22aa6d9a0424c2b4292fdf43b8257df93c2f6adbf6dd
            c9c64fee26bdd292");
    let _secret = hex!("638b94532e0d0bf812cf294f36b97a5bdcb0299df36e22b7bb6858e3c113080b");
    //let key:
    //let base_nonce:
    let _exporter_secret = hex!("04261818aeae99d6aba5101bd35ddf3271d909a756adcef0d41389d9ed9ab153");
    
    let recipient_public_key = x25519_dalek::PublicKey::from(pkRm);
    let recipient_secret_key = x25519_dalek::StaticSecret::from(skRm);
    let he_encryptor = HpkeIesX25519Sha256ExportOnly::encryptor_from_key(recipient_public_key);
    let he_decryptor = HpkeIesX25519Sha256ExportOnly::decryptor_from_key(recipient_secret_key);

    let ( encryptor, decryptor) = HpkeIesX25519Sha256ExportOnly::derive_pair_from_seed(&ikmR).unwrap();
    assert_eq!( encryptor.get_encapsulator().as_bytes().as_slice(), pkRm.as_slice());
    assert_eq!( decryptor.get_decapsulator().as_bytes().as_slice(), skRm.as_slice());

    //let kdf = LabelledTkdf1::<HmacReset<Sha256>,LabelHpkeV1>::new_with_label::<LabelKdf::<kem_id::DhKemX25519HkdfSha256,kdf_id::HkdfSha256,aead_id::ExportOnly>>().into();
    
    //let mut pred_rng = PredictableRng::new(&skEm);
    
    let exporter_context= hex!("");
    let exported_value = hex!("be6c76955334376aa23e936be013ba8bbae90ae74ed995c1c6157e6f08dd5316");
    let (enc_calc, calc_exported_value) = he_encryptor.single_shot_sender_export_deterministic::<U32>(&ikmE, &exporter_context, &info, Some(Psk{val:&psk, id:&psk_id})).unwrap();
    assert! ( calc_exported_value == exported_value);
    assert! ( &enc_calc.as_ref() == &enc);
    let exporter_ctx2 = he_decryptor.setup_receiver_export(&enc_calc, &info, Some(Psk{val:&psk, id:&psk_id})).unwrap();
    let recv_exported_value = he_decryptor.single_shot_recv_export::<U32>(&enc_calc, &info, &exporter_context, Some(Psk{val:&psk, id: &psk_id})).unwrap();
    assert! ( recv_exported_value == exported_value);
    
    let exporter_context = hex!("00");
    let exported_value = hex!("1721ed2aa852f84d44ad020c2e2be4e2e6375098bf48775a533505fd56a3f416");
    let (_enc_calc, calc_exported_value) = he_encryptor.single_shot_sender_export_deterministic::<U32>(&ikmE, &exporter_context, &info, Some(Psk{val:&psk, id:&psk_id})).unwrap();
    assert! ( calc_exported_value == exported_value);
    let recv_exported_value = exporter_ctx2.export::<U32>(&exporter_context).unwrap();
    assert! ( recv_exported_value == exported_value);
       
    let exporter_context = hex!("54657374436f6e74657874");
    let exported_value = hex!("7c9d79876a288507b81a5a52365a7d39cc0fa3f07e34172984f96fec07c44cba");
    let (_enc_calc, calc_exported_value) = he_encryptor.single_shot_sender_export_deterministic::<U32>(&ikmE, &exporter_context, &info, Some(Psk{val:&psk, id:&psk_id})).unwrap();
    assert! ( calc_exported_value == exported_value);
    let recv_exported_value = exporter_ctx2.export::<U32>(&exporter_context).unwrap();
    assert! ( recv_exported_value == exported_value);
   
}

#[test]
#[allow(non_snake_case)]
fn test_rfc_9180_a_7_3 () {
    // mode: 2
    // kem_id: 32
    // kdf_id: 1
    // aead_id: 65535

    let info = hex!("4f6465206f6e2061204772656369616e2055726e");
    let ikmE = hex!("43b078912a54b591a7b09b16ce89a1955a9dd60b29fb611e044260046e8b061b");
    let pkEm = hex!("5ac1671a55c5c3875a8afe74664aa8bc68830be9ded0c5f633cd96400e8b5c05");
    let _skEm = hex!("83d3f217071bbf600ba6f081f6e4005d27b97c8001f55cb5ff6ea3bbea1d9295");
    let _ikmR = hex!("fc9407ae72ed614901ebf44257fb540f617284b5361cfecd620bafc4aba36f73");
    let pkRm = hex!("ffd7ac24694cb17939d95feb7c4c6539bb31621deb9b96d715a64abdd9d14b10");
    let skRm = hex!("ed88cda0e91ca5da64b6ad7fc34a10f096fa92f0b9ceff9d2c55124304ed8b4a");
    let _ikmS = hex!("2ff4c37a17b2e54046a076bf5fea9c3d59250d54d0dc8572bc5f7c046307040c");
    let pkSm = hex!("89eb1feae431159a5250c5186f72a15962c8d0debd20a8389d8b6e4996e14306");
    let skSm = hex!("c85f136e06d72d28314f0e34b10aadc8d297e9d71d45a5662c2b7c3b9f9f9405");
    let enc = hex!("5ac1671a55c5c3875a8afe74664aa8bc68830be9ded0c5f633cd96400e8b5c05");
    let _shared_secret = hex!("e204156fd17fd65b132d53a0558cd67b7c0d7095ee494b00f47d686eb78f8fb3");
    let _key_schedule_context = hex!("02
            9bd09219212a8cf27c6bb5d54998c5240793a70ca0a892234bd5e082bc619b6a
            3f4c22aa6d9a0424c2b4292fdf43b8257df93c2f6adbf6ddc9c64fee26bdd292");
    let _secret = hex!("355e7ef17f438db43152b7fb45a0e2f49a8bf8956d5dddfec1758c0f0eb1b5d5");
    // let key:
    // let base_nonce:
    let _exporter_secret = hex!("276d87e5cb0655c7d3dad95e76e6fc02746739eb9d968955ccf8a6346c97509e");

    let recipient_public_key = x25519_dalek::PublicKey::from(pkRm);
    let recipient_secret_key = x25519_dalek::StaticSecret::from(skRm);
    let sender_secret_key = x25519_dalek::StaticSecret::from(skSm);
    let sender_public_key = x25519_dalek::PublicKey::from(pkSm);
        
    let he_encryptor = HpkeAuthIesX25519Sha256ExportOnly::auth_encryptor_from_keys(recipient_public_key, sender_secret_key);
    let he_decryptor = HpkeAuthIesX25519Sha256ExportOnly::auth_decryptor_from_keys(recipient_secret_key, sender_public_key);

    //let mut pred_rng = PredictableRng::new(&skEm);

    let (enc_calc, exporter_ctx) = he_encryptor.setup_sender_export_deterministic(&ikmE, &info, None).unwrap();
    assert! ( &enc_calc.as_ref() == &enc);
    assert! ( &enc_calc.as_ref() == &pkEm);

    //let kdf = LabelledTkdf1::<HmacReset<Sha256>,LabelHpkeV1>::new_with_label::<LabelKdf::<kem_id::DhKemX25519HkdfSha256,kdf_id::HkdfSha256,aead_id::ExportOnly>>().into();

    let exporter_ctx2 = he_decryptor.setup_receiver_export(&enc_calc, &info, None ).unwrap();

    let exporter_context = hex!("");
    let exported_value = hex!("83c1bac00a45ed4cb6bd8a6007d2ce4ec501f55e485c5642bd01bf6b6d7d6f0a");
    let calc_exported_value = exporter_ctx.export::<U32>(&exporter_context).unwrap();
    assert! ( calc_exported_value == exported_value);
    let recv_exported_value = he_decryptor.single_shot_recv_export::<U32>(&enc_calc, &info, &exporter_context, None).unwrap();
    assert! ( recv_exported_value == exported_value);

    let exporter_context = hex!("00");
    let exported_value = hex!("08a1d1ad2af3ef5bc40232a64f920650eb9b1034fac3892f729f7949621bf06e");
    let calc_exported_value = exporter_ctx.export::<U32>(&exporter_context).unwrap();
    assert! ( calc_exported_value == exported_value);
    let recv_exported_value = exporter_ctx2.export::<U32>(&exporter_context).unwrap();
    assert! ( recv_exported_value == exported_value);

    let exporter_context = hex!("54657374436f6e74657874");
    let exported_value = hex!("ff3b0e37a9954247fea53f251b799e2edd35aac7152c5795751a3da424feca73");
    let calc_exported_value = exporter_ctx.export::<U32>(&exporter_context).unwrap();
    assert! ( calc_exported_value == exported_value);
    let recv_exported_value = exporter_ctx2.export::<U32>(&exporter_context).unwrap();
    assert! ( recv_exported_value == exported_value);
}



#[test]
#[allow(non_snake_case)]
fn test_rfc_9180_a_7_4 () {
    //mode: 3
    //kem_id: 32
    //kdf_id: 1
    //aead_id: 65535
    let info = hex!("4f6465206f6e2061204772656369616e2055726e");
    let ikmE = hex!("94efae91e96811a3a49fd1b20eb0344d68ead6ac01922c2360779aa172487f40");
    let pkEm = hex!("81cbf4bd7eee97dd0b600252a1c964ea186846252abb340be47087cc78f3d87c");
    let skEm = hex!("a2b43f5c67d0d560ee04de0122c765ea5165e328410844db97f74595761bbb81");
    let ikmR = hex!("4dfde6fadfe5cb50fced4034e84e6d3a104aa4bf2971360032c1c0580e286663");
    let pkRm = hex!("f47cd9d6993d2e2234eb122b425accfb486ee80f89607b087094e9f413253c2d");
    let skRm = hex!("c4962a7f97d773a47bdf40db4b01dc6a56797c9e0deaab45f4ea3aa9b1d72904");
    let ikmS = hex!("26c12fef8d71d13bbbf08ce8157a283d5e67ecf0f345366b0e90341911110f1b");
    let pkSm = hex!("29a5bf3867a6128bbdf8e070abe7fe70ca5e07b629eba5819af73810ee20112f");
    let skSm = hex!("6175b2830c5743dff5b7568a7e20edb1fe477fb0487ca21d6433365be90234d0");
    let psk = hex!(" 0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82");
    let psk_id = hex!(" 456e6e796e20447572696e206172616e204d6f726961");
    let enc = hex!("81cbf4bd7eee97dd0b600252a1c964ea186846252abb340be47087cc78f3d87c");
    let _shared_secret = hex!("d69246bcd767e579b1eec80956d7e7dfbd2902dad920556f0de69bd54054a2d1");
    let _key_schedule_context = hex!("03446fb1fe2632a0a338f0a85ed1f3a0ac475bdea2cd72
            f8c713b3a46ee737379a3f4c22aa6d9a0424c2b4292fdf43b8257df93c2f6adbf6dd
            c9c64fee26bdd292");
    let _secret = hex!("c15c5bec374f2087c241d3533c6ec48e1c60a21dd00085619b2ffdd84a7918c3");

    let (encapsulatorR, decapsulatorR) = HpkeKemX25519HkdfSha256::derive_from_seed(&ikmR.into());
    assert_eq!(encapsulatorR.as_bytes(), pkRm.into());
    assert_eq!(decapsulatorR.as_bytes(), skRm.into());
    let (encapsulatorS, decapsulatorS) = HpkeKemX25519HkdfSha256::derive_from_seed(&ikmS.into());
    assert_eq!(encapsulatorS.as_bytes(), pkSm.into());
    assert_eq!(decapsulatorS.as_bytes(), skSm.into());
    let (encapsulatorE, decapsulatorE) = HpkeKemX25519HkdfSha256::derive_from_seed(&ikmE.into());
    assert_eq!(encapsulatorE.as_bytes(), pkEm.into());
    assert_eq!(decapsulatorE.as_bytes(), skEm.into());

    //let recipient_public_key = x25519_dalek::PublicKey::from(pkRm);
    //let sender_public_key = x25519_dalek::PublicKey::from(pkSm);
    //let sender_secret_key = x25519_dalek::StaticSecret::from(skSm);
    //let recipient_secret_key = x25519_dalek::StaticSecret::from(skRm);

    let he_encryptor = HpkeAuthIesX25519Sha256ExportOnly::auth_encryptor_from_keys(pkRm.into(), skSm.into() );
    let he_decryptor = HpkeAuthIesX25519Sha256ExportOnly::auth_decryptor_from_keys(skRm.into(), pkSm.into());

    //let mut pred_rng = PredictableRng::new(&skEm);

    let (enc_calc, send_exporter_ctx) = he_encryptor.setup_sender_export_deterministic(&ikmE, &info, Some(Psk{val:&psk, id:&psk_id})).unwrap();
    assert! ( &enc_calc.as_ref() == &enc);

    let recv_exporter_ctx = he_decryptor.setup_receiver_export(&enc_calc, &info, Some(Psk{val:&psk, id:&psk_id})).unwrap();
            
    let exporter_secret = hex!("695b1faa479c0e0518b6414c3b46e8ef5caea04c0a192246843765ae6a8a78e0");
    //let kdf = LabelledTkdf1::<HmacReset<Sha256>,LabelHpkeV1>::new_with_label::<LabelKdf::<kem_id::DhKemX25519HkdfSha256,kdf_id::HkdfSha256,aead_id::ExportOnly>>().into();
    
    assert_eq!( &recv_exporter_ctx.exporter_secret, &exporter_secret);
    
    let exporter_context = hex!("");
    let exported_value = hex!("dafd8beb94c5802535c22ff4c1af8946c98df2c417e187c6ccafe45335810b58");
    let send_exported_value = send_exporter_ctx.export::<U32>(&exporter_context).unwrap();
    assert! ( send_exported_value == exported_value);
    let recv_exported_value = recv_exporter_ctx.export::<U32>(&exporter_context).unwrap();
    assert! ( recv_exported_value == exported_value);

    let exporter_context = hex!("00");
    let exported_value = hex!("7346bb0b56caf457bcc1aa63c1b97d9834644bdacac8f72dbbe3463e4e46b0dd");
    let calc_exported_value = send_exporter_ctx.export::<U32>(&exporter_context).unwrap();
    assert! ( calc_exported_value == exported_value);
    let recv_exported_value = recv_exporter_ctx.export::<U32>(&exporter_context).unwrap();
    assert! ( recv_exported_value == exported_value);

    let exporter_context = hex!("54657374436f6e74657874");
    let exported_value = hex!("84f3466bd5a03bde6444324e63d7560e7ac790da4e5bbab01e7c4d575728c34a");
    let calc_exported_value = send_exporter_ctx.export::<U32>(&exporter_context).unwrap();
    assert! ( calc_exported_value == exported_value);
    let calc_exported_value = recv_exporter_ctx.export::<U32>(&exporter_context).unwrap();
    assert! ( calc_exported_value == exported_value);
}



// https://www.ietf.org/archive/id/draft-wahby-cfrg-hpke-kem-secp256k1-01.html
// B.1. DHKEM(Secp256k1, HKDF-SHA256) HKDF-SHA256 AES-128-GCM
#[test]
#[allow(non_snake_case)]
fn test_p256k1_b_1_1 () {
    let info = hex!( "17adde3164d65a90d077fd9a0fdba665152c3336");
    let ikmE = hex!( " 4e627f7d755a76961e60ee218c2ab33ee877c49a2363bf03ae4dea2c811bf3c6");
    let skEm = hex!( " 30fbc0d41cd01885333211ff53b9ed29bcbdccc3ff13625a82db61a7bb8eae19");
    let pkEm = hex!( " 04591775168f328a2adbcb887acd287d55a1025d7d2b15e1937278a5efd1d48b
                19c00cf07559320e6d278a71c9e58bae5d9ab041d7905c66291f4d08459c946e18");
    let ikmR = hex!( "1020a03f4ec8eaf31018ee2c06774580fa5c6a1d5ead187bbcaf1412d003e381");
    let skRm = hex!( "a795c287c132154a8b96dc81dc8b4e2f02bbbad78dab0567b59db1d1540751f6");
    let pkRm = hex!( "043ee7314407753d1ba296de29f07b2cd5505ca94b614f127e71f3c19fc7845d
                af49c9bb4bf4d00d3b5411c8eb86d59a2dcadc5a13115fa9fef44d1e0b7ef11cab");
    let shared_secret = hex!( " 7eabf4bab973fc9cc8b3bb2fdaa4d7f154309c31d11214cc48b4a8f
                3d65236f7");
    let key = hex!( "c508c44d920152fb8dd597c8edce4cd1");
    let base_nonce = hex!( "4ac4413d13c5713d6c76fad2");
    let exporter_secret = hex!( "dd82a88bd58f05bc453a77495898af2df905be8b6ffe096a071b8
                0edf3428d1c");

    let (pkrm3, skrm3) = HpkeKemSecP256k1HkdfSha256::derive_from_seed(&Array::from(ikmR));
    assert_eq!(pkrm3.as_bytes().as_slice(), &pkRm );
    assert_eq!(skrm3.as_bytes().as_slice(), &skRm );

    let (pkem3, skem3) = HpkeKemSecP256k1HkdfSha256::derive_from_seed(&Array::from(ikmE));
    assert_eq!(pkem3.as_bytes().as_slice(), &pkEm );
    assert_eq!(skem3.as_bytes().as_slice(), &skEm );
    
    let encapsulator = HpkeKemSecP256k1HkdfSha256::from_bytes_encap(&GenericArray::from_slice(&pkRm));
    let decapsulator = HpkeKemSecP256k1HkdfSha256::from_bytes_decap(&GenericArray::from_slice(&skRm));
    
    //let mut pred_rng = PredictableRng::new(&skEm);

    let (c0_calc, k_calc ) = encapsulator.encapsulate_deterministic(&ikmE).unwrap();
    assert_eq!(c0_calc.as_slice(), &pkEm);
    assert! ( k_calc == shared_secret );

    let k_calc2 = decapsulator.decapsulate(&c0_calc).unwrap();
    assert_eq!(k_calc2, shared_secret);

    //let kdf = LabelledTkdf1::<HmacReset<Sha256>,LabelHpkeV1>::new_with_label::<LabelKdf::<kem_id::DhKemSecP256k1HkdfSha256,kdf_id::HkdfSha256,aead_id::Aes128Gcm>>().into();
    let (key2, base_nonce2, exporter_secret2) = HpkeHkdfSha256::derive::<U16, U12, U32, LabelKdf::<kem_id::DhKemSecP256k1HkdfSha256,kdf_id::HkdfSha256,aead_id::Aes128Gcm>>(false, &shared_secret, &info, None).unwrap();
    assert! ( key2 == key);
    assert! ( base_nonce2 == base_nonce);
    assert! ( exporter_secret2 == exporter_secret);
    
    // Repeat using full HPKE types
    let decryptor = HpkeIesK256Sha256Aes128Gcm::decryptor_from_bytes(&GenericArray::from_slice(&skRm));
    let cipher_context = decryptor.setup_receiver_cipher(&c0_calc, &info, None).unwrap();

    assert_eq!(cipher_context.base_nonce, base_nonce); // only base nonce is readily accessible
}



// https://www.ietf.org/archive/id/draft-wahby-cfrg-hpke-kem-secp256k1-01.html
// B.1. DHKEM(Secp256k1, HKDF-SHA256) HKDF-SHA256 AES-128-GCM
#[test]
#[allow(non_snake_case)]
fn test_p256k1_b_1_2 () {
    let info = hex!( "70aa544b76a9d75a2b98682243489b1a2a315cc2");
    let ikmE = hex!( " 4c74b4c2bf105ba4390c23399b43a0f08de95686133e90288deafcea786f313e");
    let skEm = hex!( " be124a18ba7956629489da30493aae91a51ad2bd1a41f34b39ec6b28de946576");
    let pkEm = hex!( " 048f1100da3b5413c417e224262b45f146884e21691c0ffff11cd04a762598c5
                e739f8c5d460a328de39c94a1ab922c9419be89cc36d262cb7ce8a28f850f8e8ff");
    let ikmR = hex!( "f3dc9707eac8feb1a86c96279e23318fae9f3e2c04aca5ca9e2ace204488bd35");
    let skRm = hex!( "040fc95447fff5a811321da69ff4655d185d58edef93453ab23dfb1be2f02702");
    let pkRm = hex!( "04a3935d9f2ea9c4b23cdf49f4761625b2acbc1fc89532fe2c3af9d1b1c61b9f
                167f61ba6125d47151df26e2ecfa851bd79719c99ff354c9b9e9619f25cb6ba6d7");
    let ikmS = hex!("9fbf7fcf111cc65b6079290c65d0839396104f2dfd39ad34196a4b29d4122383");
    let _skSm = hex!("040fc95447fff5a811321da69ff4655d185d58edef93453ab23dfb1be2f02702");
    let _pkSm = hex!("04a3935d9f2ea9c4b23cdf49f4761625b2acbc1fc89532fe2c3af9d1b1c61b9f
                167f61ba6125d47151df26e2ecfa851bd79719c99ff354c9b9e9619f25cb6ba6d7");
    let shared_secret = hex!( " a2dad1b68920ce1052742b1f293d819735a6486a2ebe7443a655105
                9a538bfdc");
    let key = hex!( "56fe074940f495dc98c84b6328be4ebc");
    let base_nonce = hex!( "86a7381e39a2385c9a1c3118");
    let exporter_secret = hex!( "e0abbed4f7753f450466fa5e4d37fe32ee72c5b17b0ec8de79d14
                37b49646ac2");

    let (pkrm3, skrm3) = HpkeKemSecP256k1HkdfSha256::derive_from_seed(&Array::from(ikmR));
    assert_eq!(pkrm3.as_bytes().as_slice(), &pkRm );
    assert_eq!(skrm3.as_bytes().as_slice(), &skRm );

    let (pkem3, skem3) = HpkeKemSecP256k1HkdfSha256::derive_from_seed(&Array::from(ikmE));
    assert_eq!(pkem3.as_bytes().as_slice(), &pkEm );
    assert_eq!(skem3.as_bytes().as_slice(), &skEm );

    let (pkSm3, skSm3) = HpkeKemSecP256k1HkdfSha256::derive_from_seed(&Array::from(ikmS));
    //assert_eq!(pkSm3.as_bytes().as_slice(), &pkSm );
    //assert_eq!(skSm3.as_bytes().as_slice(), &skSm );

    //let mut pred_rng = PredictableRng::new(&skEm);

    let encapsulator = HpkeAuthKemSecP256k1HkdfSha256::encap_from_keys(pkrm3.encapsulator.recipient_public, skSm3.decapsulator.recipient_private);
    let decapsulator = HpkeAuthKemSecP256k1HkdfSha256::decap_from_keys(pkSm3.encapsulator.recipient_public, skrm3.decapsulator.recipient_private.clone() );
    
    let (c0_calc, k_calc ) = encapsulator.encapsulate_deterministic(&ikmE).unwrap();

    assert_eq!(c0_calc.as_slice(), &pkEm);
    assert! ( k_calc == shared_secret );

    let k_calc2 = decapsulator.decapsulate(&c0_calc).unwrap();
    assert_eq! ( k_calc2, shared_secret);

    //let kdf = LabelledTkdf1::new_with_label::<LabelKdf::<kem_id::DhKemSecP256k1HkdfSha256,kdf_id::HkdfSha256,aead_id::Aes128Gcm>>().into();
    
    let (key2, base_nonce2, exporter_secret2) = HpkeHkdfSha256::derive::<U16, U12, U32, LabelKdf::<kem_id::DhKemSecP256k1HkdfSha256,kdf_id::HkdfSha256,aead_id::Aes128Gcm>>(true, &shared_secret, &info, None).unwrap();
    assert_eq! ( key2, key);
    assert_eq! ( base_nonce2, base_nonce);
    assert_eq! ( exporter_secret2, exporter_secret);

    // Repeat using full HPKE types
    let decryptor = HpkeAuthIesK256Sha256Aes128Gcm::auth_decryptor_from_keys(skrm3.decapsulator.recipient_private, pkSm3.encapsulator.recipient_public);
    let cipher_context = decryptor.setup_receiver_cipher(&c0_calc, &info, None).unwrap();

    assert_eq!(cipher_context.base_nonce, base_nonce); // only base nonce is readily accessible
}





// https://www.ietf.org/archive/id/draft-wahby-cfrg-hpke-kem-secp256k1-01.html
// B.3. DHKEM(Secp256k1, HKDF-SHA256) HKDF-SHA256 ChaCha20-Poly1305
#[test]
#[allow(non_snake_case)]
fn test_p256k1_b_2_1 () {
    let info = hex!( "b546c00cece2e2ff0815eb0f8124fb9028c66e80");
    let ikmE = hex!( " 41233637379f346f4e70e9ca44c31e7ee284d42a5bfd72572ae8884a09aa355e");
    let skEm = hex!( " 8979ee752423d020085c75cce1644959f819464a4c1c4e9a28ce4dd482991c1c");
    let pkEm = hex!( " 040de7712da136d40779452a32e70ec834fa092ee8e3f26450786c6cd51396e8
                596c958065594d30432e812fc7a53a10d7fce2ce9bf52ccce72cbad4c79d3b17f6");
    let ikmR = hex!( "323c89b1ca03ca9c4ac6316d02f4604f2f6804665a13d8635786281f00f18006");
    let skRm = hex!( "024be5fda9036a2d81f8c634193b5ce83e65bfc4373ae8b7a960fea8770d1f8f");
    let pkRm = hex!( "040986ec455812ddd870414c2753f75dadaefda155bc7bd18c4ab6ff3dd61b2e
                a3bee4ab2a0160b8e330757fc6d81d88ece7051bd9a07fa7e5368ea579e2e6c0e6");
    let shared_secret = hex!( " ad889cd7b11e8881252f8f12539be9f5e36d2b95c96c875fb0e449c
                711e8bc0d");
    let key = hex!( "da2f3e53e24306c97331e92f564b6c207246e9ab4dea07a472401702d0af5c53");
    let base_nonce = hex!( "d4d0dcfeeb6767d808f319e4");
    let exporter_secret = hex!( "3edae43083bb52033f9ff2eea2bf5a8bdc8bbd5509e5958b09c47
                7b32d2432ae");

    let (pkrm3, skrm3) = HpkeKemSecP256k1HkdfSha256::derive_from_seed(&Array::from(ikmR));
    assert_eq!(pkrm3.as_bytes().as_slice(), &pkRm );
    assert_eq!(skrm3.as_bytes().as_slice(), &skRm );

    let (pkem3, skem3) = HpkeKemSecP256k1HkdfSha256::derive_from_seed(&Array::from(ikmE));
    assert_eq!(pkem3.as_bytes().as_slice(), &pkEm );
    assert_eq!(skem3.as_bytes().as_slice(), &skEm );

    let encapsulator = HpkeKemSecP256k1HkdfSha256::from_bytes_encap(&pkRm.into());
    let decapsulator = HpkeKemSecP256k1HkdfSha256::from_bytes_decap(&skRm.into());
    
    //let mut pred_rng = PredictableRng::new(&skEm);
    
    let (c0_calc, k_calc ) = encapsulator.encapsulate_deterministic(&ikmE).unwrap();
    assert_eq!( c0_calc.as_slice(), &pkEm);
    assert! ( k_calc == shared_secret );

    let k_calc3 = decapsulator.decapsulate(&c0_calc).unwrap();
    assert_eq!(k_calc3, shared_secret);

    //let kdf = LabelledTkdf1::new_with_label::<LabelKdf::<kem_id::DhKemSecP256k1HkdfSha256,kdf_id::HkdfSha256,aead_id::Aes256Gcm>>().into();
        
    let (key2, base_nonce2, exporter_secret2) = HpkeHkdfSha256::derive::<U32, U12, U32, LabelKdf::<kem_id::DhKemSecP256k1HkdfSha256,kdf_id::HkdfSha256,aead_id::Aes256Gcm>>(false, &shared_secret, &info, None).unwrap();
    assert! ( key2 == key);
    assert! ( base_nonce2 == base_nonce);
    assert! ( exporter_secret2 == exporter_secret);

    // Repeat using full HPKE types
    let decryptor = HpkeIesK256Sha256Aes256Gcm::decryptor_from_bytes(&GenericArray::from_slice(&skRm));
    let cipher_context = decryptor.setup_receiver_cipher(&c0_calc, &info, None).unwrap();
    assert_eq!(cipher_context.base_nonce, base_nonce); // only base nonce is readily accessible
}





// https://www.ietf.org/archive/id/draft-wahby-cfrg-hpke-kem-secp256k1-01.html
// B.2. DHKEM(Secp256k1, HKDF-SHA256) HKDF-SHA256 Aes256GCM
#[test]
#[allow(non_snake_case)]
fn test_p256k1_b_2_2 () {
    let info = hex!( "5d5e00224d79f2a0890265c0038cb8b95fa2cc2d");
    let ikmE = hex!( " 3e1ad67e84680247c9918dbfd60751b1b1a16191929c1f4302c18947b61980ea");
    let skEm = hex!( " c958968d81e6827bc18c64511c60598411da2c21e3b74ba7e030f2d6f41d83b3");
    let pkEm = hex!( " 0459c8cec477bfb5eb8c8f91caf1b892ee89ee56f59364c19daf0153d93da0cb
                87bf76ba75bb479cf37594eea19697a459f469ed75e649de8e39cc562cad59eccc");
    let ikmR = hex!( "e536c3b25ca8e60c44a1788eca0d3cc74c143afa8418170f0219390d3c4bc291");
    let skRm = hex!( "45ea3cf6c4fcf5d9874b58f3d7a518584e4e5349756b41d79f76fdbd280259f8");
    let pkRm = hex!( "04376203ae7189b010cf97c5df7f8451c836bc4bfe9572d62c88858e1fb58179
                9c762a0157f5f15055c91da4ece1bd536d28cd2cdffd233ee9632b3f8a9c237861");
    let ikmS = hex!("88ddb133402f64de19356158d08deb4f26c1b03e0a7d86dd9bdf6811c5fcd131");
    let _skSm= hex!("45ea3cf6c4fcf5d9874b58f3d7a518584e4e5349756b41d79f76fdbd280259f8");
    let _pkSm = hex!("04376203ae7189b010cf97c5df7f8451c836bc4bfe9572d62c88858e1fb58179
                9c762a0157f5f15055c91da4ece1bd536d28cd2cdffd233ee9632b3f8a9c237861");
    let shared_secret = hex!( " df2175829001db870da7e0c91f44950281600f01eb7544a684130bd
                3316d0cac");
    let key = hex!( "c7134d59f91f41b3c8ce764fef3aa93881ada3a6238c1e2cfc75e1c14dd6845a");
    let base_nonce = hex!( "e5c60c8e0a64f115803e85de");
    let exporter_secret = hex!( "1801bd0baf8879470b9652c68e53dea9061d31f658a3bf2196628
                6dd511b2858");

    let (pkrm3, skrm3) = HpkeKemSecP256k1HkdfSha256::derive_from_seed(&Array::from(ikmR));
    assert_eq!(pkrm3.as_bytes().as_slice(), &pkRm );
    assert_eq!(skrm3.as_bytes().as_slice(), &skRm );

    let (pkem3, skem3) = HpkeKemSecP256k1HkdfSha256::derive_from_seed(&Array::from(ikmE));
    assert_eq!(pkem3.as_bytes().as_slice(), &pkEm );
    assert_eq!(skem3.as_bytes().as_slice(), &skEm );

    let (pkSm3, skSm3) = HpkeKemSecP256k1HkdfSha256::derive_from_seed(&Array::from(ikmS));
    
    //let mut pred_rng = PredictableRng::new(&skEm);
    let encapsulator = HpkeAuthKemSecP256k1HkdfSha256::encap_from_keys(pkrm3.encapsulator.recipient_public, skSm3.decapsulator.recipient_private);
    let decapsulator = HpkeAuthKemSecP256k1HkdfSha256::decap_from_keys(pkSm3.encapsulator.recipient_public, skrm3.decapsulator.recipient_private.clone());
    
    let (c0_calc, k_calc ) = encapsulator.encapsulate_deterministic(&ikmE).unwrap();
    assert_eq!( c0_calc, pkEm.into());
    assert_eq!( k_calc, shared_secret );
        
    let k_calc2 = decapsulator.decapsulate(&c0_calc).unwrap();
    assert_eq! ( k_calc2, shared_secret);

    //let kdf = LabelledTkdf1::<HmacReset<Sha256>,LabelHpkeV1>::new_with_label::<LabelKdf::<kem_id::DhKemSecP256k1HkdfSha256,kdf_id::HkdfSha256,aead_id::Aes256Gcm>>().into();
    
    let (key2, base_nonce2, exporter_secret2) = HpkeHkdfSha256::derive::<U32, U12, U32, LabelKdf::<kem_id::DhKemSecP256k1HkdfSha256,kdf_id::HkdfSha256,aead_id::Aes256Gcm>> ( true, &shared_secret, &info, None).unwrap();
    assert_eq! ( key2, key);
    assert_eq! ( base_nonce2, base_nonce);
    assert_eq! ( exporter_secret2, exporter_secret);
  
    // Repeat using full HPKE types
    let decryptor = HpkeAuthIesK256Sha256Aes256Gcm::auth_decryptor_from_keys(skrm3.decapsulator.recipient_private, pkSm3.encapsulator.recipient_public);
    let cipher_context = decryptor.setup_receiver_cipher(&c0_calc, &info, None).unwrap();
    assert_eq!(cipher_context.base_nonce, base_nonce); // only base nonce is readily accessible
}



// https://www.ietf.org/archive/id/draft-wahby-cfrg-hpke-kem-secp256k1-01.html
// B.3. DHKEM(Secp256k1, HKDF-SHA256) HKDF-SHA256 ChaCha20-Poly1305
#[test]
#[allow(non_snake_case)]
fn test_p256k1_b_3_1 () {
    let info = hex!( "609dcb9844f8412343191f93add1177186c03a36");
    let ikmE = hex!( " 77caf1617fb3723972a56cd2085081c9f66baae825ce5f363c0a86ec87013fa0");
    let skEm = hex!( " 1300156862599d00ecbb066644bf4d4505b56a9b235eae7a8632defc4335d5c0");
    let pkEm = hex!( " 0471788be0ccf916302c4f2225bba89a0ff3832df1fe50b48d8ccb910be74e30
                241428ba6de731ccf538ded2913febdfe14b2648fafb8fdd35b8aa91804c706076");
    let ikmR = hex!( "71b530bed75fc3fa2f8e8bb163203e6ee676565cc61cd59d66352676341c0688");
    let skRm = hex!( "4a99cf59fb6af25c324299a39fef2db3931667ee89528e3aacc8b61d591ad643");
    let pkRm = hex!( "04e660b55a28899c472ca023dce35f23da3cf16677dbdce9ed25353bd8b70cbb
                8bee0abd2cc8936aee263a08d5b2a15d29a16d12b75fda63b9c614c477af165e2d");
    let shared_secret = hex!( "a81a3ccf56f48c699eb9f393e0701692836f9ac2e06b493ccbf99ac
                68a792bbe");
    let key = hex!( "4c260fe82e8c3737e7a70c3223cb16fc205682255389ad4bc3e7fae42c46b062");
    let base_nonce = hex!( "e035bbf3c39ff5a7196cfe84");
    let exporter_secret = hex!( "83e82aad90186ddd7e1db090c840ee70eb6cac7531b64dc52a129
                97462c8d0d8");

    let (pkrm3, skrm3) = HpkeKemSecP256k1HkdfSha256::derive_from_seed(&Array::from(ikmR));
    assert_eq!(pkrm3.as_bytes().as_slice(), &pkRm );
    assert_eq!(skrm3.as_bytes().as_slice(), &skRm );

    let (pkem3, skem3) = HpkeKemSecP256k1HkdfSha256::derive_from_seed(&Array::from(ikmE));
    assert_eq!(pkem3.as_bytes().as_slice(), &pkEm );
    assert_eq!(skem3.as_bytes().as_slice(), &skEm );

    //let mut pred_rng = PredictableRng::new(&skEm);

    let encapsulator = HpkeKemSecP256k1HkdfSha256::from_bytes_encap(&pkRm.into());
    let decapsulator = HpkeKemSecP256k1HkdfSha256::from_bytes_decap(&skRm.into());
    
    let (c0_calc, k_calc ) = encapsulator.encapsulate_deterministic(&ikmE).unwrap();
    assert_eq!( c0_calc.as_slice(), &pkEm);
    assert! ( k_calc == shared_secret );

    let k_calc2 = decapsulator.decapsulate(&c0_calc).unwrap();
    assert_eq! ( k_calc2, shared_secret);

    //let kdf = LabelledTkdf1::new_with_label::<LabelKdf::<kem_id::DhKemSecP256k1HkdfSha256,kdf_id::HkdfSha256,aead_id::ChaCha20Poly1305>>().into();
       
    let (key2, base_nonce2, exporter_secret2) = HpkeHkdfSha256::derive::<U32, U12, U32, LabelKdf::<kem_id::DhKemSecP256k1HkdfSha256,kdf_id::HkdfSha256,aead_id::ChaCha20Poly1305>>(false, &shared_secret, &info, None).unwrap();
    assert! ( key2 == key);
    assert! ( base_nonce2 == base_nonce);
    assert! ( exporter_secret2 == exporter_secret);

    // Repeat using full HPKE types
    let decryptor = HpkeIesK256Sha256ChaCha20Poly1305::decryptor_from_bytes(&GenericArray::from_slice(&skRm));
    let cipher_context = decryptor.setup_receiver_cipher(&c0_calc, &info, None).unwrap();
    assert_eq!(cipher_context.base_nonce, base_nonce); // only base nonce is readily accessible
}





// https://www.ietf.org/archive/id/draft-wahby-cfrg-hpke-kem-secp256k1-01.html
// B.3. DHKEM(Secp256k1, HKDF-SHA256) HKDF-SHA256 ChaCha20-Poly1305
#[test]
#[allow(non_snake_case)]
fn test_p256k1_b_3_2 () {
    let info = hex!( "42bb2361c10ad20c7f7403d3e048f8f74139258a");
    let ikmE = hex!( " f402a160b0dd43a5490e9315dd8ea386eb3b2bde9e252857e8a3132fa084506b");
    let skEm = hex!( " 338693112ca52e24b33c8211cf654ed6c9c44d1e74f344c724728cd9a4554053");
    let pkEm = hex!( " 04de99438fc76aaec2117df2346593c16f0a70ea9695ca7651aff895463b91e3
                f3c846925784ddabd6b00b5094c10ba3b11bb9ff8b11ff2e853ac03373f09d9109");
    let ikmR = hex!( "d574268376eddb281b0dd1a5fda3f073d1b7b070a90387727e7433d87ec80d6d");
    let skRm = hex!( "38aca581ad6a6a202fa89ac49f89650fac018b7f1d724a72040fea497ed95b84");
    let pkRm = hex!( "04a6e334bb434dcf340fa2a8267ed828b23632de1f346b8acd7a5b8e83b9bc3f
                58bbfabfc27dad4cbc30230de97bada0568c73f1ee877a885f5a3754bfc2287c84");
    let ikmS = hex!("e9e68de251a00dcf0d91ca20883153bb69b912df0ba9c20938407c787f44ea67");
    let _skSm= hex!("38aca581ad6a6a202fa89ac49f89650fac018b7f1d724a72040fea497ed95b84");
    let _pkSm = hex!("04a6e334bb434dcf340fa2a8267ed828b23632de1f346b8acd7a5b8e83b9bc3f
                58bbfabfc27dad4cbc30230de97bada0568c73f1ee877a885f5a3754bfc2287c84");
    let shared_secret = hex!( " 9b61edd3a878a5c4386bd6c42c4f2334a1ad4029e62b4cd24b16b3d
                b41f4cb0f");
    let key = hex!( "f18103a860ae1eee5147aec66c2111ccc937529f9e0ba499038471326daa205e");
    let base_nonce = hex!( "a1172b6040d1f7da83916d94");
    let exporter_secret = hex!( "89125c238053ad3cefb2a0acdb8da1ce89785dba613a0ca83ed78
                035c51f3667");

    let (pkrm3, skrm3) = HpkeKemSecP256k1HkdfSha256::derive_from_seed(&Array::from(ikmR));
    assert_eq!(pkrm3.as_bytes().as_slice(), &pkRm );
    assert_eq!(skrm3.as_bytes().as_slice(), &skRm );

    let (pkem3, skem3) = HpkeKemSecP256k1HkdfSha256::derive_from_seed(&Array::from(ikmE));
    assert_eq!(pkem3.as_bytes().as_slice(), &pkEm );
    assert_eq!(skem3.as_bytes().as_slice(), &skEm );

    let (pkSm3, skSm3) = HpkeKemSecP256k1HkdfSha256::derive_from_seed(&Array::from(ikmS));
    
    //let mut pred_rng = PredictableRng::new(&skEm);
    let encapsulator = HpkeAuthKemSecP256k1HkdfSha256::encap_from_keys(pkrm3.encapsulator.recipient_public, skSm3.decapsulator.recipient_private);
    let decapsulator = HpkeAuthKemSecP256k1HkdfSha256::decap_from_keys(pkSm3.encapsulator.recipient_public, skrm3.decapsulator.recipient_private.clone() );
    
    let (c0_calc, k_calc ) = encapsulator.encapsulate_deterministic(&ikmE).unwrap();
    assert_eq!( c0_calc, pkEm.into() );
    assert_eq!( k_calc, shared_secret );

    let k_calc2 = decapsulator.decapsulate(&c0_calc).unwrap();
    assert_eq!( k_calc2, shared_secret);

    //let kdf = LabelledTkdf1::<HmacReset<Sha256>,LabelHpkeV1>::new_with_label::<LabelKdf::<kem_id::DhKemSecP256k1HkdfSha256,kdf_id::HkdfSha256,aead_id::ChaCha20Poly1305>>().into();
    
    let (key2, base_nonce2, exporter_secret2) = HpkeHkdfSha256::derive::<U32, U12, U32, LabelKdf::<kem_id::DhKemSecP256k1HkdfSha256,kdf_id::HkdfSha256,aead_id::ChaCha20Poly1305>> ( true, &shared_secret, &info, None).unwrap();
    assert_eq! ( key2, key);
    assert! ( base_nonce2 == base_nonce);
    assert! ( exporter_secret2 == exporter_secret);
    

    // Repeat using full HPKE types
    let decryptor = HpkeAuthIesK256Sha256ChaCha20Poly1305::auth_decryptor_from_keys(skrm3.decapsulator.recipient_private, pkSm3.encapsulator.recipient_public);
    let cipher_context = decryptor.setup_receiver_cipher(&c0_calc, &info, None).unwrap();

    assert_eq!(cipher_context.base_nonce, base_nonce); // only base nonce is readily accessible


}
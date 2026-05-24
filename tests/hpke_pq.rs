
// Test vectors from draft-ietf-hpke-pq-03

use aead::Payload;
#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-sha2", feature="rustcrypto-aes"))]
use base64::{prelude::BASE64_STANDARD, Engine};
use hex_literal::hex;
#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-sha2", feature="rustcrypto-aes"))]
use hmac::HmacReset;
#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-sha2", feature="rustcrypto-aes"))]
use hpke::hpke_kdf::{LabelHpkeV1, LabelKdf};
    #[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-p256", feature="rustcrypto-sha3", feature="rustcrypto-aes"))]
use hpke::hpke_types::{p256_kems, sha2_kdfs};
#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-sha2", feature="rustcrypto-aes"))]
use hpke::hpke_types::sha2_kdfs::{LabelledTkdf1};
use hpke::hpke_types::{HpkeAuthIesP256Sha256Aes256Gcm, p256_kems::HpkeAuthKemP256HkdfSha256, HpkeIesP256Sha256Aes256Gcm, HpkeIesP384Sha384Aes256Gcm, HpkeIesP521Sha512Aes256Gcm, HpkeIesX25519Sha256ChaCha20Poly1305, p256_kems::HpkeKemP256HkdfSha256, p384_kems::HpkeKemP384HkdfSha384, p521_kems::HpkeKemP521HkdfSha512, x25519_kems::HpkeKemX25519HkdfSha256}; 
use hpke::HpkeIes;

#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-sha2", feature="rustcrypto-aes"))]
use hpke::hpke_types::draft_ietf_hpke_pq::{HpkeIesMlKem768Sha256Aes128Gcm, HpkeIesMlKem1024Sha384Aes256Gcm};

#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-p256", feature="rustcrypto-sha3", feature="rustcrypto-aes"))]
use hpke::hpke_types::draft_ietf_hpke_pq::HpkeIesMlKem768P256Shake256Aes128Gcm;
#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-p384", feature="rustcrypto-sha3", feature="rustcrypto-aes"))]
use hpke::hpke_types::draft_ietf_hpke_pq::HpkeIesMlKem1024P384Shake256Aes256Gcm;

#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-sha2", feature="rustcrypto-aes"))]
use hpke::{aead_id, kdf_id, kem_id};
#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-sha2", feature="rustcrypto-aes"))]
use kdfs::KdfLabelled;
use kdfs::{Kdf};
use kdfs::hybrid_array::Array;

#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-sha2", feature="rustcrypto-aes"))]
use kems::{Capsulator, EncodedSizeUser2, GetEncapsulator, FromKeys, EncodeSeed};
use kems::generic_array::{GenericArray, typenum::consts::U32};

#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-sha2", feature="rustcrypto-aes"))]
use sha2::Sha256;
use sha2::{Sha384};


#[allow(non_snake_case, unused)]
#[test]
#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-sha2", feature="rustcrypto-aes"))]
// A.1.  ML-KEM-768, HKDF-SHA256, AES-128-GCM
fn a_1_1()
{
    // mode: 0
    // kem_id: 65
    // kdf_id: 1
    // aead_id: 1

    let info  = hex!("34663634363532303666366532303631323034373732363536333639363136653230353537323665");
    let ikmR = hex!("19aaaad124d9e3a3645aa45cb7f5b6db21f54832f659e0b01d54b630eb8fbb5d
        9738866d84c4e597178ae106038a6a6b475ed76cad81a5daa312c3f838a2edaf");
    let pkRm = hex!("fba8082d27891eb10fc349579dca26ba414831527d41e0841bb0154cc85436f0
        7ed2c3afed532dda70420c0c9c45a879f2774be124824c762140f11191503a24
        03a5fb353a4220b7ff9b854be523ad76031b46736f3a5021f3bd61eb9ce1931e
        5d8938a60357fcac41fc900d2d5566a9233f56c663c068b3e8e759df5b461d14
        2ec5e55b4e568894ac0a8647ccfba4b91ba9887cc1bf4bac5b31bac6586a2fa4
        7046f95bb71a0b231c7bbca1694e895711b612ae004b0c4bd3a3ada3198c2882
        0dc38c47438f5c1a338be3945a8a8b0a986dd7f6682f58c3b3d870bcdcbf6d35
        024e453d0af106c0fc1ea8549083e59d43bb867e04837cf635ae935f4dd5a30b
        7c87fa6b8167b2113c9c5fade1c59d685432b96a1772b1c98c39fcf44b13837c
        f1a982721454c8d64b9ed72e137834773b18d64bc57786941087109e8c3f5f74
        4afa3426aee52f19dc53656274d706a3f6b149bbe05a465b69cf484d8c76b67f
        38c8a1b2744fac8136e7991fabc9d296b591778f48a703a705223e1a794158b9
        1ccc78a90a3e1823059539519bf96803e7b20d99ac7206a6c93b8b859734c140
        c334261948e45e275517880b6f7b82bae01c256c633f1bf0758d2a958747695c
        d155922b29ea6b444e0c8dab9b3937f57d2c421d539a1356546221b77dc288ce
        d2f32c25744a8673c268e34e75e0cc3dc39807622754c1a3000b55446056f035
        4c119a487a67139c087768cb889729a0cf30937c89b42b65b0859337b2e17d39
        dcc65a2cad8f08c6f0192472665346d32e48f492b9931e33aa458b385c96b04d
        0614946451b7c8ebae65884d430a63199316ca997caa689911a999f41451dd62
        59e205a533d52912d0c8a8b30fcc277c0e411afa21ae98a25c2ff51d56494215
        83baedb2902db177e7bb267bdc56a4db1a82a097e0d440f3b938759ca4636990
        09cab3a5069b51a1037c81654eda9371e028ff00bc09a444dcc38f1bcb25974c
        413903252ce93999ab70b889b5c39a34d0e40f07f5485759b8cd36bca2d9c27b
        a5633ea44d8a66178ccb917b6c099fa2944d6a2354c08faf5316bda183d95045
        cb641d79bc98d7b89cbc93765f72b5e4cc1195872a35251edf229aecf92305e9
        317f3b5dcdb54ad377ccc6e5798bd18c1f587f67e932bf812ae4606bfc711831
        524d86db28956509cfdc503a9564d0561c994cca3b15b4fab316d1c48388f364
        0163a693519040c3ccdd69219b17b8ae73518ee92d99812a1c4b3af1b70736bc
        1e0269b9a8e361ec8547800a144abb2b4e269167f41dee76afd459451ae06069
        88a574f6afde2335c14216b628aad1d76d9020a49f366e8e14bc97785f40f438
        717a6f5fb29a2fec936af13cc7eaba4b52c89edbaf54d340d05a8f2ecbafd750
        08096506fa6b91f6815a3805bcc0d064dca0101bf17c8ce9ba8a951f9e259128
        6432f5591e949289eac495d68780f1d1b5855827a6316c2071af4d0510faea93
        81c580131ba6d45c51b568633255009a366e33a40a1935894e76c6a81c16054a
        26e8760fcb9c6d63e33b891c400c69aaf61c125288b73f5053e74c2a00a27636
        61141c097ebc7ac5bec419dac87133f40499557c2262aacb366a111875f4f11d
        300e82e74147801e16b36b517e05e5de2dd13ca38ef99495fc4658be484f8d7e");
    let skRm = hex!("934ba54b52a6f432074ea5f067f330d82a4da438b3aad1c93effa038b9454fd7
        72311b43acd502f94bbbad2cd16cb1d07418f7e48e74c816ca83b4d5d4be5752");
    let enc = hex!("7319e22bc7ef6d39ed28c489b24534c6df8190cb62308380ebe500897ad62d00c
       89bc1af4b4a5a1ab1c444b3728ff512cca5656cd81f6569599ce47477986dc79c
       8855fb2475e48e29f16a34b10b76f13fca41c2f8ef37d1e8ef5762efce11f3b55
       2aa94f4c68714c813a370b1d4bde0e8fc1fbc61e63a4e3a4b971e4b9928610bfa
       bfbb8f248fba8c481ab175a9b64eb8ca8743be7bf7ff754a5059444465468c1c5
       3abdfe8cdce9256d89ccbf3dc3e763118a528a673257f8da74b61281467a3293d
       c61bb3a98bb123494e6abdb82334ecccc079a85ef6f31c59b55e6955b3100488d
       13558db7e936b4d58262af3173720076028cb4ef51d63dd59d6cc8eb64fed4027
       8ff81b6336f6953ae587c8907f9486be2e074e88de72ffc81ccb9d5f3007cf4b5
       1246c5eb2479600debb3c9c3c7ca035102ef25bc7c9049b7b4a1d4443338516db
       08729123ff522ab7b9651a9e18a64dc552ed822fa2d38afa1293184e4fd0f5f57
       881018757610260ffc29abe5e9125a3b79e91b81bb9d6c8afd089116c27713738
       cc98547d3e84fa81db8bbcc3a90736781b38b011f9c640c4e40e94da11bef7e10
       04a9f021d2ad8701adcdf207c76e0540af82fa74573ab6d2c46eeea060729b85e
       8b44a1a41d33f50ca79e6d5a40ef3474ac8c40ee4e4d607f4ab0d222b3b710f05
       c42b74514375dc564385703b2c4abc857e7842f6964666997e088af9a178e65af
       da20a70fd88ac0bd2efeeeb4d8ad1355c19212832fa943ecef03bd1a9cf03a7f5
       f1b0e8455cbe16488cecb0a90fac3a88b58441a51892de677b22c121942bbd6af
       63073691315110f3d028718891237566badd09ea6dcaf905f02c5a483346a2ef0
       ec3ea6571d2a0cf57f26680c398a82f7c59c14237f79d628d7cf89fbe1b5ef6c0
       b1ae455f535937eadcc8742940c695336306a955627019d9201ee7f68c62c7f34
       f4e0901150d27025a50c69a08664cfe74b9c8d9f8c67ead1c606c10c613a1ee50
       86a8f8802dfa05fc31d684b9a4b64b665ccd3ad75e7cc384c15064d5114a38dfe
       f5070b7cbbe306a45d480fad64f2cf44641d7b61ee24ac59994ac87aa95c2b07a
       d8aceb7ca0f7dffc54e4611159c14888216abce6e9c57c3b670cfea091962c4ee
       d37b2c5aaf48ae7e09315950349bd0baacd377442d3bc6fbeb5afaa19bd1a6e26
       6a5aa7ae2737d0eec4d2e1a17793dc3364c5d79e8cb048c0cc638bd9a019833bf
       780803da5eabea8a05cca08defad47310d898c901a13f1ae61e9bf917e9033851
       85dc53cf085e8e80e4b7fb91d600f928478d01f552105d0f08e7cc56276930cf0
       819b643acd0080de144647e9d19a137385fd17c74c8e406129a178fb2db567c44
       1ea3fc00f3ed666fbc99301e8c7c21163a466075eed818fa19f3c5b9a3b89c346
       af5ce2b8dc65bbbf19a47d676ceb0a4422ccb395ab959a247da8cd679555c7d4a
       7d1b57cadf8184a5ad3f0e961dcf7b6bd83f420b3e8ef03195703f3549b7e891f
       9db6fe51e8d03e42ec73e4b222ca983");
    let shared_secret = hex!("ab72523ee276c1b5653bf19ef201178a312297b47b813b271c68b89
                 aabcf52a1");
    let key = hex!("40d9ae28dd3a899e48a737dea17f4071");
    let base_nonce = hex!("e263b670fc7cc4ec31f0c733");
    let exporter_secret = hex!("ee31d2118ae0c4d92d5011a6954ae932bb013925ed485c9d2d22b
                   70428f1c9ed");

    //let decryptor = HpkeIesMlKem768Sha256Aes128Gcm::new_decryptor_bytes(&GenericArray::from_slice(&ikmR));
    // let kdf = hpke::hpke_types::draft_ietf_hpke_pq::HpkeKemOneStepKdfKeyDerive::<kem_id::MlKem768>::derive_secret_other::<U64>(&ikmR, &[]);
    // println! ( "kdf out={:02X?}", kdf);
    // pub type HpkeIesMlKem768Sha256Aes128Gcm = HpkeIes<HpkeKemMlKem768, HpkeHkdfSha256, aes_gcm::Aes128Gcm, HpkeKemOneStepKdfKeyDerive::<kem_id::MlKem768>>;

    let (encryptor, decryptor) = HpkeIesMlKem768Sha256Aes128Gcm::derive_pair_from_seed(&ikmR).unwrap();
    println! ( "{:02X?}", encryptor.encapsulator.as_bytes());
    assert_eq! ( decryptor.decapsulator.as_bytes().as_slice(), skRm.as_slice());
    //assert_eq! ( HpkeIesMlKem768Sha256Aes128Gcm::Decapsulator::encode(&decryptor.decapsulator).as_slice(), skRm.as_slice());
    assert_eq! ( encryptor.encapsulator.as_bytes().as_slice(), pkRm.as_slice());

    // sequence number: 0
    let pt = hex!("34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739");
    let aad = hex!("436f756e742d30");
    let nonce = hex!("e263b670fc7cc4ec31f0c733");
    let ct = hex!("c7cc1822fee767a90cde7b17f66f98acc96742159ceac9f9403c6a8f378411f4a1
      26124d3c267ed86389a670c69db9cf49b351ca29c4a5e2688ac6818a7761d9656d
      4bd0ae2634c7306b");

    let mut decryptor2 = decryptor.setup_receiver_cipher(enc.as_slice().try_into().unwrap(), &info, None).unwrap();
    assert_eq! ( decryptor2.base_nonce, nonce);

    let pt2 = decryptor2.open(Payload{msg: &ct, aad: &aad }).unwrap();
    assert_eq! ( pt.as_slice(), pt2.as_slice());

    // let sequence number: 1
    let pt = hex!("34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739");
    let aad = hex!("436f756e742d31");
    let nonce = hex!("0e0a56bbb96f8a4f6783c7dc");
    let ct = hex!("1fb9a4f62097c68343babbc54ce313909a181d22eeafe58ea2505087096e6ae3ed
      06144b7d68a0e37a1f6b6108b1553651cd7ac323ecce898f73df0b88c3787126d0
      9a459380d0ba6eb4");

    let pt2 = decryptor2.open(Payload{msg: &ct, aad: &aad }).unwrap();
    assert_eq! ( pt.as_slice(), pt2.as_slice());

    let decryptor3 = decryptor.setup_receiver_export(&GenericArray::from_slice(&enc), &info, None).unwrap();
    let exporter_context = hex!("70736575646f72616e646f6d30");
    //L: 32
    let exported_value = hex!("6e94c470456dc829a017fbb0a46c2a0a7a95201bf47c88a5009c22d10f16900f");
    let kdf = LabelledTkdf1::<HmacReset<Sha256>,LabelHpkeV1>::new_with_label::<LabelKdf::<kem_id::DhKemSecP256k1HkdfSha256,kdf_id::HkdfSha256,aead_id::Aes256Gcm>>().into();
    
    let exported_value2 = decryptor3.export::<U32>(&kdf, &exporter_context);
    assert_eq!( exported_value.as_slice(), &exported_value);
    
    let exporter_context = hex!("70736575646f72616e646f6d31");
    // L: 32
    let exported_value = hex!("77d8231301d7da124c55368967d7cfa7815e5461a6d50135b04a8533e8000ee1");
    let exported_value2 = decryptor3.export::<U32>(&kdf, &exporter_context);
    assert_eq!( exported_value.as_slice(), &exported_value);
}

#[allow(non_snake_case, unused)]
#[test]
#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-sha2", feature="rustcrypto-aes"))]
// A.2.  ML-KEM-1024, HKDF-SHA384, AES-256-GCM
fn a_2_1 () 
{
// mode: 0
// kem_id: 66
// kdf_id: 2
// aead_id: 2
    let info = hex!("34663634363532303666366532303631323034373732363536333639363136653230353537323665");
    let ikmR = hex!("30f75d13c02f5eed4fe46696b45424e5dd3ef6109797d2f0ac661affabf16595
        853e623063b54d4569d99e9c8b8a64d34822faca8947fc5c00c3943a49b88c5d");
    let pkRm = hex!("d7673326e702e98a9db79aa259b3a384978015743ebfebaf181a6f8fc5778266
        78aea1a846cb1b87395be441146f501ba908cbd38904551abc56169b24ba6555
        57935e34b83ab869e2cc9bb00549fe3ca7cf8c59898212d3f2aa292a91c2497d
        22abaeedd330b42074af4baf321031bc05435a6353f281104415c494355983f9
        1f0f657182909512ab260e19018d7300aba33e09934851bba4c3d326a5c80a4c
        f96a11f4b191f226d80b62b1e093f6034b20710eb4728a377765ca157748b5b3
        2e315f3abc7582e69af1d1c78a44cc97a8ab8f2c103c66ab8aea2b25a861e8cb
        6ea07907e8734bd74420596081dfd14a7e57b5e650bdf0bccf22dc9636ec3743
        3a474eb6124e2c144bfcbf4e3a5a453125ecd208f9ec228fd96d929c958f67be
        29a98d0450a29cb468fbb58b6c273964abbc7bec9a2cf7a8be424a57379fa861
        a58e7baadeda270c723b42209fcd593462a75272850ba50129f63bb15270cd39
        623d69f7306c75a9297b6219ccaca21bca63e8a8c7709648db85827814f137ca
        032724c7ab659c8988dc9952fcc8ac6041bcea29ae51744c87799d0ab3358e63
        4890944595b3c5267ac1ccd473a85cbd0e1839218368457378a6e401eb257781
        d1370d1860657679de292c45884f8a995960e3af398c54539628ac785cafa1b4
        78e992976452e6a15c44827367dc14e6944422b5188c7a438a998b3f51944350
        237cac37d46bac8ad51be7fb4f9d60b27910920d2174fa27b5ff0cbdf1035300
        d6840cc71028ab4d46885acf21300da2867b8220e27b463e18bde80b8ba75754
        f9988c08181f154b402f3414832cba4a78a41a263949d46b44389ae9f4550718
        98a3637642b3511af302b4b522d801246494961f1c8369d62aa8106b254344a4
        902d0542cb71e1bdd974a1328315de962feb775b5478572bb12737901ff8f257
        b8752f05c3465b7400b60534866154d6e640ba5038ae5779c510adfd751dbb45
        28a89c8456d51196766ad69147ac73a65311a4c6442058e969e85c10985551da
        63017df11551d12bc0768c336a19ceba7790641092ab90b28a3c55b56d765966
        f5292a350010f3c6b206d0be3e2a21e57675fbcb758a44c44fd88c815535049b
        7abf7a6db8c8bae5f0b0e6c19e6b264e71678878bc024803c5d7e98f148039b2
        2c97963019622812e3086995982709d170a686cbfc5b099e0c07c11118c6a215
        49105a088abdb5a3a9e7d96f2ab02f55b66ba26aaa08921896c9b191cb4c8375
        17d8a73901d014cf543845d95d77c26ed49c78315911c05cbffdd046616a6bf1
        71347dfbbc45b6059253aaa93623f2157690a9073c4a9d05b76aa9d62dd53a78
        58e26970d97121ac824158a70df837b0560b691a0f0201316ecc50e6f7040e27
        8ba46050f8bcbe61eaccc58530b24567943384c15a550ea8853298ca69f01d19
        16976be74368833aff3680bf13b2a308ac426935a93b70cf0b31e8c87dff3a20
        29d947e861a27a829995a83948c00121f5ad6c488415941801fbcbe4c461a176
        c35aa2922aa782b7b40042a560ebc39fa2f26813a47cc2b77e34265a56351552
        c0be52278e098aa38ea53eac2450b165762a53ac3ff39069d456507681eadc9f
        30cc3fba635e7c4426c5b85b6ed9139f12397d91a91e023de1c8aaf348a47803
        2eaf48650f68336b2687d564adbc5611ad1416f4401836a539389a68354a996f
        c2b850e718d9d4c57bf38dd9892b3110224d1c6f2c2b20da8a060dfc343ff153
        b2d3bd5e52ae106357dc7b490be82079800773502ef4024384a743c2ac9742b4
        2b9f5533eef9bb74f60f832470e029506d91b7dbdc44b5a05ff19c09bd903fa2
        8270a168a95ce6231f35bf79726050a697b146622c1c4fdcd2aede0570766c68
        998c5ed19b7832e108ae18a9f7088226923b59917cd9f62365768f629a13daea
        4cbde23531202433061414c846c0239d70d7ba26f83ce2dcc2e0db22b1f75120
        b104f776cb97f45655928ec3a32c260893c03c36e4d0ad6134cc47920f902731
        17931ef6b6268c803712d78fc9b3bd62148e5ec49546e5b624568c19638d2539
        38db039b31795a64818e0f915aec0a3ae8c752396346a2f9213aa80ce30364f7
        e810b508949d71bca5a3a806c9c5e57bb03d540b7df42fbfb210a31b36c0cb82
        0011fa80540512f7e37c3b0ca5f342f46065d64f132fe8dd137f27856a982419");
    let skRm = hex!("1ac1cf1fdbb5a854937963f1d18537a461815522da648b94a607f8b5831962a1
        07a34caa9203ea0178cea9a2e89e9e52c2143423d22af331a72c9ce10a133fc2");
    let enc = hex!("90d3bc233d3daad86ba35343ef9db886deb170dabc3c7751ed46fa11cec64b9ac
       f593beb26434d8a7d85c9113e2c09f4eeaf76c40d91c8dc54b1d21cdf4c5eea89
       d218919baf2e3dee51d6ef2f5a7841afebb408a9f4525b42d0d8b27de847d1501
       6e9d60c6b4e9c627aa6b8f4cc22eb38b2d801f02ad143eebcc65e31414f1d7c0b
       a5873aa48453f7565b539bd7c73911829550c58ac5c422146e64f3257f4edf6d3
       ccb7086ab2f06e2da9ba9d935ccd2b86de9b7bc74a0c6187fc589f8eb45f44b48
       0989f0965a15a9ca715fcb0f4bdc15933daa90d91cfdff61e5b9ffda7322a17cd
       5f70a99e05dd619e04b08ad61e762e858b4ad90062a85840106b7e632e5294b71
       0225d6050e74a11dc13454535047e4a19615b9bdb5d172bdc0e300aec455d24d9
       d900ea78b81e80fe497ec53dba2dbea149aebe0d0f9238c5bdce9ae6fa5c89a42
       e633a2a9d831e20db53de08de0dd2919ed8122b058bfd177ee8b0b4469466dc1c
       4aae00a62f1f968fcb06ca9023a59b43dc68bf4c359a31f6b31b9b5022b9cf21a
       79612de558ba9e94987e9693c55992d4deaf8f77910894d9bbf59503c1e6aa1ce
       f4ac4064d36c23c10f36ebecf6142ec14c03815c0a14c9e54eb39a625484ca328
       e025875b875c3b6f5df221246fad83a9f0f740ed66fc2d166d51acab9eb8d133c
       e30f9399f9e62915bb5ffd566343cb339d9dce31a68fec86bf03c4ca68bd20085
       d690afabfad1891b722bd6d0c8a71aa5f226c219704d139de0deaa624661133bb
       d3dfcd40f58fa9d69ec256b89e2c060760f1d37f44e64f5e57615d20599cc6ae2
       127509e4ccb0b002549fba8ff367cb75a86aac8c42cb93eee32a97c42243a4078
       7f11ee990ffd03934f59a8341d8ff72f0fa87e0358691836f91e2274eda9c1b77
       c33367e6b87968a75751550fe05b08e97aebdd5930386568a1543f83bba96fd46
       9da7f1ade90bc95cfce3c15516f8dee3c644c5a130120ce1b9fc518ec974fb64f
       f7416a21eee6140ca35c44ac2ddda01ba52659e720a130ef5af60300523e38490
       d71667d9664339277b3a9f382a61848969686326fadb69c9597778f7a04c114da
       c32fb8418c90ab81cc02f8d3f5c10448f247701a3b0c65dac417d867a5ea0cf82
       ef81f006c36dbd91862e69bdb44116b9ae583afdc42ace6e6ab655771e92f95f1
       be64a841e6028145f7ce998cc400c5ddc261b182095e451003859bac43bbf15fa
       ba56a7ff00328e81ce1b17536871d34fbc89a9aea3dfca0c8d44517de921d0996
       a0f316665f9706127b83d2d9326dbbb11e66250d9853a1f3edcc6f75dab803bf6
       c904af59b0cce6f51b636912f9cccbe4c8b1665751b449e495f10b567b682aeb5
       ecbf04d18d321f98d8f3e068ac84bd7918595df9a819b60e77841f407e60697b0
       715b9c8b426b0995d7fb372b261911f1947a4fc4c4bc259091f963393f384a590
       12b60bac7f68cbc0c4e4dbd8a28a0f7cba688dc9155b9b994db01b2c897a2e12f
       502379a344052f03f619861c426e70c3147a07737ae434130c76fafdb630a8387
       6e38120186442a535613cba2bc1e995bdf514b4544db16212f44f58f4cca2d4dc
       6fab1950d1489789ae32e13d0880725ba5ff09f841b2b105cc3ed8d653d8d92e4
       cfe7cb8b35f3394829cf1ed2a1c4f60cb259e93e6c7fd6a734c4e997d85b93b27
       dcf72f95660ad2dde3829ac0fc255756b4070a1e0c8e8f5c2e72e251710d0c7c5
       f0ad9f5f83ce74c4625235c9f12c04082eac22faeffd4c1900c0898b3dfa4db1f
       6e7ab039c33f33741baf10ba0f6adb8a02634deab73b88f8aaa8a735714478d5b
       9f951ec4dfd491310d7769d8d1384d879afdc296562ba96ebb2311513161dbfe1
       b5400b1591e8827e2526a7bc837ca5e3546a300afefc26229dab431b797ea6cc0
       c5ebcc68258315e9883a2fc027fcf4bdd257cccad2f577316a6c8be53602b4bb0
       4b793e984e2a3dee7f0eb10087e61785e6c6a126717c20a799865d8f71c7f5b0a
       673473557f9842e7e8565c629e1f180ce757884fd4bda718aedb09ac500b07745
       39d67633d8bfa00c6c7e53451f7e9d19cd71c974d55f4ed42c4bb8d20b93ed1c6
       5ba2babaf9a0adf6b225b5f2a72c51f7a04d0e3a8a7915465dc0694b45280cd1e
       6405728509536b98f07954ddf98df2a0cb07980317352239aed0108199080bade
       97b5078a4a2fbf26");
    let shared_secret = hex!("3a8c0fe7356b0208769fbc76237adc9650ff17ff7c6ee1e23801e84
                 6e2b95742");
    let key = hex!("fce1270fe05d40a6aeb0592ac71ddfd55101b4d318863839511d908f3983f485");
    let base_nonce = hex!("f09225e3efc44884518d6fb4");
    let exporter_secret = hex!("ed85347a28a6c60123cd0cd5cd03f7919e9af237ab0a0a0855cad
                   93decc04ef8a03ecdf7beeff4a3d21d30c44f61b71a");

    let (encryptor2, decryptor2) = HpkeIesMlKem1024Sha384Aes256Gcm::derive_pair_from_seed(&ikmR).unwrap();
    let decryptor = HpkeIesMlKem1024Sha384Aes256Gcm::decryptor_from_bytes(skRm.as_slice().try_into().unwrap());
    
    let mut decryptor2 = decryptor.setup_receiver_cipher(enc.as_slice().try_into().unwrap(), &info, None).unwrap();
    assert_eq!( decryptor2.base_nonce, base_nonce);
    //sequence number = hex!("0
    let pt = hex!("34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739");
    let aad = hex!("436f756e742d30");
    let nonce = hex!("f60e5f7f7adecdcb235a6ab3");
    let ct = hex!("005ed7cf363d8ddc0ae98272ca1a7a52a41881084299d9c8e4cfc12b00f52fd8f1
      791107b25ed7481532981fe7afa8bb9e4586199a285dbd38883832b88a24a2db8b
      cf44775cf755d1ec");
    
    let pt2 = decryptor2.open(Payload{msg: &ct, aad: &aad }).unwrap();
    assert_eq! ( pt.as_slice(), pt2.as_slice());

    //sequence number = hex!("1
    let pt = hex!("34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739");
    let aad = hex!("436f756e742d31");
    let nonce = hex!("f09225e3efc44884518d6fb5");
    let ct = hex!("c0f89431f47e694b63be6c1d303a980d48a1464592b91ab27ba200fd416559dbd6
      f2344318e841c7c2257384a47f55853f174f31f2efff37429c73120c4dd72e24d4
      319d382609253f40");

    let pt2 = decryptor2.open(Payload{msg: &ct, aad: &aad }).unwrap();
    assert_eq! ( pt.as_slice(), pt2.as_slice());

    let decryptor3 = decryptor.setup_receiver_export(enc.as_slice().try_into().unwrap(), &info, None).unwrap();

    let exporter_context=hex!("70736575646f72616e646f6d30");
    //L: 32"
    let exported_value=hex!("03cc889db1e10b62bb1d4aba594f9480911fb3ea785c94735944d3
                  b37592afef");

    let kdf = LabelledTkdf1::<HmacReset<Sha384>,LabelHpkeV1>::new_with_label::<LabelKdf::<kem_id::MlKem1024,kdf_id::HkdfSha384,aead_id::Aes256Gcm>>();
    let kdf2 = kdf.into();
      
    let exported_value2 = decryptor3.export::<U32>(&kdf2, &exporter_context).unwrap();
    assert_eq!( exported_value, exported_value2);

    let exporter_context=hex!("70736575646f72616e646f6d31");
    //L: 32
    let exported_value=hex!("22f64bead57f2fced75f040fe88e42ce086f0c8266a0bfca2577ca
                  0f928a86b6");
    let exported_value2 = decryptor3.export::<U32>(&kdf2, &exporter_context).unwrap();
    assert_eq!( exported_value, exported_value2);

}


#[allow(non_snake_case, unused)]
#[test]
#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-p256", feature="rustcrypto-sha3", feature="rustcrypto-aes"))]
// https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/
//     A.3.  QSF-P256-MLKEM768, SHAKE256, AES-128-GCM
// A.3.1.  Base Setup Information
fn a_3 ()
{

// mode: 0
// kem_id: 80
// kdf_id: 17
// aead_id: 1

use hpke::{hpke_types::draft_ietf_hpke_pq::{HpkeKemMlKem768}, kem_id};
use kdfs::{Kdf, misc::PassThroughKdf};
use kems::{GenerateCapsulatorFromSeed, hybrid::{ExpandSeed, QsfCombiner2}};
use shake::Shake256;
    let info = hex!("34663634363532303666366532303631323034373732363536333639363136653230353537323665");
    let ikmR = hex!("53030f657b3571b44f1b2b85ad6c72e6607d2538c7118b254c76e15277ffc0a2");
    let pkRm = hex!("4466431596c2bda2b49ce5aa83ac520e72bf763a5295009ee6fc7c7cf3a5cd5b
        7e373ac6e2b03685846d36bb691fda571fd149f08aa94d748c67b095b002b4bc
        315df4526469640908580cb2e88afbb692a13a8a372cb17b768925d4367b2a64
        e75b81941651ca0aa24d65bec90c9443c0897207362a8727100356f4006f6e33
        64edb7c310f390c0dc0971b870bcacbc7d5a4770e22dc5e95353181581927555
        f87fd15c48db0455bac9a53639b26e18c854f5bdd7c821d04b2c25aa972ef619
        c54671fa14679fd652ff980bf0906a7d2b396c9bbd2045a916952f7cb920f4bb
        199010a8129b08ffac3305b6388bc59f435b5e1c483c0cc248ed1c15b63a9717
        555476e7a2a5b9b732447340651510079886c66db8a777b704068ac748161a91
        86d201a50675398003d773c4bfb895e1267b6c952fc542b485518affa69de663
        a7af223679106247794604969216a5b2b2e98d6cbb4aa5993682d0aafb713f56
        568d2537a32f3a5b8443c3455364b3982a73fb5bac928b12f817a39811f8d6aa
        2ae0c5a73145d7e03b785278fc360ae93472c7e0c0f24b75fb57cb348c2a9fa4
        280975c7fbc8a11dbb56d0c4ad74225b7186cbbf5a82b377592c0ab5bbd69851
        b664130ab47438cab5db0891d28e2b556754a094e16729cd566c87f2c57dd17b
        35430b48309153f9295d671d3da8797e0a91ad7087597c819557368bc83a24b7
        a980713f0a937c3925aa02a7c98d499c61632052219ff350c4118126c78346ee
        f9167cd39c37ea67eb67c2d6f3310c521d7bd17ef3fa2d58e7827064255419ad
        d24147a99a2ecf128542947367f74ed31085a2874f7e300b71286327e712a4e3
        3c4d856535038088898a23f42c3541ce3afc5e57e259225c1d86499b09943479
        352c85113e86238158a440cf24af9cd74b60b41359905864801f349556ca712d
        a0013adf566aa1f82e20949f076a2e5d9064c8895500a825a49ca8e9326b3dc5
        85fef48da3340a6005538236a61e898cd9f7116e381a86d992a740670fc733a2
        b8bf2729a4c571aaf2733c01690fd563cce52854d3c39fa903afc522cf957b27
        98f165cc41203096a7a2e517a92c891fd30d553308524a22e48802a374a5abb3
        7e7b894697057dd0babdc2cac5157744bc465bafc51809f66ca3893be26064b2
        0b8bcc4bce02b808dd1645cda41754871dd3929232618a649b0c26dc9705d4a1
        70e67fd1982785f595874a604b946babe85b4486354e904eaf9629c1a0bfe438
        800915bcff568273a991313357f8acc8df276a9441a167e78e32dc9c93c5c8da
        e009a687cb255953d6d0905246a2bcb091b3036ea77011fe0a012b528b705b62
        489a8babd78c369a9d0779b80974804c0baf12b42627632b8050a1bc28889e47
        12b4113276735d9cc4b2d9e0b80b95853ef36cfd0168644b95e9e423da6ba92e
        9c79b67b9c35239ea5ec251004bda34818bba919e6958790c52da42328c9321b
        502997458bad9967c0f23a9df73bbef7b2268f363d9fea33ef474a5b67a37499
        18f0c9b87f6aaf54611e5a32b2db13b140c5a03d3ac3ee0b7d91ea47bf1513fb
        66bbf772a9a7904ca1613e921111fbb6cd77f6a73713cd5861c5d208706b6acd
        93a97f2ba2f2e51fc8ca3311df611f41e151ac3c147247d36e7eed9e17727f67
        
        045657593e448dd0a5bdb8d6666517d7c7b977f2b5ce7dad79aff17f74077d58
        ecdce06e3ff69d53437b89cfac002386023159fbc66dd533807ad7515b05034c
        85");
    let skRm = hex!("b7e8e6ce3110eedd569219287bf268cc99730e051cee6b3ce66206bc2b426329");
    let enc = hex!("03789ff0079cac0a5970a544fc2afd9d5e67b8be679da649056199bbf24d0b47
        2d7936e3047ae98801e6d16ef42710009aa4aed663adb869c8fdb2edd4543ace
        210845b0e3b37d01a8a514f9af09502c654b8b695a948d1d6209be5ae7c3dbc7
        a5780501a1337215be3421ad1f4ad0105938df4918dd6fb149de82e96824d34e
        167ad8ef8ef14a82b69a0f5b53345c5529d456d35cd999e84856e655534c2281
        050c7453230383018914cbff18ec2963adba2fec9a2256ee68212b01c1a6a723
        b743331b9cda7cc5a2b53d9d29026ebdb9cad710da27285394b5103fb72de3a3
        540abffcc45368c0c5b0baa6b447ee23f31e96b227835ab6153d1da7961b1118
        3d7c4a7ae83148ce69b54f4973772bf9b73aea56134f809fe70fa961bb2f940a
        f3576fce36aa7337d9268556373be21c2fac16b6edd71f20abe8abdc34cd7ebf
        cbead2b59412455794863bd2af4cd900b196a43ce865b816f0a7e693f2ee9cf5
        7d18ab9c6e53822cb62a98a3ec36914d8d79d0879c4f7230f68a7e92e795f3df
        4504c713ccabff038d26889eef1a5daa85dfbc55bea514efaea6a5d2dbfbbbaf
        f9b9399a083d0bfa6ab3e0150e228027f2dec7a382f0bee352e4937726322b0f
        547390237e730e9e5ffe93231d1b274b7a469675c97847200db3e483240e1a40
        8c946ceeba8921d3a21335df852825634b5e4ac415cd4bb9dc7a779580c697c8
        a2e8a44e0caa8b1fc24c131593ae8bfa1ceda3c6354bde687a858048a8ba3208
        83a0008f1416ea354200a165d657dc83d0e70be89e930c110571271154421f36
        bb2697bd000f61c7b81404d63859ab564186bcfcae5ecd3fef794422f5564e18
        336b4d45b3320c8bc58615700a2aff7441daf73f7691538e02566dd30de47141
        24be55f461d8a3cc9afe9aaa16ff0bdc2a00a1c166d86f835a6d9b4af7367a64
        1da4f3473284cb1aae89bbeadcff6833245293bf1e355ab46f2c73a02bfe7faf
        7b49da1d39b3211b5b250b2efb99ed653c67d808c9a3eaaac54d9ec3af4653d2
        ec8f247b6bc91992c3235d6105f75fc2d35b9feb686eaf6650d79b95d3d13493
        5fc357c23588a277cc72d2a12c045e52dc2baf0332b00244c32b89f94412f422
        20f2a0ee9f174e5bf6a40775ad342306606c55f89e71148be23853729f884525
        6475653d8eebafced59a60ed40d22e1494c28d6b85d0bf2d398ebdc57d8c8b01
        e4081768852ceb5c9ab72f823bb5f195112b3281e4f9043eeaf3c318b6c05bcd
        603daf5ace18345695d4fb9a8a3092a2136e0ea76b9a7df45b259427215e960d
        6f4a5115d42e12aaadaece7b0ee54cb8df9a50c625a53d74d28582756d09f8be
        6e575d8ee0a98b0047cee0d7b10c7bdbfa14e5abfaa4ea4fb205d3a5e1a026c2
        7d74f2bf20a4b2c964e0d77d78c99dcc3ecc8eeca6f6045aed2a05640ffb90e8
        b3dcd3a250036661fe25241dde2b1dfe524a0654d43185f9680de661d854af15
        c5de6e198a616c6350efa50840778dd290c0eaf8716dded32c73434e00d51c79
        72c995ca10b70d212e958aa96912eee7e795f355c63110dbcc123c5f7007b440
        2c");
    let shared_secret = hex!("f486c3c6cbb6b9eec34c92e1a4c6c34d67c2fc5131fd024e99f91548ca55e6c5");
    let key = hex!("32d5734f193d7d5778e1f74b19ec76e2");
    let base_nonce = hex!("49f4e2c4cf39ad5e89432f6c");
    let exporter_secret = hex!("aab252b76068d21edf5618c2e6c9df0bafdcdb470a5d9444bf8f15701be6ce9b");
    
    // pub type HpkeKemP256HkdfSha256 = kems::eckem::EcdhKemUncompressed<p256::NistP256, hpke::hpke_types::p256_kems::HpkeKemKdfP256HkdfSha256, U32, 
    //     //hpke::HpkeEcKeyGen<Hpke<sha2::Sha256>,kem_id::DhKemP256HkdfSha256>>;
    //     kems::eckem::SeedAsScalar>;
    //     //hpke::HpkeEcKeyGen2<hpke::hpke_types::draft_ietf_hpke_pq::HpkeKemOneStepKdf2<kem_id::DhKemP256HkdfSha256>>>;

        

    //  pub type HpkeKemQsfMlKem768P256 = kems::hybrid::HybridKem::<
    //         HpkeKemMlKem768,
    //         HpkeKemP256HkdfSha256, 
    //         //kems::eckem::EcdhKem<p256::NistP256, kems::eckem::EcCombinerNoPubKeys<kdfs::misc::PassThroughKdf>, typenum::consts::U32, kems::eckem::EcUncompressedEncoder<p256::NistP256>, kems::eckem::SeedAsScalar>, 
    //         QsfCombiner2<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, kems::draft_ietf_hpke_pq_01::QsfLabelP256MlKem768>,
    //         //ExpandSeed<U32, HpkeKemOneStepKdf2<kem_id::QsfKemMlKem768P256Shake256Sha3256>>>;
    //         ExpandSeed<U32, kdfs::cshake::XofKdf<sha3::Shake256>>>;
    //         //
    // pub type HpkeQsfMlKem768P256Shake256Aes128Gcm = HpkeIes::<HpkeKemQsfMlKem768P256, 
    //     hpke::hpke_types::sha2_kdfs::HpkeTwoStepHkdf<sha2::Sha256>, aes_gcm::Aes128Gcm>;
    
    let seed2: Array<u8, U32> = hpke::hpke_types::draft_ietf_hpke_pq::HpkeKemOneStepKdfKeyDerive::<kem_id::QsfKemMlKem768P256Shake256Sha3256>::derive_secret_others(&ikmR, None).unwrap();
    assert_eq! ( seed2.as_slice(), skRm);


    // let (e,d) = hpke::hpke_types::draft_ietf_hpke_pq::HpkeKemMlKem768::derive_from_seed(&seed2);
    // println! ( "ss={:02X?}", e,)

    let (encryptor, decryptor) = HpkeIesMlKem768P256Shake256Aes128Gcm::derive_pair_from_seed(&ikmR).unwrap();
    //let (encryptor, decryptor) = HpkeKemQsfMlKem768P256::derive_from_seed(&seed2);
    //assert_eq!( decryptor.decapsulator.as_bytes().as_slice(), skRm);
    println! ( "pkRm=({}){:02X?}", encryptor.encapsulator.as_bytes().len(), encryptor.encapsulator.as_bytes());
    assert_eq!( decryptor.decapsulator.as_seed_bytes(), Some(skRm.into()));
    assert_eq!( encryptor.encapsulator.as_bytes().as_slice(), pkRm);
    
//     let decryptor = HpkeQsfP256MlKem768Shake256Aes128Gcm::decryptor_from_bytes(skRm.as_slice().into());
//     assert_eq!( decryptor.decapsulator.as_bytes().as_slice(), skRm);

//     // let mut decryptor2 = decryptor.setup_receiver_cipher(enc.as_slice().into(), &info, None).unwrap();

//     // //let sequence number = hex!("0
//     // let pt = hex!("34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739");
//     // let aad = hex!("436f756e742d30");
//     // let nonce = hex!("49f4e2c4cf39ad5e89432f6c");
//     // let ct = hex!("ece905f63a28c505fab9c5fb505fdfa283f00e211c3a2a591ab88c5d69baec80
//     //     0e67d25eca6877c67b0a3d960608715bc77c09e879da96cb511857af6ed2bb77
//     //     9d5d3a5f19696908a4f1");
//     // let pt2 = decryptor2.open(Payload{msg: &ct, aad: &aad }).unwrap();
//     // assert_eq! ( pt.as_slice(), pt2.as_slice());

//     // //sequence number = hex!("1
//     // let pt = hex!("34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739");
//     // let aad = hex!("436f756e742d31");
//     // let nonce = hex!("49f4e2c4cf39ad5e89432f6d");
//     // let ct = hex!("2dbd0be2b0f6fae70af1bc63ba4a69a2ed136db379bab588e8b0dc6c557ffd65
//     //     5dd8131c48fc2d749d4497b6c681aa3bbbbdd6376275075c26f214d547859085
//     //     90de4e2817d6c8e3099e");
//     // let pt2 = decryptor2.open(Payload{msg: &ct, aad: &aad }).unwrap();
//     // assert_eq! ( pt.as_slice(), pt2.as_slice());

//     // //sequence number: 2
//     // let pt = hex!("34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739");
//     // let aad = hex!("436f756e742d32");
//     // let nonce = hex!("49f4e2c4cf39ad5e89432f6e");
//     // let ct = hex!("16560c07a109c5622fe7d7f77c924f7568708baf2a9da53986fc367cc318a3ca
//     // 9201caf2f4d9ec509d5ff8b1b50f7c7d7e0aa83cb376b90e8a043e735a835a71
//     // bd2e3c36d0bb835119c4");

//     // let pt2 = decryptor2.open(Payload{msg: &ct, aad: &aad }).unwrap();
//     // assert_eq! ( pt.as_slice(), pt2.as_slice());

//     // let decryptor3 = decryptor.setup_receiver_export(enc.as_slice().into(), &info, None).unwrap();

//     // let exporter_context=hex!("70736575646f72616e646f6d30");
//     // //L: 32"
//     // let exported_value=hex!("13692d4e39966ab8e802797324308b804b41ded773f817d6f6849db66319e638");
//     // let exported_value2 = decryptor3.export::<U32>(&exporter_context);
//     // assert_eq!( exported_value.as_slice(), &exported_value);

//     // let exporter_context=hex!("70736575646f72616e646f6d31");
//     // //L: 32
//     // let exported_value=hex!("777a5b866dcb6b65e39b33993197b89a278ff48e8a15c5f2a168d46277f2cdd6");
//     // let exported_value2 = decryptor3.export::<U32>(&exporter_context);
//     // assert_eq!( exported_value.as_slice(), &exported_value);

}


// // #[allow(non_snake_case, unused)]
// // #[test]
// // #[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-p256", feature="rustcrypto-sha3", feature="rustcrypto-aes"))]
// // // https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/
// // //     A.3.  QSF-P256-MLKEM768, SHAKE256, AES-128-GCM
// // // A.3.1.  Base Setup Information
// // fn a_3_1_v3 ()
// // {

// // // mode: 0
// // // kem_id: 80
// // // kdf_id: 17
// // // aead_id: 1
// //     let info = hex!("34663634363532303666366532303631323034373732363536333639363136653230353537323665");
// //     let ikmR = hex!("53030f657b3571b44f1b2b85ad6c72e6607d2538c7118b254c76e15277ffc0a2");
      
// //     let pkRm = hex!("4466431596c2bda2b49ce5aa83ac520e72bf763a5295009ee6fc7c7cf3a5cd5b
// //         7e373ac6e2b03685846d36bb691fda571fd149f08aa94d748c67b095b002b4bc
// //         315df4526469640908580cb2e88afbb692a13a8a372cb17b768925d4367b2a64
// //         e75b81941651ca0aa24d65bec90c9443c0897207362a8727100356f4006f6e33
// //         64edb7c310f390c0dc0971b870bcacbc7d5a4770e22dc5e95353181581927555
// //         f87fd15c48db0455bac9a53639b26e18c854f5bdd7c821d04b2c25aa972ef619
// //         c54671fa14679fd652ff980bf0906a7d2b396c9bbd2045a916952f7cb920f4bb
// //         199010a8129b08ffac3305b6388bc59f435b5e1c483c0cc248ed1c15b63a9717
// //         555476e7a2a5b9b732447340651510079886c66db8a777b704068ac748161a91
// //         86d201a50675398003d773c4bfb895e1267b6c952fc542b485518affa69de663
// //         a7af223679106247794604969216a5b2b2e98d6cbb4aa5993682d0aafb713f56
// //         568d2537a32f3a5b8443c3455364b3982a73fb5bac928b12f817a39811f8d6aa
// //         2ae0c5a73145d7e03b785278fc360ae93472c7e0c0f24b75fb57cb348c2a9fa4
// //         280975c7fbc8a11dbb56d0c4ad74225b7186cbbf5a82b377592c0ab5bbd69851
// //         b664130ab47438cab5db0891d28e2b556754a094e16729cd566c87f2c57dd17b
// //         35430b48309153f9295d671d3da8797e0a91ad7087597c819557368bc83a24b7
// //         a980713f0a937c3925aa02a7c98d499c61632052219ff350c4118126c78346ee
// //         f9167cd39c37ea67eb67c2d6f3310c521d7bd17ef3fa2d58e7827064255419ad
// //         d24147a99a2ecf128542947367f74ed31085a2874f7e300b71286327e712a4e3
// //         3c4d856535038088898a23f42c3541ce3afc5e57e259225c1d86499b09943479
// //         352c85113e86238158a440cf24af9cd74b60b41359905864801f349556ca712d
// //         a0013adf566aa1f82e20949f076a2e5d9064c8895500a825a49ca8e9326b3dc5
// //         85fef48da3340a6005538236a61e898cd9f7116e381a86d992a740670fc733a2
// //         b8bf2729a4c571aaf2733c01690fd563cce52854d3c39fa903afc522cf957b27
// //         98f165cc41203096a7a2e517a92c891fd30d553308524a22e48802a374a5abb3
// //         7e7b894697057dd0babdc2cac5157744bc465bafc51809f66ca3893be26064b2
// //         0b8bcc4bce02b808dd1645cda41754871dd3929232618a649b0c26dc9705d4a1
// //         70e67fd1982785f595874a604b946babe85b4486354e904eaf9629c1a0bfe438
// //         800915bcff568273a991313357f8acc8df276a9441a167e78e32dc9c93c5c8da
// //         e009a687cb255953d6d0905246a2bcb091b3036ea77011fe0a012b528b705b62
// //         489a8babd78c369a9d0779b80974804c0baf12b42627632b8050a1bc28889e47
// //         12b4113276735d9cc4b2d9e0b80b95853ef36cfd0168644b95e9e423da6ba92e
// //         9c79b67b9c35239ea5ec251004bda34818bba919e6958790c52da42328c9321b
// //         502997458bad9967c0f23a9df73bbef7b2268f363d9fea33ef474a5b67a37499
// //         18f0c9b87f6aaf54611e5a32b2db13b140c5a03d3ac3ee0b7d91ea47bf1513fb
// //         66bbf772a9a7904ca1613e921111fbb6cd77f6a73713cd5861c5d208706b6acd
// //         93a97f2ba2f2e51fc8ca3311df611f41e151ac3c147247d36e7eed9e17727f67
// //         045657593e448dd0a5bdb8d6666517d7c7b977f2b5ce7dad79aff17f74077d58
// //         ecdce06e3ff69d53437b89cfac002386023159fbc66dd533807ad7515b05034c
// //         85");
// //     let skRm = hex!("b7e8e6ce3110eedd569219287bf268cc99730e051cee6b3ce66206bc2b426329");
// //     let enc = hex!("e9743db2238854898474eae10e2bc6178ac503dc6284cd2e4531c969b1987e610
// //        45b2680c61206dfd50d073628fd3f0261b397febcb9e9952a5bc2d56a3eff03a8
// //        0abe8a206d1cb076dc65f68bcd3006cf219c09f62589ba9fa70a68368b1d2d44");
// //     let shared_secret = hex!("f486c3c6cbb6b9eec34c92e1a4c6c34d67c2fc5131fd024e99f91548ca55e6c5");
// //     let key = hex!("32d5734f193d7d5778e1f74b19ec76e2");
// //     let base_nonce = hex!("49f4e2c4cf39ad5e89432f6c");
// //     let exporter_secret = hex!("aab252b76068d21edf5618c2e6c9df0bafdcdb470a5d9444bf8f15701be6ce9b");
    
// //     let (encryptor, decryptor) = HpkeQsfP256MlKem768Shake256Aes128Gcm::derive_pair_from_seed(&ikmR.into());
// //     assert_eq!( encryptor.encapsulator.as_bytes().as_slice(), pkRm);
// //     assert_eq!( decryptor.decapsulator.as_bytes().as_slice(), skRm);

// //     let decryptor = HpkeQsfP256MlKem768Shake256Aes128Gcm::decryptor_from_bytes(skRm.as_slice().into());
// //     assert_eq!( decryptor.decapsulator.as_bytes().as_slice(), skRm);

// //     let mut decryptor2 = decryptor.setup_receiver_cipher(enc.as_slice().into(), &info, None).unwrap();

// //     //let sequence number = hex!("0
// //     let pt = hex!("34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739");
// //     let aad = hex!("436f756e742d30");
// //     let nonce = hex!("49f4e2c4cf39ad5e89432f6c");
// //     let ct = hex!("ece905f63a28c505fab9c5fb505fdfa283f00e211c3a2a591ab88c5d69baec80
// //         0e67d25eca6877c67b0a3d960608715bc77c09e879da96cb511857af6ed2bb77
// //         9d5d3a5f19696908a4f1");
// //     let pt2 = decryptor2.open(Payload{msg: &ct, aad: &aad }).unwrap();
// //     assert_eq! ( pt.as_slice(), pt2.as_slice());

// //     //sequence number = hex!("1
// //     let pt = hex!("34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739");
// //     let aad = hex!("436f756e742d31");
// //     let nonce = hex!("49f4e2c4cf39ad5e89432f6d");
// //     let ct = hex!("2dbd0be2b0f6fae70af1bc63ba4a69a2ed136db379bab588e8b0dc6c557ffd65
// //         5dd8131c48fc2d749d4497b6c681aa3bbbbdd6376275075c26f214d547859085
// //         90de4e2817d6c8e3099e");
// //     let pt2 = decryptor2.open(Payload{msg: &ct, aad: &aad }).unwrap();
// //     assert_eq! ( pt.as_slice(), pt2.as_slice());

// //     //sequence number: 2
// //     let pt = hex!("34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739");
// //     let aad = hex!("436f756e742d32");
// //     let nonce = hex!("49f4e2c4cf39ad5e89432f6e");
// //     let ct = hex!("16560c07a109c5622fe7d7f77c924f7568708baf2a9da53986fc367cc318a3ca
// //     9201caf2f4d9ec509d5ff8b1b50f7c7d7e0aa83cb376b90e8a043e735a835a71
// //     bd2e3c36d0bb835119c4");

// //     let pt2 = decryptor2.open(Payload{msg: &ct, aad: &aad }).unwrap();
// //     assert_eq! ( pt.as_slice(), pt2.as_slice());

// //     let decryptor3 = decryptor.setup_receiver_export(enc.as_slice().into(), &info, None).unwrap();

// //     let exporter_context=hex!("70736575646f72616e646f6d30");
// //     //L: 32"
// //     let exported_value=hex!("13692d4e39966ab8e802797324308b804b41ded773f817d6f6849db66319e638");
// //     let exported_value2 = decryptor3.export::<U32>(&exporter_context);
// //     assert_eq!( exported_value.as_slice(), &exported_value);

// //     let exporter_context=hex!("70736575646f72616e646f6d31");
// //     //L: 32
// //     let exported_value=hex!("777a5b866dcb6b65e39b33993197b89a278ff48e8a15c5f2a168d46277f2cdd6");
// //     let exported_value2 = decryptor3.export::<U32>(&exporter_context);
// //     assert_eq!( exported_value.as_slice(), &exported_value);

// // }







#[allow(non_snake_case, unused)]
#[test]
#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-x25519", feature="rustcrypto-sha3", feature="rustcrypto-aes"))]
fn a_4 ()
{
  // QSF-X25519-MLKEM768, SHAKE256, AES-128-GCM
  // mode: 0
  // kem_id: 81
  // kdf_id: 16
  // aead_id: 1

//use hpke::{hpke_types::draft_ietf_xwing::HpkeIesXwingMl768X25519Sha256Aes256Gcm, kem_id};
//use kdfs::cshake::XofKdf;
use kdfs::{Kdf, u0};
use kdfs::iso11770_6::Okdf3;
use kdfs::misc::PassThroughKdf;
use kems::eckem::{self, SeedAsScalar};
use kems::hybrid::{self, HybridKem, QsfCombiner};
use kems::x25519kem::X25519Capsulator;
use kems::xwing::LabelXWing;
use kems::{GenerateCapsulatorFromSeed, xwing::XwingMlKem768X25519};
    let info = hex!("34663634363532303666366532303631323034373732363536333639363136653230353537323665");
    let ikmR = hex!(" 40b788ef18afdd04b04c3c0097298981d17000fbde80f26410af13972c2392a6");
    let pkRm = hex!("dbca2aaf9b531844221bf5b4c3a2a50c557a5ea82686544e8ab211bf12ae3e91
        cae13192e66baefa713732c580d5a17d493741593c395f3acdc9c6349e4abd3f
        0a46f0f2a7a28c883a783a6111973a272117956e0219858514862b41774590bf
        43c173139cb7e1401069428365e77c6fc67dd60a4b412a17a3d1a86f87065598
        6c883082ea3bbf2b1386a9800a59335b7c72831b72c28fb966454827d28aa38f
        51a67138310607b58c00752bd012e44103c0fc2d3de1284f6c9d1ea659d6579f
        c50442f3654b162473cad076cb11c16c159fbee9931fab5014d55550d58d2460
        7383e0c8d1f4bf9c44836fccc39c8584f9a15f2a3885353b39e6080f2b1482f2
        76beb6726dcfd197ba63bbaab9226f0ba58de627eae2ac60275067fab60520a5
        2ea215c8f96293b85256017c3107091fd7cbf53c6379296c175338a1302467aa
        8f49a76189e311305256da625fbf0070abc52f2f3b72293298857231e015b720
        0b3b18521f4cbc843a82290925a907fb22a0592704d22c21d3520303264cd548
        39683fde63872ebb06dbbaad2294bcf525529cdb3937a49bd652261aeb0552ac
        39a2d373a5770184ca2abfcaae8321167839c21f75b4f02836727a19ceeac87c
        91ce34589badf8728a06c3dfd1643e73087d27b6bd153ba7c09712caa87d4679
        82290f76e6227ca095e78ba18e9b8615c184f43180eaa57ef81899f13a5fa700
        93ac46210c890f93974f268124bd39b7d2962ed1ea6928fb96cf832df95a9142
        b97f3a7703ee899961c352d3d4a103818f1c486642330bb4d8a4f6c7638ac36c
        ab66b1b47530a35925dd8a2c2824a407fbcf062b46e03235c333b64cca84cf53
        1ea92614b9487ae9dbc6d723120f66ca42b676d75c3cad68a14f351849daa032
        e0190b9016b7cb6837065149c5c98b36705112424a07af3b008ea8e33c5d08b3
        09d95e1953237db87aad9b7219529481ba97dd67b732d020bdd22b8f6a0b930a
        48f9c60c521c7a3b78baa7d9882c2ac8e5e3b12c3a2d11d41c0110b0becb1404
        ec99d6754d03aa77e6a785bddb491a0a701b9c7400f3ca864275f74bb350e314
        85a03649ca5c2eac3d65e2a562e98a3aeb727e0792157450a163beea8362845a
        600ee81888f47e5b6c5c35db7f1355b69a084cc7ba6f4d56b09ab8416b73c5fc
        808db150224d7c406e04389ab43a02bcc3a2a3049921b1f9470c74b1a2027942
        6d948fe3544069cc1b37e3189a67586ebc9f11c75a5f1a67a3c097d9e6a8abc9
        244cf10f314c92b6b1939957b23290ad6043911cbc55a4887f484600fbd11874
        8a3f3ad34da5474ae8b5c7d86b0e7468364c408ccab4c057264aa3d1a0c4acb0
        f4da6eeb576062b73328b15b0416cd7cda84a969764f54c063c17e6d4b88acd4
        0c25d2627908a750a1353169983a0363ab58c3370389e066a9a5da7580239d8a
        e77f6d985d9a97498a3a708958868dc53dc581573723c00921c915a50cba27ba
        0b653e2d6152312284a6584fc2261f932243f694922f240d2f18c314cb51fb62
        0318867eb3bc4b85e47f1d92798ff77bfc495472d9cae08946829a2dd8ab4a37
        725524fa24e773915c9b15c3971706ebb6c020b500c3063775790ddac2dd0296
        0d3926191a5ad266012dc66d577a2e7b215f58ba789a2636ab34aaf103df986b
        fdd5a19f5970fceefe08bc7f6dff9feb9fecf8d580afc5a7881b653c9823ac1f");
    let skRm = hex!("d61fe5a7623cb620e8abfba744d8397c16ba339b6e6d536750f986eb7da0af0a");
    let enc = hex!("9b746d4dc64172d615b7f74d084ec77b4b58dc081a7f87e9737be34
                 953116b51"); // Seems incomplete...
    let shared_secret = hex!("4df3cc9cba7bf5d7dafcc223768d14db875e02501aea8b8e6ad3d50aa59ff696");
    let key = hex!(" e19766ff8ef162c573ca582f33112f81");
    let base_nonce = hex!("7ce026ebc977d1c4650f060f");
    let exporter_secret = hex!(" 689735dca0af69034517c6c944501c387f4e86ae344b7a6a600c7566e742b53c");

  // pub type HybridKemQsfX25519MlKem768 = kems::hybrid::HybridKem::<
  //           hpke::hpke_types::draft_ietf_hpke_pq::HpkeKemMlKem768,
  //           HpkeKemX25519HkdfSha256, 
  //           //kems::eckem::EcdhKem<p256::NistP256, kems::eckem::EcCombinerNoPubKeys<kdfs::misc::PassThroughKdf>, typenum::consts::U32, kems::eckem::EcUncompressedEncoder<p256::NistP256>, kems::eckem::SeedAsScalar>, 
  //           kems::hybrid::QsfCombiner2<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, kems::draft_ietf_hpke_pq_01::QsfLabelP256MlKem768>,
  //           kems::hybrid::ExpandSeed<typenum::consts::U32, hpke::hpke_types::draft_ietf_hpke_pq::HpkeKemOneStepKdf2<kem_id::Xwing>>>;
  //           //

    pub type HybridKemQsfX25519MlKem768 = kems::hybrid::HybridKem::<kems::ml_kem::MlKemWrapper<ml_kem::MlKem768>,
         kems::x25519kem::X25519Capsulator<kems::eckem::SeedAsScalar>,
         //kems::hybrid::QsfCombiner<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, kems::xwing::LabelXWing>, kems::hybrid::ExpandSeed<typenum::U32, kdfs::cshake::XofKdf<sha3::Shake256>>>;
         kems::hybrid::QsfCombiner<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, kems::xwing::LabelXWing>, kems::hybrid::ExpandSeed<U32, shake::Shake256>>;
    use kems::ml_kem::MlKemWrapper;

    // struct LabelXWing2 ();
    // impl Label for LabelXWing2{
    //     const LABEL: &'static[u8] = b"\\.//^\\";
    // }

    // pub type XwingMlKem768X255192 = HybridKem::<
    //     MlKemWithAddKeyDer<ml_kem::MlKem768, PassThroughKdf, U32>,
    //     X25519Capsulator<eckem::EcCombinerNoPubKeys<kdfs::misc::PassThroughKdf>, U32, SeedAsScalar>,
    //     QsfCombiner<Okdf3::<sha3::Sha3_256, u0>, LabelXWing2>, 
    //     hybrid::ExpandSeed<U32, XofKdf<sha3::Shake256>>>; // Works
    
    // pub type HpkeQsfX25519MlKem768Shake256Aes128Gcm = HpkeIes::<HybridKemQsfX25519MlKem768, 
    //     hpke::hpke_types::HpkeTwoStepHkdf<sha2::Sha256>, aes_gcm::Aes128Gcm>;
    
    let seed2: Array<u8, U32> = hpke::hpke_types::draft_ietf_hpke_pq::HpkeKemOneStepKdfKeyDerive::<kem_id::Xwing>::derive_secret_others(&ikmR, None).unwrap();
    assert_eq! ( seed2.as_slice(), skRm);

    let (encapsulator, decapsulator) = XwingMlKem768X25519::derive_from_seed(&skRm.into());
    assert_eq!( encapsulator.as_bytes().as_slice(), pkRm );
    assert_eq!( decapsulator.as_seed_bytes(), Some(skRm.into()) );
    
    //println! ( "encapsulator_bytes={:02X?}", encapsulator.as_bytes());
    //println! ( "decapsulator_bytes={:02X?}", decapsulator.as_bytes());

    //let (encryptor, decryptor) = HpkeQsfX25519MlKem768Shake256Aes128Gcm::derive_pair_from_seed(&seed2);

    // let shared_secret2 = decapsulator.decapsulate(GenericArray::from_slice(&enc)).unwrap();
    // assert_eq!(shared_secret2, shared_secret);

//     //let (encryptor, decryptor) = HpkeIesXwingMl768X25519Sha256Aes256Gcm::derive_pair_from_seed(&seed2.into());
//     //let (encapsulator, decapsulator)= XwingMlKem768X25519::derive_from_seed(&seed2.into());

//     let encryptor_bytes = encryptor.encapsulator.as_bytes();
//     println! ( "encryptor_bytes={:02X?}", encryptor_bytes);
//     // println! ( "decryptor_bytes={:02X?}", decryptor.decapsulator.as_bytes());

//     assert_eq!( encryptor.encapsulator.as_bytes().as_slice(), pkRm);
//     //assert_eq!( decryptor.decapsulator.as_bytes().as_slice(), skRm);

//     //let decryptor = HpkeQsfX25519MlKem768Shake256Aes128Gcm::decryptor_from_bytes(skRm.as_slice().into());

//     //assert_eq!( decryptor.decapsulator.as_bytes().as_slice(), skRm);

//     let mut decryptor2 = decryptor.setup_receiver_cipher(enc.as_slice().into(), &info, None).unwrap();

//     //sequence number: 0
//     let pt = hex!(" 34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739");
//     let aad = hex!(" 436f756e742d30");
//     let nonce = hex!(" 7ce026ebc977d1c4650f060f");
//     let ct = hex!(" 6301266decd458adf8f166cb67d38b82d9b9b7d741fc974e0b2269c0dd2bd406
//     beb41c0ddec7e7a08cdc13753e6de943507b31f1bbe1b4722ece5cfe055f3348
//     a052b932a959f680035c");
//     let pt2 = decryptor2.open(Payload{msg: &ct, aad: &aad }).unwrap();
//     assert_eq! ( pt.as_slice(), pt2.as_slice());

//   //sequence number: 1
//     let pt = hex!(" 34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739");
//     let aad = hex!(" 436f756e742d31");
//     let nonce = hex!(" 7ce026ebc977d1c4650f060e");
//     let ct = hex!(" 339e6308fca6817a5aa1d1f5705cda2ccfd8b2c898c7109f9f6e34ff74affbde
//     ec21839c40643a0d8a7cd51da3fa33cbe0e013dfcee57968e988cecfef4fd258
//     e07c1d7a15d885997bf2");
//     let pt2 = decryptor2.open(Payload{msg: &ct, aad: &aad }).unwrap();
//     assert_eq! ( pt.as_slice(), pt2.as_slice());

//     let decryptor3 = decryptor.setup_receiver_export(enc.as_slice().into(), &info, None).unwrap();
    
//     let exporter_context = hex!(" 70736575646f72616e646f6d30");
//     //L: 32
//     let exported_value = hex!(" 7e7675b50eaed4142b679607ec84142d1facd33d1d4364dbeb5d44411b0be192");
//     let exporter_value2 = decryptor3.export::<U32>(&exporter_context);
//     assert_eq! ( exporter_value2, exported_value);

//     let exporter_context = hex!(" 70736575646f72616e646f6d31");
//     // L: 32
//     let exported_value = hex!(" 78bca296eeceee4f1fd600de5d8cabf93972053925d095478684dfa7f2a76fa5");
//     let exporter_value2 = decryptor3.export::<U32>(&exporter_context);
//     assert_eq! ( exporter_value2, exported_value);
}



#[allow(non_snake_case, unused)]
#[test]
#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-x25519", feature="rustcrypto-sha3", feature="rustcrypto-aes"))]
fn a_5 ()
{
  // QSF-X25519-MLKEM768, SHAKE256, AES-128-GCM
  // mode: 0
  // kem_id: 81
  // kdf_id: 16
  // aead_id: 1

//use hpke::{hpke_types::draft_ietf_xwing::HpkeIesXwingMl768X25519Sha256Aes256Gcm, kem_id};
//use kdfs::cshake::XofKdf;
use kdfs::{Kdf, Label, u0};
use kdfs::iso11770_6::Okdf3;
//use kdfs::misc::PassThroughKdf;
use kems::eckem::{self, SeedAsScalar};
use kems::hybrid::{self, DeriveExpandSeed, HybridKem, QsfCombiner};
use kems::x25519kem::X25519Capsulator;
use kems::xwing::LabelXWing;
use kems::{GenerateCapsulatorFromSeed, xwing::XwingMlKem768X25519};
    let info = hex!("34663634363532303666366532303631323034373732363536333639363136653230353537323665");
    let ikmR = hex!(" 300495cc3d5349e45e700a4b3b57aed43f5c930092ef27c77dc8eea28f9d659c");
    let pkRm = hex!("25165a85c6450338519454bb15404c835307cc3bb261a39df9958c7e5cadcbf9
        36f638846b979326ea9f029a5620371375e9c8e878a73cd98afad8b8afbc609b
        b3ad1db41708f09faa693fdaf1063cb80d3602b3fe0188b89887c2bb9dcd1734
        b61000ac7c3604c776f8f177f2615e8d7800fff3380229c2478a04535039df73
        711b18358a99ac8e222f2e5a652bd040e103581f48362cf1a5fca7c00fe287d8
        dbac5d202d89660307261f8af568c96c5ee4188a1dc2b1098b6588cac56ae5c8
        90dc8fea3b0e1a3b8927132cd689651a54240239b7c79a2882e04ef5fcc3b39b
        b9737acfe015c7afe7cbf1cb0dfdfa09d1b0171914b3a3199c2638b1c6293b9f
        43114d0603003655970948d1383f16ea80dfb39907c08f79c08c092267b57303
        96628dbd458eaf1719bd493074ea13af5b3ecac60b05215c250831d043c3653c
        0e0c91aaee69c8b5a3189e8c5c88c587fdb332e64abae74585f0a29900e67dde
        b47048a4849360b3b6d508bb447b846b0729b3aadedb05c63ab88a50988595a8
        20040f13a5a61f7ccb65b1a8b30998ef4c56d0a3b0a41241d6f85aa3c6b37259
        b7a034a022a9a21bd7accf252dbd2b9868909b2f10cc727b652f4217f65ab3e8
        3b038f056a5dcc26f56052b4836a08d21b988b48f7b86d94057437686330199a
        52530855961e41a422e92685737a5c080a2723240a65258d12020f322528514c
        00ad628f10a533afd2a818eb6b207a93ee42cdb13b5dbb6700ea58ce3cca1923
        e2b295990aca10a115d5b7bf903b2ca5097ca2353cc1a81d9407c6c24e1640c9
        3ad7c1c493b369db5756c1a94050187a5472688580b7348b1fd58ff0c8763299
        73f1e27a4db7617473696ca779ec77814592982e82231d11b4f706581615a381
        236fa1d90ae424a18e5b7d96495b81700bf082b5a7fbaaa9725892e1796b7c2a
        5c1923b1907aa3c75d6aa75ca6081bccc25c9d0c6316a759a6a532139c884c48
        3f24989f4cdab312f0268df2167e4370bbf20832220d6db47c254b8d664c7db8
        a0aee12608feaa57f783c2995497533385d979c98275c611d18d2754aee4e588
        999548c05779a60bbbede8cf48ac34ea6665f1028ad6767c9923618a6a46b7e6
        922532522b15b0631918937270b184793337187704a929cbc13c3c4be5e2b00d
        d9249d0a61344b742d3a4c21154a8cb3bc27b1ac3c1818f233c8419c1f44c727
        2930be46db6a1a4ba6339a8e2e795820e06e9d812d15d46d48e7bcf9b7b2e0b4
        cdfddcb2d9c6c85d650b3eb52ab4d992f1441a5db389b71b5d9f33cca70370a2
        2512eae42da47367a10b2ff321b28c44c4b5a85b46010dc7ebb220218f76138e
        f5da4cfdd9429c2a14af883533a39eececbef0931336ec82aaf30c19646760e0
        c3d3f50cc291414512a273b522005d51e7521209e37fb74bae743a1b00036498
        543044a11bc380971a6ccc9e05861c54bf52f53deb8a5fab9c87d12181e165a9
        fae2632783a12ae515c1c7433003049eb070a5a97c805631db6597c19a22dd5b
        692b3a5a2d20cda0b9548d75600c8824e5f81b51138f7af6c59341b5a200869d
        9b7f033c02738a970753c35835564d02c68d748cf7bba0137a8f041234001d41
        3c99ef9eff24bf6311eb7d76bb793e5b76a589590e4e1b05997fbc526d804664
        ed341de14f5e4e780f21450f814a2f9a15cd912305f5f02c7ff919d7aa6bdc2b");
    let skRm = hex!("56caee1294459fc2f369b0262b0a35f9783c547aedfcca0ad4f0d30e9e907663");
    let enc = hex!("9b746d4dc64172d615b7f74d084ec77b4b58dc081a7f87e9737be34
                 953116b51"); // Seems incomplete...
    let shared_secret = hex!("4df3cc9cba7bf5d7dafcc223768d14db875e02501aea8b8e6ad3d50aa59ff696");
    let key = hex!(" e19766ff8ef162c573ca582f33112f81");
    let base_nonce = hex!("7ce026ebc977d1c4650f060f");
    let exporter_secret = hex!(" 689735dca0af69034517c6c944501c387f4e86ae344b7a6a600c7566e742b53c");

  // pub type HybridKemQsfX25519MlKem768 = kems::hybrid::HybridKem::<
  //           hpke::hpke_types::draft_ietf_hpke_pq::HpkeKemMlKem768,
  //           HpkeKemX25519HkdfSha256, 
  //           //kems::eckem::EcdhKem<p256::NistP256, kems::eckem::EcCombinerNoPubKeys<kdfs::misc::PassThroughKdf>, typenum::consts::U32, kems::eckem::EcUncompressedEncoder<p256::NistP256>, kems::eckem::SeedAsScalar>, 
  //           kems::hybrid::QsfCombiner2<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, kems::draft_ietf_hpke_pq_01::QsfLabelP256MlKem768>,
  //           kems::hybrid::ExpandSeed<typenum::consts::U32, hpke::hpke_types::draft_ietf_hpke_pq::HpkeKemOneStepKdf2<kem_id::Xwing>>>;
  //           //

    pub type HybridKemQsfX25519MlKem768 = kems::hybrid::HybridKem::<kems::ml_kem::MlKemWrapper<ml_kem::MlKem768>,
         kems::x25519kem::X25519Capsulator<kems::eckem::SeedAsScalar>,
         //kems::hybrid::QsfCombiner<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, kems::xwing::LabelXWing>, kems::hybrid::ExpandSeed<typenum::U32, kdfs::cshake::XofKdf<sha3::Shake256>>>;
         kems::hybrid::QsfCombiner<kdfs::iso11770_6::Okdf3::<sha3::Sha3_256, kdfs::u0>, kems::xwing::LabelXWing>, kems::hybrid::ExpandSeed<U32, shake::Shake256>>;
    use kems::ml_kem::MlKemWrapper;

    // struct LabelXWing2 ();
    // impl Label for LabelXWing2{
    //     const LABEL: &'static[u8] = b"\\.//^\\";
    // }

    // pub type XwingMlKem768X255192 = HybridKem::<
    //     MlKemWithAddKeyDer<ml_kem::MlKem768, PassThroughKdf, U32>,
    //     X25519Capsulator<eckem::EcCombinerNoPubKeys<kdfs::misc::PassThroughKdf>, U32, SeedAsScalar>,
    //     QsfCombiner<Okdf3::<sha3::Sha3_256, u0>, LabelXWing2>, 
    //     //hybrid::ExpandSeed<U32, XofKdf<sha3::Shake256>>>; // Works
    //     DeriveExpandSeed<U32, XofKdf<sha3::Shake256>, HpkeKemOneStepKdf2::<kem_id::Xwing>>>;
    
    // pub type HpkeQsfX25519MlKem768Shake256Aes128Gcm = HpkeIes::<HybridKemQsfX25519MlKem768, 
    //     hpke::hpke_types::HpkeTwoStepHkdf<sha2::Sha256>, aes_gcm::Aes128Gcm>;
    
    let seed2: Array<u8, U32> = hpke::hpke_types::draft_ietf_hpke_pq::HpkeKemOneStepKdfKeyDerive::<kem_id::Xwing>::derive_secret_others(&ikmR, None).unwrap();
    assert_eq! ( seed2.as_slice(), skRm);

    let (encapsulator, decapsulator) = XwingMlKem768X25519::derive_from_seed(&skRm.into());
    //let (encapsulator, decapsulator) = XwingMlKem768X255192::derive_from_seed(&ikmR.into());
    assert_eq!( encapsulator.as_bytes().as_slice(), pkRm );
    assert_eq!( decapsulator.as_seed_bytes(), Some(skRm.into()));


    //let (encapsulator, decapsulator0 = DeriveExpandSeed)
    

}

#[test]
#[allow(non_snake_case, unused)]
#[cfg(all(feature = "rustcrypto-ml-kem", feature="rustcrypto-p384", feature="rustcrypto-sha3", feature="rustcrypto-aes"))]
fn test_a_6 () 
{
// A.6.  QSF-P384-MLKEM1024, Unknown KDF, AES-256-GCM
// A.6.1.  Base Setup Information
// mode: 0
// kem_id: 81
// kdf_id: 17
// aead_id: 2

use hpke::{hpke_types::draft_ietf_hpke_pq::{HpkeIesQsfMl1024P384Sha256Aes128Gcm, HpkeKemQsfMlKem1024P384}, kem_id};
use kems::{GenerateCapsulatorFromSeed, draft_ietf_hpke_pq::QsfLabelP384MlKem1024, eckem::{EcCompressedEncoder, EcdhKem, SeedAsScalar}, hybrid::{DeriveExpandSeed, ExpandSeed, HybridKem, QsfCombiner2}, ml_kem::MlKemWrapper};
use p384::U48;
  let info = hex!("34663634363532303666366532303631323034373732363536333639363136653230353537323665");
  let ikmR = hex!("6a206c70294ca1d907679a1739327522c5c3b04aaf3950bcf5b1ba7463954021");
  let pkRm = hex!("58ba2106c3c59680a0e7272a30c038fde90e6b11bf4cf54bbfc3171e39415698
        b168fc1a792acc7a7037de424fb805509d085b50b07aea08814bc38989da188e
        e7841762c4e4b5cb682b6febfaab69c00e0f1451c385386c4a77b4a83c83015e
        b6575fe9c7cc4a91c1bd33a8e71a36980a809c174b86e43e41c741ec27651d61
        ccdd723bc9e14193f801f21656392c521c9a712b6b919afb7fb53bc4db9c062b
        d62a680c8aacd0ac0963556429a604731e4406af0c0572d017adea480d989460
        6ec625367a14dfd727f4256d0c24af2bb92eedc9be4b896a4ec7ad26b0822dcb
        14f8e834030356df118ade762350ebbf822521bbc692c04382048ca8ec8c0f46
        f47941fa095600215740674f6a7acfc86f98896b938002ca4c72fa74861b476f
        b7f4b353e3444006633d69a3d60c278b2c04fa70371d5387af12197c579208b6
        c63d2aaadee6656ddc1109284631624fb57656c51c406dc1779b410bfe270c8a
        ab666b8501deb03c7dac31b4216c933164ff1cbf1fe45ac38409ff4cc9443b31
        4f932e7e2b97abb91d76da6b8748028cc292683736fbe9b166aaa7fc108744a7
        189fe2261222821e78955e613b57567433e84638c93032947555113fb6aa299f
        526e1d015a012a1095bc08167731dad92e99342f3894b3e50712e89268ca1823
        edb68b2d763de3510d7a56bf0cc9c3335cbf21765e58dc60c8ebb40cf817925b
        ca7b08642415509968b7dfa80328b29e6e9aa1f8054e7b08a555c4602f51879e
        f10e70b735f8e35a17326558d443a76b44b769489d2076128bb2e3814fc37c7a
        dc4b10c2d16f22c579597907bd59a0621757a18848e4e813e5920670d783f9d2
        bf3becac75b16932367a61846d043b7070453bde730996b099e6b6700e0411c0
        4abc591682c6a25a0a1c11817375bde7a5a3f3523d08464bb091976b02a0277d
        f0da8212b27edea6042829654654115853c05bd7b18ec47638275560c1569e71
        373a443262ca5b68dac2eb7279eca47748d624ebb35442f50aef8a474fb22b44
        945f30e58e85a79ab8997b853b09c74a3536f863f1f81ca3307a1ffc8259b87e
        86c975a9db5f4a471b31137d04462fbc6415dd2a435fb097df3499ba9b1bd22a
        9670f939a0bbb9ca597b5e1caebd14b4d07ace7f9694bc13350c20801682cb68
        1bcdc8469ba19a814028845095540f9ac51f4b3a2176abd8230b8ee9061dca7b
        9268817e649f87267c40d5095063a7b8f5003708aa1f04988b83c6ddfb1bb424
        a2343c8389e4cba0f72510719df443520f205696b657e0173a70b81dad274084
        fb3189c2abf0b4c760f8cdb6ea18f54c97c1c9b95c987ca544637c743723897c
        797c7294cbca996c9ef0d849c2542f93e23a632a2fc9a2aa3aeac7bba3c1f945
        c82fc1be6f46aca0796a08780ed2527e60e1c131b9049956969e6370c8424845
        d34a6b4b45a01b2254701c9155533d4062214a61b196734551bd74c412278b45
        740c5905dcc39545ac13c727833b5cdea8a0eeb5a9fd15c6a27c922c8b0b67b7
        3fb0160f5641583ff70dcf96a62f540f08b3b51c9cc1df5a19886a2b24f67ed0
        a38fa821610d547b5016cae503ba7cb37fe3da2d71caba4d4b79141ba797b24e
        92c2bc77eb7559933b50e76d7707ab72bb7ffdc8a7ac95431c7649ded8b143d4
        247178ccff9c3b2ab098d8aa1c2465c5814ac493a27005033a8725317b284c4a
        abb90063cca18b0ea15251a1108e9231bce7926516901f2cc524e65798535880
        98c33572e48a1bf7789f3357611c37874898d8689dbc03a5aec003b7b97c19d4
        c266ea6a8289859734985ccb0241cb1ed4755e4c5b5fe9b48ae8307b5b0629d3
        ab1015920149706661610743944f572781b8f04d368825b8d7a4906b42f78117
        6fe90637f2698a0860f5616415f447798278ec415fa3623d926286e4e0409ad7
        ba403a1178ec21297c176aba4e2b91604e7a22afb53ad477b1e203707e9c4d3f
        bc79baacb15832ada4f9c4af91669022c5a008949bbba38f53ae92a041146917
        ae9c49dd4a2bd5a263da2c9e4f4184958c3fcc1c722ae071882baf1cecb251f8
        8a9ffbc32dc9b48b9b42b4a59a6a21978ec59e93a825ca642433809b0b098fda
        1b9e1a0a05c41ba0a2a91d66e56755588202fab248b8afa59976a472176e9573
        0a678297a305a9c288116ed96e44a825a9e10e5cf6d08de4c5cc9456bee0e22d
        
        044ae9db3d1d9e509523d7b0fe9eb8aae8c435c6860add6a537fc5b319011985
        b5d1e306d6cf495e3c0cbb939f618b1aeaaf0a2961b974ff20cda4c94c915aa4
        6c0f06b9f88a964beef0ce9f2bb578cfe39408c340ab68f3658ce90d4fc84491
        c9");

  let skRm = hex!("23456b644f15c3f35650958af845450ca744f66246d21150e2b49278b02650fe");
  let enc = hex!("02f83d55376a5f005d56f1532ec8a1e2942a75a64b258d94ee54ab236a185352
     eecdfb3935667dd48fec4b9e6b7fc9d9324d92f42b83ae191e75f4d243b7caca
     cdde0a84d4b1bb47f6447214e03c907ac4f59f1917fb332aac94ec82f627f280
     982a6d73db299e7215257388779a17100d530c74fc5d4ae291238757c49e4678
     f99d263f713d2537cb43cedb89c573a245e152fed045baa55343a3e1590a2829
     ed5b42c5b238c584ed57af07eb4b513b3205714dd70970abb28f440f562286e9
     23e66c19f096bf968d9beef678168a1cbb2e52b5cbac6b9e8a72b5d109df5a93
     c5fe8ffa741d3f7035c64163528f8455aa977fda78fa3340efce01ea948f7675
     82153884848c4c5be5cd4664c9ce250c667b49e6bb8336c8aad4edbd21c1577c
     85afd7e5f0582ee883819c07219bfb5d34d8e5643e8b0a505aca6009288ced94
     01f15765ef099e96d66771d002f160f890316131e804be9fb34cf730e28a1a42
     f79a4522114d7bd7a7765e475c03cfdb660860ff23db8f990a203ab4caa58a06
     bf4c18a5a492b140f47b4f33cfdd99e65a497deabe2ad5f4c06f54ec2bb52c9b
     ef6552a37add9d5e1455f7222eff7c2fcb61b5a29a54fe388c1f00b13229a11d
     cb6b2423a9fdff7576a7afdb8ddff35e9c231ba0227c99c81cf599ab23e37d7d
     713b4b74f4ec30e790a23f3ad58123d29ad77484ed0e8da734e51c1d87bda010
     2cb4e6edd416cc66cd0b90699115e31db39b244b9f954b8655de06a9adf0b485
     3773b67a94116a2161880589bc745d0c2b8057936502d4f936aa9819786de214
     e125216e593cf75ca5641c6075848bde1414ebb103d86bbeb76682a07a2958ab
     99ebe6110fe2562c64bf81443b4babc874a54ebcbe83523c03d816f5f0d7e159
     3432179aa3adf4ce056f6c4ca6cdcc99661bcb6459599b59315c479a2474d3bc
     ff17a7904763383f16e8f07236c4c703a878b9184bfeeb37528173be18e28f79
     a7050e4bf7690d5472ac679e44ae34f20d1bcf1d468e9c1187d2e7190a2d6e7e
     4edfdefb14f35992a8c6986debfb9f00d208a5bea6c1b3b2573321d960a41154
     6316fc5df13ffae0cf214abb19e1f774eb3888d13f8be919f96652640812fcfa
     1c9357847ccde925cf583f255eddd3f4030a7fcdcbc9dbc38a52196c32f183ec
     8bec10f6852e1acec443fcb8a6b4606f51bc8d67bea702712e9d79a917b522a6
     923e1b5a0207691482446290b418ffeb39ec811e82144f28188bc95be90cf6ea
     3f475aee6bfe0ac1d8f23595032bea0ad3e854fec5f87515873ff9534d3d63fe
     28884f3e1ec77113315ab832b605e04fbc2c08c67b51dc19c9e470edf995bc13
     2883167d32b1d80646e83a52596aab2867660b24fb676477372fb3be783460ac
     0e9c679cbdc2585e450374a2149e4f6f2a0e16778e248672b12138a5e8bae21f
     751244517f096ed46370f4792bad4729461087726eb66de827f166278ab356e6
     ff88fb3f18001a7b8ae26c8cc1b6c93631853aeee57b595c4e3cae6119b05e53
     453d1e702da3607d495a4f08e08a55e4b2a49e6195723ce7a6b03702ac1406ab
     cf55cd9f24641feea6ff39077afedcf292306e44a78ec0e9d23b41b2a3cbd3a3
     922a58883ed751d3b456ded8c7f3783b5b148c7d19c2b08406b801edd3dac7d2
     a2af089d4e43271d9e5ee4b2508cdb81f79c296a329db6c0f045d1ed696ad48b
     103ebbf785daabe239b1f84ba812ef53bb6cda1125d3c68f41fdba345cb82823
     05ff5ebea3591886d7d9a0ae1af6ac5ed31abea38446f354934a42f69437d5cd
     d3dcdca348369625e923a78161016462dbc242100eac2fdfe0b45ce4c8649930
     6db07b7f13a26359495c2081cad2c9cd7c28a23da1414616a442a657c63d91d4
     0bc5c6eba106788d7f398ab16545f470b5c08200517646183334f9445e212504
     b0a684b19ca5cb1d6172e6b4c10ebc2e220ad820db9a437d56ea16c8773c45cd
     16983924a0b6a335b8cb72094504f424823bc9123bed718b053de67f97451205
     05724ad0ff6929ad7b57fb00c054d631b44e0014b51c7cc8e8f978ec8e10148a
     2d8660d81e3fde150752d38478c18e6f951142b5cff4c8d2df3d21a2d6e01bbe
     c62a54b1807ae7aae2def15c00a2369e8fb94c33c47c687238849cbf991abb94
     61a6536aa0371279b0fb4b62f5153f94d0b92a650867e15ac655d0dc9f10d5d6
     124c78b73c73eac18d138e9d4246b576ab97d6c0165646cd8553f310cdaab2c5
     1282a30f0b2a5f3dd58dc918e40b105d37");
  let shared_secret = hex!("250dbc9910b47b6f51097fd484d3996dc8335706c006a0fce77729a51280e4c2");
  let key = hex!("45d95d7e3239dc99b4d8cf3b5bb1b89ed74327cc531690fb4ab03066d87a66c1");
  let base_nonce = hex!("c7e928d294ac6b06f9f1d34a");
  let exporter_secret = hex!("aaadc292e6288db742f9f9e2435e1095324ef7d9029d5c77814328ddd813eed2");

  let seed2: Array<u8, U32> = hpke::hpke_types::draft_ietf_hpke_pq::HpkeKemOneStepKdfKeyDerive::<kem_id::QsfKemMlKem1024P384Shake256Sha3256>::derive_secret_others(&ikmR, None).unwrap();
  assert_eq! ( seed2.as_slice(), skRm);

//let decryptor2 = HpkeQsfP384MlKem1024Shake256Aes256Gcm::decryptor_from_bytes(skRm.as_slice().into());

  let (encryptor, decryptor) = HpkeIesMlKem1024P384Shake256Aes256Gcm::derive_pair_from_seed(&ikmR).unwrap();
  //let (encryptor, decryptor) = kems::draft_ietf_hpke_pq_01::HybridKemQsfP384MlKem1024::derive_from_seed(&seed2);
  //assert_eq!( decryptor.as_bytes().as_slice(), skRm);
  println!( "pk={:02X?}", encryptor.encapsulator.as_bytes());
   assert_eq!( encryptor.encapsulator.as_bytes().as_slice(), pkRm);
  assert_eq!( decryptor.decapsulator.as_seed_bytes(), Some(skRm.into()));

//   let decryptor2 = HpkeQsfP384MlKem1024Shake256Aes256Gcm::decryptor_from_bytes(skRm.as_slice().into());
//   assert_eq!( decryptor2.decapsulator.as_bytes().as_slice(), skRm);

//   let mut decryptor3 = decryptor.setup_receiver_cipher(enc.as_slice().into(), &info, None).unwrap();
// // A.5.1.1.  Encryptions

// // sequence number: 0
//   let pt = hex!("34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739");
//   let aad = hex!("436f756e742d30");
//   let nonce = hex!("c7e928d294ac6b06f9f1d34a");
//   let ct = hex!("db5a0fa80eb3481c985374e459afba1ebf2b4358964a3d5bee3833c6250c7fd1
//     a73fdc53d0faa3847524a780c2a068d3d618860c38c6547a0134972cd8abbf4d
//     f3949b0aed6f8d574262");
//   let pt2 = decryptor3.open(Payload{msg: &ct, aad: &aad }).unwrap();
//   assert_eq! ( pt.as_slice(), pt2.as_slice());

// //sequence number: 1
//   let pt = hex!("34323635363137353734373932303639373332303734373237353734363832633230373437323735373436383230363236353631373537343739");
//   let aad = hex!("436f756e742d31");
//   let nonce = hex!("c7e928d294ac6b06f9f1d34b");
//   let ct = hex!("34cca436f7f47a76c1cbf0b3cd03adb8cb887b6bb4c16d29e808d303a34e3d3b
//     78d460f5abf08047f30fd35dd80e46629044a6dfbf163bbf7735d8f6452675f4
//     9b7bc245dc39c8cba716");
//   let pt2 = decryptor3.open(Payload{msg: &ct, aad: &aad }).unwrap();
//   assert_eq! ( pt.as_slice(), pt2.as_slice());

//   let decryptor4 = decryptor.setup_receiver_export(enc.as_slice().into(), &info, None).unwrap();
   
//   // A.5.1.2.  Exported Values
//   let exporter_context = hex!("70736575646f72616e646f6d30");
//   //L: 32
//   let exported_value = hex!("95ccd83cfd9722eb5d9229d3a1e66c0b6910f30adb6bf1a5550692bd5ad480ec");
//   let exporter_value2 = decryptor4.export::<U32>(&exporter_context);
//   assert_eq! ( exporter_value2, exported_value);


//   let exporter_context = hex!("70736575646f72616e646f6d31");
//   //L: 32
//   let exported_value = hex!("a64c081fdac68d7d75a705489019e16c819f9129f217207b9ea440651cc66ade");
//   let exporter_value2 = decryptor4.export::<U32>(&exporter_context);
//   assert_eq! ( exporter_value2, exported_value);
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
    let decryptor = HpkeIes::<p256_kems::HpkeKemP256HkdfSha256, sha2_kdfs::HpkeHkdfSha384, chacha20poly1305::ChaCha20Poly1305>::decryptor_from_decapsulator(decapsulator);

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
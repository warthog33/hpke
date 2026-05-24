use aead::inout::InOutBuf;
use aead::{KeyInit, Payload};

use kems::{Array};
use kems::generic_array::GenericArray;

use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;

use aead::AeadInOut;
 
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, base64::{Base64, UrlSafe}};

use josekit::jwe::JweHeader;

#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
struct JwkEc {
    kty: String,
    #[serde(rename = "use")]
    use2: String,
    alg: String,
    kid: String,
    crv: String,
    x: String,
    y: String,
    #[serde_as(as = "Base64<UrlSafe>")]
    d: Vec<u8>,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
struct Jwe {
    #[serde_as(as = "Base64<UrlSafe>")]
    ciphertext: Vec<u8>,
    #[serde_as(as = "Base64<UrlSafe>")]
    iv: Vec<u8>,
    #[serde_as(as = "Base64<UrlSafe>")]
    tag: Vec<u8>,
    aad: Option<String>, // Leave as String because we need to use the encoded value as well as the decoded value
    protected: String,
// The recipients field is an array of objects
    pub recipients: Vec<Recipient>,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct Recipient {
    pub header: Option<RecipientHeader>,
    // In HPKE-PQ, this 'encrypted_key' holds the KEM's 'encap' output
    #[serde_as(as = "Base64<UrlSafe>")]
    pub encrypted_key: Vec<u8>,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct RecipientHeader {
    pub kid: String,
    pub alg: String,
    #[serde_as(as = "Base64<UrlSafe>")]
    pub ek: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProtectedHeader {
    pub enc: String,
    pub alg: Option<String>,
    pub kid: Option<String>,
} 

// https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/11/
#[test]
#[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-sha2", feature="rustcrypto-aes"))]
fn test_draft_ietf_jose_hpke_encrypt_integrated_encryption  ()
{
    use hpke::hpke_types::HpkeIesP256Sha256Aes128Gcm;

    let jtk = r#"
    {
        "kty": "EC",
        "use": "enc",
        "alg": "HPKE-0",
        "kid": "G5N__CqMv_kJGieGSFuAugvl0jrQJCZ3yKwVK6sUM4o",
        "crv": "P-256",
        "x": "gixQJ0qg4Ag-6HSMaIEDL_zbDhoXavMyKlmdn__AQVE",
        "y": "ZxTgRLWaKONCL_GbZKLNPsW9EW6nBsN4AwQGEFAFFbM",
        "d": "g2DXtKapi2oN2zL_RCWX8D4bWURHCKN2-ZNGC05ZaR8"
    }"#;

    let jwe = "eyJhbGciOiAiSFBLRS0wIiwgImVuYyI6ICJpbnQiLCAia2lkIjogIkc1Tl9fQ3FNdl9r\
            SkdpZUdTRnVBdWd2bDBqclFKQ1ozeUt3Vks2c1VNNG8ifQ.BIh6I40uiBbK8-\
            UK7nHdo3ISEfgwJ_MF3zWjQzLt00GhFF2-\
            1VgWKHSYLXdeVeRV7AinyocYiCYmISvW0yqiDmc..Ov-\
            llz6VUyiw8nZL0OPGLGZckLTm5UcTZFg.";

    //let key : JwkEc = serde_json::from_str(jtk).unwrap();
    let key = josekit::jwk::Jwk::from_bytes(jtk).unwrap();
    //let key2 = josekit::jwk::alg::ec::EcKeyPair::from_jwk(&key).unwrap();
    
    //let priv_key_vec = key.parameter("d").unwrap(); //&BASE64_URL_SAFE_NO_PAD.decode(key_json["d"].as_str().unwrap()).unwrap();
    let priv_key_vec = &BASE64_URL_SAFE_NO_PAD.decode(key.parameter("d").unwrap().as_str().unwrap()).unwrap();
    //let priv_key_vec = key2.();
    dbg!(&priv_key_vec);
    
    let mut jwe_iter = jwe.split_terminator('.');
    let header_base64 = jwe_iter.next().unwrap();
    let header_vec = &BASE64_URL_SAFE_NO_PAD.decode(header_base64).unwrap();   
    let encapsulated_key = &BASE64_URL_SAFE_NO_PAD.decode(jwe_iter.next().unwrap()).unwrap();
    let aad = &BASE64_URL_SAFE_NO_PAD.decode(jwe_iter.next().unwrap()).unwrap();
    let ciphertext = &BASE64_URL_SAFE_NO_PAD.decode(jwe_iter.next().unwrap()).unwrap();

    //let protected: ProtectedHeader = serde_json::from_slice(&header_vec).unwrap();
    let protected = JweHeader::from_bytes(&header_vec).unwrap();
 
    assert_eq!(protected.content_encryption(), Some("int"));
    assert_eq!(protected.algorithm(), Some("HPKE-0"));
    assert_eq!(protected.key_id(), Some("G5N__CqMv_kJGieGSFuAugvl0jrQJCZ3yKwVK6sUM4o"));
    assert_eq!(aad, &[0u8;0]);
    
    let decryptor = HpkeIesP256Sha256Aes128Gcm::decryptor_from_bytes(GenericArray::from_slice(&priv_key_vec));
    let plaintext = decryptor.single_shot_open(GenericArray::from_slice(&encapsulated_key), 
        &[], Payload{msg: ciphertext.as_slice(), aad: header_base64.as_bytes()}, None).unwrap();

    assert_eq! ( plaintext, b"hello \xF0\x9F\x8C\x8E");
}




#[test]
#[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-aes"))]
fn test_draft_ietf_jose_hpke_encrypt_key_encryption  ()
{
    let jtk = r#"
    {
        "kty": "EC",
        "use": "enc",
        "alg": "HPKE-0",
        "kid": "G5N__CqMv_kJGieGSFuAugvl0jrQJCZ3yKwVK6sUM4o",
        "crv": "P-256",
        "x": "gixQJ0qg4Ag-6HSMaIEDL_zbDhoXavMyKlmdn__AQVE",
        "y": "ZxTgRLWaKONCL_GbZKLNPsW9EW6nBsN4AwQGEFAFFbM",
        "d": "g2DXtKapi2oN2zL_RCWX8D4bWURHCKN2-ZNGC05ZaR8"
    }"#;
    let jwe = r#"
    {
        "protected": "eyJlbmMiOiAiQTEyOEdDTSJ9",
        "ciphertext": "9AxOd65ROJY1cQ",
        "iv": "2u3NRi3CSr-x7Wuj",
        "tag": "1NKYSWVV4pw5thsq7t6m6Q",
        "recipients": [
            {
            "encrypted_key": "l9VRW1K5CA037fY2ZqVF4bDej413TaAtfjoe3k89-eI",
            "header": {
                "alg": "HPKE-0",
                "kid": "G5N__CqMv_kJGieGSFuAugvl0jrQJCZ3yKwVK6sUM4o",
                "ek": "BJl0V6KLl3HOAZbzFwiAL9eaYbFQPg7-ROmIJpluIQjNS5zultZsC4rGhGzmW1GUWG8bzJUWLQtxFF9oze0AKhU"
            }
            }
        ]
    }"#;

    let key : JwkEc = serde_json::from_str(jtk).unwrap();
    let jwe: Jwe = serde_json::from_str(jwe).unwrap();
    
    //let protected_base64 = &jwe.protected;
    let protected_header = &BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap();
    let protected_header: ProtectedHeader = serde_json::from_slice(&protected_header).unwrap();

    assert_eq!( protected_header.enc, "A128GCM");
    
    let priv_key_vec = key.d; //&BASE64_URL_SAFE_NO_PAD.decode(key_json["d"].as_str().unwrap()).unwrap();
    let recipient1 = &jwe.recipients[0];
    let Some(recipient1_header) = &recipient1.header else { panic! ( "missing header")};
    
    let encrypted_key = &recipient1.encrypted_key; //  &BASE64_URL_SAFE_NO_PAD.decode(payload_json["recipients"][0]["encrypted_key"].as_str().unwrap()).unwrap();
    let payload_alg = &recipient1_header.alg; //payload_json["recipients"][0]["header"]["alg"].as_str().unwrap();
    let encapsulated_key = &recipient1_header.ek; //&BASE64_URL_SAFE_NO_PAD.decode(payload_json["recipients"][0]["header"]["ek"].as_str().unwrap()).unwrap();
    let iv = jwe.iv; //&BASE64_URL_SAFE_NO_PAD.decode(payload_json["iv"].as_str().unwrap()).unwrap();
    let tag = jwe.tag; //&BASE64_URL_SAFE_NO_PAD.decode(payload_json["tag"].as_str().unwrap()).unwrap();
    let mut buffer = jwe.ciphertext.clone(); //BASE64_URL_SAFE_NO_PAD.decode(payload_json["ciphertext"].as_str().unwrap()).unwrap().clone();

    assert_eq!(payload_alg, "HPKE-0");

    let decapsulator = hpke::hpke_types::draft_ietf_jose_hpke_encrypt::HPKE0P256Aes128::decryptor_from_bytes(GenericArray::from_slice(&priv_key_vec));
    let cek = decapsulator.single_shot_open(GenericArray::from_slice(&encapsulated_key), &[], Payload{msg: &encrypted_key, aad: &[] }, None).unwrap();

    let decryptor = aes_gcm::Aes128Gcm::new(&Array::try_from(cek.as_slice()).unwrap());
    decryptor.decrypt_inout_detached(&iv.as_slice().try_into().unwrap(), 
        jwe.protected.as_bytes(), InOutBuf::from(buffer.as_mut_slice()), 
        &tag.as_slice().try_into().unwrap()).unwrap();

    assert_eq! ( buffer, b"hello \xF0\x9F\x8C\x8E");

}



/// From v16, 6.3
#[test]
#[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-aes"))]
fn test_draft_ietf_jose_hpke_encrypt_key_encryption_2  ()
{
    use hpke::hpke_types::draft_ietf_jose_hpke_encrypt::HPKE0P256Aes128;

    let jtk = r#"
    {
        "kty": "EC",
        "use": "enc",
        "alg": "HPKE-0-KE",
        "kid": "9CfUPiGcAcTp7oXgVbDStw2FEjka-_KHU_i-X3XMCEA",
        "crv": "P-256",
        "x": "WVKOswXQAgntIrLSYlwkyaU1dIE-FIhrbTEotFgMwIA",
        "y": "jpZT1WNmQH752Bh_pDK41IhLkiXLj-15wR4ZBZ-MWFk",
        "d": "MeCnMF65SaRVZ11Gf1Weacx3H9SdzO7MtWcDXvHWNv8"
    }"#;

    let jwe = r#"
    {
        "ciphertext": "uF1XBbVZWhYm_pDbeJvI_fkuqFJiKd1WMP3O_BAGOP-LkpTLE3Et2VQNcOpPAIBfyx8rUzshGqiOFOWzcoWZ3mIwYuDvvAW3-P1RCS8Dtq70JRvahO5O8sAN1vzJg8_dyBPnwsQY6Cy3RhMD6sSSCjjSw0FYmmx67IiI2zJ6Wr8z69k0f34ZTh43k4C-pTwaUSvjl2XI_YrUgdDVYmY_MJ5vmlPTcceMaefP8Onz_fx5xOcGfnVBVz2gpMQPuQL8k5Rk5KJvPGfFfN6hrgWkK_LDzi4lrfnIrvNsk3BCBeZPpc-n19-u7W4-GQxLjAlVyMHeGk5K4tU6gHB8PnnQ4ND5ZTtyXrJWQW-Qr1iFev6g",
        "iv": "mLiHjYaQA42nPm1L",
        "recipients": [
            {
            "encrypted_key": "hU6b0hp4-y4ZoK1Qz8YWmDmqDmgTto3HW25-RyPhcLU",
            "header": {
                "alg": "HPKE-0-KE",
                "kid": "9CfUPiGcAcTp7oXgVbDStw2FEjka-_KHU_i-X3XMCEA",
                "ek": "BGWPWLoD5BUjFEDIjMS-yvtcCXBn5A-kuv2RjzUY_2hKUjgZINqtEy1aHZ8dWxAiyApV5JafG76W8O_yZzy5T54"
            }
            }
        ],
        "tag": "K22C64ZhFABEu2S2F00PLg",
        "aad": "VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc",
        "protected": "eyJlbmMiOiJBMTI4R0NNIn0"
    }"#;

    let key : JwkEc = serde_json::from_str(jtk).unwrap();
    let jwe2: Jwe = serde_json::from_str(jwe).unwrap();
    
    let protected_vec = BASE64_URL_SAFE_NO_PAD.decode(&jwe2.protected).unwrap();
    let protected_header: ProtectedHeader = serde_json::from_slice(&protected_vec).unwrap();
    assert_eq! ( protected_header.enc, "A128GCM");

    let recipient1 = &jwe2.recipients[0];
    let Some(recipient1_header) = &recipient1.header else { panic! ( "missing header")};
    let mut buffer = jwe2.ciphertext.clone(); //BASE64_URL_SAFE_NO_PAD.decode(jwe2.ciphertext).unwrap();

    assert_eq!(recipient1_header.alg, "HPKE-0-KE");

    let recipient_structure = [ b"JOSE-HPKE rcpt".as_slice(), &[0xFF], protected_header.enc.as_bytes(), &[0xFF], &[]].concat();

    let decapsulator = HPKE0P256Aes128::decryptor_from_bytes(GenericArray::from_slice(&key.d));
    let cek = decapsulator.single_shot_open(GenericArray::from_slice(&recipient1_header.ek), &recipient_structure, 
            recipient1.encrypted_key.as_slice(), None).unwrap();
    
    let decryptor = aes_gcm::Aes128Gcm::new(cek.as_slice().try_into().unwrap());//&Array::try_from(cek.as_slice()).unwrap());
    
    let aad2 = format!("{}.{}", &jwe2.protected, &jwe2.aad.as_ref().unwrap()); //payload_json["aad"].as_str().unwrap());
    decryptor.decrypt_inout_detached(&jwe2.iv.try_into().unwrap(), 
        &aad2.as_bytes(), InOutBuf::from(buffer.as_mut_slice()), &jwe2.tag.try_into().unwrap()).unwrap();

    let aad = BASE64_URL_SAFE_NO_PAD.decode(&jwe2.aad.unwrap()).unwrap();
    assert_eq! ( aad, b"The Fellowship of the Ring");
    //assert_eq! ( buffer, b"You can trust us to stick with you through thick and thin\xE2\x80\x93to the bitter end. And you can trust us to keep any secret of yours\xE2\x80\x93closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.");
    assert_eq!( buffer, "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".as_bytes());

}

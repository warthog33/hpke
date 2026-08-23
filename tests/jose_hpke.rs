use aead::inout::InOutBuf;
use aead::{KeyInit, Payload, AeadInOut};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use hpke::hpke_types::HpkeIesP256Sha256Aes128Gcm;
use hpke::hpke_types::draft_ietf_jose_hpke_encrypt::HPKE0P256Aes128;
use josekit::jwe::JweHeader;
use kems::{Array};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, base64::{Base64, UrlSafe}};

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
    y: Option<String>,
    #[serde_as(as = "Base64<UrlSafe>")]
    d: Vec<u8>,
}


#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
struct Jwe {
    #[serde_as(as = "Base64<UrlSafe>")]
    ciphertext: Vec<u8>,
    #[serde_as(as = "Option<Base64<UrlSafe>>")]
    iv: Option<Vec<u8>>,
    #[serde_as(as = "Option<Base64<UrlSafe>>")]
    tag: Option<Vec<u8>>,
    aad: Option<String>, // Leave as String because we need to use the encoded value as well as the decoded value
    protected: String,
    // The recipients field is an array of objects
    pub recipients: Option<Vec<Recipient>>,
    #[serde_as(as = "Option<Base64<UrlSafe>>")]
    encrypted_key: Option<Vec<u8>>,
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

#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct ProtectedHeader {
    pub enc: Option<String>,
    pub alg: Option<String>,
    pub kid: Option<String>,
    #[serde_as(as = "Option<Base64<UrlSafe>>")]
    pub ek: Option<Vec<u8>>,
} 

// https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/11/
#[test]
#[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-sha2", feature="rustcrypto-aes"))]
fn test_draft_ietf_jose_hpke_encrypt_integrated_encryption  ()
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
    
    let decryptor = HpkeIesP256Sha256Aes128Gcm::try_decryptor_from_slice(&priv_key_vec).unwrap();
    let plaintext = decryptor.single_shot_open(&encapsulated_key.try_into().unwrap(), 
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

    assert_eq!( protected_header.enc.unwrap(), "A128GCM");
    
    let priv_key_vec = key.d; //&BASE64_URL_SAFE_NO_PAD.decode(key_json["d"].as_str().unwrap()).unwrap();
    let recipient1 = &jwe.recipients.unwrap()[0];
    let Some(recipient1_header) = &recipient1.header else { panic! ( "missing header")};
    
    let encrypted_key = &recipient1.encrypted_key; //  &BASE64_URL_SAFE_NO_PAD.decode(payload_json["recipients"][0]["encrypted_key"].as_str().unwrap()).unwrap();
    let payload_alg = &recipient1_header.alg; //payload_json["recipients"][0]["header"]["alg"].as_str().unwrap();
    let encapsulated_key = &recipient1_header.ek; //&BASE64_URL_SAFE_NO_PAD.decode(payload_json["recipients"][0]["header"]["ek"].as_str().unwrap()).unwrap();
    let iv = jwe.iv; //&BASE64_URL_SAFE_NO_PAD.decode(payload_json["iv"].as_str().unwrap()).unwrap();
    let tag = jwe.tag; //&BASE64_URL_SAFE_NO_PAD.decode(payload_json["tag"].as_str().unwrap()).unwrap();
    let mut buffer = jwe.ciphertext.clone(); //BASE64_URL_SAFE_NO_PAD.decode(payload_json["ciphertext"].as_str().unwrap()).unwrap().clone();

    assert_eq!(payload_alg, "HPKE-0");

    println! ("len={}", priv_key_vec.len());

    let decapsulator = hpke::hpke_types::draft_ietf_jose_hpke_encrypt::HPKE0P256Aes128::try_decryptor_from_slice(&priv_key_vec).unwrap();
    let cek = decapsulator.single_shot_open(&encapsulated_key.try_into().unwrap(), &[], Payload{msg: &encrypted_key, aad: &[] }, None).unwrap();

    let decryptor = aes_gcm::Aes128Gcm::new(&Array::try_from(cek.as_slice()).unwrap());
    decryptor.decrypt_inout_detached(&iv.unwrap().as_slice().try_into().unwrap(), 
        jwe.protected.as_bytes(), InOutBuf::from(buffer.as_mut_slice()), 
        &tag.unwrap().as_slice().try_into().unwrap()).unwrap();

    assert_eq! ( buffer, b"hello \xF0\x9F\x8C\x8E");

}



/// From v16, 6.3
#[test]
#[cfg(all(feature = "rustcrypto-p256", feature="rustcrypto-aes"))]
fn test_draft_ietf_jose_hpke_encrypt_key_encryption_2  ()
{

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
    assert_eq! ( protected_header.enc.as_ref().unwrap(), "A128GCM");

    let recipient1 = &jwe2.recipients.unwrap()[0];
    let Some(recipient1_header) = &recipient1.header else { panic! ( "missing header")};
    let mut buffer = jwe2.ciphertext.clone(); //BASE64_URL_SAFE_NO_PAD.decode(jwe2.ciphertext).unwrap();

    assert_eq!(recipient1_header.alg, "HPKE-0-KE");

    let recipient_structure = [ b"JOSE-HPKE rcpt".as_slice(), &[0xFF], protected_header.enc.unwrap().as_bytes(), &[0xFF], &[]].concat();

    let decapsulator = HPKE0P256Aes128::try_decryptor_from_slice(&key.d).unwrap();
    let cek = decapsulator.single_shot_open(&recipient1_header.ek.as_slice().try_into().unwrap(), &recipient_structure, 
            recipient1.encrypted_key.as_slice(), None).unwrap();
    
    let decryptor = aes_gcm::Aes128Gcm::new(cek.as_slice().try_into().unwrap());//&Array::try_from(cek.as_slice()).unwrap());
    
    let aad2 = format!("{}.{}", &jwe2.protected, &jwe2.aad.as_ref().unwrap()); //payload_json["aad"].as_str().unwrap());
    decryptor.decrypt_inout_detached(&jwe2.iv.unwrap().try_into().unwrap(), 
        &aad2.as_bytes(), InOutBuf::from(buffer.as_mut_slice()), &jwe2.tag.unwrap().try_into().unwrap()).unwrap();

    let aad = BASE64_URL_SAFE_NO_PAD.decode(&jwe2.aad.unwrap()).unwrap();
    assert_eq! ( aad, b"The Fellowship of the Ring");
    //assert_eq! ( buffer, b"You can trust us to stick with you through thick and thin\xE2\x80\x93to the bitter end. And you can trust us to keep any secret of yours\xE2\x80\x93closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.");
    assert_eq!( buffer, "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".as_bytes());

}





// https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/20/
#[test]
fn test_draft_ietf_jose_hpke_encrypt_20_a_1 ()
{
    let jtk = r#"
    {
     "kty": "EC",
     "crv": "P-256",
     "x": "qy-BxXhaelX9Fqe8muRTu8HhseHYgMMGxyfAnIy0MC0",
     "y": "ctfHN7Y4pkj7vZI-sgJ6BqsYwG-PDnB8j7TsfzHHJOI",
     "d": "aAKxBMAkNm2AZDGv7LN5yodDwahJ5rKbrgiiz3dUIH4",
     "alg": "HPKE-0",
     "use": "enc",
     "kid": "KfvD-eYaynUKba0ow-v9uoEV-twV6mYDyiAOWO6LoPM"
   }"#;

    let jwe = r#"
    {
     "protected": "eyJhbGciOiJIUEtFLTAiLCJraWQiOiJLZnZELWVZYXluVUtiYTBvdy12OXVvRVYtdHdWNm1ZRHlpQU9XTzZMb1BNIn0",
     "aad": "VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc",
     "encrypted_key": "BNC1LPfAH7I5Fxi7X7lrQLFkdpZcSGoXpBw4FYvCY1wZqAX53caa-lyNLPHkzwQMAMFHoOoN_TRGSzb2Gw4aDlA",
     "ciphertext": "I0sH6mQa6r-mgLHqI23-wzBmsTULQoNtANiHF_incW5y5BIB7qo0XN3NoOqf1IvH1UEfE1_Tu9Baf6M3z_E9eJK1oDV1Q8A6VnZUnhj0cf2UNQhufoVJOlpbPolLiecxwitIqYKPKfzJmG1uZ7lA0xUAiNPkUR9OSHpLYr9HWAa1DWDbczWOMtFnxCJwd-PfyjX5-5-X6kAcdj5z-Kx4losmN2k7r2T1BUnHNnZlSgcz5nSZBxvKqkXX3xl0Tw9ys--37IJD7UcIFfST6b0PXHzuKSw-attSD_67SRcpcxUTm3nyvtroYF8sg0ztQLuNkC-gwe7-uxPNO2iBDIypgImhvlTaAEcuHJDtFgU5geIXFMAlMDAg7cSk4ssR"
    }"#;

    let key : JwkEc = serde_json::from_str(jtk).unwrap();
    let jwe: Jwe = serde_json::from_str(jwe).unwrap();
    
    let protected_header: ProtectedHeader = serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap()).unwrap();

    assert_eq!(protected_header.alg.unwrap(), "HPKE-0");
    assert_eq!(protected_header.kid.unwrap(), "KfvD-eYaynUKba0ow-v9uoEV-twV6mYDyiAOWO6LoPM");

    let encapsulated_key = &jwe.encrypted_key.unwrap(); //protected_header.alg; //&BASE64_URL_SAFE_NO_PAD.decode(payload_json["recipients"][0]["header"]["ek"].as_str().unwrap()).unwrap();

    let aad = [jwe.protected.as_bytes(), b".", jwe.aad.unwrap().as_bytes()].concat();
    
    let decapsulator = hpke::hpke_types::draft_ietf_jose_hpke_encrypt::HPKE0P256Aes128::try_decryptor_from_slice(&key.d).unwrap();
    let plaintext = decapsulator.single_shot_open(&encapsulated_key.try_into().unwrap(), &[], Payload{msg: &jwe.ciphertext, aad: &aad }, None).unwrap();

    assert_eq! ( plaintext, b"You can trust us to stick with you through thick and thin-to the bitter end. And you can trust us to keep any secret of yours-closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.");
}



// https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/20/
#[test]
fn test_draft_ietf_jose_hpke_encrypt_20_a_2 ()
{
    let jtk = r#"{
     "kty": "EC",
     "crv": "P-256",
     "x": "erH26InyPQifTIwmyKs63u4SUzglAHXNm2ZWT2LQ-rM",
     "y": "GTGOC0_TnYc_Cm4dsgY8qdixil7AObs5-Xtk0QJeoH8",
     "d": "MzJOwOcw1LDGZ-Ia6Zz5ay9zWUZKIhXkBcfq0dPA5Do",
     "alg": "HPKE-0-KE",
     "use": "enc",
     "kid": "23i_7tQXiLxih47kQtE2yHy7d8q253Kp9R9i6aDyHng"
    }"#;

    let jwe = r#"
    {
     "protected": "eyJhbGciOiJIUEtFLTAtS0UiLCJraWQiOiIyM2lfN3RRWGlMeGloNDdrUXRFMnlIeTdkOHEyNTNLcDlSOWk2YUR5SG5nIiwiZW5jIjoiQTEyOEdDTSIsImVrIjoiQkNlSmd0RGZGeVdtTDlJek0yT1Vnd1owWm9tWHVhb3BEcW5fR0JYX2V4N0pENlRyWWpLOUI5R2ZRYWhIamRuTGlsQ2V6WlNSX2NvaUtnVC1IQVhnSlFNIn0",
     "aad": "VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc",
     "iv": "hsc8LLwbgwf33MdT",
     "ciphertext": "vwkACubXsG6xfuEbeZW24DJWq-ZlRExN1uaTyfwaNoCwDaURkrC0Vkc5w9B_KntgOMYvOgAVfSkqkztcRFX-AKIaOKGKYvPAY9ujuQtyA7SFMvaOjmao2XD96LtoeexaYrganCxHvJhjgyRH8xpb_QYVUGdmpjj9r_uNqZVTAuuUlrE87LbGkNaQuHpRCpYG7JbYHp8Sovnbepy84ORGXkhg7KamMfQQQ_ob5C5aY0g2BBqRgyuNErzDCq3RVVo91ddpGbSys25jlvAbqziBW1YOLIoLoGJDdqbykKzjravg1R1g7QCOpdN0ozcE_oEEHFEyRTilYRkxH_CqV2hxhakqDpGj3Q9qHGigJEk",
     "tag": "Afab-bCOAfBSYJgIsaxxZQ",
     "encrypted_key": "-mXiAU7aot-kdZ8KhWDoM_jXHk6_B5g0vH77u6r49os"
    }"#;

    let key : JwkEc = serde_json::from_str(jtk).unwrap();
    let jwe: Jwe = serde_json::from_str(jwe).unwrap();
    
    let protected_header: ProtectedHeader = serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap()).unwrap();

    println! ( "protected={:?}", String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap()));

    assert_eq!(protected_header.alg.unwrap(), "HPKE-0-KE");
    assert_eq!(protected_header.kid.unwrap(), key.kid);
    let content_encryption_alg = protected_header.enc.unwrap();
    assert_eq!(content_encryption_alg, "A128GCM");

    let iv = jwe.iv; //&BASE64_URL_SAFE_NO_PAD.decode(payload_json["iv"].as_str().unwrap()).unwrap();
    let tag = jwe.tag; //&BASE64_URL_SAFE_NO_PAD.decode(payload_json["tag"].as_str().unwrap()).unwrap();
    let mut buffer = jwe.ciphertext.clone(); //BASE64_URL_SAFE_NO_PAD.decode(payload_json["ciphertext"].as_str().unwrap()).unwrap().clone();

    let encapsulated_key = &protected_header.ek.unwrap();
    let encrypted_key = &jwe.encrypted_key.unwrap(); //protected_header.alg; //&BASE64_URL_SAFE_NO_PAD.decode(payload_json["recipients"][0]["header"]["ek"].as_str().unwrap()).unwrap();
    let recipient_extra_info = b"";

    let aad = [jwe.protected.as_bytes(), b".", jwe.aad.unwrap().as_bytes()].concat();
    let recipient_structure = [ b"JOSE-HPKE rcpt".as_slice(), b"\xFF", content_encryption_alg.as_bytes() , b"\xFF", recipient_extra_info].concat();
    
    //let decapsulator = hpke::hpke_types::draft_ietf_jose_hpke_encrypt::HPKE7P256Aes256::decryptor_from_slice(&key.d).unwrap();
    let decapsulator = hpke::hpke_types::draft_ietf_jose_hpke_encrypt::HPKE0P256Aes128::try_decryptor_from_slice(&key.d).unwrap();
    let cek = decapsulator.single_shot_open(&encapsulated_key.try_into().unwrap(), &recipient_structure, Payload{msg: &encrypted_key, aad: &[] }, None).unwrap();

    let decryptor = aes_gcm::Aes128Gcm::new(&Array::try_from(cek.as_slice()).unwrap());
    decryptor.decrypt_inout_detached(&iv.unwrap().as_slice().try_into().unwrap(), 
        &aad, InOutBuf::from(buffer.as_mut_slice()), 
        &tag.unwrap().as_slice().try_into().unwrap()).unwrap();

    assert_eq! ( buffer, b"You can trust us to stick with you through thick and thin-to the bitter end. And you can trust us to keep any secret of yours-closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.");
}





// https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/20/
#[test]
fn test_draft_ietf_jose_hpke_encrypt_20_a_3 ()
{
    let jtk = r#"{
     "kty": "EC",
     "crv": "P-384",
     "x": "CTphb4EF35SSZgrk9rYHXkdalQLTGRApFRiAF8eVteQtOIZRbZKV0iEv9eiSElLT",
     "y": "6KddFD8aAVzoJNq1Jr_4oZ3t7SGZm3qgXMHN7sB_KAlxTydxRaVXArFKQyyffOj6",
     "d": "UzFpz5G-_kWkiCKWCWdRXFxVoz9fTY4u9I_XmfPoOI7eEf0glEARLbsx06wb1EYu",
     "alg": "HPKE-1",
     "use": "enc",
     "kid": "K4P-SJHnqUpz-qTXlYCBV6ITFu8sH_gsx2KGMEcjk9s"
     }"#;

    let jwe = r#"
    {
     "protected": "eyJhbGciOiJIUEtFLTEiLCJraWQiOiJLNFAtU0pIbnFVcHotcVRYbFlDQlY2SVRGdThzSF9nc3gyS0dNRWNqazlzIn0",
     "aad": "VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc",
     "encrypted_key": "BFX1YGr3AR4szfTMVMWctHh2LGBPFdGdJCfft3QYR0mL-zCeJgZkcYzFlD1EID8dFfDv_YNU8DRmm3qzQ8oMsW4ZA3Qs_iQpaEVj3AOsNWFD-yLq1dt1fF4r6VAufu0unw",
     "ciphertext": "_AB6I_8GkA-U9Il2XFNJ3kBDAJ9P1erWUzWzBFgRFM1NhlkE6phABLmhTNc517Vk-YJ0P_7WQqbUnMwgRBQYDycPdhh11ZGvRYI6EjbHXRD8ctVDX_WaWE6RPfY3GxA1Rplh5ZcKYus2Pln1nOseFvC9NEZkuLNLyM8jBVgwq_EQtH1GQlSZwK8I1TyBOcBtWcXnYqy-XK8Rbj3eifbQESKZPedVqMXcQ03u4xdikZp5aqLJCLmwN16pYTgSzXDW0d0IHPc1tqLF4eUFrFfPokckpe92pP5q1DMetRLP7G46oPLXMBQ8tFd_FxtdVF1mrqV3l2KB-JC6unu9ZWwEBt6s-p1xZ2jjIiqTC0Hy-0pK8YmfOEKj5SKk_re1"
    }"#;

    let key : JwkEc = serde_json::from_str(jtk).unwrap();
    let jwe: Jwe = serde_json::from_str(jwe).unwrap();
    
    let protected_header: ProtectedHeader = serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap()).unwrap();

    assert_eq!(protected_header.alg.unwrap(), "HPKE-1");
    assert_eq!(protected_header.kid.unwrap(), key.kid);

    let encapsulated_key = &jwe.encrypted_key.unwrap(); //protected_header.alg; //&BASE64_URL_SAFE_NO_PAD.decode(payload_json["recipients"][0]["header"]["ek"].as_str().unwrap()).unwrap();

    let aad = [jwe.protected.as_bytes(), b".", jwe.aad.unwrap().as_bytes()].concat();
    
    let decapsulator = hpke::hpke_types::draft_ietf_jose_hpke_encrypt::HPKE1P384Aes256::try_decryptor_from_slice(&key.d).unwrap();
    let plaintext = decapsulator.single_shot_open(&encapsulated_key.try_into().unwrap(), &[], Payload{msg: &jwe.ciphertext, aad: &aad }, None).unwrap();

    assert_eq! ( plaintext, b"You can trust us to stick with you through thick and thin-to the bitter end. And you can trust us to keep any secret of yours-closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.");
}


// https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/20/
#[test]
fn test_draft_ietf_jose_hpke_encrypt_20_a_5 ()
{
    let jtk = r#"{
     "kty": "EC",
     "crv": "P-521",
     "x": "ACDaefJAD-xbCAk4C5QadlEtEinEV9JRqyz7MHzSjK-8V2zn0dvNYRtdQYfyddZ1LiN9dzTxuyEaqlJ44-NzoJQc",
     "y": "AF9ye0Rd9NTTGSTlkBUcpzXttxHOaTfQi5E6QNublPXTyuRX-X54EDzdy1tnsBECHNmTAx7rNiR42_Y6ZbKauCTE",
     "d": "APRq4c1AiF5IoYKHKz7TaFknSvSxn-gH5ZurH386OD1dO6I2tcbHlfPPoFUO8miVUihJuHIpcxDFGIRwe6kgPZ-V",
     "alg": "HPKE-2",
     "use": "enc",
     "kid": "MDVVyxq8x1VX7I1X3oVf3nJY51r55uNlZ9xHpC-7sS0"
     }"#;

    let jwe = r#"
    {
     "protected": "eyJhbGciOiJIUEtFLTIiLCJraWQiOiJNRFZWeXhxOHgxVlg3STFYM29WZjNuSlk1MXI1NXVObFo5eEhwQy03c1MwIn0",
     "aad": "VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc",
     "encrypted_key": "BABLi4eakSyaQfL3PjQqiFyDexcKydTcQirDIQRFF2f9uh9eZUECuH6Ows0u8YFnjCkg3zJ3yR0IX96ZbvHxfEVwgwC231EE1fQQiaHHYCOLQ8eA7uv8lyLgSk6Z542ocdJUWWbxMMbnBwkEWKnCxYtynpohK_aSvTo1tVceSeZx9wGfOg",
     "ciphertext": "u5D9fUTR78AJtFaJ0u64aF7t9cBTVcfdP6KCl2atfY8F6RfnejVqeq8kQOGdhwAijGihwWy8-hIVVK0HpT3VZdP1Wblf1FdHdbtgIt9m8Eb530sDFWmO7hdgz6P_yc134MyA_SXYDpMEP0SEN-q53flL3c-hYpNHVFp6cACAbzZ8Gqg4tomZAuxiuODgrj14P4gCuhgas8h_AyxDC0kPctSBime1Tcnekp7TnJjVUpcmyzzpSSUwmec1J526NCkbDFLiY1dr3Tq7UjZi6cnfsA00d2HPWCW8x6UjEY7aehKTKz06_IowoDzeryLGntpYwt9DeJp5ZXeaCd9eLlRDXo70Ow9Wy21flTWDv9h7CVUpNE-JP3ULAF7FGOiA"
    }"#;

    let key : JwkEc = serde_json::from_str(jtk).unwrap();
    let jwe: Jwe = serde_json::from_str(jwe).unwrap();
    
    let protected_header: ProtectedHeader = serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap()).unwrap();

    assert_eq!(protected_header.alg.unwrap(), "HPKE-2");
    assert_eq!(protected_header.kid.unwrap(), key.kid);

    let encapsulated_key = &jwe.encrypted_key.unwrap(); //protected_header.alg; //&BASE64_URL_SAFE_NO_PAD.decode(payload_json["recipients"][0]["header"]["ek"].as_str().unwrap()).unwrap();

    let aad = [jwe.protected.as_bytes(), b".", jwe.aad.unwrap().as_bytes()].concat();
    
    let decapsulator = hpke::hpke_types::draft_ietf_jose_hpke_encrypt::HPKE2P521Aes256::try_decryptor_from_slice(&key.d).unwrap();
    let plaintext = decapsulator.single_shot_open(&encapsulated_key.try_into().unwrap(), &[], Payload{msg: &jwe.ciphertext, aad: &aad }, None).unwrap();

    assert_eq! ( plaintext, b"You can trust us to stick with you through thick and thin-to the bitter end. And you can trust us to keep any secret of yours-closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.");
}



// https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/20/
#[test]
fn test_draft_ietf_jose_hpke_encrypt_20_a_7 ()
{
    let jtk = r#"{
     "kty": "OKP",
     "crv": "X25519",
     "x": "Pyv22rGl5uY-24SOA_wda7PO4bIw6bobrD1_5VgF3H4",
     "d": "VtBu3AuB4_RKgDCDqj1j-_Kzf12ekvaGxoAGmMDcDks",
     "alg": "HPKE-3",
     "use": "enc",
     "kid": "n9hjOrhXxsQ_lTMu3PqkjHgwJURHZPF3HY5p-LFEgyg"
   }"#;

    let jwe = r#"
    {
     "protected": "eyJhbGciOiJIUEtFLTMiLCJraWQiOiJuOWhqT3JoWHhzUV9sVE11M1Bxa2pIZ3dKVVJIWlBGM0hZNXAtTEZFZ3lnIn0",
     "aad": "VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc",
     "encrypted_key": "Ch0FElgndJcJkvCLEWpRpYJo3gbwn-CzVke-s_XH5Qc",
     "ciphertext": "9iGWYstawHANKOPNlkohsf0uSr5B1fSsTt5AYJzgI7WckZSyHooM2gEGrNf1b8TzPtWAnq7fGXgSTd76-Bg_DsDu-EsdEnb9XE9-7jaLLbP_pJ2JNK6R1k420ZvpTqlAPk0Zu1tW8ZREYDtbw0K8aM4gIY4P8vqFba2mJxv0OxEXTP5ur2pTOOcWhZ0E4ICUMDD1xcgzgziEsunxeFdU2X2okwVRr6pQP4XIe81bde7OY1qhaa84mxmMBNoOBgkE3vlV58KHR_JFKUkGlt_0FKBsrpt1yq9gZUzF2_8uqD1xHiMrw3zyLcKH0hdJvLfZv3s_0sYAk98tPF4uZVmkyF-FC0n83vghekRCLR_HJg_QZhfWsSAhETnydVyJ"
    }"#;

    let key : JwkEc = serde_json::from_str(jtk).unwrap();
    let jwe: Jwe = serde_json::from_str(jwe).unwrap();
    
    let protected_header: ProtectedHeader = serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap()).unwrap();

    assert_eq!(protected_header.alg.unwrap(), "HPKE-3");
    assert_eq!(protected_header.kid.unwrap(), key.kid);

    let encapsulated_key = &jwe.encrypted_key.unwrap(); //protected_header.alg; //&BASE64_URL_SAFE_NO_PAD.decode(payload_json["recipients"][0]["header"]["ek"].as_str().unwrap()).unwrap();

    let aad = [jwe.protected.as_bytes(), b".", jwe.aad.unwrap().as_bytes()].concat();
    
    let decapsulator = hpke::hpke_types::draft_ietf_jose_hpke_encrypt::HPKE3X25519Aes128::try_decryptor_from_slice(&key.d).unwrap();
    let plaintext = decapsulator.single_shot_open(&encapsulated_key.try_into().unwrap(), &[], Payload{msg: &jwe.ciphertext, aad: &aad }, None).unwrap();

    assert_eq! ( plaintext, b"You can trust us to stick with you through thick and thin-to the bitter end. And you can trust us to keep any secret of yours-closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.");
}


// https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/20/
#[test]
fn test_draft_ietf_jose_hpke_encrypt_20_a_9 ()
{
    let jtk = r#"{
     "kty": "OKP",
     "crv": "X25519",
     "x": "N5icT6hvBDpsc9a2t1mXfsDBGsvi4VNTNoINejK5nCY",
     "d": "0EeYQgglJkckhiVP5aGzyrQHepapUd39QlbI53HnWOQ",
     "alg": "HPKE-4",
     "use": "enc",
     "kid": "EMf0FmafX1CDECti7cvCWZddOvzvPf3_nmXI39eiO18"
   }"#;

    let jwe = r#"
    {
     "protected": "eyJhbGciOiJIUEtFLTQiLCJraWQiOiJFTWYwRm1hZlgxQ0RFQ3RpN2N2Q1daZGRPdnp2UGYzX25tWEkzOWVpTzE4In0",
     "aad": "VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc",
     "encrypted_key": "WPuUGt62N-ZPXl0IMvwqVI5AuWnkn-ShiF3T5xF2KAQ",
     "ciphertext": "dKwJ1poXJWUfVzLGr1UbCfJpZ8bx4tLlzFMwlcb-RN4do0umqfRc_J70pxgWt6MEpFxAFd8ZzDUzGtjZbt4k1c5vcCX8_XLT87JUYEAFLcPzgT6pdqgEjOJHd3E84HgphLSC-D117RVpHH-lkUp7NKg8hbJ67ZrDnPvT_JwpAw8898diWI-Gys3K6tSox0RLHFVldHTjJQWE28EPWWJ6ewklqd28rgTMc8zm2lpapa3p5hOSYxUB2IQ6CkU7U7SaPNrW3VspdVCbpjajOchTWIBokxihbxyIH3IT5xMhYjhcrkFRLbF1X_adZjTF1nQFXnBSynAnEs5q2RBExeNLYb6Dc9TDDzjV009xEqX7mpsrhJKlkw5-SlFIsaF4"
    }"#;

    let key : JwkEc = serde_json::from_str(jtk).unwrap();
    let jwe: Jwe = serde_json::from_str(jwe).unwrap();
    
    let protected_header: ProtectedHeader = serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap()).unwrap();

    assert_eq!(protected_header.alg.unwrap(), "HPKE-4");
    assert_eq!(protected_header.kid.unwrap(), key.kid);

    let encapsulated_key = &jwe.encrypted_key.unwrap(); //protected_header.alg; //&BASE64_URL_SAFE_NO_PAD.decode(payload_json["recipients"][0]["header"]["ek"].as_str().unwrap()).unwrap();

    let aad = [jwe.protected.as_bytes(), b".", jwe.aad.unwrap().as_bytes()].concat();
    
    let decapsulator = hpke::hpke_types::draft_ietf_jose_hpke_encrypt::HPKE4X25519ChaCha20Poly1305::try_decryptor_from_slice(&key.d).unwrap();
    let plaintext = decapsulator.single_shot_open(&encapsulated_key.try_into().unwrap(), &[], Payload{msg: &jwe.ciphertext, aad: &aad }, None).unwrap();

    assert_eq! ( plaintext, b"You can trust us to stick with you through thick and thin-to the bitter end. And you can trust us to keep any secret of yours-closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.");
}


// https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/20/
#[test]
fn test_draft_ietf_jose_hpke_encrypt_20_a_11 ()
{
    let jtk = r#"{
     "kty": "OKP",
     "crv": "X448",
     "x": "fjqBGwWuU4fodrTA1rAnN8x1WykKMo_MXoFDdssKrzo_FAj1v70mJx5dn6ZdJ896Tg0HcLSPjlE",
     "d": "aw967bbjUbpRJLrL18RI0EfPRQGRHCVC1eUdM7sTODLvnPXYniZ0Sx0wMWi7gHLFH2GQPPc254g",
     "alg": "HPKE-5",
     "use": "enc",
     "kid": "VlMlFEMhh4sRZdmn0SZIcar1R4xs_g1lj04VbypUALQ"
   }"#;

    let jwe = r#"
    {
     "protected": "eyJhbGciOiJIUEtFLTUiLCJraWQiOiJWbE1sRkVNaGg0c1JaZG1uMFNaSWNhcjFSNHhzX2cxbGowNFZieXBVQUxRIn0",
     "aad": "VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc",
     "encrypted_key": "9iaTop5blWck0Uc_ozrHcl2qWFfKSD6o4c_C941JenqyncVyhPD6wlzoyAQ9BQdb23DGzgSwkc4",
     "ciphertext": "On1bbT5LwjcoHTUdnST4CxrHQ-LDr3fnKjX07Tkwpg7ZfdXFYTUIO636QxV7FwF28rOlVN14RQdDAOGBuDKuPaUlWeCrmv8RBUNk1VxSLjqH9t-_jkqVZcrDKJId_V8CWu28f8Aj3ZOULDMByyex2yrdO9icyn3zm2DhO6CEQskZywNUiZH1yDaGSS5WhtchdvhI_GznPws3s5VuQECS7B-Iwlm8vZyKFkmfDgtr4wjSKS4fcTwtP_F-7OyYvXgzGMBX2CTdbzArBJ4LKXbjEwWf-UEMNaLksc0LLd-nta6pfhGDB44btYtochVDzA4zcQvW9CfE_9em2h1cpGiQURa2mwmUEatyTE45BpcVZlg_gU5YgJMxreLHSNb9"
    }"#;

    let key : JwkEc = serde_json::from_str(jtk).unwrap();
    let jwe: Jwe = serde_json::from_str(jwe).unwrap();
    
    let protected_header: ProtectedHeader = serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap()).unwrap();

    assert_eq!(protected_header.alg.unwrap(), "HPKE-5");
    assert_eq!(protected_header.kid.unwrap(), key.kid);

    let encapsulated_key = &jwe.encrypted_key.unwrap(); //protected_header.alg; //&BASE64_URL_SAFE_NO_PAD.decode(payload_json["recipients"][0]["header"]["ek"].as_str().unwrap()).unwrap();

    let aad = [jwe.protected.as_bytes(), b".", jwe.aad.unwrap().as_bytes()].concat();
    
    let decapsulator = hpke::hpke_types::draft_ietf_jose_hpke_encrypt::HPKE5X448Aes256::try_decryptor_from_slice(&key.d).unwrap();
    let plaintext = decapsulator.single_shot_open(&encapsulated_key.try_into().unwrap(), &[], Payload{msg: &jwe.ciphertext, aad: &aad }, None).unwrap();

    assert_eq! ( plaintext, b"You can trust us to stick with you through thick and thin-to the bitter end. And you can trust us to keep any secret of yours-closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.");
}


// https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/20/
#[test]
fn test_draft_ietf_jose_hpke_encrypt_20_a_13 ()
{
    let jtk = r#"{
    "kty": "OKP",
     "crv": "X448",
     "x": "wKnPzBmQ6-0gjEaxhJNY6mG0mDDsVZ_Hvah1mYzPDkUWgPRIQXwr32LDjohWSDLTGeIq1HQ5K6E",
     "d": "LMXuTYqcBW6XUwctj79OVmuuj2P26jBJ8Uaz6d0sae3GrbGOEVYrs6FGBwphzT8ie65RYAz4uNU",
     "alg": "HPKE-6",
     "use": "enc",
     "kid": "bjp4-nQuEki4p5Z7ewD3ScjtBwu3glF6OdfloVMoiew"
   }"#;

    let jwe = r#"
    {
     "protected": "eyJhbGciOiJIUEtFLTYiLCJraWQiOiJianA0LW5RdUVraTRwNVo3ZXdEM1NjanRCd3UzZ2xGNk9kZmxvVk1vaWV3In0",
     "aad": "VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc",
     "encrypted_key": "rBiPWmIS81SOhelCXdTXZRuPo3P1bwojxmRJg1pjfzUszzBu8R1gFRB6ys9q3parvYE9iXG1qvk",
     "ciphertext": "TbXxj9-BYgLgY1MjODWPGeri42N1sLdCFdjeXqs7J41XSeoEhTkI5Yi798SEkisrVEj8mbvLjbZIJGj3B5RgqIEf1H966WzEN5v8lzSOcCe30tFINLRYvapLCf6SZgBq65LNgdh3ESdbWz2lzil4NnRWEvxOTb0hEtWYqNccb2LFZKK3FJ-cwu3AqlDw9jzW6z_DU0_Jvlm81nhVXQWSBXsYtEx934ILrQP_he-YJeIBWCnmhwpyNoaO7sd_rx0E8LpOIgz4qghnc3SmEy57bOl-vh9piCv9kG-Uo-Q1Izf5yOmM5j4u-0uNTTInJPhVoXymUH3CHStxbApPOqqBfYIg6xpBuL3EZWKTzL5MldbsGQojbMzuz5kUm2Zz"
    }"#;

    let key : JwkEc = serde_json::from_str(jtk).unwrap();
    let jwe: Jwe = serde_json::from_str(jwe).unwrap();
    
    let protected_header: ProtectedHeader = serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap()).unwrap();

    assert_eq!(protected_header.alg.unwrap(), "HPKE-6");
    assert_eq!(protected_header.kid.unwrap(), key.kid);

    let encapsulated_key = &jwe.encrypted_key.unwrap(); //protected_header.alg; //&BASE64_URL_SAFE_NO_PAD.decode(payload_json["recipients"][0]["header"]["ek"].as_str().unwrap()).unwrap();

    let aad = [jwe.protected.as_bytes(), b".", jwe.aad.unwrap().as_bytes()].concat();
    
    let decapsulator = hpke::hpke_types::draft_ietf_jose_hpke_encrypt::HPKE6X448ChaCha20Poly1305::try_decryptor_from_slice(&key.d).unwrap();
    let plaintext = decapsulator.single_shot_open(&encapsulated_key.try_into().unwrap(), &[], Payload{msg: &jwe.ciphertext, aad: &aad }, None).unwrap();

    assert_eq! ( plaintext, b"You can trust us to stick with you through thick and thin-to the bitter end. And you can trust us to keep any secret of yours-closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.");
}




// https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/20/
#[test]
fn test_draft_ietf_jose_hpke_encrypt_20_a_15 ()
{
    let jtk = r#"{
        "kty": "EC",
        "crv": "P-256",
        "x": "z860carZ9CSxTjXo7MK65h_TaZX7ipi2iUh_Bh-VP54",
        "y": "i9X0v8PwcNgbsoMhAz-_W2OPaFU--BQAgWVzJVOfedo",
        "d": "nklFxo0VoD3POieIKD2I_6O4pyuoX1755y_r8My3kL4",
        "alg": "HPKE-7",
        "use": "enc",
        "kid": "YGdLPiZno0vV3kJKu4kEMQEjK3_upFF2D_lFDf1FFwk"
    }"#;

    let jwe = r#"
    {
     "protected": "eyJhbGciOiJIUEtFLTciLCJraWQiOiJZR2RMUGlabm8wdlYza0pLdTRrRU1RRWpLM191cEZGMkRfbEZEZjFGRndrIn0",
     "aad": "VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc",
     "encrypted_key": "BJsgimlSAygpn6mErqMkZcmzVLsX6V9aYArVYAjg2LEi2shWQopeMMr5n4VNH_kCeuqXRd2LtFjQd2eWsXTAcs8",
     "ciphertext": "ny4HVMntsCPyijVFtO41pSpN_jusNGtAaYjD_glEgkQlnMlJuDyiTbL9_IgWjcmaQv-ahcToh6pussscT37Oki95DB56UEK1sgwv23m54UgDFDS3Q2UI48pRzgsONMJdc46-UjqCXvDgbGZfA7Afn-mCGJZo90Tr2QyDMpevwYv4-Zd6ldw2QrF7pUXXOLUP8yh2Y8qZB7JkyUvN5gH8QIgIcC11a-2-YWWSO3JgpJ4R51YESAOJ6MbaW2otZU7JY9GW7dKpwd3mym6IxJ4onwSvABkmVaFSqxOEBlStSLirlR0sf1q9HK_gn8HHNjlaNNja2yE3C42ESTWAoH1uapvfMaQJE1ZWG7ru77nMBQJPRxAb-dXTUJa3jeVF"
    }"#;

    let key : JwkEc = serde_json::from_str(jtk).unwrap();
    let jwe: Jwe = serde_json::from_str(jwe).unwrap();
    
    let protected_header: ProtectedHeader = serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap()).unwrap();

    assert_eq!(protected_header.alg.unwrap(), "HPKE-7");
    assert_eq!(protected_header.kid.unwrap(), key.kid);

    let encapsulated_key = &jwe.encrypted_key.unwrap(); //protected_header.alg; //&BASE64_URL_SAFE_NO_PAD.decode(payload_json["recipients"][0]["header"]["ek"].as_str().unwrap()).unwrap();

    let aad = [jwe.protected.as_bytes(), b".", jwe.aad.unwrap().as_bytes()].concat();
    
    let decapsulator = hpke::hpke_types::draft_ietf_jose_hpke_encrypt::HPKE7P256Aes256::try_decryptor_from_slice(&key.d).unwrap();
    let plaintext = decapsulator.single_shot_open(&encapsulated_key.try_into().unwrap(), &[], Payload{msg: &jwe.ciphertext, aad: &aad }, None).unwrap();

    assert_eq! ( plaintext, b"You can trust us to stick with you through thick and thin-to the bitter end. And you can trust us to keep any secret of yours-closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.");
}


// https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/20/
#[test]
fn test_draft_ietf_jose_hpke_encrypt_20_a_16 ()
{
    let jtk = r#"{
     "kty": "EC",
     "crv": "P-256",
     "x": "1nm4Hz__urAJOmnQoT4-Cddab4mIgwNPFpo_mq__Huk",
     "y": "0zf-qAB9KJP6qgtYNSP6MTdVBxzgBachQ2XdgCsOk8o",
     "d": "8CpCdkAF51G_YJPb29O3LKLBKTibK4FHWO9lYehzLqE",
     "alg": "HPKE-7-KE",
     "use": "enc",
     "kid": "SMa7O1lSKSi2LJCin1PfZRYA7KGKky5oSfaMO9UOYWA"
    }"#;

    let jwe = r#"
    {
     "protected": "eyJhbGciOiJIUEtFLTctS0UiLCJraWQiOiJTTWE3TzFsU0tTaTJMSkNpbjFQZlpSWUE3S0dLa3k1b1NmYU1POVVPWVdBIiwiZW5jIjoiQTI1NkdDTSIsImVrIjoiQkFyRmpzNzhKekJ0aTM0a2toZ3NCanRHOGFGSWduSDBSclRtczZ2ck00QnVFMUVFajY4RGJBallMenVjWmJnSFpZTk50NjJQOFJTaU5mVWsycjFURFZRIn0",
     "aad": "VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc",
     "iv": "sXE8-PM-BegS6637",
     "ciphertext": "ge8gDn9qTkGUqH53xmrFgSKAqcmduhDJolm9-sm-tQs5HBc2vgCWwCZbeHc3P64tRAYUTqqlAHrgqYaMxT7EIawB_WVr5yAOdMu4zPsysaUikKAG6aZLywpdEaOGn6TxCdTUczJQ59bza8JxscPGzPdko8z73QUBnuYnr1lUlJWy9pWj29mwVwGJA0T9AvQucNdgb8lQEEcpPiaajGSPYIXV6XeKUQlblUstGl1S6dScULaCw5RAX7gAlHmLDMF0QMG8Hpiehok1bfDOE0gRqhlu1ywc69-X_4ESQFc9v4tph7r6nYBdy9qa-dP_qeVBstgDuvud0kcQH6Xmozg9PTAoS-W7_LA7aIuEmuE",
     "tag": "I7DBYo_2YzG2JC3mWifjFw",
     "encrypted_key": "BcEhfoYFVMDky_AjhhCCAm97yYO-JgiClODO0rLqq0k0lIPut-RPfaqHKITbK8ng"
    }"#;

    let key : JwkEc = serde_json::from_str(jtk).unwrap();
    let jwe: Jwe = serde_json::from_str(jwe).unwrap();
    
    let protected_header: ProtectedHeader = serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap()).unwrap();

    println! ( "protected={:?}", String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap()));

    assert_eq!(protected_header.alg.unwrap(), "HPKE-7-KE");
    assert_eq!(protected_header.kid.unwrap(), key.kid);
    let content_encryption_alg = protected_header.enc.unwrap();
    assert_eq!(content_encryption_alg, "A256GCM");

    let iv = jwe.iv; //&BASE64_URL_SAFE_NO_PAD.decode(payload_json["iv"].as_str().unwrap()).unwrap();
    let tag = jwe.tag; //&BASE64_URL_SAFE_NO_PAD.decode(payload_json["tag"].as_str().unwrap()).unwrap();
    let mut buffer = jwe.ciphertext.clone(); //BASE64_URL_SAFE_NO_PAD.decode(payload_json["ciphertext"].as_str().unwrap()).unwrap().clone();

    let encapsulated_key = &protected_header.ek.unwrap();
    let encrypted_key = &jwe.encrypted_key.unwrap(); //protected_header.alg; //&BASE64_URL_SAFE_NO_PAD.decode(payload_json["recipients"][0]["header"]["ek"].as_str().unwrap()).unwrap();
    let recipient_extra_info = b"";

    let aad = [jwe.protected.as_bytes(), b".", jwe.aad.unwrap().as_bytes()].concat();
    let recipient_structure = [ b"JOSE-HPKE rcpt".as_slice(), b"\xFF", content_encryption_alg.as_bytes() , b"\xFF", recipient_extra_info].concat();
    
    //let decapsulator = hpke::hpke_types::draft_ietf_jose_hpke_encrypt::HPKE7P256Aes256::decryptor_from_slice(&key.d).unwrap();
    let decapsulator = hpke::hpke_types::draft_ietf_jose_hpke_encrypt::HPKE7P256Aes256::try_decryptor_from_slice(&key.d).unwrap();
    let cek = decapsulator.single_shot_open(&encapsulated_key.try_into().unwrap(), &recipient_structure, Payload{msg: &encrypted_key, aad: &[] }, None).unwrap();

    let decryptor = aes_gcm::Aes256Gcm::new(&Array::try_from(cek.as_slice()).unwrap());
    decryptor.decrypt_inout_detached(&iv.unwrap().as_slice().try_into().unwrap(), 
        &aad, InOutBuf::from(buffer.as_mut_slice()), 
        &tag.unwrap().as_slice().try_into().unwrap()).unwrap();

    assert_eq! ( buffer, b"You can trust us to stick with you through thick and thin-to the bitter end. And you can trust us to keep any secret of yours-closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.");
}
















use aead::inout::InOutBuf;
use aead::{KeyInit, Payload, AeadInOut};
use aes_gcm::Aes256Gcm;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use hpke::hpke_types::draft_ietf_jose_hpke_pq::{HPKE8MlKem768P256Aes256, HPKE9MlKem768X25519Aes256, HPKE10MlKem768P384Aes256, HPKE12MlKem768Aes256, HPKE13MlKem1024Aes256};
use kems::{Array};
use kems::generic_array::GenericArray; 
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, base64::{Base64, UrlSafe}};



#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
struct JwkHPKE {
    kty: String,
    alg: String,
    kid: String,
    #[serde(rename = "pub")]
    #[serde_as(as = "Base64<UrlSafe>")]
    pub2: Vec<u8>,
    #[serde(rename = "priv")]
    #[serde_as(as = "Base64<UrlSafe>")]
    priv2: Vec<u8>,
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
    #[serde_as(as = "Option<Base64<UrlSafe>>")]
    encrypted_key: Option<Vec<u8>>,
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

// https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-pq-pqt/00

#[test]
fn test_draft_ietf_jose_hpke_pq_pqt_a_1 ()
{
    let jtk = "\
    {\
     \"kty\": \"AKP\",\
     \"alg\": \"HPKE-8\",\
     \"kid\": \"DmOWQi-VwrjZWjO6mQQWdv3CJ_v9k_PH3vS7S0xoah8\",
     \"pub\": \"6XRnIatC1KtI7DZlj8ISDxZvtsFeBOPKQETMRRYb45dR0kw6TDSb8UMXHH\
       WhUBdbEBof5gvIJacZG4exGku4JsysQcc9AVR6Ydih7kaPNQgCiiKw9QACNCMWx2\
       p171RVCpGSFoOwaejNGZeNJKS4jqulOWFQHGtbWhl64HZzlkZMxhqdA-EecEOLhz\
       CkbCMMtXxb-cxUVkOxQpKkO5ofmEaKH7tjyNZyVsxqgUZFn6K8jOq9g6GCOEG4aw\
       GB6AZC72yNXLDBnVCy_7OMn2bAeos8AvhHkbsL0hsFFjsnWcG_IYvNPzUAcyGZlp\
       sqjXJIh4AUxTi6iFeJFOE08nNM3KQEYlxkMAulVas2E4KU_TGeoEJeZjA5TPWVAQ\
       iPFFQ4nNRh1kotf4OHtHQVpaMzAypItIXAU8LI_gl4rdFKTfYu18MKnygjEnO9Z7\
       e2cYwj_hqx-AQdA6ulQBcNR4DFSCOTLnMB22GMXGVOMDCmiaxZvchp9iEKNJG4Tk\
       ZQmoKwR9pbEbahmsm1WvUbR6kEqNYOE0MMsRWNM3RBNltm0Iqo8RKMlpRq5RceWR\
       RdjRkKdChyhuJ2ebBI05iRsuE6AwWEbCV6dQqNZ0gqdeU5imECjFWLNqYvs0BaxD\
       gmoSdg4rFlq3UrZ3gLD4UTT4kM97HO5iedxoox__octTEEImMTf8uJI2M0nKTIpb\
       WBHlofTfulcqVXjFYpr9GvuKM_mElaoJwn3MQYrFNLcwY-fzy9fqvGFtF-62fHcp\
       cL7SVUu9KW7igiAHQfwXmCnMQzsxwLowVk8mFjDYgV2iIoNIeuwZdc8-I0A1CLiq\
       OQNwCLObgSMVeo-WUvzmocsFOUtSUS1chNNwpjMCGKuHxOYOcvKLxH7mvPp6czIo\
       vPsqQUZdloA5Wqt8U1sDRZfrhRlUi4IVoTmevBpaEYK_Jze3cIMOkRKdO5Y1tB4T\
       IcAHE8oNUarUEYx1YDUinIolRBBDyBAmR7rbV4iGenGHwgeTIZ0cpppFEDbkAX4A\
       aG4YKGdGWrgWhhiDoPX2mda_BLOSilnlhmM2BhqGZBkKK2E1B5fgER-_AMYeVl9H\
       EoKCFHm6KApgnLVnYMQjEv7kC6tsqxs-pOcnSs2EpGKMMk4gdIlcFNxsVU6sXINH\
       ADvNmtNyQgjRFKhmNPtYchXHWz_tgccWNkm1DD6qMATOoZcscAu8BBpKUwUIkIUI\
       CwKpay5KUsFjKpC9HPqSONVMVu7GYysVC8UDTMetWoXlSiDetoiolwFGGpIscf1i\
       c_rUhbD3pyxVI8DqCsdFg2NcSvIJRoJBO12KHKRIYnc8ObgCzJBULNZ1Rmc5tCbm\
       cW_mmhg0OiA7EJjwi_eoY82_g0eiyAr0K4DmBy8yqWDZV45KfAnYQBQZvK8zlj0n\
       pGqVWusxzP1mw_Dbhnp-Z6SyIrHNI9unG7DbeDhcnBD2QBp2t6cNgvUoCLzPReQP\
       Yy_bwVEwcrPSO4SjUG8mhuybiU5NWdgIRD95gD1ApNRoZeJIhfP7yM1vt1ZCxfV0\
       xEvUSb25DOebimyplEvv7nxam2hbnlRQme00B5wPt9pETxPSQE4ZUd6u60U9e6F3\
       C-Fqjwfg_xYMk3oOcZQ-P5NrsNxK3ho7xmtpSKVahpf_2P_o2Vz8YFc7t2S7jAx9\
       bRLQQpbA\",\
     \"priv\": \"c1il1CJwUdajeAm8PMZMq4mw2PH9Z2vThLkHU2MQ10A\"\
    }";

    let jwe = "\
    {\
     \"protected\": \"eyJhbGciOiJIUEtFLTgiLCJraWQiOiJEbU9XUWktVndyalpXak82\
       bVFRV2R2M0NKX3Y5a19QSDN2UzdTMHhvYWg4In0\",\
     \"aad\": \"VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc\",\
     \"encrypted_key\": \"zRayDf-tglGK_UsfOjbbVDf_GPQKpRLNx-pusFTw6REZlhoX\
       c8INMxK5ETEdsx-0MTVa_8AIou9zUiaHPw-Iv1nk7X0rdIFYjKOTnjRUy_DuRIRa\
       b_o1qSZ5-x6sBn8McfjuKMvcJbwU2uqW9NJyQtK_2yNmVvrYiPEhnuO73O_BSv_G\
       SBSoHgFWEpbb5FeH7ujs7Pq0bV_pdI3XnabhvIPVTmnrkzP2J4vcYt00B-wxAxiL\
       Uc9zaitKnkn_ofTtOp1lUUeuUzKDPYuo4x-GRZsG_gf2Ez8FFE0RIJq6AmYr3DKt\
       SziHFqeim8uVI8_mtE0wIj6BM6eYYL7c79MNoDlop5P3QI3-PrZ7HrqULs1U6W7U\
       DScowuP80jJQjawMUd1itDjlB1BkwVH2u0BwoHWzA4NxdgsusIbDDmH1f-k8Y5t4\
       7tb3B1FeBYK0G5MbXQmc-h53dACqTqd8nJq7jQNfzmELY7aWmT_Z72KGyfwUY731\
       JCeODbDIW37g0mdOR7ZcFgHm_Usj02Pj2J_Fsw2N3vkb_IEWi8abtP7NTaB6mYmI\
       -aNGqDEfXRVI5K7ReLaHOqWxtPkkfysYbeUDZncwkt16rFa0FzeL40sfv7yr0J8K\
       s-HXPItnfmha_FDB4MuSlxmH8fADldjXNozWwB8HWSCEp111sdh_cP44rRNxPZbs\
       S7UWyTldMixcjKNncA1dNhafJ5qXjq32NUiN8R2BPkWCBzKMfaKN7bujZphGIRZe\
       kETFSx2Cp9mO6hG-CqV2dsu9I_MDHgiWEV8GwFC4HyILVJRc9qysutXw0b2UupEo\
       s9BzuUaoYTvGHwpNWzB77-vON3w_FV94KrwQbiki9_vbVtct5ODB9Kf8KCHv5DPw\
       YGi7e41zKoS1Rm2Nczt56SC_RqKn9nFR8yfH7bEhvnsQHi_qXHWOFWN7f72H9Cb1\
       ascZo6XTYaVUCi_RiRS8wgLG0LvOyCfpzgVNpbFhPGBbTZceZW6eSGNGK-RQ0zb5\
       sJFZSuM9P2cK23dnogEGTPRLp9DWs3NUBW0Z1yVQw1v9gukwcM0xYlo-zfQbwWzH\
       IdzJboQR-DqeOllx_Jjh1tZPC_nRBdu4DPX5KP6JDsIrv7hw6YQ5ocQwQMdcoGcF\
       WsrKEOk2ei5HBjbfJQngzKT89TpNaBH_wXpZqUL25bltMM48JG6rTiG96eSF24BD\
       ONDAUDgrzPBoT_ipdN3Tie0hQHxTsT4cZP9o0PeEYgu0CGPUG0wcirNh1hnhf-PT\
       EAgfCoTyqOJ_iVj_HZO748slRlMJ4P-Ij4qah8aYhAWJYSdzfBCkMPXX-bzw4ovK\
       uCbFlOwT3I_tj0lggb-vVqSzv5nkHyqjvzGTmEK1Tq_Wy6uxyD4gUBPKkNoPMvA6\
       SeghLYy3c8XF80XxStZX5OAQV36AavxZrGyX3gMS024KX-wbNytokZbocP4EOLum\
       sml35g9ePuXmJjEweCm-D5fqMe_uaLaRP9RveNyNsCd3arMLkn5PSpRTuTsMOhLm\
       45olI85aNT9TrL1oMw\",\
     \"ciphertext\": \"Kqt2-MjNX9R4OmghbRcEPdzNJvCyvAUbezJcRvKnbzWqu3JsfGk\
       O54gurgSvQcQhAnTWLfJbDJvFJWzqCkXoqgYtgsvrnxFNqJ_j7194RxeH39eXb0M\
       oVkTgPRQO1gmbtr9VPTrkPXlGCWZjrdVGEUZ5qJZvZfHIYyo2_egOP5CuMzbZuNQ\
       tjxeTdagfBqAymYpk5O8VqubF160UrVDZnDfm3ndEGH4oFZwPVtPH2IaYcubiTm1\
       00oxPdTTKZX1PeieRG5RodWY6rMsrA0_dMbXrTDg3spqXloEySB5i9w9ChHZ4s1U\
       HzihtusJvw4qI1kQSZZc6RxELIzED3s5OHhpuzKTrl-3vVwlf9Ily74215pZwdJW\
       7CVWTL-Xe9fhxEA\"\
    }";

    let key : JwkHPKE = serde_json::from_str(jtk).unwrap();
    let jwe: Jwe = serde_json::from_str(jwe).unwrap();
    
    let protected_header: ProtectedHeader = serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap()).unwrap();

    assert_eq!(protected_header.alg.unwrap(), "HPKE-8");
    assert_eq!(protected_header.kid.unwrap(), key.kid);

    let encapsulated_key = &jwe.encrypted_key.unwrap(); //protected_header.alg; //&BASE64_URL_SAFE_NO_PAD.decode(payload_json["recipients"][0]["header"]["ek"].as_str().unwrap()).unwrap();

    let aad = [jwe.protected.as_bytes(), b".", jwe.aad.unwrap().as_bytes()].concat();

    // provided = 1153 = 1088 + 65
    //println! ( "encapsulated_key=({}){:02X?}", encapsulated_key.len(), encapsulated_key);
    //let x = GenericArray::default();
    // expected = 1121 = 1088 + 33
    //println! ( "expend={}", x.len());
    
    //let decapsulator = HPKE8MlKem768P256ChaCha20Poly1305::decryptor_from_slice(&key.priv2).unwrap();
    let (_encapsulator, decapsulator) = HPKE8MlKem768P256Aes256::derive_pair_from_seed(&key.priv2).unwrap();
    let plaintext = decapsulator.single_shot_open(&GenericArray::from_slice(&encapsulated_key), &[], Payload{msg: &jwe.ciphertext, aad: &aad }, None).unwrap();

    println! ( "{}", String::from_utf8(plaintext.clone()).unwrap());
    //assert_eq! ( plaintext, b"You can trust us to stick with you through thick and thin-to the bitter end. And you can trust us to keep any secret of yours-closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.");
    assert_eq! ( plaintext, "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".as_bytes());
}


// https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-pq-pqt/00
#[test]
fn test_draft_ietf_jose_hpke_pq_pqt_a_2 ()
{
    let jtk = "\
    {\
     \"kty\": \"AKP\",\
     \"alg\": \"HPKE-8-KE\",\
     \"kid\": \"clBPky-tElQGRa8AQ1MYfMPvfqmhOs_5lIejOuqAdps\",\
     \"pub\": \"pxQRXrRJLke8BMBXa1FT74gM9fq71fEwRPRndVsmsYAMU6llEnJaeKAagj\
       xk44yl9Psn7YBn3tVXXLVrqIxyWhGsP2pmH4Y2eogBaRMGBfQy-TM_RzdFE-hKLH\
       qHPmqP_PZES2s6O9tBkvk7D6fKZKiBDSKrvWgrKCIo1DccgfHEayxCtex1w1ZjVw\
       eIZWtVA3V_JdijzobGiSU0dzqyjVBBCQVcWiSFLLuX6rFtiPpsa3SlavpKHaRTIZ\
       x_5ocCO1LBAKq4jwew4jxnhRujX4VcaOE2MQQ3FUmT6UgMpWSfymJNBOqwN3uU3E\
       O_ktgMPwdfrRVihSgirkiV7BhSW9uN95OTigiJIiedxPV6asK27cCcPhN0lJQOyn\
       lah8BjySYKwdMRHyxVVhGDmnJ36veTEDoboBhq5iAkcqwed7O-KwC09XcVciegq-\
       tYI2NWMOkBdXE_W2qvvPIkJpOYtKAztpUcxhBBPitRGQcdz-wD4nik2DFk82sfDN\
       pC_lV_XWYR3KVwiBix2tCB3tw-j9loE3AaxGefsyl0PPQsFGu2i5qutBlUclRUhM\
       UkiGcyEnx5S0xNYzyuM-lAa3WpNzlEc_SoqmKvobZp0pi-ExYnpIQJ7nPJFNXJ9i\
       g3kvpNCxnKlEwsP5w91SbOcLOBQ5dIq-moh4kK9ZCry_JkAmmAxhu9kGCughacCP\
       aUqgZrigO9bQHHw0giX2EB5hA-r6VxzMwYJcox9SxD0tJVsAMhCUGhGuS5wodrPh\
       ay-ss78AMZiXm3D3mDe-sA0VVRLaN3HgmZw-kud8su7bKh9zYec4iHaygQq2ySGo\
       eOKoGesVK77fiLlWaYLNtqEmywBblQlkZbOIUmcVmsTwd1yZG-rPIka_eJ9gAE4T\
       e4XgExooaJI4LAdaif1stG-lEZF8RmNlmvm4wdAMZQAqPPLiOwkVAhshMUfavMeV\
       iGedgk57y3JNpgqQuX-sEI5NmNMFW47wR3AesCpuuq_Skqj8EdeWWaIwh-L8iDYC\
       c7N-tLhNwgJOpnI2pH-CpgVShigKi6brIjB4QEV-JtRzKFZ_ZF0wM9GYTNsBM7dX\
       lxPUUVjLCyWFWYScRdwHypH_deyvaEjny-0DgpOuR5pxBWtFGEsoAQJBmPZFumwY\
       B5dZkyBRJrQPUENMNw0eZ_1yql1oFIdTQCQgEln9BFfCPB6MCX8kZknPovhJmq74\
       BALPWaINeZhniI48FGf8tz8VdJ11Mu7qxrNiUHNApTMcke3Aw2qKl-NtFeR8Ou6f\
       qQH0d2ShV-GvCcuxjKfUdNU1y5zYhlu6ZZwvkZ39jKl-t7Eyw6rAEnUfWA2hEXXM\
       aDqBVRYvqwhiM0nboODhWUJUW8OEpBp9eI3eel7tRFViiZQ7KsZmUBVyVfGJQvh7\
       DM51VAvUUSi_xPQzsz--yWJ3DFmYWF6eMQk7FdUXu7HmFxMfuNNGHMypx8S9RqfC\
       iI9OfOeqwVSaa2MAd-b2cgDAo8qVeCGcMVU9FRwrUscVeltcJI42sZiaoXFPUlyA\
       KncyajZ6gZhFNexIDWiSCp4L54nM948L-KcoFnZwHsueAjiJwE9dcy6kUtyQ6v0_\
       OxWb8OuM04u96GtOld8wVIcB7QE2fd7g9XTCdShgpdmMgNnGKrJM0A2Rbtmnn-gd\
       xGbyArJA\",\
     \"priv\": \"biUK5NqJzXzWEAN0F2zzkrEr9Rp_QX55is_j7VYuHCQ\"\
    }";

    let jwe = "\
    {\
     \"protected\": \"eyJhbGciOiJIUEtFLTgtS0UiLCJraWQiOiJjbEJQa3ktdEVsUUdS\
       YThBUTFNWWZNUHZmcW1oT3NfNWxJZWpPdXFBZHBzIiwiZW5jIjoiQTI1NkdDTSIs\
       ImVrIjoiOUdINDFMenpHYXBiUGFPeV92T0RZVEh1c0ROVjFLdl9xVnlZVDU3b1RZ\
       SlRqS3cwOVhUa25BZFJSa0VSTHdQdWZIZ1pKU1FpVzNHVGZXMVNiRVpmNFhDWjhi\
       c1ozY1c1U2V1SlVDNmlvXzU4enM5SGR6bEE5bnQ3MVp1eE5XbzFvbUxkYkZZTzRn\
       YkE4SXNBaDY3QnB6RS16eVVkWGlVRndvWTBTMDRpUE5RMmlmc0VlWEVFdW43ZXJX\
       Q3QzbnVYdEdXeTRxMTBSSWlRcDRWdUdGdWpRNk02UUptby1NVVRJdDdzOGtGWWN0\
       Ujk3U0ZDU0FFMEZVYnJqRnlOMExsRG9JS01VT1JUWHVpdUctWDNyOFdEdEFMM2Np\
       TGs4T0RNX1NRa19veTlCSmJJYmRJT0VFZk9QWU5udXl6VHhuNHpUZDFqd29zOTVp\
       UmRxSWFBR0JGaTJaajZOcWxfWWQtWU1aeFB3NFQ4UGkwb2R5cGRZYjVZdVJZbDdH\
       WlItamRTUEFCSjV0dEt1X1JSSnlZODB3ekNUa014WnI1bVUxZXZpWU9WQm1DY2RT\
       cFpfY1p0Y2ZxNzNKMHYzV2ctd3U0QmdwWFR4VFZYMjB5aldTaFY1TlhHTjE3Z0pw\
       cVpiTmFMTFVpMU9YRk9EaDcwR0lhZmNqbmFiVFVsRDJWR3RMZnBySGMyVlA4VHR5\
       Y0FLc05LbDNSeVExNDB3d2pONnZMRFljRUlyUUt3UzlUZURqcXVpTVJxeXlKcHpY\
       MXFCTTRSVENnMUdEWVNKSTJKQWVXZDNWbTBwOUcwRV9DS29DOTMyelB5c21zWnFo\
       TFBpNEhjNE9vOUZLb3haQm9JLVI1NUM3NXg2TFJrUHNvRFRJaE5BbW9yRURiOURR\
       cTJPQnZnZllwRnB2ZzE2TXZVNTFVRURyUHBBbFRabWVWcHpxay1qR1huc2NjaU5r\
       elMtLU05SHVUb2ltY0RDbTNUdUo4bGxfcjV0T2JIVXZxYklBSGl4MGJvX3ltelR1\
       WjRVSDdyckNmMk9sSzhGbG5xVkxwa3JmeE9uY0tadWVWUGs0NEE4VkEzX3luQmVz\
       dV9ORGtJcEFUaHhoYmEwd0ZmYmlERVQ5OFdYNHhBNjlfU2RaTm1KMUM3SklMWHVz\
       SnItd2d0c3MtZlNqZ3VKdHVpR1pUVzR3UWxKNW1jbnhFcXVKVEc4Zm5UcnExRVZ4\
       d1R2Rkg5akZlXy1uUWtfMEEwaVFaT0dBLUFfRUZvWHEyeWM1QnM1N1NON2FzQ2k5\
       YnR5Z1BvTnR6cy1VaUtMb1lJaXF0YzlHRlUtbXhtQ3BSaHh0WXpaZ1o2MTRPZU5t\
       emVFUFV0SWVYT2Q2ZDdhX0l3dWdkQ1lfaU9HOVVZNnV1QjlXclpuc085LW1fYUdK\
       QzZES09VWXVpUVhVRTVaVS00MnNicHYwdDFKUXVVZF9od01HUUpuMVNtN3NBeUpp\
       MTlYcTdyYTNtcnJVY2FGUmk4d2J0dk5Ea2JRZ2RLYmduaDFGMVZRU2lDWk5JRk1o\
       TTdBVDNaUmdhVjhVZndYa2hmdHhoUTdIYmNzM2ZuNnZMUjNkLXJiQ285QVFULUFl\
       UW94LThDbm5DVXBoSHczemQ3MGJBRFQtYTFRQ19MM0p3ampDNEdFSTR6NmtKMno0\
       UGNOa2FxN0hlcC1RVENiUzZ0NE52NVZLU1FLNXc2Y0ZNclVsTktWNHpFTnBpU0Ri\
       TWk0ODZTWEdlZE51R0ZPUUVYTGtYYmJPV2gzNm5adVVEcTh4d3B4al9hemN0OTdR\
       VE1OWEpBVFpXRWZ4ZjBBQlo2dnlyMkhhN0tGUWtacWpwMGR1bWVmTzRtcGVnNm5y\
       OU1UaGFyQUMyYndrWVBVSV9EQXlZT3hPOUlGdmsyNDdUMnF5Y3VWSVBWNzV0UDdm\
       Sk96Sk1wWktUeHZjdTRJQnNFOW5hbEdXOTMweld2QW9Hb1dsdkxRZ0ZQSm9fMjI5\
       TnIyN25IcWZfMzRzYUpidVQ5RjBzX0F0THpENjdjWnYzWXJjQ29XX3NHcXUyam9p\
       Z2xRN0kybUEifQ\",\
     \"aad\": \"VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc\",\
     \"iv\": \"GRZLhvvj7vBw-FZm\",\
     \"ciphertext\": \"D5bqaQekeFnn_YlzsERq8jp5w6Y0t2gulaz_ql9AIqozptDIHEA\
       aYwGJzfgv2W_woeFLXUnnZlnG_aed4vvmFi1r7CLamiwk8Xie_bPEt7Icffle4mj\
       j8DJr5KZUNNfStrKH5_DJRl53dOEeuAhYdXU08OgBh4ezaTx5I_2fDqVXSGfO5sA\
       WHINXWEPsrf1k275iMApQthhD4aAO2hYLAuAGwFGsySvXoj85BsNH3vLALi-H-RS\
       oXWNt64OxLyMXY6L5TVBBaSnn19-h6hZIZU7bVQfckoSKftZphRR99hWxZ2JQabT\
       YQMk_UdW7SUBJUJe0s47uFrKC1T468hp0WFenqHZjS2oaAodaCZdIayGt\",\
    \"tag\": \"8A439opYUyFbYJdDno_Bfw\",\
    \"encrypted_key\": \"K4m6zdOhTuo7VRZuZOmmypBM_WxLAI16vZklK3EnnrPLTyXK\
       rUqySJOIn6TPhnn_\"
    }";

    let key : JwkHPKE = serde_json::from_str(jtk).unwrap();
    let jwe: Jwe = serde_json::from_str(jwe).unwrap();
    
    let protected_header: ProtectedHeader = serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap()).unwrap();

    println! ( "protected={:?}", String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap()));

    assert_eq!(protected_header.alg.unwrap(), "HPKE-8-KE");
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
    let (_encapsulator, decapsulator) = HPKE8MlKem768P256Aes256::derive_pair_from_seed(&key.priv2).unwrap();
    let cek = decapsulator.single_shot_open(GenericArray::from_slice(&encapsulated_key), &recipient_structure, Payload{msg: &encrypted_key, aad: &[] }, None).unwrap();

    let decryptor = aes_gcm::Aes256Gcm::new(&Array::try_from(cek.as_slice()).unwrap());
    decryptor.decrypt_inout_detached(&iv.unwrap().as_slice().try_into().unwrap(), 
        &aad, InOutBuf::from(buffer.as_mut_slice()), 
        &tag.unwrap().as_slice().try_into().unwrap()).unwrap();

    assert_eq! ( buffer, "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".as_bytes());
}






// https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-pq-pqt/00

#[test]
fn test_draft_ietf_jose_hpke_pq_pqt_a_3 ()
{
    let jtk = "\
    {\
     \"kty\": \"AKP\",\
     \"alg\": \"HPKE-9\",\
     \"kid\": \"BeWp7Y5tolX2sSYMKIaG6WUVE-arTKcS2Ok8EgqFqrE\",
     \"pub\": \"ZEbKruTLTRJZf-UygOWQwuBNzChq8yuhGTVITLeU7emGD9tF9oFEy1BP9h\
       mBRWo84Zyjr8xlvkadCNyu5iOfuoIC7pA5JCc3A7BNp2ZK8TnNPTsYJ9BTicjChl\
       IMMYKVSnk9WjCj3EqM90RaRiSHYxMUJ0VV8fY_06BqrODCwNO_6BYGaaxHszSAVp\
       armkEiSQOZwyB6xsc0dsU2MGVGANQDBCu3NSs2gZmN1fslWpxzqyN4YtZhwkozcm\
       sGztObngYHXEtgqpo44mKqXHfMBIxjvsqgZ-vNzGyp04OErotG5QOeu5gQZquZ4T\
       lS7JqxjjN0ktJ9Wqofvlq1i0JG97VL7aJ0IHJpnFl8-4cbqwq7-Wan_9U0fJux18\
       PBDBq3jkQiwLiXZOk9Klgin6BGwpx-JPedIOOEEEnKLpQwg3lOZGuHfXGCT5BkGf\
       k4sVVR3dg7uMvC4yFS5ftvggIWfMPI4LV-3DECG-pDe1vEpQFE5EwSBHUhpyjAWu\
       MEHbpTKau5oGmVAIYXRKZfZ3CIFQV3gHoBZdZQoRhEXzKmdkPB2jJI16FnFGUK_G\
       SZYsXK68IUk_lEnihTadnBEhM78-wh9ZtAXQsKgQtUdWR7nFt6yWAkSQIegmJzzk\
       Ew4_FBrNYUIXC930h1dYi1sZw5ZHo3dmY3Viq4pLiiixN9LrdzV6RGIwR8fmpqbq\
       NAc_cVsFePATiHnwBQ5kej1BLMAkUfYhJpX1lV-9tloZLA6JdkRoAeXnEvIxyY1T\
       UYpugYuZUeERwlWygVnOidsIi_Apo1KAUm-TocR6m0zGtG2YQ07mUeI2yqbctcg6\
       EvYVVBLDu_RJeLFyAw-Xd_WXgWNoIzoOM5CXLOtDCcJwMoLJknW1dgNxdFZHG1mQ\
       g9T5wBMbEBpjK8a9oOnfxVblik3eUHYkS7TVhKSqCOuyOBzDQuVtHAt9Q6OCoOgu\
       qUmJeBV4GSd5IPSnpCendqBjEKZ2JTkNwFkuqqbmilEnYMHEOtMUyveWZi6_qm2k\
       PG7aVcjFV9U4pXZEuRIJcugvJUH3qw9UQ7smgqsaJMFzrDVsAGQWItDJxcEOgBdB\
       TAiit99igYmAeEyNoK-GQ46OYsNzq5-CuCiCGJZKNObWhddnROkmY6jFG7K_k_Rg\
       vAj_aW0oPIEzGz0jBtZqVDMTFHF6d4q9erpHOaO8h9e7k2nnrGyHgkJYOPQImVrL\
       Nc93OEJ1qLzUSwJaho8KqwNlOHqDuJgmKoSfEhqXQRfIh68qNqZ6SC9JYJ_-lwpK\
       k_TQUYxJUdRkHB9fgkBwyoGsi0nLpOhMinsIc32CMyHMqvBsc9DlSgmZOBgiovyn\
       Etj_gqdVZ3ZYwDAaSaXTG7wLMyNwBfVycm5TdMQeZs8dwu6pifo_UYzBhj1EY8u3\
       IdS3OVajDKZqkw9zeTacE2kwVsCkDOK_y-wQXEvyFCbAYW3IANbpAuIwpirGJfFT\
       WHIFEm1CqL4FXPt8a9DusGHQCuq3bEkCtpnRiOTGOqgVSZSWkuoxbGnluihrRc5N\
       YY87PCvMSRVxthHPS6-Af2yP_HWMkcfu3DwNyCFxBJgfvtXGLFSm8Zq6EG4zipdI\
       VLeDl-Mg6s_8jDce27ki2xqXVQWA\",\
     \"priv\": \"tQDSUt-Mgd0LNFiUK9VEluJnrtg057pCq97A54EdbiM\"\
    }";

    let jwe = "\
    {\
     \"protected\": \"eyJhbGciOiJIUEtFLTkiLCJraWQiOiJCZVdwN1k1dG9sWDJzU1lN\
       S0lhRzZXVVZFLWFyVEtjUzJPazhFZ3FGcXJFIn0\",\
     \"aad\": \"VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc\",\
     \"encrypted_key\": \"FNPUnD-x_KD2ZlRpfS1i5otH3zXS0p5YqAX1IQXDg7KkVDfP\
       rigLJiUX2olBxmMcer7yXyH1L1VMt3AnbWWHAH68JXG4maBWMtpy-ahh6X7k16Jr\
       zCzzQCuRWS2qDMNw_jjb7L_LiR6N9VigfKC63i8D5fL9P3y84jab77h5BFeH_px4\
       XNXdj4IZpoQbrF496F3TMCpj0F7VIOPOH9Vjt6gH4sOAvkeuX5riGG9F0dhN67Gm\
       RHAeCZyW8ywvfzjADZnRG0_SX-bfcmICTJziIVy4KaEMH0YvmIrYmQe9jI-XKCIo\
       eSQpXbvXQtniw6vWhPV5pDldRF89fshN1VIhTT2zsP9of5loHM9DJp7ac8SvhRIP\
       m2GHocU9JtRN0MIkeUEqLMnJlp1dBJl3D3qwcOTvAO0A3ZA876Xu8Gsgcn5VsJj-\
       O1AN2eB08BR3NNGDuuUsgxPVXQWyAFSQ_UlG7IVRp_8__NxfW4cbpCjcE9hvvlQD\
       -xFS0a6rQOKImWKzwKmY8GiU2SUEAwN6rSPHr8JyGfh0YrA0--FgPuab6PPGrZ1q\
       z427SQIxlJBCipWPLlhJzvbWUGCw0g8Tk2DQGnCBMZNc4lBNVhnKedQ57g6erNBh\
       0MOZSXj-SLul57DSBXguw9jMUtsJZoF8PjIc-eSrQrZude3S9illlCRM1dfSaxPk\
       825PQjBFlMnEb9qe-Uc65ALr093ikk5eYF1mUJ31EAJYBVl4gU6RmD7Dp0Iu1X1z\
       wxB7JZYZCqUOmhyB1lf8oA994ChY_VkprCF_A0NcLpee8iW7d077OVODp14M4w7D\
       6hPLJDa4T0GDjMH-o21b2n6YqoxbUuPPGAPCypb7e9zGliZWkpIyBXzvw8pwQ708\
       iFc4AMZswlS8cYiS-6n3VrGosvT5UplUHdpPONfN_UYHOFwIWwErmxABUZbKNHWM\
       0t1opDlysAIXm5lSOf7NFAVA05UQGofBty1N1rnSey6ElXk9lf3gdxKDfkgZVqKl\
       Tiuh54bm9L3Kgu6ZLKqTyxOWYiYW2T2G79tXyLAQDrl6FxRwlGpUWGhqsmN_MSIm\
       cSR3R7Y7uwsQshS6hg7zXJo4IQ3ok7-RvP1-bn9d9goAHPSYASnrWAG8IsIFRK2y\
       JyAEIiUNL_tFQ3TulU3uEgJIECrqKn6jFcLQ_er4AnCEJy3Old1rXxZsMSLhHuuc\
       qhkByUT2iP5jsupSeTaCgRUKUMQwJ9iUeLAp4aAIZAertDuVVZli5fRrFByO6h7w\
       Z6ewNkNen3vwFgDU3V1_xXIZCo_GFghO-oGMysxETIB-IvqRH0qLWNn0z771zago\
       T4Ri2HmQNRcKmA9uBpSpJ2nYIkMJ98CYm5kHvlgZgZp_YEffITAXZ9drxobjxrm4\
       o73l9nhtDdPpY3D1ztv3l3kFX0K2OdpG5whWZ4kuEYmPuugT49EVQXS4Xdpo_aS6\
       RNKwc7ffpbhl-ztL-H54o9-NIoveutL8V957RA\",\
     \"ciphertext\": \"V4iZyqGIdT83y_Eb6dE2c5l0-LMzKAXVnJwmXt9337d9haaaHlG\
       YFUKvF3zvTZGBJ2PXLQEFWmqZ59lseWeSGA1TklJIWjQbb-1oCdE8607piGyFiGy\
       jlsd5CEzfJuVZXmYQz3J4g6NIHlMGIoKTx6aa_A-qYkszxoKdlvnmwHLhm95vr9k\
       9GNxWIblWK-rJkntpPTWecV7Y1nI2yb3nzJUBDfqDzfKb9YW2x--8KFs8n4RcSZr\
       3d07RCB7QyxQKl9AFd5n5thTO4_UcRChvfc1aawFV4lnTHCGLRAwPo9P0JMNf3v5\
       1mfSstGwvRotRG2t9S3IWG4C_94VOeEVZPlclmt5uYJXPvQ4Fip4RHtwG1mRFRtT\
       TzTblfqELzPe0VA\"\
    }";

    let key : JwkHPKE = serde_json::from_str(jtk).unwrap();
    let jwe: Jwe = serde_json::from_str(jwe).unwrap();
    
    let protected_header: ProtectedHeader = serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap()).unwrap();

    assert_eq!(protected_header.alg.unwrap(), "HPKE-9");
    assert_eq!(protected_header.kid.unwrap(), key.kid);

    let encapsulated_key = &jwe.encrypted_key.unwrap(); //protected_header.alg; //&BASE64_URL_SAFE_NO_PAD.decode(payload_json["recipients"][0]["header"]["ek"].as_str().unwrap()).unwrap();

    let aad = [jwe.protected.as_bytes(), b".", jwe.aad.unwrap().as_bytes()].concat();

    // provided = 1153 = 1088 + 65
    //println! ( "encapsulated_key=({}){:02X?}", encapsulated_key.len(), encapsulated_key);
    //let x = GenericArray::default();
    // expected = 1121 = 1088 + 33
    //println! ( "expend={}", x.len());
    
    //let decapsulator = HPKE8MlKem768P256ChaCha20Poly1305::decryptor_from_slice(&key.priv2).unwrap();
    let (_encapsulator, decapsulator) = HPKE9MlKem768X25519Aes256::derive_pair_from_seed(&key.priv2).unwrap();
    let plaintext = decapsulator.single_shot_open(&GenericArray::from_slice(&encapsulated_key), &[], Payload{msg: &jwe.ciphertext, aad: &aad }, None).unwrap();

    println! ( "{}", String::from_utf8(plaintext.clone()).unwrap());
    //assert_eq! ( plaintext, b"You can trust us to stick with you through thick and thin-to the bitter end. And you can trust us to keep any secret of yours-closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.");
    assert_eq! ( plaintext, "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".as_bytes());
}


// https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-pq-pqt/00
#[test]
fn test_draft_ietf_jose_hpke_pq_pqt_a_4 ()
{
    let jtk = "\
    {\
     \"kty\": \"AKP\",\
     \"alg\": \"HPKE-9-KE\",\
     \"kid\": \"I8THo1KoAq9OG96cJTyk2WF8abZqb3kKKHgdfajHUb8\",\
     \"pub\": \"8rGsDcYDVYgHXJdoG_y4snlf_zZ2J7IJ_dyGafoU-8PBqdSb4dKAAggLvU\
       LOi_kwqxCdLXqh7sinPlUPEQAXeaITnOkYJhCJN_tpWBBbZclC4sAXNHItUAV4Kf\
       AmEgyll0KiqKRohYQjhwSlSAQhA9NwAPJhYMgZPWkDf1zFJexT_prKclLGRzU-Ak\
       uACumcboErJqGYIRdXVfN7JqfIXfcNI_QCSpcpuAk_wMOWxOIj2WxdCMMfd1QBFK\
       oAi1cM-_cuL1JWwOK5SsC7FKg5YJZdZPJ53RkFUusZPrhcWsZMsOFXJmgOjeV9bU\
       WA1npKEJt7nDeU9EGbICVel-RChriHe1tcx4OFgUCrCBvEpJl9d0am5jqwYQB-Wm\
       wVZ3IFVHM2c5NCb_MHhknJsaCqrSMmEUJ7XBpTWbdUlMNMMiq9Pcd2WwvMyoZmNa\
       c_xKmk5VxkBqorWUZ3ieVwcGYt7cZO2mvJwilCccsz6TTIZnuymJU57-J510EbVf\
       GXSBN3_BCpfwHAAqV-rZab5oWPFeYQikjAHieblCgN7bSKl6U-NCpoaPA-n1Q3jM\
       Y-vzFy4iaM8ThfoXdzXQo0oLCvyOZ4aqlv4EqYQRFh51RN6Jkyk5eqUUaHmaAV_y\
       yj7wBEkZNIDWNOy7ZAunaDl5tXFpUaPmHLQ4RQV1fCA8Y27gQ_4nOY2zdHhnq12W\
       OrvNN-DrdGI0ShpNWzARMtM6yiDXUV2yR_b6KTDyq0YyMzQCHBQhscrXCN2QxXd4\
       hHj-gjZzoJlim6XybGlrG6EaMkvIKfwuhZ7oxRTuC3hGJBSkMptQNg3Th4luol-F\
       l7WepM0vOYOVyYdRANeszJ6WTKZJCtzUhPcSBzeImXaDqNeCAt9jIBXpoJX6m8RV\
       iM4bW8YgtR6vK2ceNW5yWCAfOA9NmiBDAhFaMNTnueistr2eEJhzFZ2wJsT1MG-v\
       G2EIyuUNBqwlNjVvR4vfEAWOmeBuA5v7By3ycsOMFv2hk2eGssIzmE86ZOj5Oj11\
       QWFPRrSMx5zLdDu0ep_pPCYNUicStcDtIvy-pfJ2uEdBoJ5hdE9duIGZOlTeozIW\
       deEcBrv-sEJmKk7hNeOSBpVpAlYDTDTVpvOik-mJAR_hbNnfCY55sFD7C-zxOfrj\
       QdYwWLDSSH5mV4IQKzseJ8x1w5cbWWzbUqF2pNZBDEAjSpiqqVxgOAikaOwzMaWA\
       ERNOeX6NFYkmga2nREl5t46woTvbqBTSxBMOxcS3KCbzmTcqrLVfS9Cci5DaAdUj\
       ad8NzMQBoHywWIAFTA8Bl4p8cb7GqR9FcJYVsM6QlcjcGCZ5KhahgYOlBH5lw6bR\
       Mi48JzHrRWa1otXxmXprcLF4QiBKEZfKpHrSsszlCAKOKytlG7_xtNPRZ_UeZmeT\
       RiyHWVDCcQSzM2W9U_7hfGa-BErmW20CNBitqWZmEkmGRci2KxP7cJceuTXjpYAc\
       VWm1x4ZVN1_JtCisCU5egDoXIi8uFHwZigKhcBUBIS-AepvSKNdCA3HqeWzydKaR\
       zM6Hd1iEyiOQZdz4pcGDrkcsbOgiUpCHGM_OPeIAPlZ8DqRjh6Wxa8O8YwyrfJZs\
       6vLUcAjW-Jn5AaNpQFWU_VdbhTDQ\",\
     \"priv\": \"q_aDEMZpRAjbiqHwO23vKcgImYieSqUsCK7wWZEsq8Y\"\
    }";

    let jwe = "\
    {\
     \"protected\": \"eyJhbGciOiJIUEtFLTktS0UiLCJraWQiOiJJOFRIbzFLb0FxOU9H\
       OTZjSlR5azJXRjhhYlpxYjNrS0tIZ2RmYWpIVWI4IiwiZW5jIjoiQTI1NkdDTSIs\
       ImVrIjoiVHd6VWlPTlprbjNvSEl3RU1BX3FXbUtRU1UzNndNOEl6NUItMzFzdEp1\
       dV9BV3lfTDFSU0xxQkZtQmNlOEotY25hUVhSczk0eVRIT1d2Z1hDMlVuektZdUQy\
       ay0wOERaU2xUb05nZldPaWl6UEV3a2FRQ2dEcFZlZkh2NklTWkctbzRoS3ZrZ2Zm\
       VkxiQTNjdUhNOW14d1VKdTJGUWdLVjU2TUhQZzJIbDBLQm9ydXlQMGU4SUg3SW45\
       RDV5V2R1WjR6SDJjM1lac3hnSXZMSzY1SU9nSVNvbDFEOHZ2M1k2YnptS0tUQlI1\
       MHZrZ3oyZ3JESVNTMjE5Yl9qM01FRWFXeWdZNFNxQ2x1S2lzN2lkWll1SzM0d0Fi\
       Ym1MT0tUWGhVNmxGajV1Nml3eTJLX1MweFJVS29kZmlzU24zOC1hRlREcEtSVEN4\
       Wk55WFNSYWNHOXBMNnE2Q3h6UGZ4U2hHSXpjT2JTYm9oREdTdklnRHAybW1POFV1\
       RGNfU18tR1lDN2tyaEpZNk9YRDBsNzR1OE5KQ2lOVGU3LXhPWlNnZVoyNVBiWm9F\
       ZXc5b0VINVhFZy0tV3MyZE5uTEpvdEFQaXN2NkNDZVVXQjFESENVUXpqSnNZTThf\
       aFpKZ0R3RmZydzExOEZwaWJVOFlDd1lNUEF4THpzcTJjLTN0MG00ZnJEcFN0RWNn\
       VHRSM2FnaFlyYW5zTHJmcmxKUkIzTmZpcmpnMFRYdjBEV1ZzM18wRUdqNDNDOWdG\
       MWRiSXFyTmVpYlBVTGRCRVdZNjR2Uk1IOWJBSGlzTDE0NlQ1RlBuWTRiTzFhTldC\
       NU9tZXJ6OXBGb2Fhcm9McDl0a1k1Z0NqREhvdmNORUFqNnBNVHhFa2tJMDhSRHlJ\
       SkdqRHc2Yi1ObGZsQldpSEZTQjdtZzJ0RUVuZGhjNmFRcmJkU2dUQ3liSnVfV0xB\
       UDlQcEVoeDlqUG9vWm5tVGdXVWtVNHdtUXd0WHk4RzhVc3pMbXduWHpwck5mZF9J\
       RVg5b1ZQQml5VDFZejFoQnJhMnVpWFZQWXM4ZGdlUWdKYnJIaWVzVnRzNlpuMGxI\
       OVl3c2J3QjZTNGlkd2J0UWZEVTliVU4tUzNrRWZnWkJZVEFBS1Z0eS1Eam1tMEZr\
       TTktTW9zUVNyNjVOM1NueEtoYVVNbHU0U3VPUG53bVMzVXRaMDZFQXZXSWQtNEoz\
       RkY0Z3B0RXR4czMxY3JEOF90eG9ydGpnR2FUV0o5dmdrZTMxeC1VUmlGb2hobUlM\
       SmtHYjJ2UC04dmYxOHhOWGZmR20xeHZDR2dESXJya0V4YXJRSlBDLVdRbzdhaVcx\
       NkRpc1JfZHQzRGVGeEdZTUt6S0ZGLUJmYWJ6bGFNRE5aMjhTeTdzUkRPbllpQklk\
       ODNRS2FGSXNKZjMxOEZvV0JqSVRqUmtjbnRPNXBsM0FpRUNFTVhfUU9tRXVOamdL\
       aXNlNmZIYW1XYkZoOUhRdEZUZFJmRE5QMWxxUTFpSnpTSmhIMlVkMC1VMGFoZ2dr\
       MFdOLTZpWnhDSy1oOHQ5WlY2UFMtV0oxU3ZDeTkzaHBqWEV6LVA0RTV5VHhlSFd6\
       ZVB5eUxWQzhqazFxOGZhc3FqRC1HZC1tMW9peDdIOHpOX19GblB0UTNrNFdWeEs2\
       N1hsX0NpRTJnZjRsZ2FFclZCMDI0czI0SUtZRjVwNEZZdTluaGEwVDJuMkVTMU11\
       RmR4Zk9pajdMN3dORGxLSjdXWTBUNnUzdGtMdnBKWTBxNS12NldQYk55dVBlbHdr\
       cGxlZlJocFkxNk5UY2RacGozSlVSU0VWN3pjNzlLTTNkNmR6QzNEb3FZMWNlUlhS\
       VUluRDZmY1lDVHRXUVRqd1dXRjVib25uVWIzcktzeTRxcDBqRHZuR2NPRG9NVVhk\
       cm81Uzd4WWJ6di1aSTIyTzBWS1NDbGE1N3VzV0VqQzNxM2JvUHNobm90emE1X042\
       clFuOVQxOWJSWVF3In0\",\
     \"aad\": \"VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc\",\
     \"iv\": \"d8CFuwBEVbiI_nK7\",\
     \"ciphertext\": \"kmsiEt2hnihtuOyfGiFAs26cHoVya0vXhz62N6vmF4NnZP879ES\
       3YkengaFdFYG3l16-N7GVar6OR0h-atBeDoMeGNv7QHLE9Pky5arS4kaL4y7j9Bc\
       ffzA1Lq-Hx0cQzgvWu7c9xkOXDb6zS0liTxV6-ZMFHHdHdAd5ErMvQNtUwh8rvG1\
       APw6QMrzb3SGUsmlTWE4-IMgq4KRKKNHHsdztLynzDcskM0yyASkO0giKYcp85uz\
       Z3WYwnm5LOOen06Fi1Kj-U9Hd0JmIVsy58mNnCZSeEfLdIGyP3HvLqj4ngp_OvNu\
       BKEp12OBbouXpJ4xuPla9FdgLoF3Foiw2GRhoqtYWSYuu4oRgmlXYOuSB\",\
    \"tag\": \"l7BtLt_8bQpsUK0NS-G5Gg\",\
    \"encrypted_key\": \"hEaoX4fNiWQ-xb_y31sERZsttys1fGKexhdYll0PkJDtNclb\
       -M9rmeB7xQypVLaM\"\
    }";

    let key : JwkHPKE = serde_json::from_str(jtk).unwrap();
    let jwe: Jwe = serde_json::from_str(jwe).unwrap();
    
    let protected_header: ProtectedHeader = serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap()).unwrap();

    println! ( "protected={:?}", String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap()));

    assert_eq!(protected_header.alg.unwrap(), "HPKE-9-KE");
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
    let (_encapsulator, decapsulator) = HPKE9MlKem768X25519Aes256::derive_pair_from_seed(&key.priv2).unwrap();
    let cek = decapsulator.single_shot_open(GenericArray::from_slice(&encapsulated_key), &recipient_structure, Payload{msg: &encrypted_key, aad: &[] }, None).unwrap();

    let decryptor = aes_gcm::Aes256Gcm::new(&Array::try_from(cek.as_slice()).unwrap());
    decryptor.decrypt_inout_detached(&iv.unwrap().as_slice().try_into().unwrap(), 
        &aad, InOutBuf::from(buffer.as_mut_slice()), 
        &tag.unwrap().as_slice().try_into().unwrap()).unwrap();

    assert_eq! ( buffer, "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".as_bytes());
}




// https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-pq-pqt/00

#[test]
fn test_draft_ietf_jose_hpke_pq_pqt_a_5 ()
{
    let jtk = "\
    {\
     \"kty\": \"AKP\",\
     \"alg\": \"HPKE-10\",\
     \"kid\": \"EkIcXLM8dkXQX6mzrxYWNBY8lndA5H3H-v8TfiSDLfI\",
     \"pub\": \"1KUYqsq90ghiwoFuSJjL1qKhZhRQujGf6cXJtSRSJoShpMyQGMdsu-eTJT\
       E6FnZeUQNtWyNfsRAjzQqYgCvKB9MWZddwzkYlCqRSXlcSHmgQCLkj9_TIJZipHI\
       XL1km4_2nGOIQ80PCbxscLN-iyKKt9ikJt1Ks95aa_PSwRnum14MVuHIyZu5wAQx\
       PNTjw9S3EnI0ODyDaPaVG5zHqIB-mW83I6WfJUFQRErfRHjTwWhztsYLNkldjHMZ\
       YKxAiwouemzdymoIoBxaebXIyLnHsAycKP3NByWaxMXrEpdJMGQveDwbW1sXOffA\
       ulTzw7boeHBdQcGINzg7xiIXcgYeq95KmqbNqKMkZNFiA5wFpOjoy1kUE9snCwVs\
       V-I_dUrWckargyJNUONoRMOCox4cuziEUU3WkBK9pOBKV1WjrL0kBqBZUy2DhsmJ\
       LG6QjJLng4M6S4AxAmCwp_2zNjFGaMbLZCoKqPt-FGe_uXyAVqoYeZ2jAfWgQubr\
       RAl3NVd4RzAnQh4hp4gPU_t9mwS7sD1kd3-zm0sCiqRedvNGag59JDFAIxuUaw-X\
       rMyVx6dZG5xfOnaUE8ivuZ64iPQ9asASugUFVJtuQgD7pONlw0cUQq2-qVV-QTS3\
       SG_Agdn-SDhqe8ixVrqQI0TYmFVAquRniDgEx68NM4jmyPvwuEQeN10piAj9w7jO\
       dF98dutkd6UsQGpPcgXcsCRXrN9uSLpVQCJUUzFoG3SBcuUEhh7DOr6mAcG0Zae0\
       c9E5e2qTZ6bUU3E2KZZXub-xcZj7oGSspwgrG2ITd-xzi6aexu7guYMMaP4ek3PE\
       hjUFwV5HgtzNSgp9SOQEAPlYJs8mCpE5tNsYquJ0Q3CXYa6uqe5SKYY8MOpmkpua\
       jOmIQEbvUjmJQxjSQxPXcDP0a0ucdbG0k0kshqrPAUWvSoLSjAVxAdgyxe5pdXIC\
       krSjs0LuG7fac0gctlw9RIurq36EF4EitsM0WhAeubkmEd7ghIB_FImfQKx7JaJs\
       cx0taYAehRD3lN3dA8m-NNd2JkX2DBXmQyKqh1JslcaCHNYaco5rlRqvpwR0t94_\
       nNbklO5oAy25ZcJ2iaAiwAkPSWptfMRAM1P_TMoTFTv6R-qKAexgqtKYBK5_aJKp\
       GjCri4GSkwv1RPeXC3mrOJNAJ_8_jNl1yVjVVVh9lDSTQGOrtYWlmHA9jGATRK3e\
       so_DO5ONWRytaY_awbxLJ3ZeSttLZEl3Jj79kd1LigAXFmLiS5fNxiqElcjugb3W\
       x2dNPEhVlc2dI06Nm4nnfIEUZDwzkfDcU1-dJV0PcUCbAbPyoraEqVSGJwMVFkt5\
       a9QqqUXKY03hJsTaqEukgM0rYoPlEJ_UuqRptoGFZBWdSct2pEI7muOZA0licZpu\
       Yqx4jGCAkjS_xuaFKjieExA1IGySoEX5ETuREZTtNdp9hDKyJQ76wVcoVqlniEHe\
       UTSdxgTIEGM3NLacqxHFVAmgURfAojo2UCx4sXXdK47RtBuQiBf5Z-0hx2DDqvgk\
       TOKzy5trEJ9MhvKctYsYRWQsWz5ly0WTAgUeLPWYWkLXxi5BYAF2KqF2yCatyQ_F\
       QZO7mwCZUB5ZutKQcxAOAcm3JGQRsDL3cG2MBlH4UkOihSUNsbsrJ3p9i6HEFc8I\
       VmiViuBtEZbdFZ4wKD1Jqah3ghkjtHbhwLdME4ZQKs5jJZvjGFBsGZG0KCYGKbf9\
       QQ8Ooc-PNjyOqzo2k2y-ETtMCos6KdcnGbyrEBVKk2rKLJuaDF_CQ9q0YQdsQ70V\
       aBjeckNGLL22OvhiVN7jbL1kJ8bubIYeymm1KyLRcT0xmpDDgYtvAsygUdQykKbt\
       SmOxhHZrcIFeKazWWe6qcSZCOML0hszyw16MGUiLtVfEAvp8gzrGWQFCA6aDhrnS\
       s8YDMAz5Yoflp2wai8H7gC27ltycEpVsWz9oBhQPcmq9C6h_kX7RqfrtusXPBai1\
       pGXBIz_tu9V6ETzgszMUFOFdoKxscc5JcNWgWRaayYDBy08VenbQggLsOd_BsJ8k\
       VV2fwnIp4dGUmthqqjVkrGtl1OKCYX5_wb8D6mCByPQ_BsXIMEJqvQYJp8bSZ0Bp\
       3NUvY7EBwNvM1gfMiOw_pwcXoglaZNgzWLi_VBzXIY9lcM4qjigOlj9JyfbYRGPk\
       TJ5Gj4Taj57OC-wIVoeofByZ5tLATYBKFPwjA6SlRhI8j4EiKN\",\
     \"priv\": \"Ru9DwxiJ7BdWBh82FsXaAPPR4s5MZoadKL9y2wGmino\"\
    }";

    let jwe = "\
    {\
     \"protected\": \"eyJhbGciOiJIUEtFLTEwIiwia2lkIjoiRWtJY1hMTThka1hRWDZt\
       enJ4WVdOQlk4bG5kQTVIM0gtdjhUZmlTRExmSSJ9\",\
     \"aad\": \"VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc\",\
     \"encrypted_key\": \"PqSkdKSW75FL3sRXdax8xJP8rcRgzVg3pvPe5diLa2U7Zq5r\
       klP-pVqcS_4YmoS132XKT-AFp3Ft2qcWu10h2vvFSoCLH1-6IKIIE8xYHe8zFg09\
       mgOcLhevHKPnQ2d6KscghZLUJjeN3KmFRS8Px2QmnttXHl_aCkcWC8ztu70fHA0f\
       R9miNtjeP92J69aXXBjzqYvPn7ZIapiYUXTQaLvMQNiMOwMv7g5DYY7mFTBh9nWy\
       Pmxv-WrOKGsd9-Bo_farLI64EIgkAogMKA7Xda6v1gCu6ne6nQoP3Q9YLENSDkfg\
       Bbj0FBbAehOLOEGkkhCB9qX0FvicV98CBXwI_42bYar3v-My_g5-elG5v6OqdMB4\
       foD8cwo1QG4YB7jHwqrRBHp8Je5lWIHhIUjmwrKNM7_kwp9phQ4Ix7SUX8nEIhXA\
       wwaNmlEzcxm5VdGlts1SPtqtOfRmmRSpwJVArA50tURKaMsrpx8rLJKkJEpyUWm_\
       4O_1U-7fQXCfURH0LVPPePi7wg-AYizp5zAGJPTZSBqM89imBiC-a0jeyPJBgm-Z\
       DD-kD2_Q5JnTUMWTm3v0oPp0gYW3eO-rCjLebcHq9XQInKq_wgm3ccCkjuWvsHUy\
       Wsw6gQDEqljNSCyWIHS4RJospOwuJ1ruw1sY0mVzvpK9q7AMFJ7_8WRAgKe6pokS\
       Q-3J-stoVjNaT8T9cW8zbm1_2y5epgDzPlI1UFVXWG3U6VB7fQAiL5w7HUgTB-2G\
       QMxRURz951l0jLvi7SkZGFag8F3BBrH_H_x9kt9aVj6QFuQHK-gCK5OAbgeGNLlE\
       uG4aVGz6EHvc58gXr7AsXr_aSscewPPSNy06kQnh8Q1xJIuxvybQANSKUk79ueUz\
       oOPBL0Inkyoym-nAI25gpM1cDFUzbmOjrWOaSLHz8CojJckAzuh25IROCzHhMNSa\
       -y6_mFt2htSFUQAMrZ6Rx3kq4KK2MlK61VLVYKUHmvMA8SuiYCgQVdKzoG2sYvPj\
       QLFE4eNKaPXA6wmrOheu_-0pLB4ysflgpCkEH3hW7xuNbMGgkkg95ljQ5xJCSl3Y\
       tGyCKYAyU4wgLX5t8ojnke8eCyaS0Pz70dr5j5viS3s0CzNh37gAEq-ez9_TeW43\
       aUBHp4raYtb-oedm7lGl0FuhgCU0DkzC9pH30gL7SRXM17eLGO9PBG2hwMjtb2oK\
       YScDiObG_16sFSOI2_jhWjv7qfz7IFX3Jr91MfIB8foQPBgfy0TFPGjoOb41uquC\
       5f2qJYIDkne66XA0cvxrSfQ3070a4DeNrT0l7q6BIR-CbX186OxuCB5r790vyQAT\
       5WyXf9OXkC9woysfEf0WkHvEme9-LQTeZJp_ZRXaJSbOJZslF80NaTY4t4IPfHDD\
       chntXHyvttJMJSlaJMKjXYOyQOr2JqIDJ-95aoDQdg7Up8jR4MpAL9pbmbh_7AmN\
       VGjN9S0u2aszJfUDNqg1LL1CD9WqDg6DqHUWkVv0XZ20tf1fcOkDuc9EHPjyyjNZ\
       7kTsrRHqp49vsRayY6jkKJPndLtZQTGiiKsdZEavlGo5XiBeNrr0OWY-YheDQMHx\
       K2aQH0GxQbigqriclmQiaaKn3LTv7MtkdSo-8QaZBgO6tF60i0gKtrPNkHcyYQic\
       vZj_RIZGh0-VfA_GutRs9ozqSzajcbmjoZl50rsLK5MUOXHGztEi2hd-z9rF62Yp\
       YLlpnF7dSlsc11LlSuxEjiorshM5F3EqolNsnjHCEA2XywYfgYE7cDHD07cvjCC_\
       Fj7mlWSFhE4pyX-jOEtSAD9c-iEUSVXcScjeApwg9_c7hYC3njVQtvkI7qh7bA8w\
       _fgMiwrqq25EJEw3pw1z59uoEhB5txVzzyfZiv9xvm3S1sYMC_UL55nCad2KwjaE\
       avl2NGua6WBbHlIUQ2EhwmwzCUWvvbk53c6WoJtsEWP2h6CNN5y1mi9_7HSrIU6K\
       VQXC32jUsQ542Xv_eVzGz6uaxRsBK-QE7CovOhUpFHR9lf4gmJaox5GwhImq6bes\
       AmBy6g-3PwpwxpYAXP3qRefX9jngLfJXc25eQvpwmNjKQMnoHrs9C1pZGFsE1r99\
       wKUcahH7bIvQDk4GKFcL4eoUqlij1RlP16c2G1LImEWOBXWoqubqVqfU6OvH8Njq\
       YKc7deIHGfrpu9fQCy0l9En-bLXwCAFklKXjeVmmvEilbaucHuvznrgZYexz\",\
     \"ciphertext\": \"9kfFny-tTRwymjXj75P84eWObnYaSy3BpPcM4Duh-TMYi2ZjKUD\
       ogtdcCwN92Whe-O8RCBcEy31EMcair8LuViyVmB1MTe2EmjZAf-jAxy4VY5nKU41\
       dP3KB3TRNeN-6Yb8XmGa2jW7pFHab8lTz4_LiepU19MVN-J4L4aKrd0fHt87VQLH\
       H6swyz-NdheA9cvVQWcV-cOaoh0gfED9mekWhF3iLKVfTeJjs7R_ZbcmKnfx-rwc\
       Pcp0bfQlOwqpjygmjyC27i_WKX6VAzwf0onjH1mgWUU8VuND53DzSgjnMvc8QNhD\
       3VoJyAM55LF-sb83nH_ShtyiQCVl5r66uZCXkbMMVgySw1EBsfmLJUZzuiZtr9U8\
       ipA94iU9xM9zIPw\"\
    }";

    let key : JwkHPKE = serde_json::from_str(jtk).unwrap();
    let jwe: Jwe = serde_json::from_str(jwe).unwrap();
    
    let protected_header: ProtectedHeader = serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap()).unwrap();

    assert_eq!(protected_header.alg.unwrap(), "HPKE-10");
    assert_eq!(protected_header.kid.unwrap(), key.kid);

    let encapsulated_key = &jwe.encrypted_key.unwrap(); //protected_header.alg; //&BASE64_URL_SAFE_NO_PAD.decode(payload_json["recipients"][0]["header"]["ek"].as_str().unwrap()).unwrap();

    let aad = [jwe.protected.as_bytes(), b".", jwe.aad.unwrap().as_bytes()].concat();

    //let decapsulator = HPKE8MlKem768P256ChaCha20Poly1305::decryptor_from_slice(&key.priv2).unwrap();
    let (_encapsulator, decapsulator) = HPKE10MlKem768P384Aes256::derive_pair_from_seed(&key.priv2).unwrap();
    let plaintext = decapsulator.single_shot_open(&GenericArray::from_slice(&encapsulated_key), &[], Payload{msg: &jwe.ciphertext, aad: &aad }, None).unwrap();

    println! ( "{}", String::from_utf8(plaintext.clone()).unwrap());
    //assert_eq! ( plaintext, b"You can trust us to stick with you through thick and thin-to the bitter end. And you can trust us to keep any secret of yours-closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.");
    assert_eq! ( plaintext, "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".as_bytes());
}



// https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-pq-pqt/00
#[test]
fn test_draft_ietf_jose_hpke_pq_pqt_a_6 ()
{
    let jtk = "\
    {\
     \"kty\": \"AKP\",\
     \"alg\": \"HPKE-10-KE\",\
     \"kid\": \"UVzPOxx3jthVCg56hBO353HIP_hObFaFrI-pf3maRr4\",\
     \"pub\": \"9ALOt9bAhXcL6nyuwPy-cqzMgPbADhIWe-g3IFA6fFUeidZ_SDun5zbISB\
       E1i5YKT9STKCBYVlCUZlAo8lnMtbc73bNy3DNkQvii6TptYNmPTXmwauN5qsUFM5\
       ouqjFtwBhQTFkVR1i5YuOynqhC4fp5Z3lcEesDFRQxhwGJlNgxiNGWkNKkeWBVEL\
       xU4yUPHUt366Z5_8eFxGxpRALKxrfNamuU5zeokAxmLAsVKZkwfIISxQV6EgQ0JC\
       gApfRXp1gaHWk_5hBrD6WKlwagDFWO9npfrhFtHHNCm5U_FdTNheampphf0LJpdO\
       LL2BGZWtqYn7xDuegxEJCBiWoBoEl4wpMcz4kqIDchWzTAvaCLtXvB0FOYlKqGY_\
       MosDMIfYRpfkxlTdKDxMxWC_YZdTQCW9aGZqu-gqw5RCmwkzUUxKrMW8lVWbRXHs\
       Ga1WQmMTJlTLGGRnBP54YwisvJp3tRvzy3y-JXDadAxeK5u9UJIMZLvgmAs9cC3x\
       t79YahZbo8FzIRCQIpUJsh7uC7VaG7f4KzgDZSEIaIqMRKY7uTUvasmiZbtoBMU_\
       GPrwZ0XmFNi3R5bua0ieBu0RWducQaqrlQAPYVfRkuFHkPsMmcFToVmQtq4YlhE3\
       hsSpdVIVs-PEGeKcciBDtJEIkJzxt2tsDPfagb7DlQQmqMsTg5d9K-2FYFUny6n3\
       sXL3wdffoM2kG_XLwmpPERyxOi2uq_rYYazOHBWPxCdPg-bBkWy4uLOqp81vSHx0\
       R-JpavAMEfs0dzLAFYo7a8BEpUcmNo4cciVsoOV7lUkqNskhXCtSeoSKw8zDxCo0\
       ye1cMGNuogZnKNCPhGUSo9igeAcGqkHofMS3B4SJcnHYMMD0QJ7eDE_Hh0cMsT54\
       aueuuJ8PauLHuT4mokG1s2exZP3uaXG1BmPMtpARyCJTNax2Qd1OVqqxukummV33\
       Ja8pdC2zULU_XATzZjBdiQZ6e3R3vLQgtH5vpvnzBHvbRHAbKJdQS_szVihbeUxg\
       EdGSwtcgHNQMMamedO3qmHYsRqc9lPo-W34_CUhyDHq6K8n0kgcxFBI-RmM_iE8R\
       IyfrulMyNPXdnJ1dJociljcSUyjpZIRgE5BCeS7sGp1ZJ6c8w7JhiSDEWTl2OUb9\
       GsbXNLo6PMrIBWkgl_A5EpMipqwgLQPHTCTmIJF0usHcYnMtECT7U1dPQVKgSvNu\
       saXldU5miARrvOn0osBnk_uzPBayCi8DU7chRXMnoMSQlhOmeNIwS6d9RM64HI0o\
       AcwAAFkYyV-pMvqRuz4Ax-EWlHubrGDvbMWTwMNpZOhzNhwDIslaggOoqHqZMego\
       zO4qkjcueLDPBBZTamjdeShbkQfvcSRix_fdphv6sdnXyN7Umr9kxA_3dLS4m0AF\
       uPBACn_Sohc-gLwRSHLueo3vut9VUbltNXTyQSHBzC_TgYVtCBPLKWlSvGhNw5eX\
       iARYI659l2ObeD-8JQFjwN1fEcesBjfXWJKOhJoYbC2dUO6fLKolxt72UU5ZWcdw\
       Yjq9W1WEO8z6C1s_QqaDOrKCtuLRCO03lcXLIkKHkwAaspTVw3nhB8_6kn1heCfj\
       afA1lds2dx-4zBechsq2E7l6GnobhnhUp0-HQXuGeTSiO4aamm0tou3-inXpNzuX\
       sR6CYPG2q1RYAlgWoLJAMijgTMRNxtvGSPg1d52qxDXBQIpJOTScQf3fONnHBb5G\
       ZHTmiQ-BW9zyhPM5KUEoZ07nx_beEhzrtMX8VZOJe5swcdalMC8MejzOYvLhh7jd\
       FYkeIbbgkxMBMZEkHHtfijFgC0T7qCLTkQAtXA6wKZLgjHwxsWDjsTDuuXglDFxx\
       hv_dJNUXLD6XQe4vkDxnEI3xFBzVmoZ6VsRmwKdZVo3WylBShYO1h8YBaT8iARj8\
       x6NekIPsaFFbs_KOhLR_ttA7ETiGCrn_U_E4UFjCqyGcZPEFvPc7YNcyMi60ujwI\
       h1pWQEIDG8I5qsZwMPRXY1MXY_ipyOVmE2sxUbhWGDrHgxl7Rm0swGBmY8JdBH_d\
       Z7IqQUmpfcFmsztkfIoV36-la8UmqjSN56xacvlWK6Wwj7RTcE5jkstUY_rBwX1k\
       BU8IITnA8irT2vsR028wS2lsVFIVcmlGloIbCU6Oazzm3MujqBobbHMKqXnv9Op4\
       37pCNlilyNtAXS_6ZEcLdUIe3wTTxAd5idwaPiZKy9o3KyjiWZ\",\
     \"priv\": \"uSDPZnwwnLpJ18lwAGHj75e-fGohW7zOWhAG-7DGLis\"\
    }";

    let jwe = "\
    {\
     \"protected\": \"eyJhbGciOiJIUEtFLTEwLUtFIiwia2lkIjoiVVZ6UE94eDNqdGhW\
       Q2c1NmhCTzM1M0hJUF9oT2JGYUZySS1wZjNtYVJyNCIsImVuYyI6IkEyNTZHQ00i\
       LCJlayI6Inp3aHhKWTNHNmlqSW82TDJCMk55b3lpT0JVY1FlVVE0bTYtZlFVTHR2\
       eGFHVDh5T0k2SWFsNUlaa2pxSnZIVlZ4NEgzY0cydXhxRFZ4dXVOQlotTjBuWW9P\
       SnotQnJjTnh0dnRUMHlldXo0dE44QmlIVm05R2dFNGtGR2JGTk1FeUNfbm1vbDZv\
       Y0xmY2NWMXJCUGxvQV8yZE1BVFpJNWJlWlFpTjlKTmw2UWktSmdZbHlHTHlFX0Nt\
       ZnhXWXhVRjBTVzlhS3NmaEpVUlJRVDVlb1FiMURNTm9sZi1EQlBlMkh2cWZxS25J\
       alU2T1JBb2ZSbThEdEJFOEFaTmZwRUJWTUZYTU9JcWFYVnV3OHdCWkhXVkRKQk5V\
       OU1NSUtlUFBqRW1UT3F3QVFCZmp1eC1ES1dYc0J4S2xmREFyYUV4UUtVUWI1LWVH\
       Sjk5RTRJLVFGd1dRSDdWYVFRRWgwQ1lXNkU4b3JFeXpzQXc0ZlIza2wzbGJyVmc0\
       Z1R1NnNpX2lnaXZYV05EOUNXU3BXNy1FSzE2amlQQUtlaEQ1c2w2eUt5RnZLc3R3\
       cUZVcWVidlBPb3EyTDRaWGxnX2VGcTdnYjluSkV5eUFvT0NPSEVJRmViQlVFOHg0\
       ODJLWXJuMTlsQlEwWGtEdmhXRjBIV1BYdFpWN05fZVBFX0J5dk5zMlpqY21uaHNJ\
       Sm5ESUZHbHkxeGlZcVVvX1RPbkhzdjhXQzc1QmhZbmRGYkZsa2lKOGVZU21QU2hk\
       NkR5aGhzdnc0amR6MzN0TWUxdmlVUnI2VVB3TjFueUQ2OE9hWkl0OW5NQ2dERVJX\
       aUZENmN2eWRZU0tUdVBqaXR0ODFWX1JsYnItXzB6M0h4Z2F4dUNxWWhwR05GOEto\
       RENPUUdVc01OcURUQzdqeGZYejRiWUZxS2ZldGxrTWdsUVRtaEpmaGdSUHpUNC15\
       dzMxR3RWb3ZaRENGQmZ1N0dkRVVsM01zcVdCckI5aG9GdEpfdkI3V0liZ3lVblBh\
       S1JqZ09SeFhkLTNmQzF1bC1fS3RaWS04aDJRYmtsMlBibWc2NEtjNktQN0FRcVo4\
       UHA4U1BTY1AyR1dWVUJjY2NZUHJ3ejJWVzhLSXRBRFhhb0ltSkZJN05OX2xzM3V1\
       RnA5SnhkcjBpQmJhV1RrbjNUa2lLanNxVmVBd3ViMktqZWRhcGNYT1BkNzhCeGVX\
       dFJxcHVPVUJHU1hyVEVjYkJLdUxaS0ROOWtPV3RZRVJ4VThlZzU4QWJqWkN3UE82\
       aDJNN1VDNlRhMTlWQXdLcXZNQ3ZFNXhyNTl6bmlzY3I5cmhfUzRFU0RtZVlSd0U3\
       ODVUNmRnVTdWSV8wdGg0NjJETDhxVVQtNWs0dlloVW9xbDZRUkg2SWdLNGtKb2FK\
       LUFoTEpkclFiRnczaU1KcUF3b0ZRbzF5MHduelVOUk9nU3hrSVJsd2ZaZnM5aDg3\
       aTVWRzhkQW1Yam50ZnZMbXU2WWd0Q3FsdlpQOWFpQ09jbHlPMnp0MlpZdmhqdVJu\
       T24wb0ZTVF9YNEdfZFlQSl9nbURLWFJlLXhDb19peV82eERVYmhfVExHc3EwNkpI\
       OHFBU3p6UWZRX1VONEVLN3FreEQ0S0lqaGQxQXZlX0NDNGtUWTF2UE9MR1NMX3Ns\
       YU9EdVBGbjM1d3pwU1Q3LUF1blRBdGZwbFBTNl84bXpjUGtudmZ1VUg5b1BMTVp0\
       RVk5UFlSNVBDdmh4ejF2WlVPaHAzdjFIX3B6N1gxTFQ3UWw4OHU2OEhOOF9VYUdi\
       MHpna2ViNGVOSW9ZZFdDdEFncDl4SUVwemJDSTU5UzZzTnN6UkZWQnVOOENLZm9j\
       eDM3dE83Z2Rzd25fMkFyQUpsTTN1TTZXM2hVTHFKSFl1TmRCa0cxTXphVjktZThu\
       MUduUk5rVGFycEIzeUIyd24zdi1ScDdmSzBBczJfSmFWdDFReFkwTTlDWWZsbV9B\
       YVlyRnBXMzcxb2pGTFlhZ2pLdXR5YzhyWENReElfWDBnVUgzSVBFc016ZGcwSm5z\
       Y08zN2dQLUVWc1kwYlU3bnVSanZWdE43Z0NtN2JYNTlnQ2FzZ0pRaTdBNU9DaDA1\
       N2gtSnZMVjllaGJnX1Fxb3h5VFJIQURGaGpXQ3o3aGt2Nk9tTE9TWVRjUFFwRUJB\
       cE10NkpLSVpYNktFRkhCTEI4RTZsSjRyYU9VQTlLRDU3akxpQmdZNGlXall5clg5\
       QkZhNFFteXJsZV9uaFh4aG9qZ3EwbVVGb0VKVURFQlZYSGFUTnhBQ3c1T2lJUmpu\
       MVItdThqakppVm9rYnhEa3pxdTBqVzFsX29xUW9WdVVRN2QzNWU4TndfcWppQzdM\
       NDBfUUdDTGJUMlRxdWJzR1VMNF84bDYxeUVHdFFVWEpzTnpNUVpwblI1V0xmMGhX\
       UjhjeXdiM1poZExQeHVjVEZXYzhZWG9zRHp0MEM3UUs1MjcyX2l6djdwb2pkWWdS\
       Y3k2MlNTS0RqYXBwTG9NbFlMWjVqS0g1bXlETlI5a1hiTktIWDcyajlYQURGTVhi\
       RV8wZko1bkljbTJ0VHlLT3FxSmdvR1ZqUnZlTE1YNUZQdVRST19iQVUybFlWdXhB\
       ZXUtM0tuVzJ3dTROUHRIbjNPWHUtM0NMbFZQSjczR0s3aXRmXzlhTjVzdmduVnFO\
       d20yX2lXc1NndlJldThiY1JHRms4NU0zRGJHVXdlN0ozYXFYQ3Q3aV9KdVdRU0Ji\
       WE1ieTRSSFFTbVpxSFBqV1ZERWQxaTBHWjJZV0EzaWlYY0U2a3FTUGRmWE5BVF9S\
       UEpocFRjUTJrbWFrOTV4NVMtMVdvSjJXQ0NWdWEyODVnNFZaQ0x2Wmd1QjNESzJR\
       UGVQRGRkdHoxOVVaVGdvWmpZdjA0V0hwTXhLN0lyZ3llS1IwV01FbjdjWDBiQ0Q4\
       OTJjeE5FZXRhYmJNZFlYQ2tEcyJ9\",\
     \"aad\": \"VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc\",\
     \"iv\": \"QhIHZiO-gUr7ZkJU\",\
     \"ciphertext\": \"9ct3eSqXU0voatHvMht3bpOxfTEsFNcxgPHqJykMbQYsRzdgD5w\
       N4KpdUZ8OzxwI65OB6ifP3ekDEwqOybu8W8jlPlW-5O_Rpn7anpoYDKDw_Na6_gE\
       IsdJi89L_9N_3gh8v4dM8n4feY_jVmuWf2JLNrLuIaghtginwHzVeSctFF_anTP6\
       toPOAql9Nm2v4UYJlNoi56oN4jZKYSZoQq8l4Bhiw2I7IlU33_bhUOu7U8AcaEJ3\
       bemHgGY9grjv9E7zVk6VSsWx2kdmCMHc7uPHoT0akt-pzUBmbmJXq86z5BrWdfwP\
       i-Z1IZ_h86rShfB3hF8FKjCQrpQCCiAO3gWO6UBa_Uyse4ma0K5uqBQol\",\
    \"tag\": \"H9VOy57gURPVe2hxW6pq0Q\",\
    \"encrypted_key\": \"FF9SOzjoJxyoocqLxl7zsPeX7982LMT7kDpWdliwzPAQh4sW\
       KE_8VGvncRwTGS41\"\
    }";

    let key : JwkHPKE = serde_json::from_str(jtk).unwrap();
    let jwe: Jwe = serde_json::from_str(jwe).unwrap();
    
    let protected_header: ProtectedHeader = serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap()).unwrap();

    println! ( "protected={:?}", String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap()));

    assert_eq!(protected_header.alg.unwrap(), "HPKE-10-KE");
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
    let (_encapsulator, decapsulator) = HPKE10MlKem768P384Aes256::derive_pair_from_seed(&key.priv2).unwrap();
    let cek = decapsulator.single_shot_open(GenericArray::from_slice(&encapsulated_key), &recipient_structure, Payload{msg: &encrypted_key, aad: &[] }, None).unwrap();

    let decryptor = aes_gcm::Aes256Gcm::new(&Array::try_from(cek.as_slice()).unwrap());
    decryptor.decrypt_inout_detached(&iv.unwrap().as_slice().try_into().unwrap(), 
        &aad, InOutBuf::from(buffer.as_mut_slice()), 
        &tag.unwrap().as_slice().try_into().unwrap()).unwrap();

    assert_eq! ( buffer, "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".as_bytes());
}



#[test]
fn test_draft_ietf_jose_hpke_pq_pqt_a_7 ()
{
    let jtk = "\
    {\
     \"kty\": \"AKP\",\
     \"alg\": \"HPKE-12\",\
     \"kid\": \"jw8GWrYDUzjH0aZRXlCtcokQwI4elPLJKKulziQwsB4\",\
     \"pub\": \"2dmLwuO_9-eptid4KThePBhKHFBdOwVPc8lNjbeSGLOmFdmzR3yD_-ZucZ\
       grSHqacNVD_oES2ZCS9CEeFQyNgYQxrBRb1gQ8JYC9PmiNFWdbN-eixSaWsYaLTw\
       ekCiucwOhsSwSusRgMt0Ii2DyKl6m2J1fDgDCCevVhe8II0Axm2JaJZaNgftU9pL\
       E8QwAKY9tfotx3wzQRXdE61rmcEQOfIQiJr6TG-YSl_cERxbsJFryH1gmugWkjcF\
       Oje9NSiZfLa2mi_0s6MHpkAQhxm2EVaCfHM8fMsCpkBqKOgPTKkCGTG0A6RnKgA7\
       SclXi8P8kJupx46Km3ueR6KEGF2RtBt6SmFkceujZ3oWt7Toqtc1SBjFONk0GRuZ\
       ABZisiUhqXM9I_T7yagLhdQqOvsrIVllCfFOFHiJhPFEPLOAMyQUrCj7d1V8h-cr\
       AhypiQYQFFqSq309oeRqYGVHyPLEe5m_lvfxfFMSitRcFrmchO2ORCbZQTm-tioy\
       slu6UNDwYWarR0UmgJIPlfNLJ98XNO5LO3fjiz84hHC0nLnOqmD_O4kWEDXkBCPW\
       s_mzomlZKncZdiQDGXsucMUUhs-ySo_aqslswumfk45GsP_pUj51ROcVqgjzCSyd\
       tkaKN2nkolubGv4mvNAacz99oLKLzDbqAIqoRTAbGAJVywNpBuzFw_2gGiqSidtr\
       UmCJcuaihnoAB-dlpCLgcNUTATJ1RtClSbXpGW9XJQ9cQ003UwfVIp8owxEsFqgk\
       HEjRsDjJJ9sikq9AaSzoJ6q-mQSRcycAaM-OdwaohFsrEEtVRZ07C8UahelEMmZ2\
       qtEMEHpkEBiNAQ95l6mBjLFdXGKoOvBIu9oshYa3G_raBO4rg6F4kKkhO0h0u7us\
       KC8mWQedfJ3WtAmpiNwNJxCdRRjtdigjoVbRMkImVvJhaaI2KRQ3AYneWcAbRra3\
       aY3SkKjkMhPZp2NVqyd3XDUNAiFgHDOfvJMFOkz-VgWTlfMze2z8w3wPUtZpjH4b\
       QUtXslmVxUGwi1_Du6qHyin9xPO8Sv6eNKqthW9YwYiBjE79AHNJYx7nQ63IM9G9\
       RtF3GbWQtP9kye16Who5sZi9k-9BhOxwwXLeiqHOwPRFMGyQE5ySd9hOUSaNGajV\
       WZytWOmpt8RSrLnXY4moxAKZEGfhIFYIOVRImjtLGeEBZfRyVSYwfPLJnH5SDBBi\
       moltw1Uhx3HQBOd6FmuGsRViYu_UfKDxKscAgJB0FYS6FyoKxIeknPHpowlJdJdb\
       pMF9QIF2mNynddFEfGJHYldfBxyHQCIJaWxHwFTfYxeiKrtucnrCmm2wBWI3wntU\
       UrC5d1vGmLI_q6Vcd5sXiVm5ZvENddrPeInGaLYUgj6Nl5HiMhXjp7t2lLMRNNtk\
       oomRx0UgwsgQJx6LEC6_s0G6E4nXe52UVdkfsQzKpB7dmaxSkWWGupmgdBcXpyX9\
       yqYDqZiFyu3pbHo7VEAC0Lp1Oya1pCP6kONJZuDGRscQrObIuBmZwzj4B_CwSeu6\
       ZnJ4QYCR374LlG4VHMX9hIw7S-tp1j0QZb3ojmna67QydOt-M\",\
     \"priv\": \"oNrZa1bdAQtxbp26w5mcZgzw7fKR0WxEbpRhVH5tcPRQxzIk3Iiqt6p9F\
        n88pjYoaUmmlaNymuTk_ws1WgWd2g\"\
    }";

    let jwe = "\
    {\
     \"protected\": \"eyJhbGciOiJIUEtFLTEyIiwia2lkIjoianc4R1dyWURVempIMGFa\
       UlhsQ3Rjb2tRd0k0ZWxQTEpLS3VsemlRd3NCNCJ9\",\
     \"aad\": \"VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc\",\
     \"encrypted_key\": \"sq1TmK2Oa6_P7yp6eYYDAzYv1biKXQ9fO2zORNkdFAFOnTZT\
       KN4MvaESlHx-Bx75d9enCHMhkYtrGgvfpjTCH-XmrRp-UexBp2mKVo1C3LFOBZIn\
       oESOf33-1BhbM2X3M2j-mhm7i4VGIO60UrHeSaZgH2mAqSZgkHHP6y5WiPutwnAA\
       dP_SlpswWEZDPvwzvCNI-pvSaqW1rzUe8iDGHycTkpv6V1mKUaXIhaETVmNQFRXZ\
       IvkQDf6cVatOtkiBCsHLFUNpaSUjXJdwJBdDsqjbfa_TFJaqgy3vtOiRYOBtKDla\
       UWcI1osJXSCpkOfXB8halKlq42khbFf7nbDon4H0EJSGoKHvUw0LG8zVlPzw8_DY\
       s9XiYTpWAYeAX-mkJmX1FH8H8IgYR6APRsAzwagCGIUlCIbY6TKSRAENxAS1fy19\
       XVpne8ouZQ8lWVKIm9bqgRcin7T5lYQiG3lkGdqlN54LndxCWQWfC6fX66UDH1rG\
       tF09PC7i30NcyuteFBaVXPoSluaKYKOwFiQIxtL9MEVGEWazgJEdxvgoiZnCQCF5\
       RqinqYbFrKtgej-4Adck_uz6H4G2l35EGc8BfUhYOc_ddqs2nJcF6JPjj29ASvYZ\
       l4MjWpR11YEQPEXlSIK9aLIXgujxai7FJL_nhqSFm5AiAp3Bdszp_146vMoPaV3P\
       7d1C_WgLS8i5i_2qmzXn5KorN00g6Cd36VdRGQHftpr1X6vvQit7eLKf4jqQ2DIT\
       cXGJPqi4oZn0FHlQoTfBegmDnosVyaoYyrSPglCMBM7XtvjefhVTSsz7oQHclYUt\
       fGnCsPUh06nVJ51PdZA2SX20md97TH6RPq4dnn2GIebn3Hzc1JjuDkrkfRf_2NNd\
       THyv03IXGXjygigb6w2BRDYu_oPSLyDJ9MBvJAJv_f9JFOlqEiYD9LFwR_3rEJAv\
       QkEL6xA9DOF_3urdOrYwMAZ-Up1AqBxUzMJ8WVkbElwQKMe7o4gZ_AHV27NSWf78\
       kjGVNsCQoNMSGtrvx3eojYcfK3mFJUUBjnognrn23Dq5_mR2s64XdLcL5nJY0D5p\
       ulB90x094S04rb_6wO9OpfmdRlRbuh0O5LpNlmLYPpa_BZtwNwtmCNKsxRW-BrpO\
       y_kfOxpl2UaewqWjEIBvoIKqThfkqx9GiMEhCQTUKZR8cejvbWRWtVgJxJLTA0IW\
       3QyMU8_Gi9MXMG7NOrE0OspkRe_gAexc8sGO9O58qYbfSuqlTR7GHkLaUczi7yej\
       tYYGzjastPKFMYHOHsBYau2FgF6eNrFWVeE-bkNWrgs4sZycpIJEYktDvvODRZHG\
       -7TpFbLRyAOCcqBoQXnWcCMzjMmmecRi7yZepjAaslZuF7hGRGCMivDUVNQIEytC\
       -nigKVoi6Ya0pZ3yC4aVBFPPitRFKK15ktdh8T-g8Lk04_faM3LoZMCnLgU\",\
     \"ciphertext\": \"opqe-7Y8RSKoR6OAbqm0n0GuRQa0oLttHqH6RXRDR2dqgnn1P9a\
       5tpqnUAalwkyT9UUkvi5CPpZkFk-2rw9THiUMRNhP9TWcqmLF4iC9pzFJZWflW0A\
       sjTDU9SKe8JFFUgcLejw2v_pyRDcPB2zvMQxxlLfsXXggtntqT4DCPBI3rBMfTt_\
       V6RDEWKLFSseOF54zdIw6z-aBnhEOB5OW4seXHvCSVmdrH5B_vimGVciBZW86e2x\
       wix0PAIqg0CnFHMqarOLADeWfj2bBwUI1FtXi0YxwXOQEy-5hRch76wuQ01gQWUd\
       qLd-PPxfUWkGJukZ4XWifc0p6ho0SSLgkFERvpugQTqyi7G8fHlQMSjSIkRcVFXy\
       DBwXQUG7BhMTnrA\"\
    }";

    let key : JwkHPKE = serde_json::from_str(jtk).unwrap();
    let jwe: Jwe = serde_json::from_str(jwe).unwrap();
    
    let protected_header: ProtectedHeader = serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap()).unwrap();

    assert_eq!(protected_header.alg.unwrap(), "HPKE-12");
    assert_eq!(protected_header.kid.unwrap(), key.kid);

    let encapsulated_key = &jwe.encrypted_key.unwrap(); //protected_header.alg; //&BASE64_URL_SAFE_NO_PAD.decode(payload_json["recipients"][0]["header"]["ek"].as_str().unwrap()).unwrap();

    let aad = [jwe.protected.as_bytes(), b".", jwe.aad.unwrap().as_bytes()].concat();

    let decapsulator = HPKE12MlKem768Aes256::decryptor_from_slice(&key.priv2).unwrap();
    //let (_encapsulator, decapsulator) = HPKE10MlKem768P384Aes256::derive_pair_from_seed(&key.priv2).unwrap();
    let plaintext = decapsulator.single_shot_open(&GenericArray::from_slice(&encapsulated_key), &[], Payload{msg: &jwe.ciphertext, aad: &aad }, None).unwrap();

    println! ( "{}", String::from_utf8(plaintext.clone()).unwrap());
    //assert_eq! ( plaintext, b"You can trust us to stick with you through thick and thin-to the bitter end. And you can trust us to keep any secret of yours-closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.");
    assert_eq! ( plaintext, "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".as_bytes());
}


// https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-pq-pqt/00
#[test]
fn test_draft_ietf_jose_hpke_pq_pqt_a_9 ()
{
    let jtk = "\
    {\
     \"kty\": \"AKP\",\
     \"alg\": \"HPKE-13\",\
     \"kid\": \"wIKmf5ISyZZlOkqqjwW707KCxkqEc4cJg7fYFLBkr5o\",\
     \"pub\": \"59oD4empWTtMhOR7pGVyBEKEb5lttgUhITCq85eyJGpyZXa56wd-HfoHj9\
       MxM4pg4Se_iwmjBEZZv5UHbYpoUGKW-QFh5CGjCCuvtjIAofAShNEaBpQ2dBGnkX\
       eBGZhx_EPA3Fxv33tY9WAoUNVhEEa1sRuAwLI5dFe8ZRLDDCUoz9h1Axpa2pxP1P\
       lmj6gRtDayfAU9mvWZhhpwZ3ydbnIEjPFLgwwPYGUCYtNj87i4K4aHa2QcWlyJlS\
       OO0umCHFJbsEsNL0VNaQsieSWP_2FB90mYBuQsY5UCN1g8p-DFicWAAEtUE0uukY\
       e9X5u3z6y7A6Bb9HyAFhKH4TelarS7xSfBK6xxK6MpbGzP5YSBoZF8MBBeMNbLwN\
       SJ9dlMKYZmPIO7Z_Y4bjlnUzCsK-aC_sERbElaSzFiLImIwQp1IMxuC-igzqljtx\
       epYXCinRi8yhyiHNMuAlDJAcLL11uW7faXb2J3OdrFLrdKjwNYrOdMw8uZaexXkW\
       dCUlKV8CdJrBKKx3a6oJApUhM3lAolyquTeXeGx1AryyhGualBEPrFI3ROcgRHWI\
       FaCYFF7YZjkVB7CYKOVOpXWOdnHCSNOPMWWtGvVERXRbe0K6eeX0iXB_YxddByq3\
       IwCIczXwYA1luZjKjMXORjv_qVTzI7HPBFeVGdXIc5TxTARJR15lEEoLRIOPuzce\
       k2q-KlyyIzSqZqrHeereRhJHBPliMsJYGOAsR_NSLLxwDHWggO5mqxnxoNyVMXYP\
       gxerB763eZZtwjBuobvGpwtNwgjlqmZLfLP1wqdcpINlheQZcQsjIO3YdWIQu01V\
       svmgPAlkSAYnqkhmJbnDk3RcqGdHZzFekkcas2_sSrBsEdqhsQXBWoYkOqrbLP5M\
       qaIaKjQuOwutCgsUOoLImGwcwpNYW-gJyj4dckDfhrqcN2zreQW-gqmMgnXUZa5i\
       Ex8-xa5sRQmVmKEwls3_GpMrtUV2yG2elPFtTAlHxZsgUjm-ExxgxmmyagstzJFF\
       CrmJAqNCKnU9Ee2paKzQBw7qihMvNBNCQ5vtmQq-BWwDQDeMwRaiJYJVqGnNPOUK\
       oT23hTU3rPosAGctpODVOyFPLHY7ZoQlqKkwZ7F_dbSWLJROyFVrahcPMtt4Afyi\
       ozSqlJAgpfS-mBxieo4WHD_7GxHeSzW9Wk-pmmlDiytqaw9lyCDDZnLxUT2qF55S\
       QuvPYr-JFgyVma4LsB2kARISdQ02eQwZvBlYTHK4EN9fhFMvS2MZYfbOKJocaKOa\
       p-djcCMWp8yoyUP9OKuaabs9o51bqKCgcoRqFjqWQZCWXBgbDOyBAhAwlJRycioj\
       eH6NtUBDxSM0t_I1q8lQli9nNGKHklGEd86spm1nRMTARzy-qmGTlUb8g9HUvF3l\
       y516YoKeVBcuUppUp0v4u2Tme_llhNa5EF-6IHybjP_VUBg4NOGmGE59kKXURxiA\
       Uz8vidSWLO9RkG1IQoNtJ9r3Uyx-woFTUp3IC_eHCfA4Gb5FlIqDUcCRZIkHgOod\
       AofbtWyQRZkAFs_8iQS1UGT-O25ajAD2jMnAgXbWOqdrIvRaMkOnl0QOOZwKkMfo\
       k53vOqRJumO8dGIuCK5IUARRdJspF8dkMsrky2M5BA_QqfGIZ7vYfG_LcifNpQAx\
       Cj73qrNZZCEgWH3KVq0QaaR3QIMXGS-Ag7LMYC3lNPB8VOUvgC6wEZIdmct4NR48\
       IPNDjOEihG8qzFgtkZ8rdJ51UA3lFFMZhRsucj-GGkhChGRkib4rxL-Rkoi5Vbdw\
       xZkOYIMDhTXYN3pUOG-2p0Z4y4_TezT3BvbtmzEDOiSUiSOvMVSphsEeAkv4woy8\
       he85DPxxMwsACgpelKX-hjqYMaott-8WChtrrENzPHlxd6H7ipoyo9nACk8Mke51\
       QCBxM1Y2dL-fLEKjMDblS59wsk1yHI_BF6u6kdDAhvfyNQ_4g-uFxqSkgbC1FYs7\
       jNguciJEUFSfNta4ZDUcyWrrmHmymm7dwGzHBWoaBc_cI7ghNGM2yGhWu3XSdLp1\
       aLnaCiRXeYb5UNiRXUL6CNAqp0K6GVHkxowUsEBIV9qA-BiLg\",\
     \"priv\": \"JKfunEpR_O-GX8PenAcjHl37FB3kSP3X6v8Bg8HIcIR1snymjQjiWomcA\
       q17HbYyeeOm2yIEgzjuncXDElfXbA\"\
    }";

    let jwe = "\
    {\
     \"protected\": \"eyJhbGciOiJIUEtFLTEzIiwia2lkIjoid0lLbWY1SVN5WlpsT2tx\
       cWp3VzcwN0tDeGtxRWM0Y0pnN2ZZRkxCa3I1byJ9\",\
     \"aad\": \"VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc\",\
     \"encrypted_key\": \"A7QASMGmBzxW6c03sNy4wWpCV2IpNMWZpGMzU6potmBO-Veh\
       OaVw8vteHXEL_ARRxHUswAAQKBND01MeyByhBUjQ6Z_3IqDseFE54QQiPGdI44Cz\
       -XDpbux06YP1z6cyGDxcX25UOU-CID_g8wG_TIhmOIEx4PUSuCz_ZVZniLKDlIDb\
       WF_v6NR-BhYC6y__2mxfejVIk-ONgGPOKzY2CnmLRzb4f2lWLzD3tcAXDeGCYnom\
       eVS_bea2cygy2lsuGnfAvqfGztHiY6dbIuePMLEFuPYbIk6jlbMewAmfqH9hqxdm\
       DJNLesqlQIwCyrYJAEfPOjsXgWeUhnkWrMN8r0IoCCPtpzvIehuYYCkjVQS8GDAf\
       wg5CKxRRZ7Ji1B-SDAZ4_rTwgua_cxWLMeXFokqw2MS3x6Ssl-Hw9Ielaqnt1crd\
       6gYHBnaPL57txOyX5J5pRBhENsfQq9YTUWAnzQvOaGyo9KHg04I-RI--hjQFGvtd\
       QEg9UrwEEsVYAk-AUU-lqAGw5b6yVqvbZKkhnxHAsOYpmXrmAd_6ABT1Imovxggj\
       09foCoS8d2foO8ddQh7Vu0w0unJNY22bR6o29L5Ac1tNq4Co0TMztnmOUnR9o_Tl\
       p_7Zox87UwClvJj8PO-b81yBaZduQ311WK50d0fwH2PruOTvWiPS1UFs3EmhplkS\
       chKAbkCHSASvcBlbE-dzvF-FoKBDpocQc10C7h7ap2fl3-2amAlcGqIvb8LuzCM8\
       vxqCRxewZtgbfKPPTQvEzYPx4Ub-Unh72MnHjH-oPylXY5p2cCdqi6xhJwEE-dqX\
       tzn0z50JsisNuNvIM-nmALE8JFknNWqTCMskSTt98b9OktDA0QMNuNdZkAiOgLYf\
       6UFGWrt0RJyKRVLlKB4myD-YbKLw9nbtk0a4I6Dk2rSSpGJ_KZEbq9G-OQFIcved\
       1l8FRGCM8hA888k25jxRxrfSjndnSs_o3nhDdaZBQOBqzm1mYQm4Vc5eq6bo5F9J\
       bdvdXVwWS2sZsz-ef4qOoY0HS0FsgwmE4vnMLcsQCQuBgRONd6PL185D-PryaVCi\
       g98n0r9MPSKSQrvtam6vVqbrKdubBniUkMndhnGg1cPoU8ndo4yS9gwqvtqeWhVN\
       eOCu-cHtvgHO1F0-5-CHt4y3wK5RyhCZTt1JirBZivjDzZNM23c51qNmLjUWlGze\
       upK5HJMe3qScz1KRxVxJXleDL2XF8X8_5PZm7Xc-1eE50AaP-4PgCGDvSzEdxkle\
       6Epb5LwzGPD8w8frzil7xZr5cd7rQg8_Il-MZUupS_YM4CTBL6SgIlsa5DeMoKTb\
       Hn1EXI-e32RammLK79-8exaeaCBFscqqnWXbH4ZW_mGHsgmYPy86U6RXARFgNtsO\
       e7atKQNRk_Xsy7-EGV1kfEckX4VlhbyGl5l5Wd5PhMAFlUiMvJ37uBFAVEPyzptr\
       IxzQk4dMJdkeHKjDFScThbWOxwJlf3es9BiG_jr3cV1jeIpqdF78ZmG0nfGbbPid\
       zweVR9QlCvjYgFU9ZhakNLDoErV_euHoEOdWSuvV0u890cth5InzQzqxtEQb7hrH\
       rgrCUQpclMRw0LoHQligiZnl1quJaWBljyBVxjLHAVkwNwmzmOgcnzrgNJw2iKmb\
       J0V819rmHaoXl5Qf5HMReaBLds3qIFjkVapofh2UMgJbsPdGRshFnpZLQZZ-tN9S\
       KVQhZSqeIW7n3bjphf1spLCc78FycqyqRr--ZZBcZ01S06Jo_hfbHLUomm0v35JV\
       c2K81LZNHq62gDJYJhH0cww4oE8_M0wKkjn_TQ1JZFxGWkAqnG_MVLxhrIyYosG3\
       ufWoC-lVu9Qj8L6C21flexkjs54kz197UoDqEOgUIBA6dY0f_hy-QZjtJie0zNWZ\
       c-uEoia4UKYJOwpnLE4grZdN3rA6SkeaY_l8zewMuMgO6pNlQiyZyFDmyywzfEB3\
       eEMc6KcimnMSuZGG-J_UmEnysYAve5AbnpgdSuqRQj8kzb2yfNUwV6fcl7v_njYR\
       9uh0m4Nqc7PB8OgYS8rNv9guGy30cjj-UtrhqksXCyr2rweMW6md7rLgbY8\",\
     \"ciphertext\": \"09RTEoHUgifJuBgWnroH3CcK_8dPA10jT6NxNV9hN8TDF0007Bv\
       HRzKCj0uKVqXka9e_4dN36g9mrdDTvaIkZKaWdFbLTz2xNjdYgEAM1FsJ-XBx3Kf\
       El1mvm4vSjOG6MIKtGTWIqpx_tGFSMSqbO7H7ctVJW7b70p_NPvMKM759vzodxbU\
       jlNc8AtM6YM8H4MNTI32z8uKzdxESNksyMiLEYGn2fftQaq5O9gqrUe9ojW4Q22k\
       mTu52rhIQ5TIOcLKX4QQuv7c0PZbEr0lPGbyb2N0iuALwOVy8xeIl4b_vRRQYJf9\
       MGSEgVOjcDF9Pfjh8BEfv_1GpDQyM3HLNWDQgJY19CmibuAL9F-Dz_OxETiHm8eb\
       rZwSKBudmd0vlEg\"\
    }";

    let key : JwkHPKE = serde_json::from_str(jtk).unwrap();
    let jwe: Jwe = serde_json::from_str(jwe).unwrap();
    
    let protected_header: ProtectedHeader = serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap()).unwrap();

    assert_eq!(protected_header.alg.unwrap(), "HPKE-13");
    assert_eq!(protected_header.kid.unwrap(), key.kid);

    let encapsulated_key = &jwe.encrypted_key.unwrap(); //protected_header.alg; //&BASE64_URL_SAFE_NO_PAD.decode(payload_json["recipients"][0]["header"]["ek"].as_str().unwrap()).unwrap();

    let aad = [jwe.protected.as_bytes(), b".", jwe.aad.unwrap().as_bytes()].concat();

    let decapsulator = HPKE13MlKem1024Aes256::decryptor_from_slice(&key.priv2).unwrap();
    //let (_encapsulator, decapsulator) = HPKE10MlKem768P384Aes256::derive_pair_from_seed(&key.priv2).unwrap();
    let plaintext = decapsulator.single_shot_open(&GenericArray::from_slice(&encapsulated_key), &[], Payload{msg: &jwe.ciphertext, aad: &aad }, None).unwrap();

    println! ( "{}", String::from_utf8(plaintext.clone()).unwrap());
    //assert_eq! ( plaintext, b"You can trust us to stick with you through thick and thin-to the bitter end. And you can trust us to keep any secret of yours-closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.");
    assert_eq! ( plaintext, "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".as_bytes());
}



// https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-pq-pqt/00
#[test]
fn test_draft_ietf_jose_hpke_pq_pqt_a_10 ()
{
    let jtk = "\
    {\
     \"kty\": \"AKP\",\
     \"alg\": \"HPKE-13-KE\",\
     \"kid\": \"OJo7M3Ej3shaFw4VdozYxtqoGXsMA9TDkwy4Pvn0BCo\",\
     \"pub\": \"h3uSp1uJz_gkIKvKFSE-v6IM7SQ3hRZpDpxr-3Wym8lDvzRM6yUrOOzPQK\
       FtUcU8FwxhUmVlMneNi7MenyAW_AyZtkaCAhaZhWRUGnUWcCNZkFO8K7yNU5qX0K\
       zDE5IlybiUH5GpXWrLx5fNqFU7BpzCe3K6X5JHdLG-ScfOVfgs4Eaoaym4W8oGLx\
       pSrBqZ_wYhsSiGCdguTIWfu4otmFMyaKIY46uzRTR2dvrEH1eZDhUc_lsULUSGS-\
       IuwEyBI5VNHgJj0YRuxEgU92WtFLlaRigckszNR6qrn3QgQZdC_Pk74qWPJlpbMI\
       hs-ytHTqZhi7RluIUeDMljOSNMNMw7nhe6lco61sSDirK4feYFqCcjMioL3yipPJ\
       kWWlV31MM9izaXGSUhroNdAkwMCDaUgPWN_8de7ZpNTIcnc3k5IcUg1qe0P2mYbw\
       wJkPDK5iKVscqdJhMA5wUK6bO6VbslDJIhfIp3a4tes1FFiDQtrTBtz7vJAMM8JK\
       BEy8nISMfKM9ZRu3F__UvDFmskvdl-YMdZ5SxCt4B4HnZbd6t_MzWGXZoFqOuaPE\
       ILzhcenNGkUxldIwfIM9UKVeGuYBNrONyef_BuCpjGLCU0RwVrAJExLjogO_ukK2\
       ipHMuA_eAB_YNEaQgarKQb-ZpojrUZt8XMSFM2dATITGHOIrkkBQFmIwHQfCR92f\
       wmz1YzRGUhHXRfjQGF23g5u_IEI_wPComPAQE3h-hajAA9bVxikYcmgQyUb_EXXz\
       RdJeVYC1jFWaMiR6RwX6SsP-fBiIIxk7dUhAY0XXlJgZok2PUxLuIqroV0X4A2VZ\
       MZQmoaFAu35CigSeo3kXKW1UkU6KGKYQOA05CnsVJ7JmJ2hiJhXfFP4Zi77xSQF7\
       SoxQsi5PqzuglA2kg2MRkq0fC2HxGWoVOe7yWBTEAvlvEHvbgo3lup8MUCsppEja\
       QgJbJFOilbpiV7bKJH_SCkDfE9LqUULeOykXV8tpaRteewTdZQzJiVLVkLpvQlVJ\
       QqGoKbC8cXD9UkPAJBD7ASEvvBYSqlSMIycHunJZdkzduGvJO-O9iVlmtgisS5wp\
       x82re6IzgT1bsniBECY4l-AFs37tuDhJZQp8kOulR4icCcemyEzMciILI0MiEB_4\
       skaXmFY_m6ify1PLs_ECRZXbWmYRZO6TpiBlUDgLSiwgVSVUIbyAxL7LOiVZQ8_5\
       q_xIeIsyUqYkcecGSdUsec7MJInYQlPJKT7WslMAAX3zl9o4ubt3aBXTe8pSV5uz\
       dNVFSL8rKed1lWw5BkT5qiJSYy0EvDemY7MUeRgpwntyDFHRSD9-Es1OfB84tq2Y\
       peHBR2g1GnbaEmflKb-3u20eB9SQhrHok7kwl_OSCEm6ELjfsI1rmxXbxl_ak-AE\
       MZ_hu75Myrc-ADNfYWexmRJZFWtCY1VJHBGjKVb8eY9upzw2PI1bNx1CAIkTQtYO\
       Cbi3nK3EFSgdVudZMARbIgPRcX1CCunFgEfTgRm_lxEcq6Qkca59JcfWTAF4SOdB\
       oi8jQn-yoTX8uZrLqqH2gCHUuTZ8A4nBULgSB8Z7sbdNB_lOdyn_yrFpACAEAl7a\
       J6MWhb-tPCJ8BSh7Qw1ypCWzVXhVScReg9ttkL0sMGYyyRI5B2dgepYJhVMLwsQA\
       IgdpfCGSEiTWSs2TpLpVi0znww9QPISQIa2pWN8Ht5PSW-iyefVdMYDosDzbOoQr\
       YNwVdhB_k6MhifKpKOrzAoQZYKdwg0krKV7ftkq7pQ-9Mc5HowjMmDfLhltEAJHt\
       Vtbzy3nnYI0-J4gAa5iHs26UC9IQEALFk2Gxx88kO3CPu3SvxGK8zD-jlrgvMffV\
       NExgpimqghNzyQhPMSw2AeA8U5_fpF9cbN0UQJx7t6gmE1c7kkepNATRecEeesdr\
       vKklyxuRazI4GL7qlKHUykktTBwQQfhNo_VMVArGSU_gjM-VaWIEJxefMJnQFsgq\
       Q0ALvBAsx0HCK1OcUkIuWaafccK2yKv6Vvf9wytulxiXknDkhMV7gTWYKcuHWDYA\
       JqezqBlWV6yvGGWkGqWquq7HwyPY-uATVbu8mdKz_H2sgmYdQ\",\
     \"priv\": \"TK5a5VLDLOMcxsYNS49vGjawNMMl0Bbm846PPVwPAKMvawmQFwwVBD-Ot\
       hN-LrGWW6f-d2jz_RlIcnSPhckg5A\"\
    }";

    let jwe = "\
    {\
     \"protected\": \"eyJhbGciOiJIUEtFLTEzLUtFIiwia2lkIjoiT0pvN00zRWozc2hh\
       Rnc0VmRvell4dHFvR1hzTUE5VERrd3k0UHZuMEJDbyIsImVuYyI6IkEyNTZHQ00i\
       LCJlayI6IjA2dmlReUFxSHZ0WE14R2lFMmw4NzByOEktYXRLOU42ZUVhcG8xajBM\
       X2dGNEp3MUF2Mjk4SkpVY2VHemh0RHMtSHhia01LS0Nsb1JHUU1rWEN3N3VYMGR4\
       emR2U3A3U3VYU3dDcmdYUEFXSWdKMVUwbVhTMFAtNG5XVjMyT29xRDlMOEFvdUc0\
       ZV90bzYwNV9RcEtiSjc5NkhSekhQeTBTODRjVmk4WVNWMWpCbGtlbnZSUXNEWHEw\
       UUxYRG9xd0ZNN1lmRjJZLThqQUJRQ0UzQ2J0T0JYdi1SZ3dSN1l1ZjB1VjFzZHpv\
       S2luM0VQTmoyMXZPcm1iUS1RSDc2YzVwR3NRaUlpQWRCUkpud1JhRFJJOE5kYW0z\
       MEFNMWVQemZ6UkVJR2dvdjhBSldaNUFWb0RpcTFSYmR5OE9PQm1fRm9ZNjJzTmZa\
       cWNIWmlnS3czcS1EeExLTmFpaEV1MEYwbDJrQ01BckJ1WDFycjF3dHA5dC1DQW5m\
       ZHhlazZlWWNoazFWOFM2RjlEMWFpUEJXeGhoTzZxRWxjMnZNYnk5eXRyTGl4d0t3\
       NVBVaWYxU1dqZEh1dlhnZy1MZDlyWDIxckhWc2NJSWRMMWI5anJxSEpjeENaN29W\
       amFiV0JpeDZDRVEzZkU5RzJTRGFTNG1uemxHQUphM0tmY01iQnU5Sm1QOWJDTjFQ\
       UUd5b21iWUNLWDZqSWstXy1lOVF1YnFicVNYVVVkNlMxU3ZrZDdWUmNZdHVmb1Mx\
       aWdINm5ET2UzZHlvYnNYLTJNTHVndlhYYThxT091UzR6eGFaMVA2LWMyalg4aG1k\
       M3FXSGpOc2YtTDk2eVFvd2gtY201ZFZ6MHhhLXpBQy16cUYxOXRGOGQ5dmdVQlpN\
       UC0tUzU4OUhpQVlLNG5MZk1CemxvSTRCR3pDN01hUElKSmp6dWJZWG1MQWhFYm0y\
       dzdtNTQ2dXNtaUQ2NTFPUUcyVkFMM3pjQ0hBQW1RLWpYalAxZUJKZGhCMnFFZjdF\
       bkhCRzMxY01fNHF1Rmt3TXNILTVnXy1rQzJuWmdOSW5HNlBHdXlTMVp4X2VyaUJX\
       VUlNOXV0TURtWG9UOGN1RUxiMnVBODhCM1RGN1BCeDVick9ZQWlIUnI5LWI0dHFm\
       UXJ1UTlvcnNHaWFDNDdOazBid2F0Q292YXl3UXhDR1hieVU3QUE4RUJhSm5UNVNT\
       V01PV1JBMDRLWU1PTFluX0MzazRUUm1ib0dpR2tjX3lfN1pKdGxjTnUxVG1xblJy\
       SVRjQWtQUDZNZlJxa1pOTGlUMWVQSElaSlp2VWV6ZkdMb1cteUFKQmptUkhvRGEz\
       SktqQmFSSVQ2V3dFSW9LbDBTZC1Gd3VBNlBnV2lsaV9yRWwwbHRVdWlmOF9heDJ4\
       RG0zRnpCc19sZFh0d0c5MTZsMHVwWFYxUkdwMlZmTlc2ak82WjRRM3VVbU82eGtn\
       Uy1VVklwbnFMdFlpek1lNWdCb2Zhb2tMV203bVotaG5VdXpwNGhndy02RWp3TlRH\
       WXp2dExseXBRVmZBM1pnZnRsVFVRYVhISDRsOFVHWFYyMTYwdUs0Vnk2bUc2WEIz\
       bTJLekYzczI3cHY4Mll5dF9qdFZxdmNfcDYxd2RpUkd2a0Y0RV8td2w3eUZaNXpq\
       Zk1BRjgta1FhZ1pTLUhWbGtTLW0xUjY3THFkRjlRcnNmSXVudThFSC12YW5zUlhx\
       UmhUTjByXzRGWGZoLTE5Y1ZjNHFnem1IVzMyNHNfZUxWa2dRSHVleUczeUlyUU9L\
       TkdwbFBjWWJFVmpuS3pvMUc0WGRlQVlWWjc3YzUyTGdBbTBlZnkycFZMRVBTd042\
       TnpXYTktY0R3bHJDZEd1dndzN2t0dnpUejk1czZDRTAtNEg5MHY5bERiNGFDREhv\
       VTJiNGVoVGl1QmpSNXB5V3JGMGRicUYyTVFMaXFqWHhmOWNzWnduU0U4Nl9TdXNh\
       X09TUlZpRXc2VzVOd2RoeWV4UnhKN1lMazVoalNLanVyNzVVUm5XQ0VpUjFiNERh\
       SXJ2ejFHd0xES3Flc0lWR19ZUEtLY0NtdGQ5VEJPNVhFWFg4TEFwNFh3aU9aT3RZ\
       UElXQW9iTHNVVDhZUDdUOHZ3MlJCYjlyeFhkZzg4U1pGYTlKaHN5b0pmRllXT24z\
       c1BEWFRCbnJsbFZhQ2tGVDhScW9hb2lDS09VUWM3czhfS1ppcmxGZkNyZlNLTVhh\
       VFk1c056RmxXT0hyWmlMMjlYZHJrZHl0WVc3ZExLWHZKUnNtMnJfMFB6OEZpc09k\
       bXZ3LUhOalFKM0dRZUY5QkNIaUY0UVdpa3hsSjMyU1BjQVZRRFp3NUEyQlE5SzU1\
       M1p5Yi1xeUNlUUlqZVNMcWlXQnFhNXRyNU82cGlwQWlZWU5GMHRIaVlCVHNkbDlv\
       dmJtdnZSRTd2S0VkMU9XUkstV2VvNFhHOVpJN0w3bml3TUk1eG5CYlJzM1NSUXlZ\
       VGNwbUdjS2dqa1pmNERhMzltRkxISy1DbmwwYzRpZjFwRm5IT05CZEE0NHJzR0Rp\
       N0UyRUZSSVcyOUJvZDJnRDJWeDJrTDhjQWh0UF9ObnFNWHhTeVZkSERwaHRiXy1Y\
       ZEsxSkY4LWJ2eUJsTkxVMDNENktZNHRtVVBmT2U5QkF0bWx6STVPZndRRjNUWC16\
       MjNfZ2pzcjI3WWRKeE1lUWFlQThNVEZadW80Nnd0ZFhVelJ2ME0yV25yaUN2bTlB\
       OFM0UG0walZyalV1cVJ0SjRLNHhMbk1GUTNkSWdIbEFqdyJ9\",\
     \"aad\": \"VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc\",\
     \"iv\": \"4kbBObrz8_rXvess\",\
     \"encrypted_key\": \"P0RlHe_TVfzgUj-hqTTlUXJgMpX8IJ6VY9sM_IWoAj9D7mEV\
       C6Hrha2xnIeUOp71\",\
     \"ciphertext\": \"rp61DElcDQKgF_QsxMP2YsdsXLUdFiBVV-FcfEg7rf5Dgny1s5Y\
       nTDs7d9Y_TPwWXEIhIUmPrsSlSd2VJPEmzW76oY663xchZ4VfXyQGHV3wmBWAIpN\
       m1rm0cIUgFJMUIkGsgGiFCs2mLhzQKpASFzzA7Iwu9jxnryhw01dMc9xbOYJ_fNr\
       MWQI5aepqyQKQcfCkSU8f_FSvp9NQypbd1jOf773NFk-vurwu9mg-I0P0UnIWcRW\
       gQpE6aXzdxZ3f8VzxxTBjpPw_HertfqyW0F-YfR3nHXwqnrItH1oY3NZWT8rPLuj\
       EqG4U5RBUY6fbNUiPc5FQCNNseTRUCWZNLFoLKQdHL4rd1IVK3MXMXuD0\",\
    \"tag\": \"857uXyIeZ-VhuBmOFb6Y3g\"\
    }";

    let key : JwkHPKE = serde_json::from_str(jtk).unwrap();
    let jwe: Jwe = serde_json::from_str(jwe).unwrap();
    
    let protected_header: ProtectedHeader = serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap()).unwrap();

    println! ( "protected={:?}", String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(&jwe.protected).unwrap()));

    assert_eq!(protected_header.alg.unwrap(), "HPKE-13-KE");
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
    let decapsulator = HPKE13MlKem1024Aes256::decryptor_from_slice(&key.priv2).unwrap();
    let cek = decapsulator.single_shot_open(GenericArray::from_slice(&encapsulated_key), &recipient_structure, Payload{msg: &encrypted_key, aad: &[] }, None).unwrap();

    let decryptor = Aes256Gcm::new(&Array::try_from(cek.as_slice()).unwrap());
    decryptor.decrypt_inout_detached(&iv.unwrap().as_slice().try_into().unwrap(), 
        &aad, InOutBuf::from(buffer.as_mut_slice()), 
        &tag.unwrap().as_slice().try_into().unwrap()).unwrap();

    assert_eq! ( buffer, "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".as_bytes());
}


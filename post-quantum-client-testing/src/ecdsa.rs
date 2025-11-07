use std::error::Error;
use base64::prelude::*;
use openssl::ec::EcKey;
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use openssl::sign::Verifier;

pub fn verify_signature(base64_sig: &str, base64_pk: &str, base64_message: &str) -> Result<bool, Box<dyn Error>> {
    
    // decode them out of base64
    let sig = BASE64_STANDARD.decode(base64_sig)?;
    let pk_pem = BASE64_STANDARD.decode(base64_pk)?;
    let message = BASE64_STANDARD.decode(base64_message)?;

    // pem decode the key and create key object for verifier
    let ec_key = EcKey::public_key_from_pem(&pk_pem)?;
    let pk = PKey::from_ec_key(ec_key)?;

    // create a verifier to verify the signature with sha384
    // this should be changed depending on what sha the ecdsa key has
    let mut verifier = Verifier::new(MessageDigest::sha384(), &pk)?;

    // update verifier with message and verify
    verifier.update(&message)?;
    let is_verify = verifier.verify(&sig)?;

    Ok(is_verify)
}



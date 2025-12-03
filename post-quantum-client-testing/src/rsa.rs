use std::error::Error;
use base64::prelude::*;
use openssl::rsa::{Rsa, Padding};
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use openssl::sign::Verifier;

// This function verifies the rsa signature
pub fn verify_signature(base64_sig: &str, base64_pk: &str, base64_message: &str) -> Result<bool, Box<dyn Error>> {

    let sig = BASE64_STANDARD.decode(base64_sig)?;
    let pk_pem = BASE64_STANDARD.decode(base64_pk)?;
    let message = BASE64_STANDARD.decode(base64_message)?;

    // pem decode the key
    let rsa = Rsa::public_key_from_pem(&pk_pem)?;

    // creates a pkey object
    let pk = PKey::from_rsa(rsa)?;

    // create a verifier with sha256
    let mut verifier = Verifier::new(MessageDigest::sha256(), &pk)?;

    // set pss padding, update verifier with message and then verify
    verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
    verifier.update(&message)?;
    let is_verify = verifier.verify(&sig)?;

    Ok(is_verify)
}

use base64::prelude::*;
use oqs::sig;
use std::error::Error;

pub fn verify_signature(base64_sig: &str, base64_pk: &str, base64_message: &str) -> Result<bool, Box<dyn Error>> {
    
    // load the falcon512 algorithm
    let sigalg = sig::Sig::new(sig::Algorithm::Falcon512)?;

    let byte_sig = BASE64_STANDARD.decode(base64_sig)?;
    let byte_pk = BASE64_STANDARD.decode(base64_pk)?;
    let message = BASE64_STANDARD.decode(base64_message)?;
    
    // create a signature and public key object from bytes
    let signature = sigalg.signature_from_bytes(&byte_sig).unwrap();
    let pk = sigalg.public_key_from_bytes(&byte_pk).unwrap();

    // run the verifier to check sig
    let is_verify = sigalg.verify(&message, &signature, &pk).is_ok();

    Ok(is_verify)
}


use std::error::Error;
use base64::prelude::*;
use oqs::sig;

// this function verifies the signature
pub fn verify_signature(base64_sig: &str, base64_pk: &str, base64_message: &str) -> Result<bool, Box<dyn Error>> {
    // initialize the mldsa65 signature
    let sigalg = sig::Sig::new(sig::Algorithm::MlDsa65)?;

    // decode them out of base64
    let sig_bytes = BASE64_STANDARD.decode(base64_sig)?;
    let pk_bytes = BASE64_STANDARD.decode(base64_pk)?;
    let message = BASE64_STANDARD.decode(base64_message)?;
    
    // convert signature and pk from bytes to and object for the verifier
    let pk = sigalg.public_key_from_bytes(&pk_bytes).unwrap();
    let signature = sigalg.signature_from_bytes(&sig_bytes).unwrap();
    
    let is_verify = sigalg.verify(&message, &signature, &pk).is_ok();

    Ok(is_verify)
}

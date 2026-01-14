use base64::prelude::*;
use oqs::sig;
use std::error::Error;
use sha2::{Digest, Sha256};

// this function verifies the falcon signature
pub fn verify_signature(base64_sig: &str, base64_pk: &str, base64_message: &str) -> Result<bool, Box<dyn Error>> {
    
    // load the falcon512 algorithm
    let sigalg = sig::Sig::new(sig::Algorithm::Falcon512)?;

    let byte_sig = BASE64_STANDARD.decode(base64_sig)?;
    let byte_pk = BASE64_STANDARD.decode(base64_pk)?;
    let message = BASE64_STANDARD.decode(base64_message)?;
    
    // hash msg with sha256
    let msg_sh256 = Sha256::digest(&message);

    // create a signature and public key ref from bytes
    let signature = sigalg.signature_from_bytes(&byte_sig).ok_or("error with signature")?;
    let pk = sigalg.public_key_from_bytes(&byte_pk).ok_or("error with public key")?;

    let is_verify = sigalg.verify(&msg_sh256, signature, pk).is_ok();

    Ok(is_verify)
}

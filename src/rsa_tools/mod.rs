use rsa::pkcs1::FromRsaPublicKey;
use rsa::pkcs8::Error;
use rsa::Hash::SHA3_512;
use rsa::{PaddingScheme, PublicKey, RsaPublicKey};
use sha3::{Digest, Sha3_512};
use std::hash::Hash;

/// Return the hash for a given input as a ['Vec<u8>']
pub fn hash<H: Hash + AsRef<[u8]>>(text: H) -> Vec<u8> {
    let mut hasher = Sha3_512::new();
    hasher.update(text);
    (&hasher.finalize()).to_vec()
}

/// Verify that a signature for a message is valid.
pub fn verify(public_key: RsaPublicKey, message: Vec<u8>, signature: Vec<u8>) -> bool {
    let padding = PaddingScheme::new_pkcs1v15_sign(Some(SHA3_512));
    let result = hash(&message);
    public_key.verify(padding, &result, &signature).is_ok()
}

/// Read in a keypair from a file.
pub fn import_keypair_from_binary(public_key_binary: [u8; 1024]) -> Result<RsaPublicKey, Error> {
    let public_key = RsaPublicKey::from_pkcs1_der(&public_key_binary)?;
    Ok(public_key)
}

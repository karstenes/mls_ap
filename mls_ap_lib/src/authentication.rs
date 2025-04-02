use ed25519::signature::SignerMut;
use openmls::prelude::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Represents a signed credential.
///
/// This struct contains the credential and its corresponding signed bytes.
#[derive(Serialize, Deserialize)]
pub struct SignedCredential {
    /// The credential with its associated key.
    pub credential: CredentialWithKey,
    /// The signed bytes of the credential.
    pub signed_bytes: Vec<u8>,
}

/// Holds the state required for signing and verifying credentials.
pub(crate) struct State {
    /// The private signing key used for signing credentials.
    pub(crate) private_key: SigningKey,
    /// The public verifying key used for verifying signatures.
    pub(crate) public_key: VerifyingKey,
}

/// Defines possible errors that can occur during the authentication process.
#[derive(Error, Debug)]
pub enum Error {
    /// Indicates an error occurred while signing the key.
    #[error("error signing key")]
    SigningError(ed25519::Error),
    /// Indicates an error occurred during serialization or deserialization.
    #[error("serde error")]
    SerdeError(serde_json::Error),
}

/// Signs a credential using the provided state.
///
/// # Arguments
/// * `state` - A mutable reference to the state containing the signing key.
/// * `credential` - The credential to be signed.
///
/// # Returns
/// A `Result` containing the signed credential or an `Error` if signing fails.
///
/// # Errors
/// * `Error::SigningError` - If signing the credential fails.
/// * `Error::SerdeError` - If serialization of the credential fails.
pub(crate) fn sign_credential_with_state(
    state: &mut State,
    credential: CredentialWithKey,
) -> Result<SignedCredential, Error> {
    // Serialize the credential to bytes.
    let credential_bytes = match serde_json::to_string(&credential) {
        Ok(v) => v.into_bytes(),
        Err(e) => return Err(Error::SerdeError(e)),
    };
    // Sign the serialized credential bytes.
    let credential_signed = match state.private_key.try_sign(&credential_bytes) {
        Ok(v) => v,
        Err(e) => return Err(Error::SigningError(e)),
    };
    // Return the signed credential.
    Ok(SignedCredential {
        credential: credential.clone(),
        signed_bytes: credential_signed.to_vec(),
    })
}

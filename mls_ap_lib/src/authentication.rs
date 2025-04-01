use crate::state;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Serialize, Deserialize)]
pub struct SignedCredential<'a> {
    pub credential: CredentialWithKey,
    pub signed_bytes: &'a [u8],
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("error signing key")]
    SigningError(String),
    #[error("serde error")]
    SerdeError(serde_json::Error)
}

pub(crate) fn sign_credential_with_state<'a>(
    state: &state::AsState,
    credential: CredentialWithKey,
) -> Result<SignedCredential, Error> {
    let credential_bytes = match serde_json::to_string(&credential) {
        Ok(v) => v.into_bytes(),
        Err(e) => return Err(Error::SerdeError(e))
    }
    SignedCredential {
        credential: CredentialWithKey.clone(),

    }
}

use super::{Error, Login};
use crate::database::{add_user, get_user};
use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use ed25519::signature::SignerMut;
use ed25519_dalek::{SigningKey, VerifyingKey};
use openmls::prelude::*;
use serde::{Deserialize, Serialize};

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
#[derive(Debug, Clone)]
pub(crate) struct State {
    /// The private signing key used for signing credentials.
    pub(crate) private_key: SigningKey,
    /// The public verifying key used for verifying signatures.
    pub(crate) public_key: VerifyingKey,
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
    credential: &CredentialWithKey,
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

pub(crate) fn register_user(db: &mut rusqlite::Connection, user: Login) -> Result<i64, Error> {
    let username = user.username;

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = match argon2.hash_password(user.password.as_bytes(), &salt) {
        Ok(v) => v,
        Err(e) => return Err(Error::HashingError(e)),
    };

    add_user(db, username, password_hash.to_string())
}

pub(crate) fn verify_user(db: &rusqlite::Connection, user: Login) -> Result<i64, Error> {
    let user_db = get_user(&db, &user.username)?;

    let parsed_hash = match PasswordHash::new(&user_db.password_hash) {
        Ok(v) => v,
        Err(e) => return Err(Error::HashingError(e)),
    };

    match Argon2::default().verify_password(&user.password.as_bytes(), &parsed_hash) {
        Ok(_) => Ok(user_db.id),
        Err(e) => Err(Error::HashingError(e)),
    }
}

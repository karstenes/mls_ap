use openmls::prelude::CredentialWithKey;

mod authentication;
mod database;

pub struct User {
    pub username: String,
    pub credential: CredentialWithKey,
}

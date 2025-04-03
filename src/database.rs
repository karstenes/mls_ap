use crate::{RegisteredUser, UserError};

use super::Error;
use openmls::prelude::*;
use rusqlite::{params, Connection, Row};
use std::path::Path;

pub fn init_database(database_path: &Path) -> Result<rusqlite::Connection, Error> {
    let database = match Connection::open(database_path) {
        Ok(v) => v,
        Err(e) => return Err(Error::SQLError(e)),
    };

    let table_credentials = database.execute(
        "CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            credential TEXT NOT NULL
        )",
        (),
    );

    if let Err(e) = table_credentials {
        return Err(Error::SQLError(e));
    };

    let table_users = database.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT,
            credential_id INTEGER UNIQUE
        )",
        (),
    );

    if let Err(e) = table_users {
        return Err(Error::SQLError(e));
    };

    Ok(database)
}

pub fn get_credential(database: &Connection, user_id: i64) -> Result<CredentialWithKey, Error> {
    let query: String = match database.query_row(
        "SELECT credential FROM credentials
            INNER JOIN users
                ON users.credential_id = credentials.id
            WHERE users.id = ?1",
        [user_id],
        |row: &Row| Ok(row.get("credential")?),
    ) {
        Ok(v) => v,
        Err(e) => return Err(Error::SQLError(e)),
    };

    Ok(match serde_json::from_str(&query) {
        Ok(v) => v,
        Err(e) => return Err(Error::SerdeError(e)),
    })
}

pub fn get_user(database: &Connection, user: &String) -> Result<super::RegisteredUser, Error> {
    match database.query_row(
        "SELECT * FROM users WHERE users.username = ?1",
        [&user],
        |row: &Row| {
            Ok(RegisteredUser {
                id: row.get("id")?,
                username: row.get("username")?,
                password_hash: row.get("password_hash")?,
            })
        },
    ) {
        Ok(v) => Ok(v),
        Err(e) => match e {
            rusqlite::Error::QueryReturnedNoRows => Err(Error::UserError(
                UserError::UnregisteredUserError(format!("User {} is not registered!", &user)),
            )),
            _ => Err(Error::SQLError(e)),
        },
    }
}

pub fn add_credential_for_user(
    database: &Connection,
    user_id: i64,
    credential: &CredentialWithKey,
) -> Result<i64, Error> {
    let credential_json = match serde_json::to_string(&credential) {
        Ok(v) => v,
        Err(e) => return Err(Error::SerdeError(e)),
    };

    match database.execute(
        "INSERT INTO credentials (credential) VALUES (?1)",
        [credential_json],
    ) {
        Err(e) => return Err(Error::SQLError(e)),
        Ok(_) => (),
    };

    let newcred = database.last_insert_rowid();

    match database.execute(
        "UPDATE users set credential_id = ?1 WHERE id = ?2",
        (newcred, user_id),
    ) {
        Err(e) => return Err(Error::SQLError(e)),
        Ok(_) => (),
    };

    Ok(newcred)
}

pub fn add_user(
    database: &mut Connection,
    username: String,
    password_hash: String,
) -> Result<i64, Error> {
    let user = get_user(database, &username);

    if let Ok(_) = user {
        return Err(Error::UserError(UserError::UserExistsError(format!(
            "User {} already exists",
            username
        ))));
    }

    match database.execute(
        "INSERT INTO users (username, password_hash)
        VALUES (?1, ?2)",
        params![username, password_hash],
    ) {
        Err(e) => return Err(Error::SQLError(e)),
        Ok(_) => (),
    };

    Ok(database.last_insert_rowid())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_rust_crypto::OpenMlsRustCrypto;
    

    fn generate_credential_with_key(
        identity: Vec<u8>,
        credential_type: CredentialType,
        signature_algorithm: SignatureScheme,
        provider: &impl OpenMlsProvider,
    ) -> (CredentialWithKey, SignatureKeyPair) {
        let credential = BasicCredential::new(identity);
        let signature_keys = SignatureKeyPair::new(signature_algorithm)
            .expect("Error generating a signature key pair.");

        // Store the signature key into the key store so OpenMLS has access
        // to it.
        signature_keys
            .store(provider.storage())
            .expect("Error storing signature keys in key store.");

        (
            CredentialWithKey {
                credential: credential.into(),
                signature_key: signature_keys.public().into(),
            },
            signature_keys,
        )
    }

    fn init_database_local() -> Result<Connection, crate::Error> {
        let database = match Connection::open_in_memory() {
            Ok(v) => v,
            Err(e) => return Err(crate::Error::SQLError(e)),
        };

        let table_credentials = database.execute(
            "CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                credential TEXT NOT NULL
            )",
            (),
        );

        if let Err(e) = table_credentials {
            return Err(crate::Error::SQLError(e));
        };

        let table_users = database.execute(
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT,
                credential_id INTEGER UNIQUE
            )",
            (),
        );

        if let Err(e) = table_users {
            return Err(crate::Error::SQLError(e));
        };

        Ok(database)
    }

    #[test]
    fn test_registration() -> () {
        let mut db = init_database_local().unwrap();

        add_user(&mut db, "testuser".to_string(), "testpassword".to_string()).unwrap();

        let user = get_user(&db, &"testuser".to_string()).unwrap();

        if user.username != "testuser".to_string() {
            panic!("Error!");
        }
    }

    #[test]
    fn test_add_credential() {
        let mut db = init_database_local().unwrap();

        add_user(&mut db, "testuser".to_string(), "testpassword".to_string()).unwrap();

        let user = get_user(&db, &"testuser".to_string()).unwrap();

        let (credential, signer) = generate_credential_with_key(
            "Sasha".into(),
            CredentialType::Basic,
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.signature_algorithm(),
            &OpenMlsRustCrypto::default(),
        );

        println!("Credential: {:#?}", credential);

        let id = add_credential_for_user(&mut db, user.id, &credential).unwrap();

        if credential != get_credential(&db, user.id).unwrap() {
            panic!("Credentials don't match!")
        }
    }
}

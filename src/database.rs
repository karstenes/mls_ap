use openmls::prelude::*;
use rusqlite::{params, Connection, Row};
use std::path::Path;
use thiserror::Error;

/// Defines possible errors that can occur during user lookup.
#[derive(Error, Debug)]
pub enum Error {
    /// Indicates an error occurred while signing the key.
    #[error("SQL error")]
    SQLError(rusqlite::Error),
    /// Indicates an error occurred during serialization or deserialization.
    #[error("serde error")]
    SerdeError(serde_json::Error),
}

pub fn init_database(database_path: &Path) -> Result<rusqlite::Connection, Error> {
    let database = match Connection::open(database_path) {
        Ok(v) => v,
        Err(e) => return Err(Error::SQLError(e)),
    };

    let tables = database.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            credential TEXT NOT NULL
        )",
        (),
    );

    if let Err(e) = tables {
        return Err(Error::SQLError(e));
    };

    Ok(database)
}

pub fn get_credential(database: &Connection, id: i64) -> Result<super::User, Error> {
    let query: (String, String) = match database.query_row(
        "SELECT username, credential FROM users WHERE id=?1",
        [id],
        |row: &Row| Ok((row.get("username")?, row.get("credential")?)),
    ) {
        Ok(v) => v,
        Err(e) => return Err(Error::SQLError(e)),
    };

    Ok(super::User {
        username: query.0,
        credential: match serde_json::from_str(&query.1) {
            Ok(v) => v,
            Err(e) => return Err(Error::SerdeError(e)),
        },
    })
}

pub fn add_user(database: &Connection, user: &super::User) -> Result<i64, Error> {
    let credential_json = match serde_json::to_string(&user.credential) {
        Ok(v) => v,
        Err(e) => return Err(Error::SerdeError(e)),
    };

    match database.execute(
        "INSERT INTO users VALUES (?1, ?2)",
        (&user.username, credential_json),
    ) {
        Err(e) => return Err(Error::SQLError(e)),
        Ok(_) => (),
    };

    Ok(database.last_insert_rowid())
}

// pub fn get_users(database: &Connection) -> Result<Vec<super::User>, Error> {
//     let query: (String, String) =
//         match database.quer("SELECT username, credential FROM users", (), |row: &Row| {
//             Ok((row.get("username")?, row.get("credential")?))
//         }) {
//             Ok(v) => v,
//             Err(e) => return Err(Error::SQLError(e)),
//         };
// }

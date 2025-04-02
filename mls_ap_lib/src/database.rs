use std::path::Path;

use rusqlite::{params, Connection, Error};


pub fn init_database(database_path: &Path) -> Result<rusqlite::Connection, Error> {
    let database = Connection::open(database_path)?;
    
    Ok(database)
}
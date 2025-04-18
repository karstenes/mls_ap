use std::{fs::File, path::PathBuf, sync::Mutex};

use actix_session::{config::PersistentSession, storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{
    cookie::{time, Key}, error::ErrorUnauthorized, web::{get, post, Data, Json}, HttpResponse
};
use authentication::{register_user, sign_credential_with_state, verify_user};
use database::{add_credential_for_user, init_database};
use ed25519_dalek;
use openmls::prelude::{CredentialWithKey, tls_codec::*};
use rand_core::OsRng;
use serde::Deserialize;
use thiserror::Error;
use base64::prelude::*;
use std::path::Path;
use std::io::prelude::*;
use std::env;
use dotenvy;

mod authentication;
mod database;

#[derive(Error, Debug)]
pub enum UserError {
    #[error("User not registered")]
    UnregisteredUserError(String),
    #[error("Incorrect password")]
    IncorrectPasswordError(String),
    #[error("User already exists")]
    UserExistsError(String),
}

#[derive(Error, Debug)]
pub enum Error {
    /// Indicates an error occurred while signing the key.
    #[error("error signing key")]
    SigningError(ed25519::Error),
    /// Indicates an error occurred during serialization or deserialization.
    #[error("serde error")]
    SerdeError(serde_json::Error),
    #[error("SQL error")]
    SQLError(rusqlite::Error),
    #[error("argon2 hashing eror")]
    HashingError(argon2::password_hash::Error),
    #[error("error relating to user login")]
    UserError(UserError),
}

#[derive(serde::Serialize)]
pub struct SessionDetails {
    user_id: i64,
}

pub struct RegisteredUser {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
}

struct AppData {
    db: Mutex<rusqlite::Connection>,
    crypto_state: authentication::State,
}

#[derive(Deserialize, Debug, Clone)]
pub(crate) struct Login {
    pub(crate) username: String,
    pub(crate) password: String,
}

fn check_auth(session: &Session) -> Result<i64, actix_web::Error> {
    match session.get::<i64>("user_id")? {
        Some(user_id) => Ok(user_id),
        None => Err(ErrorUnauthorized("User not logged in.")),
    }
}

async fn register(
    data: Json<Login>,
    db_mut: Data<AppData>,
) -> Result<HttpResponse, actix_web::Error> {
    let mut db = db_mut.db.lock().unwrap();
    match register_user(&mut db, data.into_inner()) {
        Ok(_) => Ok(HttpResponse::Ok().finish()),
        Err(e) => match e {
            Error::UserError(UserError::UserExistsError(s)) => {
                Ok(HttpResponse::Ok().finish())
            }
            _ => Ok(HttpResponse::InternalServerError().finish()),
        },
    }
}

async fn login_user(
    session: Session,
    data: Json<Login>,
    db_mut: Data<AppData>,
) -> Result<HttpResponse, actix_web::Error> {
    let mut db = db_mut.db.lock().unwrap();
    let login = data.into_inner();
    let username = login.username.clone();
    match verify_user(&mut db, login) {
        Ok(v) => {
            session.insert("user_id", v)?;
            session.insert("username", username)?;
            session.renew();
            Ok(HttpResponse::Ok().json(SessionDetails { user_id: v }))
        }
        Err(e) => match e {
            Error::UserError(UserError::IncorrectPasswordError(_)) => {
                Ok(HttpResponse::Unauthorized().body("Incorrect password"))
            }
            Error::UserError(UserError::UnregisteredUserError(_)) => {
                Ok(HttpResponse::Unauthorized().body("User not found"))
            }
            _ => Ok(HttpResponse::InternalServerError().finish()),
        },
    }
}

async fn logout_user(session: Session) -> HttpResponse {
    if let Err(_) = check_auth(&session) {
        return HttpResponse::NotFound().body("User is not logged in");
    }
    session.purge();
    HttpResponse::Ok().body("User logged out successfully.")
}

async fn update_credential(
    session: Session,
    data: Json<CredentialWithKey>,
    db_mut: Data<AppData>,
) -> Result<HttpResponse, actix_web::Error> {
    let user_id = match check_auth(&session) {
        Ok(v) => v,
        Err(_) => return Ok(HttpResponse::Unauthorized().body("User is not logged in")),
    };
    let credential = data.into_inner();
    let credential_name = match String::from_utf8(credential.credential.serialized_content().to_vec()) {
        Ok(v) => v,
        Err(_) => return Ok(HttpResponse::InternalServerError().finish())
    };
    match session.get::<String>("username") {
        Ok(Some(username)) => {
            if username != credential_name {
                return Ok(HttpResponse::BadRequest().body("Credential identity does not match username"))
            }
        },
        _ => return Ok(HttpResponse::InternalServerError().finish())
    }
    let mut db = db_mut.db.lock().unwrap();
    
    if let Err(_) = add_credential_for_user(&mut db, user_id, &credential) {
        return Ok(HttpResponse::InternalServerError().finish());
    }

    match sign_credential_with_state(&mut db_mut.crypto_state.clone(), &credential) {
        Ok(v) => Ok(HttpResponse::Ok().json(v)),
        Err(_) => Ok(HttpResponse::InternalServerError().finish()),
    }
}

async fn get_pubkey(state: Data<AppData>) -> HttpResponse {
    return HttpResponse::Ok().body(BASE64_STANDARD.encode(state.crypto_state.public_key));
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let _ = dotenvy::dotenv();

    let mut rand = OsRng;
    
    let signing_key =  if let Ok(x) = env::var("PRIVATE_KEY") {
        let key_bytes: [u8;32] = BASE64_STANDARD.decode(x).unwrap().try_into().unwrap();
        ed25519_dalek::SigningKey::from_bytes(&key_bytes)
    } else {
        let path = Path::new("./.env");
        let mut file =  if path.exists() {
            File::open(path).unwrap()
        } else {
            File::create(path).unwrap()
        };
        let key = ed25519_dalek::SigningKey::generate(&mut rand);
        write!(&mut file, "PRIVATE_KEY={}", BASE64_STANDARD.encode(key.as_bytes())).unwrap();
        key
    };

    let verifying_key = signing_key.verifying_key();

    println!("Pubkey: {}", BASE64_STANDARD.encode(verifying_key.as_bytes()));

    let secret_key = Key::generate();

    let db = init_database(&PathBuf::from("db.sql")).unwrap();

    let state = Data::new(AppData {
        db: Mutex::new(db),
        crypto_state: authentication::State {
            private_key: signing_key,
            public_key: verifying_key,
        },
    });

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    
    actix_web::HttpServer::new(move || {
        let logger = actix_web::middleware::Logger::default();
        actix_web::App::new()
            .wrap(SessionMiddleware::builder(
                CookieSessionStore::default(),
                secret_key.clone(),
            ).session_lifecycle(
                PersistentSession::default().session_ttl(time::Duration::minutes(5)),
            )
            .build())
            .wrap(logger)
            .app_data(state.clone())
            .route("/register", post().to(register))
            .route("/login", post().to(login_user))
            .route("/update_credential", post().to(update_credential))
            .route("/logout", post().to(logout_user))
            .route("/get_public_key", get().to(get_pubkey))
    })
    .bind(("0.0.0.0", 8081))?
    .run()
    .await
}

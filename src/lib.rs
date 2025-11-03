use worker::*;
use serde::Deserialize;
use argon2::{
    Argon2, Algorithm, Version, Params,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use std::sync::LazyLock;

#[derive(Deserialize)]
struct CreateRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct VerifyRequest {
    username: String,
    password: String,
}

const MAX_INPUT_LEN: usize = 2048;

static ARGON2: LazyLock<Argon2<'static>> = LazyLock::new(|| {
    let params = Params::new(
        19456, // m=19 MiB
        2,     // t=2
        1,     // p=1
        None,
    ).unwrap();
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
});

fn validate_input(username: &str, password: &str) -> bool {
    !username.is_empty()
        && !password.is_empty()
        && username.len() <= MAX_INPUT_LEN
        && password.len() <= MAX_INPUT_LEN
}

async fn create_user(env: &Env, username: String, password: String) -> Result<Response> {

    if !validate_input(&username, &password) {
        return Response::error("Bad Request", 400);
    }

    let salt = SaltString::generate(&mut OsRng);
    let phc = ARGON2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| Error::RustError(format!("hash: {}", e)))?
        .to_string();

    let db = env.d1("DB")?;
    let stmt = db.prepare("INSERT INTO users (username, phc) VALUES (?, ?) ON CONFLICT(username) DO NOTHING");
    let result = stmt.bind(&[
        username.into(),
        phc.into(),
    ])?.run().await?;

    let rows_affected = result.meta()
        .ok()
        .flatten()
        .and_then(|m| m.changes)
        .unwrap_or(0);

    match rows_affected {
        1 => Response::ok(""),
        0 => Response::error("Conflict", 409),
        _ => Response::error("Internal Server Error", 500),
    }
}

async fn verify_user(env: &Env, username: String, password: String) -> Result<Response> {
    if !validate_input(&username, &password) {
        return Response::error("Bad Request", 400);
    }

    let db = env.d1("DB")?;
    let stmt = db.prepare("SELECT phc FROM users WHERE username = ?");
    let result = stmt.bind(&[username.into()])?.first::<serde_json::Value>(None).await;

    let phc_str = match result {
        Ok(Some(row)) => {
            row.get("phc")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::RustError("phc not found".into()))?
                .to_string()
        }
        _ => {
            // always hash even if user not found
            let _ = ARGON2.hash_password(b"password123", &SaltString::generate(&mut OsRng));
            return Response::error("Unauthorized", 401);
        }
    };

    let parsed = PasswordHash::new(&phc_str)
        .map_err(|e| Error::RustError(format!("parse phc: {}", e)))?;

    match ARGON2.verify_password(password.as_bytes(), &parsed) {
        Ok(_) => Response::ok(""),
        Err(_) => Response::error("Unauthorized", 401),
    }
}

#[event(fetch)]
async fn fetch(mut req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let url = req.url()?;
    let path = url.path();

    match (req.method(), path) {
        (Method::Post, "/create") => {
            let body: CreateRequest = req.json().await?;
            create_user(&env, body.username, body.password).await
        }
        (Method::Post, "/verify") => {
            let body: VerifyRequest = req.json().await?;
            verify_user(&env, body.username, body.password).await
        }
        _ => Response::error("Not Found", 404),
    }
}

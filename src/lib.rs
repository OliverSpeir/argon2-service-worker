use worker::*;
use serde::{Deserialize, Serialize};
use argon2::{
    Argon2, Algorithm, Version, Params,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use std::sync::LazyLock;

#[derive(Deserialize)]
struct HashRequest {
    password: String,
}

#[derive(Serialize)]
struct HashPasswordResponse {
    password_hash: String,
}

#[derive(Serialize)]
struct VerifyPasswordResponse {
    ok: bool,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}

#[derive(Deserialize)]
struct VerifyRequest {
    password: String,
    hash: String,
}

const MAX_INPUT_LEN: usize = 2048;

/// Argon2id with OWASP-recommended parameters (m=19 MiB, t=2, p=1)
static ARGON2: LazyLock<Argon2<'static>> = LazyLock::new(|| {
    let params = Params::new(
        19456, // m=19 MiB
        2,     // t=2
        1,     // p=1
        None,
    ).unwrap();
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
});

#[derive(Debug, PartialEq)]
pub enum HashError {
    EmptyPassword,
    PasswordTooLong,
    EmptyHash,
    HashTooLong,
    InvalidHash,
    HashingFailed,
}

impl HashError {
    fn error_code(&self) -> &'static str {
        match self {
            HashError::EmptyPassword => "empty_password",
            HashError::PasswordTooLong => "password_too_long",
            HashError::EmptyHash => "empty_hash",
            HashError::HashTooLong => "hash_too_long",
            HashError::InvalidHash => "invalid_hash",
            HashError::HashingFailed => "internal_error",
        }
    }

    fn status_code(&self) -> u16 {
        match self {
            HashError::HashingFailed => 500,
            _ => 400,
        }
    }
}

fn error_response(error: HashError) -> Result<Response> {
    let body = serde_json::to_string(&ErrorResponse { error: error.error_code() }).unwrap();
    let mut response = Response::from_body(worker::ResponseBody::Body(body.into_bytes()))?;
    let headers = response.headers_mut();
    headers.set("Content-Type", "application/json")?;
    Ok(response.with_status(error.status_code()))
}

/// Hash a password, returning the PHC-formatted hash string.
pub fn hash_password(password: &str) -> std::result::Result<String, HashError> {
    if password.is_empty() {
        return Err(HashError::EmptyPassword);
    }
    if password.len() > MAX_INPUT_LEN {
        return Err(HashError::PasswordTooLong);
    }

    let salt = SaltString::generate(&mut OsRng);
    let phc = ARGON2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| HashError::HashingFailed)?
        .to_string();

    Ok(phc)
}

/// Verify a password against a PHC-formatted hash string.
pub fn verify_password(password: &str, hash: &str) -> std::result::Result<bool, HashError> {
    if password.is_empty() {
        return Err(HashError::EmptyPassword);
    }
    if password.len() > MAX_INPUT_LEN {
        return Err(HashError::PasswordTooLong);
    }
    if hash.is_empty() {
        return Err(HashError::EmptyHash);
    }
    if hash.len() > MAX_INPUT_LEN {
        return Err(HashError::HashTooLong);
    }

    let parsed = PasswordHash::new(hash).map_err(|_| HashError::InvalidHash)?;

    Ok(ARGON2.verify_password(password.as_bytes(), &parsed).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_produces_valid_phc_string() {
        let hash = hash_password("test-password").unwrap();
        assert!(hash.starts_with("$argon2id$"));
    }

    #[test]
    fn verify_correct_password_returns_true() {
        let hash = hash_password("my-secret").unwrap();
        assert!(verify_password("my-secret", &hash).unwrap());
    }

    #[test]
    fn verify_wrong_password_returns_false() {
        let hash = hash_password("correct").unwrap();
        assert!(!verify_password("wrong", &hash).unwrap());
    }

    #[test]
    fn hash_empty_password_fails() {
        assert_eq!(hash_password(""), Err(HashError::EmptyPassword));
    }

    #[test]
    fn verify_empty_password_fails() {
        let hash = hash_password("test").unwrap();
        assert_eq!(verify_password("", &hash), Err(HashError::EmptyPassword));
    }

    #[test]
    fn verify_empty_hash_fails() {
        assert_eq!(verify_password("test", ""), Err(HashError::EmptyHash));
    }

    #[test]
    fn verify_invalid_hash_fails() {
        assert_eq!(verify_password("test", "not-a-hash"), Err(HashError::InvalidHash));
    }

    #[test]
    fn hash_too_long_password_fails() {
        let long_password = "a".repeat(MAX_INPUT_LEN + 1);
        assert_eq!(hash_password(&long_password), Err(HashError::PasswordTooLong));
    }

    #[test]
    fn hash_max_length_password_succeeds() {
        let max_password = "a".repeat(MAX_INPUT_LEN);
        assert!(hash_password(&max_password).is_ok());
    }
}

#[event(fetch)]
async fn fetch(mut req: Request, _env: Env, _ctx: Context) -> Result<Response> {
    let url = req.url()?;
    let path = url.path();

    match (req.method(), path) {
        (Method::Post, "/hash_password") => {
            let body: HashRequest = match req.json().await {
                Ok(b) => b,
                Err(_) => return Response::error("Bad Request", 400),
            };
            match hash_password(&body.password) {
                Ok(password_hash) => Response::from_json(&HashPasswordResponse { password_hash }),
                Err(e) => error_response(e),
            }
        }
        (Method::Post, "/verify_password") => {
            let body: VerifyRequest = match req.json().await {
                Ok(b) => b,
                Err(_) => return Response::error("Bad Request", 400),
            };
            match verify_password(&body.password, &body.hash) {
                Ok(ok) => Response::from_json(&VerifyPasswordResponse { ok }),
                Err(e) => error_response(e),
            }
        }
        _ => Response::error("Not Found", 404),
    }
}

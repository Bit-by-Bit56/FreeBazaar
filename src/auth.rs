use chrono::{Duration, Utc};
use jsonwebtoken::{encode, decode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Serialize, Deserialize};
use crate::errors::AppError;


/// The Claims struct represents the data encoded within our JWT.
/// `sub`: the subject (e.g. user ID); `exp`: expiration timestamp.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

/// Generates a JWT token for the given user ID using the provided secret key.
/// The token is valid for 24 hours.
pub fn create_token(user_id: &str, secret: &str) -> Result<String, AppError> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .ok_or(AppError::Auth("Invalid token expiration".into()))?
        .timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_owned(),
        exp: expiration,
    };

    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref()))
        .map_err(|e| AppError::Auth(e.to_string()))
}

/// Validates the given JWT token using the provided secret key.
///     
pub fn validate_token(token: &str, secret: &str) -> Result<Claims, AppError> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|e| AppError::Auth(format!("Invalid token: {}", e)))
}
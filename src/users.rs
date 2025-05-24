use axum::{
    extract::{State, Extension, Json, Multipart, Path},
    routing::{get, post},
    Router,
};
use argon2::{Argon2, PasswordHash, PasswordVerifier, PasswordHasher};
use argon2::password_hash::{SaltString, rand_core::OsRng};
use serde::{Deserialize, Serialize};

use uuid::Uuid;
use std::sync::Arc;
use crate::{AppState, auth::{self, Claims}, images::{self}};
use crate::errors::AppError;

const MIN_PASSWORD_LENGTH: usize = 12;

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub email: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub token: String,
    pub user_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub user_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUserRequest {
    pub bio: Option<String>,
    pub email: Option<String>,
    pub profile_picture: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserResponse {
    pub user_id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub bio: Option<String>,
    pub profile_picture: Option<String>,
}

fn validate_password(password: &str) -> Result<(), AppError> {
    if password.len() < MIN_PASSWORD_LENGTH {
        return Err(AppError::InvalidRequest(
            format!("Password must be at least {MIN_PASSWORD_LENGTH} characters")
        ));
    }

    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| "!@#$%^&*".contains(c));

    if !(has_upper && has_lower && has_digit && has_special) {
        return Err(AppError::InvalidRequest(
            "Password must contain at least one uppercase, lowercase, digit, and special character".into()
        ));
    }

    Ok(())
}

pub async fn register_user(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, AppError> {
    validate_password(&payload.password)?;

    let mut tx = state.db.begin().await?;
    let user_id = Uuid::new_v4();

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(payload.password.as_bytes(), &salt)
        .map_err(|e| AppError::InvalidRequest(format!("Password hashing failed: {e}")))?
        .to_string();

    let user = sqlx::query!(
        r#"INSERT INTO users (
            user_id, username, hashed_password, email, role
        ) VALUES ($1, $2, $3, $4, 'user')
        RETURNING user_id"#,
        user_id,
        payload.username,
        password_hash,
        payload.email
    )
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query!(
        "INSERT INTO audit_logs (log_id, user_id, action_type)
         VALUES ($1, $2, $3)",
        Uuid::new_v4(),
        user.user_id,
        "user_register"
    )
    .execute(&mut *tx)
    .await?;

    let token = auth::create_token(&user.user_id.to_string(), &state.jwt_secret)
        .map_err(|_| AppError::Auth("Token creation failed".into()))?;

    tx.commit().await?;

    Ok(Json(RegisterResponse {
        token,
        user_id: user.user_id,
    }))
}

pub async fn login_user(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let mut tx = state.db.begin().await?;
    
    let user = sqlx::query!(
        r#"SELECT user_id, hashed_password, is_banned 
           FROM users WHERE username = $1"#,
        payload.username
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::Auth("Invalid credentials".into()))?;

    if user.is_banned {
        return Err(AppError::PermissionDenied);
    }

    let parsed_hash = PasswordHash::new(&user.hashed_password)
        .map_err(|_| AppError::Auth("Invalid password storage".into()))?;

    Argon2::default()
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .map_err(|_| AppError::Auth("Invalid credentials".into()))?;

    let token = auth::create_token(&user.user_id.to_string(), &state.jwt_secret)
        .map_err(|_| AppError::Auth("Token creation failed".into()))?;

    sqlx::query!(
        r#"INSERT INTO audit_logs (
            log_id, user_id, action_type, description
        ) VALUES ($1, $2, $3, $4)"#,
        Uuid::new_v4(),
        user.user_id,
        "login",
        "Successful authentication"
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Json(LoginResponse {
        token,
        user_id: user.user_id,
    }))
}

pub async fn get_user(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<UserResponse>, AppError> {
    let user = sqlx::query_as!(
        UserResponse,
        r#"SELECT user_id, username, email, bio, profile_picture
           FROM users WHERE user_id = $1"#,
        user_id
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound("User not found".into()))?;

    Ok(Json(user))
}

pub async fn update_user(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, AppError> {
    let mut tx = state.db.begin().await?;
    let user_id = Uuid::parse_str(&claims.sub)?;

    if let Some(email) = &payload.email {
        if !email.contains('@') || email.len() < 3 {
            return Err(AppError::InvalidRequest("Invalid email format".into()));
        }
    }
    
    let user = sqlx::query_as!(
        UserResponse,
        r#"SELECT user_id, username, email, bio, profile_picture
           FROM users WHERE user_id = $1"#,
        user_id
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound("User not found".into()))?;

    sqlx::query!(
        "INSERT INTO audit_logs (log_id, user_id, action_type)
         VALUES ($1, $2, $3)",
        Uuid::new_v4(),
        user_id,
        "user_update"
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(Json(user))
}

pub async fn update_profile_picture(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    mut multipart: Multipart,
) -> Result<Json<String>, AppError> {
    let mut tx = state.db.begin().await?;
    let user_id = Uuid::parse_str(&claims.sub)?;

    let field = multipart.next_field().await
        .map_err(|e| AppError::InvalidRequest(format!("Multipart error: {}", e)))?
        .ok_or(AppError::InvalidRequest("No file uploaded".into()))?;

    let image_data = images::validate_image(field, &state).await?;
    let filename = format!(
        "{}.{}",
        Uuid::new_v4(),
        images::get_extension(&image_data.content_type)
            .map_err(|_| AppError::InvalidFileType)?
    );

    let path = state.profile_image_dir.join(&filename);
    tokio::fs::write(&path, image_data.data)
        .await
        .map_err(|e| AppError::InternalServerError)?;

    // Delete old profile picture
    let old_filename = sqlx::query_scalar!(
        "SELECT profile_picture FROM users WHERE user_id = $1",
        user_id
    )
    .fetch_optional(&mut *tx)
    .await?
    .flatten();

    if let Some(old_file) = old_filename.filter(|s| !s.is_empty()) {
        let old_path = state.profile_image_dir.join(&old_file);
        tokio::fs::remove_file(old_path)
            .await
            .map_err(|e| AppError::InternalServerError)?;
    }

    sqlx::query!(
        "UPDATE users SET profile_picture = $1 WHERE user_id = $2",
        filename,
        user_id
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!(
        "INSERT INTO audit_logs (log_id, user_id, action_type, target_id, description)
         VALUES ($1, $2, $3, $4, $5)",
        Uuid::new_v4(),
        user_id,
        "profile_picture_update",
        user_id,
        format!("Updated profile picture to {}", filename)
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(Json(filename))
}

pub fn users_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/register", post(register_user))
        .route("/login", post(login_user))
        .route("/:user_id", get(get_user))
        .route("/", post(update_user))
        .route("/profile/picture", post(update_profile_picture))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            5 * 1024 * 1024 // 5MB limit
        ))
}
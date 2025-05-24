use axum::{
    body::Body,
    http::Request,
    middleware::Next,
    response::Response,
};
use uuid::Uuid;
use crate::{AppState, auth::{self, Claims}};
use crate::errors::AppError;
use std::sync::Arc;
use chrono::Utc;

pub async fn auth_middleware(
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let state = req.extensions()
        .get::<Arc<AppState>>()
        .ok_or(AppError::InternalServerError)?;

    let auth_header = req.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(AppError::Auth("Missing Authorization header".into()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(AppError::Auth("Authorization header must be 'Bearer <token>'".into()))?;

    let claims = auth::validate_token(token, &state.jwt_secret)
        .map_err(|e| AppError::Auth(format!("Invalid token: {}", e)))?;

    let user_id = Uuid::parse_str(&claims.sub)?;

    let user = sqlx::query!(
        "SELECT is_banned, banned_until FROM users WHERE user_id = $1",
        user_id
    )
    .fetch_one(&state.db)
    .await?;

    if user.is_banned || user.banned_until.map(|t| t > Utc::now()).unwrap_or(false) {
        tracing::warn!("Banned user attempted access: {}", user_id);
        return Err(AppError::PermissionDenied);
    }

    let mut req = req;
    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

pub async fn admin_middleware(
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let claims = req.extensions()
        .get::<Claims>()
        .ok_or(AppError::Auth("Missing claims".into()))?;

    let state = req.extensions()
        .get::<Arc<AppState>>()
        .ok_or(AppError::InternalServerError)?;

    let user_id = Uuid::parse_str(&claims.sub)?;

    let user = sqlx::query!(
        "SELECT role FROM users WHERE user_id = $1",
        user_id
    )
    .fetch_one(&state.db)
    .await?;

    if !matches!(user.role.as_str(), "admin" | "super_admin") {
        return Err(AppError::PermissionDenied);
    }

    Ok(next.run(req).await)
}
use std::sync::Arc;

use axum::{extract::{Path, State}, http::StatusCode, routing::post, Extension, Json, Router};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;


use crate::{auth::Claims, errors::AppError, roles::{require_role, RequiredRole}, AppState};

#[derive(Deserialize)]
struct BanRequest {
    permanent: bool,
    duration_hours: Option<i32>,
}

pub async fn ban_user(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<Uuid>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<BanRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::InvalidRequest("Invalid user ID".to_string()))?;

    require_role(RequiredRole::Admin, &state, user_id).await?;

    let (is_banned, banned_until) = if payload.permanent {
        (true, None)
    } else {
        let duration = Duration::hours(payload.duration_hours.unwrap_or(24) as i64);
        (false, Some(Utc::now() + duration))
    };

    sqlx::query!(
        "UPDATE users 
        SET is_banned = $1, banned_until = $2 
        WHERE user_id = $3",
        is_banned,
        banned_until,
        user_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
    })?;

    Ok(Json(json!({"status": "User banned successfully"})))
}

async fn promote_to_admin(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<Uuid>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::InvalidRequest("Invalid user ID".to_string()))?;

    require_role(RequiredRole::SuperAdmin, &state, user_id).await?;

    sqlx::query!(
        "UPDATE users SET role = 'admin' WHERE user_id = $1",
        user_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
    })?;

    Ok(Json(json!({"status": "User promoted to admin"})))
}

async fn delete_product(
    State(state): State<Arc<AppState>>,
    Path(product_id): Path<Uuid>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::InvalidRequest("Invalid user ID".to_string()))?;

    require_role(RequiredRole::Admin, &state, user_id).await?;

    sqlx::query!(
        "DELETE FROM products WHERE product_id = $1",
        product_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
    })?;

    Ok(Json(json!({"status": "Product deleted"})))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/ban-user/:user_id", post(ban_user))
        .route("/promote-to-admin/:user_id", post(promote_to_admin))
        .route("/delete-product/:product_id", post(delete_product))
}
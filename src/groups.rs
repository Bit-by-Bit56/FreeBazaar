use std::sync::Arc;
use axum::{extract::{Path, State}, http::StatusCode, routing::{get, post}, Extension, Json, Router};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;
use crate::{auth::Claims, errors::AppError, product::Product, AppState};

#[derive(Deserialize)]
struct CreateGroupRequest {
    name: String,
    description: Option<String>,
}


async fn create_group(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<CreateGroupRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let group_id = Uuid::new_v4();
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::InvalidRequest("Invalid user ID".to_string()))?;

    // Start transaction
    let mut tx = state.db.begin().await.map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
    })?;

    // Create group
    sqlx::query!(
        "INSERT INTO groups (group_id, name, description, owner_id)
        VALUES ($1, $2, $3, $4)",
        group_id,
        payload.name,
        payload.description,
        user_id
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Add owner as admin
    sqlx::query!(
        "INSERT INTO group_members (group_id, user_id, role)
        VALUES ($1, $2, 'admin')",
        group_id,
        user_id
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tx.commit().await.map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Commit failed: {}", e))
    })?;

    Ok(Json(json!({"group_id": group_id})))
}

async fn invite_user(
    State(state): State<Arc<AppState>>,
    Path((group_id, user_id)): Path<(Uuid, Uuid)>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>, AppError> {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::InvalidRequest("Invalid user ID".to_string()))?;

    // Verify inviter is group owner
    let is_owner: Option<bool> = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM groups WHERE group_id = $1 AND owner_id = $2)",
        group_id,
        user_id
    )
    .fetch_one(&state.db)
    .await?;
    
    if !is_owner.unwrap_or(false) {
        return Err((StatusCode::FORBIDDEN, "Only group owner can invite").into());
    }

    // Create invite
    let invite_id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO group_invites (invite_id, group_id, sender_id, recipient_id)
        VALUES ($1, $2, $3, $4)",
        invite_id,
        group_id,
        invite_id,
        user_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
    })?;

    Ok(Json(json!({"invite_id": invite_id})))
}

async fn group_products(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<Uuid>,
) -> Result<Json<Vec<Product>>, AppError> {
    let products = sqlx::query_as!(
        Product,
        "SELECT 
            product_id, user_id, name, short_description, 
            full_description, tags, price, images, 
            created_at, updated_at, group_id 
        FROM products WHERE group_id = $1",
        group_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e))
    })?;

    Ok(Json(products))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/create", post(create_group))
        .route("/invite/:group_id/:user_id", post(invite_user))
        .route("/products/:group_id", get(group_products))
}
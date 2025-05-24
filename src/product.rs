use axum::{
    extract::{Extension, Json, Multipart, Path, State}, routing::{delete, get, patch, post}, Router
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
use std::sync::Arc;
use crate::{errors::AppError, images, AppState};
use crate::auth::Claims;


/// Represents a review for a product.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Review {
    pub product_id: Uuid,
    pub review_id: Uuid,
    pub reviewer_id: Uuid,
    pub rating: i16,
    pub comment: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// Represents a product listed on your Bazaar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Product {
    pub product_id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub short_description: String,
    pub full_description: Option<String>,
    pub tags: Option<Vec<String>>,
    pub price: f64,
    pub images: Option<Vec<String>>,
    pub group_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

// ----- Request Payloads -----

#[derive(Debug, Deserialize)]
pub struct CreateProductRequest {
    pub name: String,
    pub short_description: String,
    pub full_description: Option<String>,
    pub tags: Option<Vec<String>>,
    pub price: f64,
    pub group_id: Option<Uuid>,
    pub images: Option<Vec<String>>,
}

/// Represens an update request
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProductRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteProductRequest {
    pub product_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct AddReviewRequest {
    pub product_id: Uuid,
    pub rating: u8,
    pub comment: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateReviewRequest {
    pub product_id: Uuid,
    pub review_id: Uuid,
    pub rating: Option<u8>,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteReviewRequest {
    pub product_id: Uuid,
    pub review_id: Uuid,
}

// ----- Handlers – Products -----

/// Create a new product.
pub async fn create_product(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<CreateProductRequest>,
) -> Result<Json<Product>, AppError> {
    let mut tx = state.db.begin().await?;
    let user_id = Uuid::parse_str(&claims.sub)?;

    if payload.price <= 0.0 {
        return Err(AppError::InvalidRequest(
            "Price must be greater than zero".into()
        ));
    }

    let product_id = Uuid::new_v4();
    let now = Utc::now();

    let product = sqlx::query_as!(
        Product,
        r#"INSERT INTO products (
            product_id, user_id, name, price, 
            short_description, full_description, tags, 
            group_id, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING *"#,
        product_id,
        user_id,
        payload.name,
        payload.price,
        payload.short_description,
        payload.full_description,
        payload.tags.as_deref(),
        payload.group_id,
        now,
        now
    )
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query!(
        "INSERT INTO audit_logs (log_id, user_id, action_type, target_id)
         VALUES ($1, $2, $3, $4)",
        Uuid::new_v4(),
        user_id,
        "product_create",
        product_id
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(Json(product))
}

/// Get a product by its UUID.
pub async fn get_product(
    State(state): State<Arc<AppState>>,
    Path(product_id): Path<Uuid>,
) -> Result<Json<Product>, AppError> {
    let product = sqlx::query_as!(
        Product,
        r#"SELECT 
            product_id, user_id, name, price, 
            tags as "tags?: Vec<String>", 
            short_description, full_description, 
            images as "images?: Vec<String>", 
            group_id, created_at, updated_at
        FROM products 
        WHERE product_id = $1"#,
        product_id
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound("Product not found".into()))?;

    Ok(Json(product))
}


pub async fn update_product(
    State(state): State<Arc<AppState>>,
    Path(product_id): Path<Uuid>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<UpdateProductRequest>,
) -> Result<Json<Product>, AppError> {
    let mut tx = state.db.begin().await?;
    let user_id = Uuid::parse_str(&claims.sub)?;

    // Verify ownership
    let product = sqlx::query!(
        "SELECT user_id FROM products WHERE product_id = $1",
        product_id
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::NotFound("Product not found".into()))?;

    if product.user_id != user_id {
        return Err(AppError::PermissionDenied);
    }

    if let Some(price) = payload.price {
        if price <= 0.0 {
            return Err(AppError::InvalidRequest(
                "Price must be greater than zero".into()
            ));
        }
    }

    let updated_product = sqlx::query_as!(
        Product,
        r#"UPDATE products
        SET 
            name = COALESCE($1, name),
            price = COALESCE($2, price),
            short_description = COALESCE($3, short_description),
            full_description = COALESCE($4, full_description),
            tags = COALESCE($5, tags),
            group_id = COALESCE($6, group_id),
            updated_at = $7
        WHERE product_id = $8
        RETURNING *"#,
        payload.name,
        payload.price,
        payload.short_description,
        payload.full_description,
        payload.tags.as_deref(),
        payload.group_id,
        Utc::now(),
        product_id
    )
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query!(
        "INSERT INTO audit_logs (log_id, user_id, action_type, target_id)
         VALUES ($1, $2, $3, $4)",
        Uuid::new_v4(),
        user_id,
        "product_update",
        product_id
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(Json(updated_product))
}

/// Upload product images via multipart form data.
pub async fn upload_product_images(
    State(state): State<Arc<AppState>>,
    Path(product_id): Path<Uuid>,
    Extension(claims): Extension<Claims>,
    mut multipart: Multipart,
) -> Result<Json<Vec<String>>, AppError> {
    let mut tx = state.db.begin().await?;
    let user_id = Uuid::parse_str(&claims.sub)?;

    let product = sqlx::query!(
        "SELECT user_id FROM products WHERE product_id = $1",
        product_id
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::NotFound("Product not found".into()))?;

    if product.user_id != user_id {
        return Err(AppError::PermissionDenied);
    }

    let mut filenames = Vec::new();
    let image_dir = state.product_image_dir.join(product_id.to_string());
    tokio::fs::create_dir_all(&image_dir)
    .await
    .map_err(|e| AppError::InternalServerError)?;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        AppError::InvalidRequest(format!("Invalid multipart field: {}", e))
    })? {
        let image_data = images::validate_image(field, &state).await?;

        let ext = images::get_extension(&image_data.content_type)
            .map_err(|_| AppError::InvalidFileType)?;
    
        let filename = format!("{}_{}.{}", Uuid::new_v4(), product_id, ext);
        let path = image_dir.join(&filename);
        
        tokio::fs::write(&path, image_data.data)
        .await.map_err(|e| AppError::InternalServerError)?;
    }

    sqlx::query!(
        "UPDATE products 
         SET images = array_cat(images, $1), updated_at = $2
         WHERE product_id = $3",
        &filenames,
        Utc::now(),
        product_id
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!(
        "INSERT INTO audit_logs (log_id, user_id, action_type, target_id, description)
         VALUES ($1, $2, $3, $4, $5)",
        Uuid::new_v4(),
        user_id,
        "product_images_upload",
        product_id,
        format!("Uploaded {} images", filenames.len())
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(Json(filenames))
}

/// Delete a product.
pub async fn delete_product(
    State(state): State<Arc<AppState>>,
    Path(product_id): Path<Uuid>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut tx = state.db.begin().await?;
    let user_id = Uuid::parse_str(&claims.sub)?;

    // Verify ownership
    let product = sqlx::query!(
        "SELECT user_id, images FROM products WHERE product_id = $1",
        product_id
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::NotFound("Product not found".into()))?;

    if product.user_id != user_id {
        return Err(AppError::PermissionDenied);
    }

    // Delete database record
    sqlx::query!(
        "DELETE FROM products WHERE product_id = $1",
        product_id
    )
    .execute(&mut *tx)
    .await?;

    // Delete associated images
    if let Some(images) = product.images {
        let image_dir = state.product_image_dir.join(product_id.to_string());
        for image in images {
            let path = image_dir.join(image);
            if let Err(e) = tokio::fs::remove_file(&path).await {
                tracing::warn!("Failed to delete image {}: {}", path.display(), e);
            }
        }
        if let Err(e) = tokio::fs::remove_dir(image_dir).await {
            tracing::warn!("Failed to delete image directory: {}", e);
        }
    }

    sqlx::query!(
        "INSERT INTO audit_logs (log_id, user_id, action_type, target_id)
         VALUES ($1, $2, $3, $4)",
        Uuid::new_v4(),
        user_id,
        "product_delete",
        product_id
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Json(json!({
        "status": "success",
        "message": "Product deleted"
    })))
}

// ----- Handlers – Reviews -----

#[derive(Debug, Deserialize)]
pub struct ReviewRequest {
    pub rating: i16,
    pub comment: String,
}

pub async fn create_review(
    State(state): State<Arc<AppState>>,
    Path(product_id): Path<Uuid>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<ReviewRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut tx = state.db.begin().await?;
    let reviewer_id = Uuid::parse_str(&claims.sub)?;

    // Validate rating
    if !(1..=10).contains(&payload.rating) {
        return Err(AppError::InvalidRequest(
            "Rating must be between 1 and 10".into()
        ));
    }

    // Check existing review
    let exists = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM reviews 
         WHERE product_id = $1 AND reviewer_id = $2)",
        product_id,
        reviewer_id
    )
    .fetch_one(&mut *tx)
    .await?
    .unwrap_or(false);

    if exists {
        return Err(AppError::InvalidRequest(
            "You already reviewed this product".into()
        ));
    }

    let review_id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO reviews (
            review_id, product_id, reviewer_id, 
            rating, comment
        ) VALUES ($1, $2, $3, $4, $5)",
        review_id,
        product_id,
        reviewer_id,
        payload.rating,
        payload.comment
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!(
        "INSERT INTO audit_logs (log_id, user_id, action_type, target_id, description)
         VALUES ($1, $2, $3, $4, $5)",
        Uuid::new_v4(),
        reviewer_id,
        "review_create",
        review_id,
        format!("Created review for product {}", product_id)
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Json(json!({
        "review_id": review_id,
        "status": "created"
    })))
}

#[derive(Debug, Serialize)]
pub struct ReviewResponse {
    pub review_id: Uuid,
    pub product_id: Uuid,
    pub reviewer_id: Uuid,
    pub rating: i16,
    pub comment: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

pub async fn update_review(
    State(state): State<Arc<AppState>>,
    Path((product_id, review_id)): Path<(Uuid, Uuid)>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<ReviewRequest>,
) -> Result<Json<ReviewResponse>, AppError> {
    let mut tx = state.db.begin().await?;
    let reviewer_id = Uuid::parse_str(&claims.sub)?;

    // Validate rating
    if !(1..=10).contains(&payload.rating) {
        return Err(AppError::InvalidRequest(
            "Rating must be between 1 and 10".into()
        ));
    }

    let review = sqlx::query_as!(
        ReviewResponse,
        r#"UPDATE reviews 
        SET 
            rating = $1,
            comment = $2,
            updated_at = $3
        WHERE review_id = $4
          AND product_id = $5
          AND reviewer_id = $6
        RETURNING *"#,
        payload.rating,
        payload.comment,
        Utc::now(),
        review_id,
        product_id,
        reviewer_id
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::NotFound("Review not found".into()))?;

    sqlx::query!(
        "INSERT INTO audit_logs (log_id, user_id, action_type, target_id, description)
         VALUES ($1, $2, $3, $4, $5)",
        Uuid::new_v4(),
        reviewer_id,
        "review_update",
        review_id,
        format!("Updated review for product {}", product_id)
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Json(review))
}

pub async fn delete_review(
    State(state): State<Arc<AppState>>,
    Path((product_id, review_id)): Path<(Uuid, Uuid)>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut tx = state.db.begin().await?;
    let reviewer_id = Uuid::parse_str(&claims.sub)?;

    // Verify review exists and belongs to user
    let review = sqlx::query!(
        "SELECT review_id FROM reviews 
         WHERE review_id = $1 
           AND product_id = $2 
           AND reviewer_id = $3",
        review_id,
        product_id,
        reviewer_id
    )
    .fetch_optional(&mut *tx)
    .await?;

    if review.is_none() {
        return Err(AppError::NotFound("Review not found".into()));
    }

    sqlx::query!(
        "DELETE FROM reviews 
         WHERE review_id = $1",
        review_id
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!(
        "INSERT INTO audit_logs (log_id, user_id, action_type, target_id, description)
         VALUES ($1, $2, $3, $4, $5)",
        Uuid::new_v4(),
        reviewer_id,
        "review_delete",
        review_id,
        format!("Deleted review from product {}", product_id)
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Json(json!({
        "status": "success",
        "message": "Review deleted",
        "review_id": review_id
    })))
}
// Returns an Axum Router that registers all product and review endpoints.
pub fn product_routes() -> Router<Arc<AppState>> {
    Router::new()
        // Product endpoints
        .route("/", post(create_product))
        .route("/:product_id", get(get_product))
        .route("/:product_id", patch(update_product))
        .route("/:product_id", delete(delete_product))
        .route("/:product_id/images", post(upload_product_images))
        // Review endpoints
        .route("/:product_id/reviews", post(create_review))
        .route("/:product_id/reviews/:review_id", patch(update_review))
        .route("/:product_id/reviews/:review_id", delete(delete_review))

}
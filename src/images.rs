use axum::body::Bytes;
use mime::Mime;
use uuid::Uuid;

use crate::errors::AppError;

pub struct ImageData {
    pub data: Bytes,
    pub content_type: Mime,
}

pub async fn validate_image(
    field: axum::extract::multipart::Field<'_>,
    state: &crate::AppState,
) -> Result<ImageData, AppError> {
    let content_type = field.content_type()
        .ok_or(AppError::InvalidRequest("Missing Content-Type".into()))?
        .parse::<mime::Mime>()
        .map_err(|_| AppError::InvalidRequest("Invalid MIME type".into()))?;

    if !state.allowed_mime_types.contains(&content_type) {
        return Err(AppError::InvalidFileType);
    }

    let data = field.bytes().await.map_err(|e| 
        AppError::InvalidRequest(format!("Failed to read file: {}", e))
    )?;

    if data.len() > state.max_image_size {
        return Err(AppError::InvalidRequest(format!(
            "File size exceeds {}MB limit",
            state.max_image_size / 1024 / 1024
        )));
    }

    Ok(ImageData {
        data,
        content_type,
    })
}

pub fn generate_filename(id: Uuid) -> String {
    format!("{}_{}", id, Uuid::new_v4())
}

pub fn get_extension(mime: &Mime) -> Result<&str, AppError> {
    match mime.subtype().as_str() {
        "jpeg" => Ok("jpg"),
        "png" => Ok("png"),
        "webp" => Ok("webp"),
        _ => Err(AppError::InvalidFileType),
    }
}
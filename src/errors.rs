use axum::{
    response::{Response, IntoResponse},
    http::StatusCode,
    Json
};
use serde_json::json;
use sqlx::Error as SqlxError;

#[derive(Debug)]
pub enum AppError {
    Database(SqlxError),
    Auth(String),
    InvalidRequest(String),
    PermissionDenied,
    NotFound(String),
    RateLimited,
    InvalidFileType,
    InternalServerError,
}

impl From<SqlxError> for AppError {
    fn from(err: SqlxError) -> Self {
        match err {
            SqlxError::RowNotFound => AppError::NotFound("Resource not found".into()),
            _ => AppError::Database(err),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::Database(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            ),
            AppError::Auth(msg) => (StatusCode::UNAUTHORIZED, msg),
            AppError::InvalidRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::PermissionDenied => (
                StatusCode::FORBIDDEN,
                "Insufficient permissions".into(),
            ),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            AppError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "Too many requests".into(),
            ),
            AppError::InvalidFileType => (
                StatusCode::BAD_REQUEST,
                "Invalid file type".into(),
            ),
            AppError::InternalServerError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".into(),
            ),
        };

        let body = json!({ "error": message });
        (status, Json(body)).into_response()
    }
}

// Conversion for other error types
impl From<std::num::ParseIntError> for AppError {
    fn from(_: std::num::ParseIntError) -> Self {
        AppError::InvalidRequest("Invalid numeric format".into())
    }
}

impl From<uuid::Error> for AppError {
    fn from(_: uuid::Error) -> Self {
        AppError::InvalidRequest("Invalid UUID format".into())
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::InternalServerError
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Database(e) => write!(f, "Database error: {}", e),
            AppError::Auth(msg) => write!(f, "Authentication error: {}", msg),
            AppError::InvalidRequest(msg) => write!(f, "Invalid request: {}", msg),
            AppError::PermissionDenied => write!(f, "Permission denied"),
            AppError::NotFound(msg) => write!(f, "Not found: {}", msg),
            AppError::RateLimited => write!(f, "Too many requests"),
            AppError::InvalidFileType => write!(f, "Invalid file type"),
            AppError::InternalServerError => write!(f, "Internal server error"),
        }
    }
}
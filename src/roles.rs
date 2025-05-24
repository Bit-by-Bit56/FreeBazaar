use uuid::Uuid;
use crate::{errors::AppError, AppState};

#[derive(Debug, PartialEq)]
pub enum RequiredRole {
    User,
    Admin,
    SuperAdmin,
}

pub async fn require_role(
    required_role: RequiredRole,
    state: &AppState,
    user_id: Uuid,
) -> Result<(), AppError> {
    let user = sqlx::query!(
        "SELECT role FROM users WHERE user_id = $1",
        user_id
    )
    .fetch_one(&state.db)
    .await?;

    match (required_role, user.role.as_str()) {
        (RequiredRole::SuperAdmin, "super_admin") => Ok(()),
        (RequiredRole::Admin, "admin") | (RequiredRole::Admin, "super_admin") => Ok(()),
        (RequiredRole::User, _) => Ok(()),
        _ => Err(AppError::PermissionDenied),
    }
}
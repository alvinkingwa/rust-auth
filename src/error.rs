use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;



#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("bcrypt error:{0}")]
    Bcrypt(#[from] bcrypt::BcryptError),

    #[error("jwt error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Email already exists")]
    EmailTaken,

    #[error("Username already exists")]
    UsernameTaken,

    #[error("Missing required information")]
    InvalidCredentials,
    
    #[error("password has to be at least 8 characters long")]
    InvalidPassword,

    #[error("User not found")]
    NotFound,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::Bcrypt(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::Jwt(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::EmailTaken => (StatusCode::CONFLICT, self.to_string()),
            AppError::UsernameTaken => (StatusCode::CONFLICT, self.to_string()),
            AppError::InvalidCredentials => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::InvalidPassword => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
        };

        (status, Json(json!({"error": message}))).into_response()
    }
}

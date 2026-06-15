use axum::{Json, extract::State};
use bcrypt::{DEFAULT_COST, hash, verify};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    AppState,
    error::AppError,
    jwt::create_token,
    mailer::{send_welcome_email,send_forgot_password_email},
    models::{PasswordResetToken, User, UserResponse, generate_random_password},
};

#[derive(Debug,Deserialize)]
pub struct ResetPasswordRequest {
    pub code: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct SignUpRequest {
    pub email: String,
    pub username: String,
}

#[derive(Debug, Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct SetPasswordRequest {
    pub email: String,
    pub temp_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct SignInRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserResponse,
}

#[axum::debug_handler]
pub async fn set_password(
    State(state): State<AppState>,
    Json(body): Json<SetPasswordRequest>,
) -> Result<Json<Value>, AppError> {
    if body.new_password.len() < 8 {
        return Err(AppError::InvalidCredentials);
    }

    let user = User::find_by_email(&state.db, &body.email)
        .await
        .map_err(|_| AppError::InvalidCredentials)?;

    let valid = verify(&body.temp_password, &user.password)?;
    if !valid {
        return Err(AppError::InvalidCredentials);
    }
    let hashed = hash(&body.new_password, DEFAULT_COST)?;
    User::reset_password(&state.db, &body.email, &hashed).await?;

    Ok(Json(json!({
        "message":"Password set successfully. You can sign in."
    })))
}

pub async fn forgot_password(
    State(state): State<AppState>,
    Json(body): Json<ForgotPasswordRequest>,
) -> Result<Json<Value>, AppError> {
    let user = User::find_by_email(&state.db, &body.email)
        .await
        .map_err(|_| AppError::NotFound)?;

    let token = PasswordResetToken::create(&state.db, user.id).await?;

    if let Err(e) = send_forgot_password_email(&user.email, &user.username, &token.token).await {
        tracing::warn!("failed to send password reset email: {}", e);
    }

    Ok(Json(json!({
        "message": "If that email exists, a reset link has been sent."
    })))
}

pub async fn reset_password(
    State(state): State<AppState>,
    Json(body): Json<ResetPasswordRequest>,
) -> Result<Json<Value>, AppError> {
    if body.new_password.len() < 8 {
        return Err(AppError::InvalidCredentials);
    }

    let reset_token = PasswordResetToken::find_valid(&state.db, &body.code).await?;

    let hashed = hash(&body.new_password, DEFAULT_COST)?;
    let user = User::find_by_id(&state.db, reset_token.user_id).await?;
    User::reset_password(&state.db, &user.email, &hashed).await?;

    PasswordResetToken::mark_used(&state.db, &body.code).await?;

    Ok(Json(json!({
        "message": "Password reset successfully. You can now sign in."
    })))
}

pub async fn sign_up(
    State(state): State<AppState>,
    Json(body): Json<SignUpRequest>,
) -> Result<Json<Value>, AppError> {
    if body.email.is_empty() || body.username.is_empty() {
        return Err(AppError::InvalidCredentials);
    }

    // generate random temporary password
    let temp_password = generate_random_password();

    let hashed = hash(&temp_password, DEFAULT_COST)?;
    let user = User::create(&state.db, &body.email, &body.username, &hashed).await?;

    if let Err(e) = send_welcome_email(&user.email, &user.username, &temp_password).await {
        tracing::warn!("failed to send welcome email:{}", e);
    }

    Ok(Json(json!( {
        "message":"Account created successfully. Check you email for your temporary password",
        "user": UserResponse::from(user),
    })))
}

pub async fn sign_in(
    State(state): State<AppState>,
    Json(body): Json<SignInRequest>,
) -> Result<Json<Value>, AppError> {
    let user = User::find_by_email(&state.db, &body.email)
        .await
        .map_err(|_| AppError::InvalidCredentials)?;

    let valid = verify(&body.password, &user.password)?;
    if !valid {
        return Err(AppError::InvalidCredentials);
    }

    let token = create_token(&user.id.to_string(), &user.email, &state.jwt_secret)?;

    Ok(Json(json!(AuthResponse {
        token,
        user: user.into(),
    })))
}

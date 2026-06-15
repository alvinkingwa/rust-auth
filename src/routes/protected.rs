// Two things live here:
// 1. require_auth — middleware that checks the JWT on every protected request
// 2. me()         — the actual protected handler GET /me

use axum::{
    extract::{Request, State},
    http::header,
    middleware::Next,
    response::Response,
    Json,
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{error::AppError, jwt::verify_token, models::{User, UserResponse}, AppState};

// Middleware runs BEFORE the handler.
// If the token is missing or invalid, we return 401 here
// and the actual handler (me) never runs.
pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,         // next = the handler waiting after this middleware
) -> Result<Response, AppError> {

    // Extract the token from the Authorization header
    // Header looks like: "Authorization: Bearer eyJhbGci..."
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ")) // remove "Bearer " prefix
        .ok_or(AppError::InvalidCredentials)?;   // return 401 if missing

    // Verify the token — checks signature + expiry
    let claims = verify_token(auth_header, &state.jwt_secret)?;

    // Parse the user id from the token's "sub" field
    let user_id: Uuid = claims.sub.parse().map_err(|_| AppError::InvalidCredentials)?;

    // Attach user_id to the request so the handler can read it
    // This avoids having to verify the token a second time in the handler
    req.extensions_mut().insert(user_id);

    // Pass the request on to the actual handler
    Ok(next.run(req).await)
}

// GET /me — returns the logged in user's profile
// Only reachable if require_auth passed
pub async fn me(
    State(state): State<AppState>,
    req: Request,
) -> Result<Json<Value>, AppError> {

    // Pull the user_id that require_auth injected into the request
    let user_id = req
        .extensions()
        .get::<Uuid>()
        .copied()
        .ok_or(AppError::InvalidCredentials)?;

    // Fetch full user from database
    let user = User::find_by_id(&state.db, user_id).await?;

    Ok(Json(json!(UserResponse::from(user))))
}
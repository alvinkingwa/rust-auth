use axum::{
    Json,
    extract::{Query, State},
    response::{IntoResponse, Redirect},
};
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope,
    TokenResponse, TokenUrl, basic::BasicClient,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::env;

use crate::{AppState, error::AppError, jwt::create_token, models::User};

// shape of the JSON Google sends back about the logged in user
#[derive(Debug, Deserialize)]
pub struct GoogleUserInfo {
    pub id: String,
    pub email: String,
    pub name: String,
}

// query params Google sends back to our callback URL
#[derive(Debug, Deserialize)]
pub struct GoogleCallbackQuery {
    pub code: String,
}

// builds the oauth2 client using credentials from .env
fn build_oauth_client() -> BasicClient {
    let client_id =
        ClientId::new(env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID must be set"));
    let client_secret = ClientSecret::new(
        env::var("GOOGLE_CLIENT_SECRET").expect("GOOGLE_CLIENT_SECRET must be set"),
    );
    let redirect_uri = env::var("GOOGLE_REDIRECT_URI").expect("GOOGLE_REDIRECT_URI must be set");

    let auth_url =
        AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string()).unwrap();
    let token_url = TokenUrl::new("https://oauth2.googleapis.com/token".to_string()).unwrap();

    BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
        .set_redirect_uri(RedirectUrl::new(redirect_uri).unwrap())
}

// GET /auth/google
// redirects the browser to Google's login page
pub async fn google_login() -> impl IntoResponse {
    let client = build_oauth_client();

    let (auth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .url();

    // send the browser to Google's consent screen
    Redirect::to(auth_url.as_str())
}

// GET /auth/google/callback
// Google redirects here after the user approves login
pub async fn google_callback(
    State(state): State<AppState>,
    Query(query): Query<GoogleCallbackQuery>,
) -> Result<Json<Value>, AppError> {
    let client = build_oauth_client();

    // exchange the authorization code for an access token
    let token_result = client
        .exchange_code(AuthorizationCode::new(query.code))
        .request_async(oauth2::reqwest::async_http_client)
        .await
        .map_err(|_| AppError::InvalidCredentials)?;

    let access_token = token_result.access_token().secret();

    // use the access token to fetch the user's Google profile
    let user_info: GoogleUserInfo = reqwest::Client::new()
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|_| AppError::InvalidCredentials)?
        .json()
        .await
        .map_err(|_| AppError::InvalidCredentials)?;

    // find existing user by google_id, or create a new one
    let user = User::find_or_create_google_user(
        &state.db,
        &user_info.id,
        &user_info.email,
        &user_info.name,
    )
    .await?;

    // issue our own JWT just like normal signin
    let token = create_token(&user.id.to_string(), &user.email, &state.jwt_secret)?;

    Ok(Json(json!({
        "token": token,
        "user": {
            "id": user.id,
            "email": user.email,
            "username": user.username,
        }
    })))
}

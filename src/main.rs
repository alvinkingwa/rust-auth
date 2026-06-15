mod error;
mod jwt;
mod mailer;
mod models;
mod routes;

use axum::{
    Router, middleware,
    routing::{get, post},
};
use sqlx::PgPool;
use std::env;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use routes::{
    auth::{forgot_password, reset_password, set_password, sign_in, sign_up},
    protected::{me, require_auth},
};

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub jwt_secret: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            env::var("RUST_LOG").unwrap_or_else(|_| "auth_backend=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let jwt_secret =
        env::var("JWT_SECRET").unwrap_or_else(|_| "change_me_in_production".to_string());
    let port = env::var("PORT").unwrap_or_else(|_| "3000".to_string());

    let pool = PgPool::connect(&database_url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    info!("Database connected and migrated");

    let state = AppState {
        db: pool,
        jwt_secret,
    };

    let app = Router::new()
        .route("/auth/signup", post(sign_up))
        .route("/auth/signin", post(sign_in))
        .route("/auth/set-password", post(set_password))
        .route("/auth/forgot-password", post(forgot_password))
        .route("/auth/reset-password", post(reset_password))
        .route(
            "/me",
            get(me).route_layer(middleware::from_fn_with_state(state.clone(), require_auth)),
        )
        .route("/health", get(|| async { "OK" }))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    info!("Listening on http://0.0.0.0:{port}");
    axum::serve(listener, app).await?;

    Ok(())
}

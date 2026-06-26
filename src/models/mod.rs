use chrono::{DateTime, Utc};
use rand::{Rng, RngExt};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AppError;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password: Option<String>,
    pub google_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct PasswordResetToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserResponse,
}




impl From<User> for UserResponse {
    fn from(u: User) -> Self {
        UserResponse {
            id: u.id,
            username: u.username,
            email: u.email,
            created_at: u.created_at,
        }
    }
}

pub fn generate_random_password() -> String {
    let charset: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    (0..12)
        .map(|_| {
            let idx = rng.random_range(0..charset.len());
            charset[idx] as char
        })
        .collect()
}

impl PasswordResetToken {
    pub async fn create(pool: &PgPool, user_id: Uuid) -> Result<Self, AppError> {
        let token = generate_random_password();
        let expires_at = Utc::now() + chrono::Duration::hours(1);

        let reset_token = sqlx::query_as::<_, PasswordResetToken>(
            "INSERT INTO password_reset_tokens (user_id, token, expires_at)
             VALUES ($1, $2, $3)
             RETURNING *"
        )
        .bind(user_id)
        .bind(&token)
        .bind(expires_at)
        .fetch_one(pool)
        .await?;

        Ok(reset_token)
    }

    pub async fn find_valid(pool: &PgPool, token: &str) -> Result<Self, AppError> {
        sqlx::query_as::<_, PasswordResetToken>(
            "SELECT * FROM password_reset_tokens
             WHERE token = $1 AND used = FALSE AND expires_at > NOW()"
        )
        .bind(token)
        .fetch_optional(pool)
        .await?
        .ok_or(AppError::InvalidCredentials)
    }

    pub async fn mark_used(pool: &PgPool, token: &str) -> Result<(), AppError> {
        sqlx::query("UPDATE password_reset_tokens SET used = TRUE WHERE token = $1")
            .bind(token)
            .execute(pool)
            .await?;
        Ok(())
    }
}

impl User {
    pub async fn create(
        pool: &PgPool,
        email: &str,
        username: &str,
        hashed_password: &str,
    ) -> Result<Self, AppError> {
        let user = sqlx::query_as::<_, User>(
            "INSERT INTO users (email, username, password)
             VALUES ($1, $2, $3)
             RETURNING *",
        )
        .bind(email)
        .bind(username)
        .bind(hashed_password)
        .fetch_one(pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(db_err) => {
                let msg = db_err.message().to_owned();
                if msg.contains("users_email_key") {
                    AppError::EmailTaken
                } else {
                    AppError::Database(sqlx::Error::Database(db_err))
                }
            }
            other => AppError::Database(other),
        })?;

        Ok(user)
    }

    pub async fn find_by_email(pool: &PgPool, email: &str) -> Result<Self, AppError> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(pool)
            .await?
            .ok_or(AppError::NotFound)
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Self, AppError> {
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await?
            .ok_or(AppError::NotFound)
    }

    pub async fn reset_password(
        pool: &PgPool,
        email: &str,
        hashed_password: &str,
    ) -> Result<Self, AppError> {
        sqlx::query_as::<_, User>(
            "UPDATE users SET password = $1 WHERE email = $2 RETURNING *"
        )
        .bind(hashed_password)
        .bind(email)
        .fetch_optional(pool)
        .await?
        .ok_or(AppError::NotFound)
    }

    // MOVED: now inside impl User so Self works
    // also FIXED: added missing .await? and Ok(user)
    pub async fn find_or_create_google_user(
        pool: &PgPool,
        google_id: &str,
        email: &str,
        username: &str,
    ) -> Result<Self, AppError> {
        let existing = sqlx::query_as::<_, User>("SELECT * FROM users WHERE google_id = $1")
            .bind(google_id)
            .fetch_optional(pool)
            .await?;

        if let Some(user) = existing {
            return Ok(user);
        }

        let user = sqlx::query_as::<_, User>(
            "INSERT INTO users (email, username, google_id)
             VALUES ($1, $2, $3)
             RETURNING *"
        )
        .bind(email)
        .bind(username)
        .bind(google_id)
        .fetch_one(pool)
        .await?;  

        Ok(user) 
    }
}
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::header::ContentType,
    transport::smtp::authentication::Credentials,
};
use std::env;

pub async fn send_welcome_email(
    to_email: &str,
    username: &str,
    temp_password: &str,
) -> Result<(), String> {
    // load smtp config from .env
    let smtp_host = env::var("SMTP_HOST").expect("SMTP_HOST must be set");
    let smtp_user = env::var("SMTP_USER").expect("SMTP_USER must be set");
    let smtp_pass = env::var("SMTP_PASS").expect("SMTP_PASS must be set");

    // build the email
    let email = Message::builder()
        .from(
            smtp_user
                .parse()
                .map_err(|e| format!("Invalid from: {e}"))?,
        )
        .to(to_email.parse().map_err(|e| format!("Invalid to: {e}"))?)
        .subject("Welcome to Auth Backend!.Your Temporary password")
        .header(ContentType::TEXT_HTML)
        .body(format!(
            // email body — plain HTML
            r#"
            <h1>Welcome, {}!</h1>
            <p>Your account has been created successfully.</p>
             <p>Your temporary password is:</p>
    <h2 style="background:#f4f4f4; padding:10px; color:#333;">{}</h2>  
    <p>Use this to set your new password.</p>
            "#,
            username, temp_password
        ))
        .map_err(|e| format!("Failed to build email: {e}"))?;

    // smtp credentials
    let creds = Credentials::new(smtp_user, smtp_pass);

    // connect to smtp server
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp_host)
        .map_err(|e| format!("Failed to connect to SMTP: {e}"))?
        .credentials(creds)
        .build();

    // send it
    mailer
        .send(email)
        .await
        .map_err(|e| format!("Failed to send email: {e}"))?;

    Ok(())
}

pub async fn send_forgot_password_email(
    to_email: &str,
    username: &str,
    reset_token: &str,
) -> Result<(), String> {
    let smtp_host = env::var("SMTP_HOST").expect("SMTP_HOST must be set");
    let smtp_user = env::var("SMTP_USER").expect("SMTP_USER must be set");
    let smtp_pass = env::var("SMTP_PASS").expect("SMTP_PASS must be set");

    let email = Message::builder()
        .from(smtp_user.parse().map_err(|e| format!("Invalid from: {e}"))?)
        .to(to_email.parse().map_err(|e| format!("Invalid to: {e}"))?)
        // CHANGED: subject now says "code" not "token"
        .subject("Reset Your Password — Your Verification Code")
        .header(ContentType::TEXT_HTML)
        .body(format!(
            r#"
            <h1>Password Reset Request</h1>
            <p>Hi {},</p>
            <p>We received a request to reset your password.</p>
            // CHANGED: "token" -> "verification code"
            <p>Your verification code is:</p>
            <h2 style="background:#f4f4f4; padding:10px; color:#333;">{}</h2>
            // CHANGED: instruction updated to say "code" not "token"
            <p>Submit this code to <strong>POST /auth/reset-password</strong> along with your new password.</p>
            <p>This code expires in <strong>1 hour</strong>.</p>
            <p>If you did not request this, ignore this email — your password will not change.</p>
            "#,
            username, reset_token
        ))
        .map_err(|e| format!("Failed to build email: {e}"))?;

    let creds = Credentials::new(smtp_user, smtp_pass);
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp_host)
        .map_err(|e| format!("Failed to connect to SMTP: {e}"))?
        .credentials(creds)
        .build();

    mailer.send(email).await.map_err(|e| format!("Failed to send email: {e}"))?;
    Ok(())
}

pub async fn send_reset_password_email(
    to_email: &str,
    username: &str,
    new_password: &str,
) -> Result<(), String> {
    let smtp_host = env::var("SMTP_HOST").expect("SMTP_HOST must be set");
    let smtp_user = env::var("SMTP_USER").expect("SMTP_USER must be set");
    let smtp_pass = env::var("SMTP_PASS").expect("SMTP_PASS must be set");

    let email = Message::builder()
        .from(
            smtp_user
                .parse()
                .map_err(|e| format!("Invalid from: {e}"))?,
        )
        .to(to_email.parse().map_err(|e| format!("Invalid to: {e}"))?)
        .subject("Your Password Has Been Reset")
        .header(ContentType::TEXT_HTML)
        .body(format!(
            r#"
            <h1>Password Reset</h1>
            <p>Hi {},</p>
            <p>Your password has been reset. Here is your new temporary password:</p>
            <h2 style="color: #333; background: #f4f4f4; padding: 10px;">{}</h2>
            <p>Please sign in and change it immediately.</p>
            "#,
            username, new_password
        ))
        .map_err(|e| format!("Failed to build email: {e}"))?;

    let creds = Credentials::new(smtp_user, smtp_pass);
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp_host)
        .map_err(|e| format!("Failed to connect to SMTP: {e}"))?
        .credentials(creds)
        .build();

    mailer
        .send(email)
        .await
        .map_err(|e| format!("Failed to send email: {e}"))?;
    Ok(())
}

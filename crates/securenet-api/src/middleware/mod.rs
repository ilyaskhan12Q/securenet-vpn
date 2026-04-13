//! Tower middleware layers for the SecureNet API.

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::IntoResponse,
    Json,
};
use jsonwebtoken::{decode, DecodingKey, Validation};

use crate::{handlers::Claims, AppState};

// ---------------------------------------------------------------------------
// JWT bearer token extractor
// ---------------------------------------------------------------------------

/// Middleware that requires a valid `Authorization: Bearer <token>` header.
///
/// On success it injects the decoded `Claims` into request extensions so
/// downstream handlers can inspect the caller's identity without re-decoding.
pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> impl IntoResponse {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let Some(raw_token) = auth_header else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "missing bearer token"})),
        )
            .into_response();
    };

    let key = DecodingKey::from_secret(state.config.api.jwt_secret.as_bytes());
    match decode::<Claims>(raw_token, &key, &Validation::default()) {
        Ok(token_data) => {
            req.extensions_mut().insert(token_data.claims);
            next.run(req).await
        }
        Err(e) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// Middleware that additionally requires the `admin` role.
pub async fn require_admin(
    State(_state): State<AppState>,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    let claims = req.extensions().get::<Claims>();
    match claims {
        Some(c) if c.role == "admin" => next.run(req).await,
        _ => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "admin role required"})),
        )
            .into_response(),
    }
}

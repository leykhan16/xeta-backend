use axum::{
    routing::{get, post},
    Router,
    Json,
    extract::{Path, State, FromRef},
    http::StatusCode,
};
use serde::{Serialize, Deserialize};
use sqlx::PgPool;
use std::sync::Arc;
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use tower_http::services::ServeDir;
use chrono::{Utc, Duration};

// ───────────────────────────────────────────────
// App State
// ───────────────────────────────────────────────

struct AppState {
    db: PgPool,
    jwt_secret: String,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in .env");

    let jwt_secret = std::env::var("JWT_SECRET")
        .expect("JWT_SECRET must be set in .env");

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    println!("Database connected and migrations run");

    let state = Arc::new(AppState { db: pool, jwt_secret });

    let app = Router::new()
        .route("/", get(hello))
        .route("/me", get(get_me).patch(update_profile))
        .route("/users/search", get(search_users))
        .route("/users/:username", get(get_user))
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/users/:username/key", get(get_public_key)).route("/messages", post(send_message))
.route("/messages/:conversation_id", get(get_messages))
.route("/conversations", get(get_conversations))
        .route("/media/upload", post(upload_image))
        
        .nest_service("/uploads", ServeDir::new("uploads"))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    println!("Server running on http://localhost:8080");
    axum::serve(listener, app).await.unwrap();
}

// ───────────────────────────────────────────────
// hello
// ───────────────────────────────────────────────

async fn hello() -> &'static str {
    "Welcome to XETA"
}

// ───────────────────────────────────────────────
// Shared error shape
// ───────────────────────────────────────────────

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ───────────────────────────────────────────────
// JWT
// ───────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    username: String,
    exp: i64,
    iat: i64,
}

fn create_token(
    user_id: &str,
    username: &str,
    secret: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let expiry = now + Duration::days(30);

    let claims = Claims {
        sub: user_id.to_string(),
        username: username.to_string(),
        iat: now.timestamp(),
        exp: expiry.timestamp(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

fn verify_token(
    token: &str,
    secret: &str,
) -> Result<Claims, jsonwebtoken::errors::Error> {
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;

    Ok(data.claims)
}

// ───────────────────────────────────────────────
// Auth extractor
// ───────────────────────────────────────────────

struct AuthUser {
    id: uuid::Uuid,
    username: String,
}

#[axum::async_trait]
impl<S> axum::extract::FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
    Arc<AppState>: axum::extract::FromRef<S>,
{
    type Rejection = (StatusCode, Json<ErrorResponse>);

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let state = Arc::<AppState>::from_ref(state);

        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: String::from("Missing Authorization header"),
                }),
            ))?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: String::from("Authorization header must start with 'Bearer '"),
                }),
            ))?;

        let claims = verify_token(token, &state.jwt_secret)
            .map_err(|_| (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: String::from("Invalid or expired token"),
                }),
            ))?;

        let id = uuid::Uuid::parse_str(&claims.sub)
            .map_err(|_| (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: String::from("Malformed token"),
                }),
            ))?;

        Ok(AuthUser { id, username: claims.username })
    }
}

// ───────────────────────────────────────────────
// User shape
// ───────────────────────────────────────────────

#[derive(Serialize, sqlx::FromRow)]
struct User {
    id: uuid::Uuid,
    username: String,
    email: String,
    display_name: Option<String>,
    about: Option<String>,
    avatar_url: Option<String>,
    public_key: Option<String>,
}

// ───────────────────────────────────────────────
// get_me — protected
// ───────────────────────────────────────────────

async fn get_me(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<User>, (StatusCode, Json<ErrorResponse>)> {

    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, email, display_name, about, avatar_url,public_key
         FROM users WHERE id = $1"
    )
    .bind(auth.id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: e.to_string() }),
    ))?
    .ok_or_else(|| (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: String::from("User not found"),
        }),
    ))?;

    Ok(Json(user))
}

// ───────────────────────────────────────────────
// get_user — public
// ───────────────────────────────────────────────

async fn get_user(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Result<Json<User>, (StatusCode, Json<ErrorResponse>)> {

    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, email, display_name, about, avatar_url, public_key
         FROM users WHERE username = $1"
    )
    .bind(&username)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: e.to_string() }),
    ))?;

    match user {
        Some(u) => Ok(Json(u)),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("User '{}' not found", username),
            }),
        )),
    }
}

// ───────────────────────────────────────────────
// register
// ───────────────────────────────────────────────

#[derive(Deserialize)]
struct RegisterRequest {
    email: String,
    username: String,
    password: String,
     public_key: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    message: String,
    username: String,
}

async fn register(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), (StatusCode, Json<ErrorResponse>)> {

    if body.password.len() < 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: String::from("Password must be at least 8 characters"),
            }),
        ));
    }

    let existing = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM users WHERE username = $1 OR email = $2"
    )
    .bind(&body.username)
    .bind(&body.email)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: e.to_string() }),
    ))?;

    if existing > 0 {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: String::from("Username or email is already taken"),
            }),
        ));
    }

    let password = body.password.clone();
    let password_hash = tokio::task::spawn_blocking(move || {
        hash(password, DEFAULT_COST)
    })
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: e.to_string() }),
    ))?
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: e.to_string() }),
    ))?;

    sqlx::query(
        "INSERT INTO users (email, username, password_hash, public_key)
         VALUES ($1, $2, $3, $4)"
    )
    .bind(&body.email)
    .bind(&body.username)
    .bind(&password_hash)
    .bind(&body.public_key)
    .execute(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: e.to_string() }),
    ))?;

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            message: format!("Welcome to XETA, {}!", body.username),
            username: body.username,
        }),
    ))
}

// ───────────────────────────────────────────────
// login
// ───────────────────────────────────────────────

#[derive(Deserialize)]
struct LoginRequest {
    identifier: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    username: String,
}

#[derive(sqlx::FromRow)]
struct UserAuth {
    username: String,
    password_hash: String,
}

async fn login(
    State(state): State<Arc<AppState>>,
    Json(body): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<ErrorResponse>)> {

    let user = sqlx::query_as::<_, UserAuth>(
        "SELECT username, password_hash FROM users
         WHERE email = $1 OR username = $1"
    )
    .bind(&body.identifier)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: e.to_string() }),
    ))?;

    let user = match user {
        Some(u) => u,
        None => return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: String::from("Invalid credentials"),
            }),
        )),
    };

    let password = body.password.clone();
    let stored_hash = user.password_hash.clone();
    let valid = tokio::task::spawn_blocking(move || {
        verify(password, &stored_hash)
    })
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: e.to_string() }),
    ))?
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: e.to_string() }),
    ))?;

    if !valid {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: String::from("Invalid credentials"),
            }),
        ));
    }

    let user_id = sqlx::query_scalar::<_, uuid::Uuid>(
        "SELECT id FROM users WHERE username = $1"
    )
    .bind(&user.username)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: e.to_string() }),
    ))?;

    let token = create_token(
        &user_id.to_string(),
        &user.username,
        &state.jwt_secret,
    )
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: e.to_string() }),
    ))?;

    Ok(Json(LoginResponse {
        token,
        username: user.username,
    }))
}
// ───────────────────────────────────────────────
// update_profile — protected
// ───────────────────────────────────────────────

#[derive(Deserialize)]
struct UpdateProfileRequest {
    display_name: Option<String>,
    about: Option<String>,
    avatar_url: Option<String>,
}

async fn update_profile(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(body): Json<UpdateProfileRequest>,
) -> Result<Json<User>, (StatusCode, Json<ErrorResponse>)> {

    let user = sqlx::query_as::<_, User>(
        "UPDATE users
         SET
             display_name = COALESCE($1, display_name),
             about        = COALESCE($2, about),
             avatar_url   = COALESCE($3, avatar_url),
             updated_at   = NOW()
         WHERE id = $4
         RETURNING id, username, email, display_name, about, avatar_url, public_key"
    )
    .bind(&body.display_name)
    .bind(&body.about)
    .bind(&body.avatar_url)
    .bind(auth.id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: e.to_string() }),
    ))?;

    Ok(Json(user))
}
// ───────────────────────────────────────────────
// search_users — protected
// ───────────────────────────────────────────────

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
}

async fn search_users(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<SearchQuery>,
) -> Result<Json<Vec<User>>, (StatusCode, Json<ErrorResponse>)> {

    if params.q.trim().is_empty() {
        return Ok(Json(vec![]));
    }

    let pattern = format!("%{}%", params.q.to_lowercase());

    let users = sqlx::query_as::<_, User>(
        "SELECT id, username, email, display_name, about, avatar_url, public_key
         FROM users
         WHERE (LOWER(username) LIKE $1 OR LOWER(email) LIKE $1)
           AND id != $2
         ORDER BY username
         LIMIT 20"
    )
    .bind(&pattern)
    .bind(auth.id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: e.to_string() }),
    ))?;

    Ok(Json(users))
}
// ───────────────────────────────────────────────
// get_public_key — protected
// ───────────────────────────────────────────────

#[derive(Serialize)]
struct PublicKeyResponse {
    username: String,
    public_key: String,
}

async fn get_public_key(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Result<Json<PublicKeyResponse>, (StatusCode, Json<ErrorResponse>)> {

    let row = sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT username, public_key FROM users WHERE username = $1"
    )
    .bind(&username)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: e.to_string() }),
    ))?
    .ok_or_else(|| (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: format!("User '{}' not found", username),
        }),
    ))?;

    let public_key = row.1.ok_or_else(|| (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: format!("User '{}' has no public key", username),
        }),
    ))?;

    Ok(Json(PublicKeyResponse {
        username: row.0,
        public_key,
    }))
}
// ───────────────────────────────────────────────
// Messages
// ───────────────────────────────────────────────

#[derive(Deserialize)]
struct SendMessageRequest {
    recipient_id: uuid::Uuid,
    ciphertext: String,
    nonce: String,
    media_url: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
struct Message {
    id: uuid::Uuid,
    conversation_id: uuid::Uuid,
    sender_id: uuid::Uuid,
    ciphertext: String,
    nonce: String,
    media_url: Option<String>,
    created_at: chrono::DateTime<Utc>,
}

#[derive(Serialize, sqlx::FromRow)]
struct Conversation {
    id: uuid::Uuid,
    participant_a: uuid::Uuid,
    participant_b: uuid::Uuid,
    created_at: chrono::DateTime<Utc>,
    last_message_at: Option<chrono::DateTime<Utc>>,
}

async fn send_message(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(body): Json<SendMessageRequest>,
) -> Result<(StatusCode, Json<Message>), (StatusCode, Json<ErrorResponse>)> {

    // Can't message yourself
    if body.recipient_id == auth.id {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: String::from("You cannot message yourself"),
            }),
        ));
    }

    // Check recipient exists
    let recipient_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)"
    )
    .bind(body.recipient_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: e.to_string() }),
    ))?;

    if !recipient_exists {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: String::from("Recipient not found"),
            }),
        ));
    }

    // Ensure participant_a is always the smaller UUID — keeps pairs canonical
    let (participant_a, participant_b) = if auth.id < body.recipient_id {
        (auth.id, body.recipient_id)
    } else {
        (body.recipient_id, auth.id)
    };

    // Get or create the conversation
    let conversation = sqlx::query_as::<_, Conversation>(
        "INSERT INTO conversations (participant_a, participant_b)
         VALUES ($1, $2)
         ON CONFLICT (participant_a, participant_b)
         DO UPDATE SET last_message_at = NOW()
         RETURNING *"
    )
    .bind(participant_a)
    .bind(participant_b)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: e.to_string() }),
    ))?;

    // Store the encrypted message — server never sees plaintext
    let message = sqlx::query_as::<_, Message>(
        "INSERT INTO messages (conversation_id, sender_id, ciphertext, nonce, media_url)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING *"
    )
    .bind(conversation.id)
    .bind(auth.id)
    .bind(&body.ciphertext)
    .bind(&body.nonce)
    .bind(&body.media_url)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: e.to_string() }),
    ))?;

    Ok((StatusCode::CREATED, Json(message)))
}

async fn get_messages(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(conversation_id): Path<uuid::Uuid>,
) -> Result<Json<Vec<Message>>, (StatusCode, Json<ErrorResponse>)> {

    // Verify the requesting user is a participant
    let is_participant: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM conversations
            WHERE id = $1
            AND (participant_a = $2 OR participant_b = $2)
        )"
    )
    .bind(conversation_id)
    .bind(auth.id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: e.to_string() }),
    ))?;

    if !is_participant {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: String::from("You are not a participant in this conversation"),
            }),
        ));
    }

    let messages = sqlx::query_as::<_, Message>(
        "SELECT * FROM messages
         WHERE conversation_id = $1
         ORDER BY created_at ASC"
    )
    .bind(conversation_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: e.to_string() }),
    ))?;

    Ok(Json(messages))
}

async fn get_conversations(
    auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ConversationWithUser>>, (StatusCode, Json<ErrorResponse>)> {

    let conversations = sqlx::query_as::<_, ConversationWithUser>(
        "SELECT c.id, c.participant_a, c.participant_b, c.created_at, c.last_message_at,
                u.username as other_username
         FROM conversations c
         JOIN users u ON u.id = CASE
           WHEN c.participant_a = $1 THEN c.participant_b
           ELSE c.participant_a
         END
         WHERE c.participant_a = $1 OR c.participant_b = $1
         ORDER BY c.last_message_at DESC NULLS LAST"
    )
    .bind(auth.id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: e.to_string() }),
    ))?;

    Ok(Json(conversations))
}
// ── Add this struct after the Conversation struct ──
#[derive(Serialize, sqlx::FromRow)]
struct ConversationWithUser {
    id: uuid::Uuid,
    participant_a: uuid::Uuid,
    participant_b: uuid::Uuid,
    created_at: chrono::DateTime<Utc>,
    last_message_at: Option<chrono::DateTime<Utc>>,
    other_username: String,
}
// ───────────────────────────────────────────────
// upload_image — protected
// ───────────────────────────────────────────────

const MAX_IMAGE_SIZE: usize = 10 * 1024 * 1024; // 10 MB
const ALLOWED_MIME_TYPES: &[&str] = &["image/jpeg", "image/png", "image/gif", "image/webp"];

#[derive(Serialize)]
struct UploadResponse {
    url: String,
}

async fn upload_image(
    _auth: AuthUser,
    mut multipart: axum::extract::Multipart,
) -> Result<Json<UploadResponse>, (StatusCode, Json<ErrorResponse>)> {

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: e.to_string() })))?
    {
        let name = field.name().unwrap_or("").to_string();
        if name != "file" {
            continue;
        }

        let content_type = field
            .content_type()
            .unwrap_or("application/octet-stream")
            .to_string();

        if !ALLOWED_MIME_TYPES.contains(&content_type.as_str()) {
            return Err((
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                Json(ErrorResponse {
                    error: String::from("Only JPEG, PNG, GIF, and WebP images are allowed"),
                }),
            ));
        }

        let data = field
            .bytes()
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: e.to_string() })))?;

        if data.len() > MAX_IMAGE_SIZE {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(ErrorResponse { error: String::from("Image must be under 10 MB") }),
            ));
        }

        let ext = match content_type.as_str() {
            "image/jpeg" => "jpg",
            "image/png" => "png",
            "image/gif" => "gif",
            "image/webp" => "webp",
            _ => "bin",
        };

        let filename = format!("{}.{}", uuid::Uuid::new_v4(), ext);
        let upload_dir = std::path::Path::new("uploads");
        tokio::fs::create_dir_all(upload_dir).await.ok();
        let path = upload_dir.join(&filename);

        tokio::fs::write(&path, &data)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: e.to_string() })))?;

        let base_url = std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:8080".into());
        return Ok(Json(UploadResponse {
            url: format!("{}/uploads/{}", base_url, filename),
        }));
    }

    Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: String::from("No file field in request") })))
}

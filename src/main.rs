use product::product_routes;
use tokio::net::TcpListener;
use axum::{body::Body, http::Request, middleware::{from_fn, Next}, routing::{get, post}, Router};
use sqlx::PgPool;
use users::users_routes;
use std::{env, net::SocketAddr, sync::Arc};
// use tracing_subscriber;
use std::path::PathBuf;
use tower_http::services::ServeDir;
use axum::middleware::from_fn_with_state;


// mod utils;
mod images;
mod auth;
mod users;
mod middleware;
mod config;
mod product;
mod roles;
mod moderation;
mod groups;
mod errors;
use config::generate_jwt_secret;


/// this struct hold the shared database connection pool and jwt secret
#[derive(Clone)]
struct AppState {
    db: PgPool,
    jwt_secret: String,
    profile_image_dir: PathBuf,
    product_image_dir: PathBuf,
    max_image_size: usize,
    allowed_mime_types: Vec<mime::Mime>,
}


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing subscriber.
    // tracing_subscriber::fmt::init();

    dotenv::dotenv().is_ok();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL not set");
    let pool = PgPool::connect(&database_url).await?;

    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| generate_jwt_secret());

    // Add image config
    let profile_dir = PathBuf::from(env::var("PROFILE_IMAGE_DIR")?);
    let product_dir = PathBuf::from(env::var("PRODUCT_IMAGE_DIR")?);
    tokio::fs::create_dir_all(&profile_dir).await?;
    tokio::fs::create_dir_all(&product_dir).await?;

    let max_size = env::var("MAX_IMAGE_SIZE_MB")?.parse::<usize>()? * 1024 * 1024;
    let mime_types = env::var("ALLOWED_MIME_TYPES")?
        .split(',')
        .filter_map(|s| s.parse().ok())
        .collect();

    let state = Arc::new(AppState {
        db: pool,
        jwt_secret,
        profile_image_dir: profile_dir,
        product_image_dir: product_dir,
        max_image_size: max_size,
        allowed_mime_types: mime_types,
    });


    let protected_routes = Router::new()
        .nest("/users", users_routes())
        .nest("/products", product_routes())
        .nest("/moderation", moderation::routes())
        .nest("/groups", groups::routes())
        .layer(from_fn_with_state(
            state.clone(),
            middleware::auth_middleware
        ))
        .layer(from_fn_with_state(
            state.clone(),
            middleware::check_banned
        ));

        let app = Router::new()
        .route("/", get(root))
        .route("/users/register", post(users::register_user))
        .route("/users/login", post(users::login_user))
        .nest_service("/static/profile", ServeDir::new(state.profile_image_dir.clone()))
        .nest_service("/static/product", ServeDir::new(state.product_image_dir.clone()))
        .nest("/protected", protected_routes)
        .with_state(state)
        .layer(from_fn(|request: Request<Body>, next: Next| async {
            let response = next.run(request).await;
            response
        }));


    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    println!("Server running on port {addr}");

    Ok(())
}

/// A simple root handler.
async fn root() -> &'static str {
    "Welcome to the Bazaar API!"
}
// Dependency injection setup
// File ini berisi konfigurasi dan inisialisasi semua dependency

use actix_web::web;
use std::sync::Arc;
use diesel::r2d2::{self, ConnectionManager};
use diesel::PgConnection;
use dotenv::dotenv;
use std::env;

use crate::domain::services::authentication_service::AuthenticationService;
use crate::application::use_cases::auth::login_use_case::LoginUseCase;
use crate::application::use_cases::user::create_user_use_case::CreateUserUseCase;
use crate::domain::services::user_service::UserService;
use crate::infrastructure::persistence::repositories::user_repository_impl::UserRepositoryImpl;
use crate::infrastructure::security::jwt_provider::JwtProvider;
use crate::infrastructure::security::password_hasher::HasherPasswordService;
use crate::interfaces::api::controllers::auth_controller::AuthController;
use crate::interfaces::api::controllers::user_controller::UserController;
use crate::interfaces::api::middlewares::auth_middleware::AuthMiddleware;

/// Struct yang berisi semua dependency aplikasi
pub struct AppDependencies {
    pub auth_controller: web::Data<AuthController>,
    pub user_controller: web::Data<UserController>,
    pub auth_middleware: Arc<AuthMiddleware>,
}

/// Menginisialisasi database connection pool
pub fn init_database_pool() -> r2d2::Pool<ConnectionManager<PgConnection>> {
    // Load environment variables if not already loaded
    dotenv().ok();

    // Get database URL from environment
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");

    // Create connection manager
    let manager = ConnectionManager::<PgConnection>::new(database_url);

    // Create connection pool
    r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create database connection pool")
}

/// Menginisialisasi semua dependency aplikasi
pub fn init_dependencies() -> AppDependencies {
    // Initialize database pool
    let pool = init_database_pool();
    let pool_arc = Arc::new(pool);

    // Initialize repositories
    let user_repository = Arc::new(UserRepositoryImpl::new(pool_arc.clone()));

    // Initialize security services
    let token_service = Arc::new(JwtProvider::new());
    let password_hasher = Arc::new(HasherPasswordService::new());

    // Initialize domain services
    let auth_service = Arc::new(AuthenticationService::new(user_repository.clone()));
    let user_service = Arc::new(UserService::new(user_repository.clone()));

    // Ensure that the password hasher is used in the user service
    let password_hasher = password_hasher.clone();
    // Initialize use cases
    let login_use_case = Arc::new(LoginUseCase::new(
        auth_service.clone(),
        token_service.clone(),
    ));

    let create_user_use_case = Arc::new(CreateUserUseCase::new(
        user_service,
        password_hasher,
    ));

    // Initialize controllers
    let auth_controller = web::Data::new(AuthController::new(
        login_use_case.clone(),
        create_user_use_case.clone(),
    ));

    let user_controller = web::Data::new(UserController::new(
        create_user_use_case
    ));

    // Initialize middlewares
    let auth_middleware = Arc::new(AuthMiddleware::new(token_service.clone()));

    // Return all dependencies
    AppDependencies {
        auth_controller,
        user_controller,
        auth_middleware,
    }
}

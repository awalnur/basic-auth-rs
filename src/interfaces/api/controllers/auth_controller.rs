// Controller for authentication
// Handles HTTP requests and responses

use actix_web::{web, HttpResponse, Responder, HttpRequest, http::StatusCode};
use serde_json::json;
use std::sync::Arc;
use log::error;

use crate::application::dtos::auth_dto::{LoginRequestDto, RegisterUserDto};
use crate::application::use_cases::auth::login_use_case::{LoginUseCase};
use crate::application::use_cases::user::create_user_use_case::CreateUserUseCase;
use crate::domain::entities::user::User;
use crate::common::errors::AppError;

/// AuthController handles all HTTP endpoints related to authentication
///
/// This controller implements:
/// * Login endpoint - authenticates users and issues tokens
/// * Register endpoint - creates new user accounts
/// * Logout endpoint - invalidates active sessions
///
/// # Example
///
/// ```
/// let auth_controller = AuthController::new(login_use_case, create_user_use_case);
/// ```
pub struct AuthController {
    login_use_case: Arc<LoginUseCase>,
    create_user_use_case: Arc<CreateUserUseCase>,
}

impl AuthController {
    /// Creates a new instance of AuthController
    ///
    /// # Arguments
    ///
    /// * `login_use_case` - Use case for login process
    /// * `create_user_use_case` - Use case for creating new users
    pub fn new(
        login_use_case: Arc<LoginUseCase>,
        create_user_use_case: Arc<CreateUserUseCase>,
    ) -> Self {
        Self {
            login_use_case,
            create_user_use_case,
        }
    }

    /// Handles login requests
    ///
    /// # Arguments
    ///
    /// * `login_req` - Login data from user
    ///
    /// # Returns
    ///
    /// * `HttpResponse` - Response with token or error
    pub async fn login(&self, login_req: web::Json<LoginRequestDto>) -> HttpResponse {
        match self.login_use_case.execute(login_req.into_inner()).await {
            Ok(response) => HttpResponse::Ok().json(response),
            Err(e) => {
                match e {
                    AppError::InvalidCredentials =>
                        Self::json_error(StatusCode::UNAUTHORIZED, "invalid_credentials", "Username/email or password is incorrect"),
                    AppError::AccountInactive =>
                        Self::json_error(StatusCode::FORBIDDEN, "account_inactive", "Your account is not active"),
                    AppError::EmailNotVerified =>
                        Self::json_error(StatusCode::FORBIDDEN, "email_not_verified", "Please verify your email before logging in"),
                    AppError::Internal(msg) => {
                        error!("Login internal error: {}", msg);
                        Self::json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", "An internal error occurred")
                    }
                    AppError::Validation(msg) => {
                        error!("Login validation error: {}", msg);
                        Self::json_error(StatusCode::BAD_REQUEST, "validation_error", &msg)
                    }
                    AppError::Domain(e) => {
                        error!("Domain error during login: {}", e);
                        Self::json_error(StatusCode::BAD_REQUEST, "domain_error", &e.to_string())
                    }
                    AppError::Database(e) => {
                        error!("Database error during login: {}", e);
                        Self::json_error(StatusCode::INTERNAL_SERVER_ERROR, "database_error", "Database operation failed")
                    }
                    AppError::ExternalService(e) => {
                        error!("External service error during login: {}", e);
                        Self::json_error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable", "External service is unavailable")
                    }
                    AppError::Configuration(e) => {
                        error!("Configuration error during login: {}", e);
                        Self::json_error(StatusCode::INTERNAL_SERVER_ERROR, "configuration_error", "Service configuration error")
                    }
                    AppError::Network(e) => {
                        error!("Network error during login: {}", e);
                        Self::json_error(StatusCode::SERVICE_UNAVAILABLE, "network_error", "Network operation failed")
                    }
                    _ => {
                        error!("Unexpected error during login: {:?}", e);
                        Self::json_error(StatusCode::INTERNAL_SERVER_ERROR, "unknown_error", "An unexpected error occurred")
                    }
                }
            }
        }
    }

    /// Handles new user registration requests
    ///
    /// # Arguments
    ///
    /// * `register_req` - New user registration data
    ///
    /// # Returns
    ///
    /// * `HttpResponse` - Response with user data or error
    pub async fn register(&self, register_req: web::Json<RegisterUserDto>) -> HttpResponse {
        let username = register_req.username.clone();
        let email = register_req.email.clone();
        let password = register_req.password.clone();
        // Validate input data
        let user_data = User::new(
            username,
            email, password,
        );
        match self.create_user_use_case.execute(user_data).await {
            Ok(user) => HttpResponse::Created().json(user),
            Err(e) => {
                // Log error for tracking
                error!("Registration error: {}", e);

                // Categorize error based on type
                match e {
                    // Handle different types of errors based on your CreateUserError enum
                    // CreateUserError::UserAlreadyExists =>
                    //    Self::json_error(StatusCode::CONFLICT, "user_exists", "User with this email or username already exists"),
                    // Add other specific error handling here
                    _ => Self::json_error(
                        StatusCode::BAD_REQUEST,
                        "registration_failed",
                        &e.to_string(),
                    )
                }
            }
        }
    }

    /// Handles logout requests
    ///
    /// # Arguments
    ///
    /// * `req` - HTTP Request containing authentication token
    ///
    /// # Returns
    ///
    /// * `HttpResponse` - Logout confirmation response
    pub async fn logout(&self, req: HttpRequest) -> HttpResponse {
        // Extract token from Authorization header
        let auth_header = req.headers().get("Authorization");

        if let Some(auth_value) = auth_header {
            if let Ok(auth_str) = auth_value.to_str() {
                if auth_str.starts_with("Bearer ") {
                    let token = &auth_str[7..]; // Skip "Bearer " prefix

                    // TODO: Implement logout use case to invalidate token
                    // if let Err(e) = self.logout_use_case.execute(token).await {
                    //    error!("Logout error: {}", e);
                    //    return Self::json_error(
                    //        StatusCode::INTERNAL_SERVER_ERROR,
                    //        "logout_failed",
                    //        "Failed to invalidate session"
                    //    );
                    // }

                    // For now we just log the token for debugging
                    log::debug!("Logging out token: {}", token);
                }
            }
        }

        // Always return success for security reasons
        // (don't want to tell attackers whether token is valid or not)
        HttpResponse::Ok().json(json!({
            "message": "Successfully logged out"
        }))
    }

    /// Helper method to create consistent JSON error responses
    ///
    /// # Arguments
    ///
    /// * `status` - HTTP status code
    /// * `error_code` - Error code for client (snake_case)
    /// * `message` - User-friendly error message
    ///
    /// # Returns
    ///
    /// * `HttpResponse` - HTTP response with consistent error format
    fn json_error(status: StatusCode, error_code: &str, message: &str) -> HttpResponse {
        HttpResponse::build(status).json(json!({
            "error": error_code,
            "message": message
        }))
    }
}

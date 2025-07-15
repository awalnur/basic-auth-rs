// Use Case for login process
// Application layer implementation for login use case

use crate::application::dtos::auth_dto::{LoginRequestDto, LoginResponseDto};
use crate::domain::services::authentication_service::{AuthenticationService, AuthenticationError};
use crate::application::ports::token_port::TokenService;
use std::sync::Arc;
use chrono::{Utc, Duration};
use thiserror::Error;
use log::{error, info};
use validator::Validate;
use crate::common::errors::AppError;

/// Use case for user login process
pub struct LoginUseCase {
    auth_service: Arc<AuthenticationService>,
    token_service: Arc<dyn TokenService + Send + Sync>,
}

impl LoginUseCase {
    /// Creates a new LoginUseCase instance
    ///
    /// # Arguments
    ///
    /// * `auth_service` - Domain service for authentication
    /// * `token_service` - Service for token management
    pub fn new(
        auth_service: Arc<AuthenticationService>,
        token_service: Arc<dyn TokenService + Send + Sync>,
    ) -> Self {
        Self {
            auth_service,
            token_service,
        }
    }

    /// Executes the login use case
    ///
    /// # Steps:
    /// 1. Validate input
    /// 2. Authenticate user
    /// 3. Generate authentication token
    ///
    /// # Arguments
    ///
    /// * `request` - Login request DTO containing username/email and password
    ///
    /// # Returns
    ///
    /// * `Result<LoginResponseDto, AuthError>` - Login response DTO or error
    pub async fn execute(&self, request: LoginRequestDto) -> Result<LoginResponseDto, AppError> {
        // Input validation
        if let Err(validation_errors) = request.validate() {
            let error_message = validation_errors
                .field_errors()
                .iter()
                .map(|(field, errors)| {
                    format!("{}: {}", field, errors[0].message.clone().unwrap_or_default())
                })
                .collect::<Vec<String>>()
                .join(", ");

            error!("Login request validation failed: {}", error_message);
            return Err(AppError::Validation(error_message));
        }

        // Authenticate user with domain service
        let user = self.auth_service
            .authenticate(&request.username_or_email, &request.password)
            .await
            .map_err(|e| match e {
                AuthenticationError::InvalidCredentials => {
                    info!("Login failed - invalid credentials for {}", request.username_or_email);
                    AppError::InvalidCredentials
                }
                AuthenticationError::InactiveAccount => {
                    info!("Login failed - inactive account for {}", request.username_or_email);
                    AppError::AccountInactive
                }
                AuthenticationError::EmailNotVerified => {
                    info!("Login failed - email not verified for {}", request.username_or_email);
                    AppError::EmailNotVerified
                }
                AuthenticationError::RepositoryError(msg) => {
                    error!("Login failed - repository error: {}", msg);
                    AppError::Internal(msg)
                }
            })?;

        // Generate token with 24 hour expiry
        let expiry = Utc::now() + Duration::hours(24);
        let token = self.token_service
            .generate_token(&user.id.to_string(), expiry.timestamp())
            .map_err(|e| {
                error!("Failed to generate token: {}", e);
                AppError::Internal(e.to_string())
            })?;

        info!("User {} logged in successfully", user.username);

        // Return response DTO
        Ok(LoginResponseDto {
            user_id: user.id.to_string(),
            username: user.username,
            token,
            token_expires_at: expiry.timestamp(),
        })
    }
}

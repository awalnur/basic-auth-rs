use std::sync::Arc;
use actix_web::App;
use futures_util::TryFutureExt;
use thiserror::Error;
use security::password_hasher::HasherPasswordService;
use crate::common::errors::AppError;
use crate::domain::entities::user::User;
use crate::domain::services::user_service::UserService;
use crate::infrastructure::persistence::models::user_model::UserModel;
use crate::infrastructure::security;

pub struct CreateUserUseCase {
    user_service: Arc<UserService>,
    password_hasher: Arc<HasherPasswordService>,
}

impl CreateUserUseCase {
    /// Creates a new instance of CreateUserUseCase
    ///
    /// # Arguments
    ///
    /// * `user_repository` - Repository for accessing user data
    /// * `password_hasher` - Password hasher for hashing passwords
    pub fn new(
        user_service: Arc<UserService>,
        password_hasher: Arc<HasherPasswordService>,
    ) -> Self {
        Self {
            user_service,
            password_hasher,
        }
    }


    /// Creates a new user
    ///
    /// # Arguments
    ///
    /// * `user` - User data to be created
    ///
    /// # Returns
    ///
    /// * `Result<User, UserServiceError>` - Created user or error
    pub async fn execute(&self, user: User) -> Result<User, AppError> {
        // Validate user data
        if user.email.is_empty() || user.username.is_empty() {
            return Err(AppError::Validation("Email or username cannot be empty".to_string()));
        }

        // Hash the user's password
        let hashed_password = self.password_hasher.hash(&user.password_hash)
            .map_err(|e| AppError::Internal(e.to_string()))?;

        // Create a new user with hashed password
        let new_user = User {
            password_hash: hashed_password,
            ..user
        };
        let user = self.user_service.create_user(new_user)
            .map_err(|e| {
                match e {
                    AppError::Conflict(email) => AppError::Conflict(email),
                    AppError::Validation(msg) => AppError::Validation(msg),
                    AppError::Internal(msg) => AppError::Internal(msg),
                    _ => AppError::Internal("Unknown error".to_string()),
                }
            }).await?;
        Ok(user)
    }
}
use std::sync::Arc;
use actix_web::App;
use thiserror::Error;
use crate::common::errors::AppError;
use crate::domain::entities::user::User;
use crate::domain::repositories::user_repository::UserRepository;


pub struct UserService {
    user_repository: Arc<dyn UserRepository + Send + Sync>,
}

impl UserService {
    /// Creates a new instance of UserService
    ///
    /// # Arguments
    ///
    /// * `user_repository` - Repository for accessing user data
    pub fn new(user_repository: Arc<dyn UserRepository + Send + Sync>) -> Self {
        Self { user_repository }
    }

    // Additional methods for user management can be added here
    // e.g., create_user, update_user, delete_user, etc.

    pub async fn create_user(&self, user: User) -> Result<User, AppError> {
        // Validate user data
        if user.email.is_empty() || user.username.is_empty() {
            return Err(AppError::Validation("Email or username cannot be empty".to_string()));
        }

        // Check if user already exists
        match self.user_repository.find_by_email(&user.email).await {
            Ok(Some(_)) => return Err(AppError::Conflict(user.email)),
            Ok(None) => {}
            Err(e) => return Err(AppError::Internal(e.to_string())),
        }

        // Save the new user
        match self.user_repository.save(&user).await {
            Ok(saved_user) => Ok(saved_user),
            Err(e) => Err(AppError::Internal(e.to_string())),
        }
    }
}

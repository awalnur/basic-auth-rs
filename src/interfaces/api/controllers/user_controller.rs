use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use actix_web::http::StatusCode;
use actix_web::{HttpResponse, Responder};
use log::{error, info};
use serde_json::json;
use crate::domain::entities::user::User;
use thiserror::Error;
use crate::application::dtos::auth_dto::RegisterUserDto;
use crate::application::use_cases::user::create_user_use_case::CreateUserUseCase;
use crate::common::errors::AppError;
use crate::interfaces::api::models::response::ApiErrorResponse;

pub struct UserController {
    create_user_usecase: Arc<CreateUserUseCase>,
}

impl UserController {
    /// Creates a new instance of UserController
    ///
    /// # Arguments
    ///
    /// * `user_repository` - Repository for accessing user data
    /// * `password_hasher` - Password hasher for hashing passwords
    pub fn new(
        create_user_usecase: Arc<CreateUserUseCase>,
    ) -> Self {
        Self {
            create_user_usecase,
        }
    }

    // Additional methods for user management can be added here
    // e.g., create_user, update_user, delete_user, etc.
    pub async fn create_user(&self, user: RegisterUserDto) -> impl Responder {
        // Validate user data
        let user_data = User::new(
            user.email,
            user.username,
            user.password,
        );
        match self.create_user_usecase.execute(user_data).await {
            Ok(created_user) => {
                info!("User created successfully: {:?}", created_user);
                HttpResponse::Ok().json(created_user)
            }
            Err(e) => {
                error!("Failed to create user: {}", e);
                match e {
                    AppError::Validation(msg) => HttpResponse::BadRequest().json(
                        ApiErrorResponse::validation_error(
                            &msg.to_string(),
                            HashMap::new(),
                        )
                    ),
                    AppError::Internal(_) => HttpResponse::InternalServerError().json(
                        ApiErrorResponse::internal_error()
                    ),
                    AppError::NotFound(msg) => HttpResponse::NotFound().json(
                        ApiErrorResponse::not_found(&msg.to_string())
                    ),
                    AppError::Conflict(msg) => HttpResponse::Conflict().json(
                        ApiErrorResponse::conflict(&msg.to_string())
                    ),
                    _ => HttpResponse::InternalServerError().json(
                        ApiErrorResponse::internal_error()
                    )
                }
            }
        }
    }
    // Handles new user registration requests
    // pub async fn get_current_user(&self, user_id: String) -> HttpResponse {
    //     // Fetch the current user by ID
    //     match self.create_user_usecase.get_user_by_id(user_id).await {
    //         Ok(user) => {
    //             info!("User fetched successfully: {:?}", user);
    //             HttpResponse::Ok().json(user)
    //         }
    //         Err(e) => {
    //             error!("Failed to fetch user: {}", e);
    //             match e {
    //                 AppError::NotFound(msg) => HttpResponse::NotFound().json(
    //                     ApiErrorResponse::not_found(&msg.to_string())
    //                 ),
    //                 AppError::Internal(_) => HttpResponse::InternalServerError().json(
    //                     ApiErrorResponse::internal_error()
    //                 ),
    //                 _ => HttpResponse::InternalServerError().json(
    //                     ApiErrorResponse::internal_error()
    //                 )
    //             }
    //         }
    //     }
    // }
}


//     /// Handles new user registration requests
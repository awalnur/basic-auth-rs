// Standard API response models
// This file contains models for consistent API responses across the application

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use actix_web::{HttpResponse, http::StatusCode, ResponseError};
use serde_json::{json, Value as JsonValue};
use crate::common::errors::AppError;

/// Standard API response structure for successful operations
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApiResponse<T>
where
    T: Serialize,
{
    /// Response status (true for success)
    pub success: bool,

    /// HTTP status code
    pub status_code: u16,

    /// Optional message providing additional context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Response data payload
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,

    /// Optional metadata for pagination, filtering, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<HashMap<String, JsonValue>>,
}

/// Standard API error response structure
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApiErrorResponse {
    /// Response status (false for errors)
    pub success: bool,

    /// HTTP status code
    pub status_code: u16,

    /// Error code identifier (e.g., "invalid_credentials")
    pub error_code: String,

    /// User-friendly error message
    pub message: String,

    /// Optional detailed error information for debugging
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<HashMap<String, JsonValue>>,

    /// Optional validation errors by field
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_errors: Option<HashMap<String, Vec<String>>>,
}

impl<T> ApiResponse<T>
where
    T: Serialize,
{
    /// Creates a new successful API response
    pub fn new(data: T) -> Self {
        Self {
            success: true,
            status_code: 200,
            message: None,
            data: Some(data),
            meta: None,
        }
    }

    /// Creates a new successful API response with custom message
    pub fn with_message(data: T, message: &str) -> Self {
        Self {
            success: true,
            status_code: 200,
            message: Some(message.to_string()),
            data: Some(data),
            meta: None,
        }
    }

    /// Creates a new successful API response with custom status code
    pub fn with_status(data: T, status_code: u16) -> Self {
        Self {
            success: true,
            status_code,
            message: None,
            data: Some(data),
            meta: None,
        }
    }

    /// Creates a new successful API response with metadata
    pub fn with_meta(data: T, meta: HashMap<String, JsonValue>) -> Self {
        Self {
            success: true,
            status_code: 200,
            message: None,
            data: Some(data),
            meta: Some(meta),
        }
    }

    /// Creates a new empty successful API response (no data)
    pub fn empty() -> ApiResponse<()> {
        ApiResponse {
            success: true,
            status_code: 204,
            message: None,
            data: None,
            meta: None,
        }
    }

    /// Converts this response to an HttpResponse
    pub fn to_http_response(&self) -> HttpResponse {
        let status = StatusCode::from_u16(self.status_code)
            .unwrap_or(StatusCode::OK);

        HttpResponse::build(status).json(self)
    }
}

impl ApiErrorResponse {
    /// Creates a new error response
    pub fn new(status_code: u16, error_code: &str, message: &str) -> Self {
        Self {
            success: false,
            status_code,
            error_code: error_code.to_string(),
            message: message.to_string(),
            details: None,
            validation_errors: None,
        }
    }

    /// Creates a new error response with detailed error information
    pub fn with_details(
        status_code: u16,
        error_code: &str,
        message: &str,
        details: HashMap<String, JsonValue>,
    ) -> Self {
        Self {
            success: false,
            status_code,
            error_code: error_code.to_string(),
            message: message.to_string(),
            details: Some(details),
            validation_errors: None,
        }
    }

    /// Creates a new validation error response
    pub fn validation_error(message: &str, errors: HashMap<String, Vec<String>>) -> Self {
        Self {
            success: false,
            status_code: 400,
            error_code: "validation_error".to_string(),
            message: message.to_string(),
            details: None,
            validation_errors: Some(errors),
        }
    }

    /// Create a new conflict error response
    pub fn conflict(message: &str) -> Self {
        Self {
            success: false,
            status_code: 409,
            error_code: "conflict".to_string(),
            message: message.to_string(),
            details: None,
            validation_errors: None,
        }
    }

    /// Creates a new not found error response
    pub fn not_found(resource: &str) -> Self {
        Self {
            success: false,
            status_code: 404,
            error_code: "not_found".to_string(),
            message: format!("The requested {} could not be found", resource),
            details: None,
            validation_errors: None,
        }
    }

    /// Creates a new unauthorized error response
    pub fn unauthorized(message: &str) -> Self {
        Self {
            success: false,
            status_code: 401,
            error_code: "unauthorized".to_string(),
            message: message.to_string(),
            details: None,
            validation_errors: None,
        }
    }

    /// Creates a new forbidden error response
    pub fn forbidden(message: &str) -> Self {
        Self {
            success: false,
            status_code: 403,
            error_code: "forbidden".to_string(),
            message: message.to_string(),
            details: None,
            validation_errors: None,
        }
    }

    /// Creates a new internal server error response
    pub fn internal_error() -> Self {
        Self {
            success: false,
            status_code: 500,
            error_code: "internal_server_error".to_string(),
            message: "An unexpected error occurred".to_string(),
            details: None,
            validation_errors: None,
        }
    }

    /// Converts this error response to an HttpResponse
    pub fn to_http_response(&self) -> HttpResponse {
        let status = StatusCode::from_u16(self.status_code)
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        HttpResponse::build(status).json(self)
    }
}

/// Extension trait to convert AppError to ApiErrorResponse
pub trait ErrorToResponse {
    /// Convert an error to an API error response
    fn to_response(&self) -> ApiErrorResponse;
}

/// Implementation of ErrorToResponse for AppError
impl ErrorToResponse for AppError {
    fn to_response(&self) -> ApiErrorResponse {
        match self {
            // Domain layer errors
            AppError::Domain(domain_err) => {
                match domain_err {
                    crate::domain::errors::domain_error::DomainError::EntityNotFound(msg) => {
                        ApiErrorResponse::not_found(msg)
                    }
                    crate::domain::errors::domain_error::DomainError::ValidationError(msg) => {
                        let mut errors = HashMap::new();
                        errors.insert("general".to_string(), vec![msg.clone()]);
                        ApiErrorResponse::validation_error("Validation failed", errors)
                    }
                    crate::domain::errors::domain_error::DomainError::BusinessRuleViolation(msg) => {
                        ApiErrorResponse::new(400, "business_rule_violation", msg)
                    }
                    crate::domain::errors::domain_error::DomainError::AuthorizationError(msg) => {
                        ApiErrorResponse::forbidden(msg)
                    }
                    crate::domain::errors::domain_error::DomainError::RepositoryError(msg) => {
                        ApiErrorResponse::new(500, "repository_error", msg)
                    }
                }
            }
            AppError::Validation(msg) => {
                let mut errors = HashMap::new();
                errors.insert("general".to_string(), vec![msg.clone()]);
                ApiErrorResponse::validation_error("Validation failed", errors)
            }
            AppError::NotFound(msg) => ApiErrorResponse::not_found(msg),
            AppError::Conflict(msg) => ApiErrorResponse::conflict(msg),

            // Authentication & Authorization errors
            AppError::Authentication(msg) => ApiErrorResponse::unauthorized(msg),
            AppError::Authorization(msg) => ApiErrorResponse::forbidden(msg),
            AppError::InvalidCredentials => ApiErrorResponse::unauthorized("Invalid username or password"),
            AppError::AccountInactive => ApiErrorResponse::new(403, "account_inactive", "Your account is currently inactive"),
            AppError::EmailNotVerified => ApiErrorResponse::new(403, "email_not_verified", "Please verify your email address"),

            // Infrastructure layer errors
            AppError::Database(msg) => ApiErrorResponse::internal_error(),
            AppError::Network(msg) => ApiErrorResponse::new(503, "network_error", "Network communication error"),
            AppError::ExternalService(msg) => ApiErrorResponse::new(502, "external_service_error", "Error communicating with external service"),
            AppError::Configuration(msg) => ApiErrorResponse::internal_error(),
            AppError::Serialization(msg) => ApiErrorResponse::new(400, "serialization_error", "Invalid data format"),

            // System & Operational errors
            AppError::Internal(msg) => ApiErrorResponse::internal_error(),
            AppError::RateLimit(msg) => ApiErrorResponse::new(429, "rate_limit", msg),
        }
    }
}

// Implement ResponseError for AppError to allow direct use with actix-web
impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        self.to_response().to_http_response()
    }

    fn status_code(&self) -> StatusCode {
        StatusCode::from_u16(self.to_response().status_code)
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

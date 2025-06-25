use thiserror::Error;
#[derive(Debug, Error, Clone)]
pub enum AppError {
    #[error("Record not found: {0}")]
    NotFound(String),
    #[error("Bad Request: {0}")]
    BadRequest(String),
    #[error("Validation Error: {0}")]
    ValidationError(String),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("Forbidden: {0}")]
    Forbidden(String),
    #[error("Internal Error: {0}")]
    InternalError(String),
    #[error("Service Unavailable: {0}")]
    ServiceUnavailable(String),
}
// Common error types and utilities

use thiserror::Error;
use std::fmt;

/// Application-wide error type organized into logical groups for better maintainability
///
/// This error type provides a unified error handling approach across all layers
/// of the application while preserving error context and enabling proper error mapping.
///
/// # Error Organization Strategy
///
/// The errors are organized into the following logical groups:
///
/// ## 1. Domain Layer Errors
/// - **Domain**: Business logic and domain rule violations
/// - **Validation**: Input validation and data integrity errors
/// - **NotFound**: Entity or resource not found errors
/// - **Conflict**: Resource conflicts (duplicates, state conflicts)
///
/// ## 2. Authentication & Authorization Errors
/// - **Authentication**: Login, credentials, and identity verification
/// - **Authorization**: Permission and access control errors
/// - **InvalidCredentials**: Specific login failure cases
/// - **AccountInactive**: User account state issues
/// - **EmailNotVerified**: Email verification requirements
///
/// ## 3. Infrastructure Layer Errors
/// - **Database**: Data persistence and query errors
/// - **Network**: HTTP, TCP, and network communication errors
/// - **ExternalService**: Third-party service integration errors
/// - **Configuration**: Application configuration and setup errors
/// - **Serialization**: JSON, XML, and data format errors
///
/// ## 4. System & Operational Errors
/// - **Internal**: Unexpected system errors and bugs
/// - **RateLimit**: Rate limiting and throttling errors
///
/// # Example
///
/// ```no_run
/// // Example usage (this is documentation, not executed as test)
/// use self::AppError;
///
/// fn some_operation() -> Result<String, AppError> {
///     // Example domain operation that might fail
///     let business_result = validate_business_rules();
///     match business_result {
///         Ok(data) => Ok(data),
///         Err(domain_err) => Err(AppError::Domain(domain_err)),
///     }
/// }
///
/// // Example helper function returning domain error
/// fn validate_business_rules() -> Result<String, crate::domain::errors::domain_error::DomainError> {
///     // Business logic implementation
///     Ok("Success".to_string())
/// }
/// ```
#[derive(Error, Debug)]
pub enum AppError {
    // ==============================================
    // DOMAIN LAYER ERRORS
    // ==============================================
    // These errors represent business logic failures and domain rule violations.
    // They should be handled gracefully and often indicate user input issues.

    /// Domain layer business logic errors
    ///
    /// This encompasses all domain-specific errors including business rule violations,
    /// entity state errors, and domain validation failures.
    #[error("Domain error: {0}")]
    Domain(#[from] crate::domain::errors::domain_error::DomainError),

    /// Input validation and data integrity errors
    ///
    /// Used for request validation, data format errors, and constraint violations.
    /// These are typically 400 Bad Request errors.
    #[error("Validation error: {0}")]
    Validation(String),

    /// Entity or resource not found errors
    ///
    /// When requested resources don't exist in the system.
    /// These are typically 404 Not Found errors.
    #[error("Not found: {0}")]
    NotFound(String),

    /// Resource conflicts and state violations
    ///
    /// When operations conflict with existing resources or system state.
    /// Examples: duplicate emails, concurrent modifications.
    /// These are typically 409 Conflict errors.
    #[error("Conflict: {0}")]
    Conflict(String),

    // ==============================================
    // AUTHENTICATION & AUTHORIZATION ERRORS
    // ==============================================
    // These errors handle user identity verification and access control.
    // They are critical for security and user experience.

    /// General authentication failures
    ///
    /// Used for token validation, session management, and identity verification.
    /// These are typically 401 Unauthorized errors.
    #[error("Authentication error: {0}")]
    Authentication(String),

    /// Permission and access control errors
    ///
    /// When authenticated users lack sufficient permissions.
    /// These are typically 403 Forbidden errors.
    #[error("Authorization error: {0}")]
    Authorization(String),

    /// Invalid login credentials
    ///
    /// Specific error for incorrect username/password combinations.
    /// Separated for better user messaging and security monitoring.
    #[error("Invalid credentials")]
    InvalidCredentials,

    /// User account is not active
    ///
    /// When user account is disabled, suspended, or pending activation.
    #[error("Account is inactive")]
    AccountInactive,

    /// Email verification required
    ///
    /// When user must verify their email before accessing features.
    #[error("Email not verified")]
    EmailNotVerified,

    // ==============================================
    // INFRASTRUCTURE LAYER ERRORS
    // ==============================================
    // These errors represent failures in external dependencies and infrastructure.
    // They often indicate system-level issues requiring different handling strategies.

    /// Database and persistence layer errors
    ///
    /// Connection issues, query failures, transaction problems, and data consistency errors.
    /// These are typically 500 Internal Server Error.
    #[error("Database error: {0}")]
    Database(String),

    /// Network and communication errors
    ///
    /// HTTP requests, TCP connections, DNS resolution, and network timeouts.
    /// These may be temporary and retryable.
    #[error("Network error: {0}")]
    Network(String),

    /// External service integration errors
    ///
    /// Third-party APIs, microservices, and external dependencies.
    /// These are typically 502 Bad Gateway or 503 Service Unavailable.
    #[error("External service error: {0}")]
    ExternalService(String),

    /// Application configuration errors
    ///
    /// Missing environment variables, invalid config files, and setup issues.
    /// These typically prevent application startup.
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Data serialization and format errors
    ///
    /// JSON parsing, XML processing, and data transformation failures.
    /// These are typically 400 Bad Request errors.
    #[error("Serialization error: {0}")]
    Serialization(String),

    // ==============================================
    // SYSTEM & OPERATIONAL ERRORS
    // ==============================================
    // These represent system-level failures and operational constraints.

    /// Internal system errors and unexpected failures
    ///
    /// Programming errors, unexpected states, and system bugs.
    /// These are typically 500 Internal Server Error.
    #[error("Internal error: {0}")]
    Internal(String),

    /// Rate limiting and throttling errors
    ///
    /// When users exceed allowed request rates or resource quotas.
    /// These are typically 429 Too Many Requests.
    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),
}

impl AppError {
    // ==============================================
    // DOMAIN LAYER ERROR CONSTRUCTORS
    // ==============================================

    /// Creates a validation error
    pub fn validation<T: Into<String>>(msg: T) -> Self {
        Self::Validation(msg.into())
    }

    /// Creates a not found error
    pub fn not_found<T: Into<String>>(msg: T) -> Self {
        Self::NotFound(msg.into())
    }

    /// Creates a conflict error
    pub fn conflict<T: Into<String>>(msg: T) -> Self {
        Self::Conflict(msg.into())
    }

    // ==============================================
    // AUTHENTICATION & AUTHORIZATION ERROR CONSTRUCTORS
    // ==============================================

    /// Creates an authentication error
    pub fn authentication<T: Into<String>>(msg: T) -> Self {
        Self::Authentication(msg.into())
    }

    /// Creates an authorization error
    pub fn authorization<T: Into<String>>(msg: T) -> Self {
        Self::Authorization(msg.into())
    }

    /// Creates an invalid credentials error
    pub fn invalid_credentials() -> Self {
        Self::InvalidCredentials
    }

    /// Creates an account inactive error
    pub fn account_inactive() -> Self {
        Self::AccountInactive
    }

    /// Creates an email not verified error
    pub fn email_not_verified() -> Self {
        Self::EmailNotVerified
    }

    // ==============================================
    // INFRASTRUCTURE LAYER ERROR CONSTRUCTORS
    // ==============================================

    /// Creates a database error
    pub fn database<T: Into<String>>(msg: T) -> Self {
        Self::Database(msg.into())
    }

    /// Creates a network error
    pub fn network<T: Into<String>>(msg: T) -> Self {
        Self::Network(msg.into())
    }

    /// Creates an external service error
    pub fn external_service<T: Into<String>>(msg: T) -> Self {
        Self::ExternalService(msg.into())
    }

    /// Creates a configuration error
    pub fn configuration<T: Into<String>>(msg: T) -> Self {
        Self::Configuration(msg.into())
    }

    /// Creates a serialization error
    pub fn serialization<T: Into<String>>(msg: T) -> Self {
        Self::Serialization(msg.into())
    }

    // ==============================================
    // SYSTEM & OPERATIONAL ERROR CONSTRUCTORS
    // ==============================================

    /// Creates an internal error
    pub fn internal<T: Into<String>>(msg: T) -> Self {
        Self::Internal(msg.into())
    }

    /// Creates a rate limit error
    pub fn rate_limit<T: Into<String>>(msg: T) -> Self {
        Self::RateLimit(msg.into())
    }

    // ==============================================
    // ERROR CLASSIFICATION METHODS
    // ==============================================

    /// Checks if error is recoverable (client can retry)
    ///
    /// Recoverable errors are typically temporary infrastructure issues
    /// that may resolve themselves with retry logic.
    pub fn is_recoverable(&self) -> bool {
        matches!(self,
            AppError::Network(_) |
            AppError::ExternalService(_) |
            AppError::Internal(_) |
            AppError::RateLimit(_)
        )
    }

    /// Checks if error is client-side (4xx HTTP status)
    ///
    /// Client errors indicate issues with the request that the client
    /// can potentially fix by modifying their request.
    pub fn is_client_error(&self) -> bool {
        matches!(self,
            AppError::Authentication(_) |
            AppError::Authorization(_) |
            AppError::Validation(_) |
            AppError::NotFound(_) |
            AppError::Conflict(_) |
            AppError::Domain(_) |
            AppError::InvalidCredentials |
            AppError::AccountInactive |
            AppError::EmailNotVerified |
            AppError::Serialization(_)
        )
    }

    /// Checks if error is server-side (5xx HTTP status)
    ///
    /// Server errors indicate issues with the system that the client
    /// cannot fix and may require system administrator intervention.
    pub fn is_server_error(&self) -> bool {
        !self.is_client_error() && !matches!(self, AppError::RateLimit(_))
    }

    /// Gets HTTP status code for the error
    ///
    /// Maps application errors to appropriate HTTP status codes
    /// for API responses.
    pub fn http_status_code(&self) -> u16 {
        match self {
            // Authentication & Authorization - 4xx
            AppError::Authentication(_) | AppError::InvalidCredentials => 401,
            AppError::Authorization(_) | AppError::AccountInactive | AppError::EmailNotVerified => 403,

            // Domain & Validation - 4xx
            AppError::NotFound(_) => 404,
            AppError::Conflict(_) => 409,
            AppError::Validation(_) | AppError::Domain(_) | AppError::Serialization(_) => 400,

            // Rate Limiting - 4xx
            AppError::RateLimit(_) => 429,

            // Infrastructure - 5xx
            AppError::ExternalService(_) => 502,
            AppError::Network(_) => 503,
            AppError::Database(_) | AppError::Configuration(_) | AppError::Internal(_) => 500,
        }
    }

    /// Gets error category for logging and monitoring
    ///
    /// Provides a stable category name for error tracking,
    /// metrics, and alerting systems.
    pub fn category(&self) -> &'static str {
        match self {
            // Domain Layer
            AppError::Domain(_) => "domain",
            AppError::Validation(_) => "validation",
            AppError::NotFound(_) => "not_found",
            AppError::Conflict(_) => "conflict",

            // Authentication & Authorization
            AppError::Authentication(_) => "authentication",
            AppError::Authorization(_) => "authorization",
            AppError::InvalidCredentials => "invalid_credentials",
            AppError::AccountInactive => "account_inactive",
            AppError::EmailNotVerified => "email_not_verified",

            // Infrastructure
            AppError::Database(_) => "database",
            AppError::Network(_) => "network",
            AppError::ExternalService(_) => "external_service",
            AppError::Configuration(_) => "configuration",
            AppError::Serialization(_) => "serialization",

            // System & Operational
            AppError::Internal(_) => "internal",
            AppError::RateLimit(_) => "rate_limit",
        }
    }

    /// Gets error severity level for logging
    ///
    /// Helps prioritize error handling and alerting based on impact.
    pub fn severity(&self) -> &'static str {
        match self {
            // Critical - System failures
            AppError::Database(_) | AppError::Configuration(_) => "critical",

            // High - Service degradation
            AppError::Internal(_) | AppError::ExternalService(_) => "high",

            // Medium - Operational issues
            AppError::Network(_) | AppError::RateLimit(_) => "medium",

            // Low - Expected business cases
            AppError::Domain(_) | AppError::Validation(_) | AppError::NotFound(_) |
            AppError::Conflict(_) | AppError::Authentication(_) | AppError::Authorization(_) |
            AppError::InvalidCredentials | AppError::AccountInactive | AppError::EmailNotVerified |
            AppError::Serialization(_) => "low",
        }
    }
}

/// Result type alias for application operations
pub type AppResult<T> = Result<T, AppError>;

/// Error context for better error tracking and debugging
#[derive(Debug, Clone)]
pub struct ErrorContext {
    /// Operation that was being performed
    pub operation: String,
    /// Additional context information
    pub context: std::collections::HashMap<String, String>,
    /// Timestamp when error occurred
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl ErrorContext {
    /// Creates new error context
    pub fn new(operation: &str) -> Self {
        Self {
            operation: operation.to_string(),
            context: std::collections::HashMap::new(),
            timestamp: chrono::Utc::now(),
        }
    }

    /// Adds context key-value pair
    pub fn with_context<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.context.insert(key.into(), value.into());
        self
    }

    /// Adds user ID to context
    pub fn with_user_id(self, user_id: uuid::Uuid) -> Self {
        self.with_context("user_id", user_id.to_string())
    }

    /// Adds request ID to context
    pub fn with_request_id(self, request_id: &str) -> Self {
        self.with_context("request_id", request_id)
    }
}

/// Enhanced error with context information
#[derive(Debug)]
pub struct ContextualError {
    /// The underlying error
    pub error: AppError,
    /// Error context
    pub context: ErrorContext,
}

impl ContextualError {
    /// Creates new contextual error
    pub fn new(error: AppError, context: ErrorContext) -> Self {
        Self { error, context }
    }

    /// Creates contextual error with operation context
    pub fn with_operation(error: AppError, operation: &str) -> Self {
        Self::new(error, ErrorContext::new(operation))
    }
}

impl fmt::Display for ContextualError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (operation: {})", self.error, self.context.operation)
    }
}

impl std::error::Error for ContextualError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Macro for creating contextual errors easily
#[macro_export]
macro_rules! contextual_error {
    ($error:expr, $operation:expr) => {
        $crate::common::errors::ContextualError::with_operation($error, $operation)
    };
    ($error:expr, $operation:expr, $($key:expr => $value:expr),+) => {
        {
            let mut context = $crate::common::errors::ErrorContext::new($operation);
            $(
                context = context.with_context($key, $value);
            )+
            $crate::common::errors::ContextualError::new($error, context)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::errors::domain_error::DomainError;

    #[test]
    fn test_app_error_from_domain_error() {
        let domain_error = DomainError::ValidationError("test error".to_string());
        let app_error: AppError = domain_error.into();

        assert!(matches!(app_error, AppError::Domain(_)));
        assert!(app_error.is_client_error());
        assert_eq!(app_error.http_status_code(), 400);
    }

    #[test]
    fn test_error_categorization() {
        let auth_error = AppError::authentication("Invalid token");
        assert!(auth_error.is_client_error());
        assert!(!auth_error.is_recoverable());
        assert_eq!(auth_error.http_status_code(), 401);
        assert_eq!(auth_error.category(), "authentication");
    }

    #[test]
    fn test_error_context() {
        let context = ErrorContext::new("user_login")
            .with_user_id(uuid::Uuid::new_v4())
            .with_context("ip_address", "192.168.1.1");

        assert_eq!(context.operation, "user_login");
        assert!(context.context.contains_key("user_id"));
        assert!(context.context.contains_key("ip_address"));
    }

    #[test]
    fn test_contextual_error() {
        let error = AppError::authentication("Invalid credentials");
        let contextual = ContextualError::with_operation(error, "user_login");

        assert_eq!(contextual.context.operation, "user_login");
    }
}

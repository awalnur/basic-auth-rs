// Domain errors specific to the authentication domain

use thiserror::Error;

/// Errors that occur in the domain layer
///
/// This enum defines all types of errors that may occur
/// in domain business logic, independent of infrastructure or
/// framework being used.
///
/// # Example
///
/// ```no_run
/// // Example usage (this is documentation, not executed as test)
/// use basic_auth::domain::errors::domain_error::DomainError;
///
/// fn process_business_logic() -> Result<(), DomainError> {
///     // Business logic implementation...
///     let condition_not_met = true; // example condition
///     if condition_not_met {
///         return Err(DomainError::business_rule_violation("Rule XYZ violated"));
///     }
///
///     Ok(())
/// }
/// ```
#[derive(Error, Debug)]
pub enum DomainError {
    /// Error when the requested entity is not found
    #[error("Entity not found: {0}")]
    EntityNotFound(String),

    /// Data validation error
    #[error("Validation failed: {0}")]
    ValidationError(String),

    /// Business rule violation
    #[error("Business rule violation: {0}")]
    BusinessRuleViolation(String),

    /// Authorization error
    #[error("Authorization failed: {0}")]
    AuthorizationError(String),

    /// Repository error
    #[error("Repository error: {0}")]
    RepositoryError(String),
}

/// Helper methods for DomainError
impl DomainError {
    /// Creates an EntityNotFound error with entity name and ID
    pub fn entity_not_found(entity: &str, id: &str) -> Self {
        Self::EntityNotFound(format!("{} with id '{}' not found", entity, id))
    }

    /// Creates a validation error
    pub fn validation(message: &str) -> Self {
        Self::ValidationError(message.to_string())
    }

    /// Creates a business rule violation error
    pub fn business_rule_violation(message: &str) -> Self {
        Self::BusinessRuleViolation(message.to_string())
    }

    /// Creates an authorization error
    pub fn authorization(message: &str) -> Self {
        Self::AuthorizationError(message.to_string())
    }

    /// Creates a repository error
    pub fn repository(message: &str) -> Self {
        Self::RepositoryError(message.to_string())
    }
}

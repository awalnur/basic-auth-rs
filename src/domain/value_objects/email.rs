// Value object is an object without unique identity
// Only defined by its values

use thiserror::Error;
use std::fmt;

/// Value Object `Email` that represents a valid email address
///
/// This Value Object performs validation to ensure that the stored
/// value is a valid email address. Email is immutable and can only
/// be created through a constructor that validates the input value.
///
/// # Examples
///
// ```rust
//
// let email = Email::new("user@example.com".to_string()).expect("Valid email");
// assert_eq!(email.value(), "user@example.com");
//
// // Invalid email will return an error
// let invalid = Email::new("invalid-email".to_string());
// assert!(invalid.is_err());
// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email {
    value: String,
}

/// Error that may occur when creating or validating an Email
#[derive(Debug, Error)]
pub enum EmailError {
    /// Occurs when the email format is invalid
    #[error("Invalid email: {0}")]
    InvalidEmail(String),
}

impl Email {
    /// Creates a new Email instance after validating the format
    ///
    /// # Arguments
    ///
    /// * `email` - String of the email address to be validated
    ///
    /// # Returns
    ///
    /// * `Result<Self, EmailError>` - Valid email or error if validation fails
    ///
    /// # Errors
    ///
    /// Returns `EmailError::InvalidEmail` if the email format is invalid
    pub fn new(email: String) -> Result<Self, EmailError> {
        // Validate email with minimal criteria
        if !email.contains('@') || !email.contains('.') {
            return Err(EmailError::InvalidEmail(email));
        }

        // Other validations can be added here
        // for example: regex for stricter format, domain validation, etc.

        Ok(Self { value: email })
    }

    /// Gets the email value as a string reference
    ///
    /// # Returns
    ///
    /// * `&str` - String reference to the email value
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// Display implementation for Email for easy printing
impl fmt::Display for Email {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

/// Conversion from String to Email with validation
impl TryFrom<String> for Email {
    type Error = EmailError;

    fn try_from(email: String) -> Result<Self, Self::Error> {
        Email::new(email)
    }
}

/// Conversion from &str to Email with validation
impl TryFrom<&str> for Email {
    type Error = EmailError;

    fn try_from(email: &str) -> Result<Self, Self::Error> {
        Email::new(email.to_string())
    }
}

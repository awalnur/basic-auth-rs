use basic_auth::domain::value_objects::email::{Email, EmailError};
use std::convert::TryFrom;

/// Tes untuk memastikan value object Email berfungsi dengan benar
#[cfg(test)]
mod email_value_object_tests {
    use super::*;

    #[test]
    fn test_valid_email_creation() {
        // Arrange & Act
        let email = Email::new("user@example.com".to_string());

        // Assert
        assert!(email.is_ok());
        let email = email.unwrap();
        assert_eq!(email.value(), "user@example.com");
    }

    #[test]
    fn test_invalid_email_without_at() {
        // Arrange & Act
        let email = Email::new("userexample.com".to_string());

        // Assert
        assert!(email.is_err());
        match email.unwrap_err() {
            EmailError::InvalidEmail(e) => assert_eq!(e, "userexample.com"),
            _ => panic!("Expected InvalidEmail error"),
        }
    }

    #[test]
    fn test_invalid_email_without_dot() {
        // Arrange & Act
        let email = Email::new("user@examplecom".to_string());

        // Assert
        assert!(email.is_err());
    }

    #[test]
    fn test_try_from_string() {
        // Arrange & Act
        let email = Email::try_from("user@example.com".to_string());

        // Assert
        assert!(email.is_ok());
        let email = email.unwrap();
        assert_eq!(email.value(), "user@example.com");
    }

    #[test]
    fn test_try_from_str() {
        // Arrange & Act
        let email = Email::try_from("user@example.com");

        // Assert
        assert!(email.is_ok());
        let email = email.unwrap();
        assert_eq!(email.value(), "user@example.com");
    }

    #[test]
    fn test_display_implementation() {
        // Arrange
        let email = Email::new("user@example.com".to_string()).unwrap();

        // Act
        let displayed = format!("{}", email);

        // Assert
        assert_eq!(displayed, "user@example.com");
    }
}

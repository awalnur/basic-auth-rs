use chrono::Utc;
use basic_auth::domain::entities::user::User;

/// Tes untuk memastikan entity User berfungsi dengan benar
#[cfg(test)]
mod user_entity_tests {
    use super::*;

    /// Helper function untuk membuat user test dengan nilai default
    fn create_test_user() -> User {
        User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            "hashed_password123".to_string(),
        )
    }

    #[test]
    fn test_new_user_creation() {
        // Arrange & Act
        let user = create_test_user();

        // Assert
        assert_eq!(user.username, "testuser");
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.password_hash, "hashed_password123");
        assert_eq!(user.email_verified, false);
        assert_eq!(user.is_active, true);
    }

    #[test]
    fn test_verify_email() {
        // Arrange
        let mut user = create_test_user();
        assert_eq!(user.email_verified, false);

        // Act
        user.verify_email();

        // Assert
        assert_eq!(user.email_verified, true);
    }

    #[test]
    fn test_deactivate_account() {
        // Arrange
        let mut user = create_test_user();
        assert_eq!(user.is_active, true);

        // Act
        user.deactivate();

        // Assert
        assert_eq!(user.is_active, false);
    }

    #[test]
    fn test_activate_account() {
        // Arrange
        let mut user = create_test_user();
        user.deactivate();
        assert_eq!(user.is_active, false);

        // Act
        user.activate();

        // Assert
        assert_eq!(user.is_active, true);
    }

    #[test]
    fn test_change_email() {
        // Arrange
        let mut user = create_test_user();
        user.verify_email();
        assert_eq!(user.email_verified, true);

        // Act
        let new_email = "new_email@example.com".to_string();
        user.change_email(new_email.clone());

        // Assert
        assert_eq!(user.email, new_email);
        assert_eq!(user.email_verified, false); // Email verification should be reset
    }

    #[test]
    fn test_updated_timestamp_changes() {
        // Arrange
        let mut user = create_test_user();
        let created_at = user.created_at;
        let initial_updated_at = user.updated_at;

        // Simulasi waktu berlalu
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Act
        user.verify_email();

        // Assert
        assert_eq!(user.created_at, created_at); // Created at shouldn't change
        assert!(user.updated_at > initial_updated_at); // Updated at should be later
    }
}

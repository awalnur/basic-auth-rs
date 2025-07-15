use std::sync::Arc;
use mockall::predicate::*;
use mockall::mock;
use basic_auth::domain::services::authentication_service::{AuthenticationService, AuthenticationError};
use basic_auth::domain::entities::user::User;
use basic_auth::domain::repositories::user_repository::{UserRepository, RepositoryResult};
use uuid::Uuid;

// Membuat mock untuk UserRepository
mock! {
    pub UserRepository {}

    #[async_trait::async_trait]
    impl UserRepository for UserRepository {
        async fn find_by_id(&self, id: Uuid) -> RepositoryResult<Option<User>>;
        async fn find_by_email(&self, email: &str) -> RepositoryResult<Option<User>>;
        async fn find_by_username(&self, username: &str) -> RepositoryResult<Option<User>>;
        async fn save(&self, user: &User) -> RepositoryResult<User>;
        async fn update(&self, user: &User) -> RepositoryResult<()>;
        async fn delete(&self, id: Uuid) -> RepositoryResult<()>;
        async fn find_active_users(&self) -> RepositoryResult<Vec<User>>;
        async fn find_users_by_role(&self, role_id: Uuid) -> RepositoryResult<Vec<User>>;
    }
}

#[cfg(test)]
mod authentication_service_tests {
    use super::*;

    fn create_test_user(active: bool, email_verified: bool) -> User {
        let mut user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            "hashed:password123".to_string(),
        );
        user.is_active = active;
        if email_verified {
            user.verify_email();
        }
        user
    }

    #[tokio::test]
    async fn test_authenticate_with_email_success() {
        // Arrange
        let mut mock_repo = MockUserRepository::new();
        let user = create_test_user(true, true);
        let email = user.email.clone();

        mock_repo
            .expect_find_by_email()
            .with(eq(email.as_str()))
            .times(1)
            .returning(move |_| Ok(Some(user.clone())));

        let service = AuthenticationService::new(Arc::new(mock_repo));

        // Act
        let result = service.authenticate(&email, "password123").await;

        // Assert
        assert!(result.is_ok());
        let authenticated_user = result.unwrap();
        assert_eq!(authenticated_user.username, "testuser");
    }

    #[tokio::test]
    async fn test_authenticate_with_username_success() {
        // Arrange
        let mut mock_repo = MockUserRepository::new();
        let user = create_test_user(true, true);
        let username = user.username.clone();

        mock_repo
            .expect_find_by_username()
            .with(eq(username.as_str()))
            .times(1)
            .returning(move |_| Ok(Some(user.clone())));

        let service = AuthenticationService::new(Arc::new(mock_repo));

        // Act
        let result = service.authenticate(&username, "password123").await;

        // Assert
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_authenticate_user_not_found() {
        // Arrange
        let mut mock_repo = MockUserRepository::new();

        mock_repo
            .expect_find_by_email()
            .with(eq("nonexistent@example.com"))
            .times(1)
            .returning(|_| Ok(None));

        let service = AuthenticationService::new(Arc::new(mock_repo));

        // Act
        let result = service.authenticate("nonexistent@example.com", "password123").await;

        // Assert
        assert!(result.is_err());
        match result {
            Err(AuthenticationError::InvalidCredentials) => (),
            _ => panic!("Expected InvalidCredentials error"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_inactive_account() {
        // Arrange
        let mut mock_repo = MockUserRepository::new();
        let user = create_test_user(false, true); // inactive user
        let email = user.email.clone();

        mock_repo
            .expect_find_by_email()
            .with(eq(email.as_str()))
            .times(1)
            .returning(move |_| Ok(Some(user.clone())));

        let service = AuthenticationService::new(Arc::new(mock_repo));

        // Act
        let result = service.authenticate(&email, "password123").await;

        // Assert
        assert!(result.is_err());
        match result {
            Err(AuthenticationError::InactiveAccount) => (),
            _ => panic!("Expected InactiveAccount error"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_invalid_password() {
        // Arrange
        let mut mock_repo = MockUserRepository::new();
        let user = create_test_user(true, true);
        let email = user.email.clone();

        mock_repo
            .expect_find_by_email()
            .with(eq(email.as_str()))
            .times(1)
            .returning(move |_| Ok(Some(user.clone())));

        let service = AuthenticationService::new(Arc::new(mock_repo));

        // Act
        let result = service.authenticate(&email, "wrong_password").await;

        // Assert
        assert!(result.is_err());
        match result {
            Err(AuthenticationError::InvalidCredentials) => (),
            _ => panic!("Expected InvalidCredentials error"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_repository_error() {
        // Arrange
        let mut mock_repo = MockUserRepository::new();

        mock_repo
            .expect_find_by_email()
            .with(eq("test@example.com"))
            .times(1)
            .returning(|_| Err("Database connection error".into()));

        let service = AuthenticationService::new(Arc::new(mock_repo));

        // Act
        let result = service.authenticate("test@example.com", "password123").await;

        // Assert
        assert!(result.is_err());
        match result {
            Err(AuthenticationError::RepositoryError(_)) => (),
            _ => panic!("Expected RepositoryError"),
        }
    }
}

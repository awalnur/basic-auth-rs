use std::sync::Arc;
use mockall::predicate::*;
use mockall::mock;
use basic_auth::application::use_cases::auth::login_use_case::{LoginUseCase, AuthError};
use basic_auth::application::dtos::auth_dto::{LoginRequestDto, LoginResponseDto};
use basic_auth::domain::services::authentication_service::{AuthenticationService, AuthenticationError};
use basic_auth::domain::entities::user::User;
use basic_auth::application::ports::token_port::{TokenService, TokenResult};
use uuid::Uuid;
use chrono::Utc;

// Membuat mock untuk AuthenticationService
mock! {
    pub AuthenticationService {}

    impl AuthenticationService {
        pub fn new(_: std::sync::Arc<dyn basic_auth::domain::repositories::user_repository::UserRepository + Send + Sync>) -> Self;

        pub async fn authenticate(&self, username_or_email: &str, password: &str) -> Result<User, AuthenticationError>;
    }
}

// Membuat mock untuk TokenService
mock! {
    pub TokenService {}

    impl TokenService {
        pub fn generate_token(&self, user_id: &str, expires_at: i64) -> TokenResult<String>;
        pub fn validate_token(&self, token: &str) -> TokenResult<String>;
        pub fn get_user_id_from_token(&self, token: &str) -> TokenResult<String>;
    }
}

#[cfg(test)]
mod login_use_case_tests {
    use super::*;

    fn create_test_user() -> User {
        User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            "hashed:password123".to_string(),
        )
    }

    fn create_login_request() -> LoginRequestDto {
        LoginRequestDto {
            username_or_email: "test@example.com".to_string(),
            password: "password123".to_string(),
        }
    }

    #[tokio::test]
    async fn test_login_success() {
        // Arrange
        let mut mock_auth_service = MockAuthenticationService::new();
        let mut mock_token_service = MockTokenService::new();
        let user = create_test_user();
        let request = create_login_request();

        mock_auth_service
            .expect_authenticate()
            .with(eq(request.username_or_email.clone()), eq(request.password.clone()))
            .times(1)
            .returning(move |_, _| Ok(user.clone()));

        let token = "jwt.token.here".to_string();
        let expiry_timestamp = Utc::now().timestamp() + 3600; // 1 hour from now

        mock_token_service
            .expect_generate_token()
            .with(eq(user.id.to_string()), gt(0_i64))
            .times(1)
            .returning(move |_, _| Ok(token.clone()));

        let use_case = LoginUseCase::new(Arc::new(mock_auth_service), Arc::new(mock_token_service));

        // Act
        let result = use_case.execute(request).await;

        // Assert
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.username, "testuser");
        assert_eq!(response.token, "jwt.token.here");
    }

    #[tokio::test]
    async fn test_login_invalid_credentials() {
        // Arrange
        let mut mock_auth_service = MockAuthenticationService::new();
        let mock_token_service = MockTokenService::new();
        let request = create_login_request();

        mock_auth_service
            .expect_authenticate()
            .with(eq(request.username_or_email.clone()), eq(request.password.clone()))
            .times(1)
            .returning(|_, _| Err(AuthenticationError::InvalidCredentials));

        let use_case = LoginUseCase::new(Arc::new(mock_auth_service), Arc::new(mock_token_service));

        // Act
        let result = use_case.execute(request).await;

        // Assert
        assert!(result.is_err());
        match result {
            Err(AuthError::InvalidCredentials) => (),
            _ => panic!("Expected InvalidCredentials error"),
        }
    }

    #[tokio::test]
    async fn test_login_inactive_account() {
        // Arrange
        let mut mock_auth_service = MockAuthenticationService::new();
        let mock_token_service = MockTokenService::new();
        let request = create_login_request();

        mock_auth_service
            .expect_authenticate()
            .with(eq(request.username_or_email.clone()), eq(request.password.clone()))
            .times(1)
            .returning(|_, _| Err(AuthenticationError::InactiveAccount));

        let use_case = LoginUseCase::new(Arc::new(mock_auth_service), Arc::new(mock_token_service));

        // Act
        let result = use_case.execute(request).await;

        // Assert
        assert!(result.is_err());
        match result {
            Err(AuthError::AccountInactive) => (),
            _ => panic!("Expected AccountInactive error"),
        }
    }

    #[tokio::test]
    async fn test_login_token_generation_error() {
        // Arrange
        let mut mock_auth_service = MockAuthenticationService::new();
        let mut mock_token_service = MockTokenService::new();
        let user = create_test_user();
        let request = create_login_request();

        mock_auth_service
            .expect_authenticate()
            .with(eq(request.username_or_email.clone()), eq(request.password.clone()))
            .times(1)
            .returning(move |_, _| Ok(user.clone()));

        mock_token_service
            .expect_generate_token()
            .with(eq(user.id.to_string()), gt(0_i64))
            .times(1)
            .returning(|_, _| Err(basic_auth::application::ports::token_port::TokenError::GenerationError("Failed to generate token".into())));

        let use_case = LoginUseCase::new(Arc::new(mock_auth_service), Arc::new(mock_token_service));

        // Act
        let result = use_case.execute(request).await;

        // Assert
        assert!(result.is_err());
        match result {
            Err(AuthError::InternalError(_)) => (),
            _ => panic!("Expected InternalError"),
        }
    }
}

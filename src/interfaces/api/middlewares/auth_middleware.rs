// Authentication middleware for protecting API routes
// This middleware validates JWT tokens and extracts user information

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, HttpResponse, Result, body::BoxBody,
};
use futures_util::future::LocalBoxFuture;
use std::future::{ready, Ready};
use std::sync::Arc;
use log::{debug, warn, error};

use crate::application::ports::token_port::{TokenService, TokenError};
use crate::common::errors::AppError;
use crate::common::models::response::{ApiErrorResponse, ErrorToResponse};

/// Type alias for token service trait object
type TokenServiceArc = Arc<dyn TokenService + Send + Sync>;

/// Type alias for middleware service future
type ServiceFuture<B> = LocalBoxFuture<'static, Result<ServiceResponse<B>, Error>>;

/// Authentication middleware that validates JWT tokens
///
/// This middleware intercepts HTTP requests and validates the Authorization header
/// containing a Bearer token. If the token is valid, it extracts the user ID
/// and adds it to the request extensions for use in controllers.
pub struct AuthMiddleware {
    token_service: Arc<dyn TokenService + Send + Sync>,
}

impl AuthMiddleware {
    /// Creates a new AuthMiddleware instance
    ///
    /// # Arguments
    ///
    /// * `token_service` - Service for token validation and operations
    pub fn new(token_service: Arc<dyn TokenService + Send + Sync>) -> Self {
        Self { token_service }
    }
}

/// Transform implementation for ActixWeb middleware
impl<S> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response=ServiceResponse, Error=Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareService {
            service,
            token_service: self.token_service.clone(),
        }))
    }
}

/// Helper function to convert TokenError to AppError
fn token_error_to_app_error(err: TokenError) -> AppError {
    match err {
        TokenError::InvalidToken => AppError::authentication("The provided token is invalid or malformed"),
        TokenError::ExpiredToken => AppError::authentication("The provided token has expired"),
        TokenError::GenerationError(msg) => AppError::internal(format!("Token generation error: {}", msg)),
        TokenError::Other(msg) => AppError::authentication(format!("Authentication error: {}", msg)),
    }
}

/// The actual middleware service that processes requests
pub struct AuthMiddlewareService<S> {
    service: S,
    token_service: Arc<dyn TokenService + Send + Sync>,
}

impl<S> Service<ServiceRequest> for AuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response=ServiceResponse, Error=Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let token_service = self.token_service.clone();

        // Extract the Authorization header
        let auth_header = req.headers().get("Authorization");
        debug!("Processing request: {:?}", req);
        if let Some(auth_value) = auth_header {
            if let Ok(auth_str) = auth_value.to_str() {
                debug!("Authorization header found: {}", auth_str);
                // Check if it's a Bearer token
                if auth_str.starts_with("Bearer ") {
                    let token = &auth_str[7..]; // Remove "Bearer " prefix

                    // Validate the token
                    match token_service.validate_token(token) {
                        Ok(user_id) => {
                            debug!("Token validated successfully for user: {}", user_id);

                            // Add user ID to request extensions
                            req.extensions_mut().insert(AuthenticatedUser {
                                user_id: user_id.clone(),
                            });

                            // Continue with the request
                            let fut = self.service.call(req);
                            Box::pin(async move {
                                let res = fut.await?;
                                Ok(res)
                            })
                        }
                        Err(err) => {
                            let app_error = token_error_to_app_error(err);

                            // Log based on error type
                            match &app_error {
                                AppError::Authentication(msg) => warn!("Access denied: {}", msg),
                                _ => error!("Token validation error: {:?}", app_error),
                            };

                            // Convert to response using our unified error handling
                            let error_response = app_error.to_response().to_http_response();

                            Box::pin(async move {
                                Ok(req.into_response(error_response))
                            })
                        }
                    }
                } else {
                    warn!("Access denied: Invalid authorization format (not Bearer)");
                    let app_error = AppError::authentication("Authorization header must start with 'Bearer '");
                    let error_response = app_error.to_response().to_http_response();

                    Box::pin(async move {
                        Ok(req.into_response(error_response))
                    })
                }
            } else {
                warn!("Access denied: Authorization header contains invalid characters");
                let app_error = AppError::authentication("Authorization header contains invalid characters");
                let error_response = app_error.to_response().to_http_response();

                Box::pin(async move {
                    Ok(req.into_response(error_response))
                })
            }
        } else {
            warn!("Access denied: Missing Authorization header");
            let app_error = AppError::authentication("Authorization header is required");
            Box::pin(async move {
                let error_response = app_error.to_response().to_http_response();

                Ok(req.into_response(error_response))
            })
        }
    }
}

/// Struct to store authenticated user information in request extensions
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: String,
}

/// Helper trait to extract authenticated user from request
pub trait AuthUserExtractor {
    /// Extract authenticated user from request extensions
    ///
    /// # Returns
    ///
    /// * `Option<AuthenticatedUser>` - Authenticated user if present
    fn authenticated_user(self) -> Option<AuthenticatedUser>;
}

impl AuthUserExtractor for ServiceRequest {
    fn authenticated_user(self) -> Option<AuthenticatedUser> {
        self.extensions().get::<AuthenticatedUser>().cloned()
    }
}

impl AuthUserExtractor for actix_web::HttpRequest {
    fn authenticated_user(self) -> Option<AuthenticatedUser> {
        // let extensions = self.extensions();=
        self.extensions().get::<AuthenticatedUser>().cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App, HttpResponse};
    use crate::application::ports::token_port::{TokenService, TokenResult, TokenError};
    use std::sync::Arc;
    use serde_json::json;
    use crate::common::models::response::ApiErrorResponse;

    // Mock token service for testing
    struct MockTokenService {
        should_succeed: bool,
        user_id: String,
    }

    impl MockTokenService {
        fn new(should_succeed: bool, user_id: String) -> Self {
            Self { should_succeed, user_id }
        }
    }

    impl TokenService for MockTokenService {
        fn generate_token(&self, _user_id: &str, _expires_at: i64) -> TokenResult<String> {
            Ok("test_token".to_string())
        }

        fn validate_token(&self, _token: &str) -> TokenResult<String> {
            if self.should_succeed {
                Ok(self.user_id.clone())
            } else {
                Err(TokenError::InvalidToken)
            }
        }

        fn get_user_id_from_token(&self, _token: &str) -> TokenResult<String> {
            if self.should_succeed {
                Ok(self.user_id.clone())
            } else {
                Err(TokenError::InvalidToken)
            }
        }
    }

    async fn test_handler(req: actix_web::HttpRequest) -> impl actix_web::Responder {
        if let Some(user) = req.authenticated_user() {
            HttpResponse::Ok().json(json!({
                "message": "Success",
                "user_id": user.user_id
            }))
        } else {
            HttpResponse::InternalServerError().json(json!({
                "error": "No authenticated user found"
            }))
        }
    }

    #[actix_web::test]
    async fn test_middleware_with_valid_token() {
        let token_service = Arc::new(MockTokenService::new(true, "user123".to_string()));
        // Create the AuthMiddleware with the mock token service
        let auth_middleware = AuthMiddleware::new(token_service);


        let app = test::init_service(
            App::new()
                .wrap(auth_middleware)
                .route("/protected", web::get().to(|req: actix_web::HttpRequest| async move {
                    if let Some(user) = req.authenticated_user() {
                        HttpResponse::Ok().json(json!({
                        "message": "Success",
                        "user_id": user.user_id
                    }))
                    } else {
                        HttpResponse::InternalServerError().json(json!({
                        "error": "No authenticated user found"
                    }))
                    }
                }))
        ).await;

        let req = test::TestRequest::get()
            .uri("/protected")
            .insert_header(("Authorization", "Bearer valid_token"))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_web::test]
    async fn test_middleware_with_invalid_token() {
        let token_service = Arc::new(MockTokenService::new(false, "".to_string()));
        let auth_middleware = AuthMiddleware::new(token_service);

        let app = test::init_service(
            App::new()
                .wrap(auth_middleware)
                .route("/protected", web::get().to(test_handler))
        ).await;

        let req = test::TestRequest::get()
            .uri("/protected")
            .insert_header(("Authorization", "Bearer invalid_token"))
            .to_request();

        let resp = test::call_service(&app, req).await;

        // Check for 401 Unauthorized status
        assert_eq!(resp.status().as_u16(), 401);

        // Verify response body format matches our new error structure
        let body = test::read_body(resp).await;
        let error_response: ApiErrorResponse = serde_json::from_slice(&body).expect("Failed to parse response body");

        assert_eq!(error_response.success, false);
        assert_eq!(error_response.status_code, 401);
        assert_eq!(error_response.error_code, "Unauthorized");
    }

    #[actix_web::test]
    async fn test_middleware_with_missing_token() {
        let token_service = Arc::new(MockTokenService::new(true, "user123".to_string()));
        let auth_middleware = AuthMiddleware::new(token_service);

        let app = test::init_service(
            App::new()
                .wrap(auth_middleware)
                .route("/protected", web::get().to(test_handler))
        ).await;

        let req = test::TestRequest::get()
            .uri("/protected")
            .to_request();

        let resp = test::call_service(&app, req).await;

        // Check for 401 Unauthorized status
        assert_eq!(resp.status().as_u16(), 401);

        // Verify response body format matches our new error structure
        let body = test::read_body(resp).await;
        let error_response: ApiErrorResponse = serde_json::from_slice(&body).expect("Failed to parse response body");

        assert_eq!(error_response.success, false);
        assert_eq!(error_response.status_code, 401);
        assert_eq!(error_response.error_code, "Unauthorized");
        assert!(error_response.message.contains("Authorization header is required"));
    }

    #[actix_web::test]
    async fn test_middleware_with_invalid_auth_format() {
        let token_service = Arc::new(MockTokenService::new(true, "user123".to_string()));
        let auth_middleware = AuthMiddleware::new(token_service);

        let app = test::init_service(
            App::new()
                .wrap(auth_middleware)
                .route("/protected", web::get().to(test_handler))
        ).await;

        let req = test::TestRequest::get()
            .uri("/protected")
            .insert_header(("Authorization", "Basic dXNlcjpwYXNz"))
            .to_request();

        let resp = test::call_service(&app, req).await;

        // Check for 401 Unauthorized status
        assert_eq!(resp.status().as_u16(), 401);

        // Verify response body format matches our new error structure
        let body = test::read_body(resp).await;
        let error_response: ApiErrorResponse = serde_json::from_slice(&body).expect("Failed to parse response body");

        assert_eq!(error_response.success, false);
        assert_eq!(error_response.status_code, 401);
        assert_eq!(error_response.error_code, "Unauthorized");
        assert!(error_response.message.contains("Bearer"));
    }
}

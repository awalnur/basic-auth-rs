use basic_auth::interfaces::api::controllers::auth_controller::AuthController;
use basic_auth::application::dtos::auth_dto::{LoginRequestDto, RegisterUserDto};
use actix_web::{test, web, App, http::StatusCode};
use serde_json::json;

#[cfg(test)]
#[cfg(feature = "e2e_tests")]
mod auth_flow_tests {
    use super::*;
    use crate::common::test_helpers;

    async fn setup_test_app() -> actix_web::test::TestApp {
        // Initialize the application with real dependencies
        // This would normally include DB setup, but is simplified here

        // In a real implementation, you would use the main app factory
        // that properly wires up all dependencies
        let app = test::init_service(
            App::new()
                .configure(|cfg| {
                    // Normally we'd configure the app here with real dependencies
                    // But for simplicity in this example, we'll leave it minimal
                })
        ).await;

        app
    }

    #[actix_web::test]
    async fn test_registration_login_flow() {
        // Setup test app
        let app = setup_test_app().await;

        // 1. Register a new user
        let username = test_helpers::random_username();
        let email = test_helpers::random_email();
        let register_data = json!({
            "username": username,
            "email": email,
            "password": "Password123"
        });

        let register_req = test::TestRequest::post()
            .uri("/api/auth/register")
            .set_json(&register_data)
            .to_request();

        let register_resp = test::call_service(&app, register_req).await;
        assert_eq!(register_resp.status(), StatusCode::CREATED);

        // Extract user data from registration response
        let register_body: serde_json::Value = test::read_body_json(register_resp).await;
        assert_eq!(register_body["username"], username);
        assert_eq!(register_body["email"], email);

        // 2. Try login with the newly registered user
        let login_data = json!({
            "username_or_email": email,
            "password": "Password123"
        });

        let login_req = test::TestRequest::post()
            .uri("/api/auth/login")
            .set_json(&login_data)
            .to_request();

        let login_resp = test::call_service(&app, login_req).await;
        assert_eq!(login_resp.status(), StatusCode::OK);

        // Extract token from login response
        let login_body: serde_json::Value = test::read_body_json(login_resp).await;
        assert!(login_body["token"].as_str().is_some());
        let token = login_body["token"].as_str().unwrap();

        // 3. Access a protected endpoint using the token
        let protected_req = test::TestRequest::get()
            .uri("/api/users/me")
            .header("Authorization", format!("Bearer {}", token))
            .to_request();

        let protected_resp = test::call_service(&app, protected_req).await;
        assert_eq!(protected_resp.status(), StatusCode::OK);

        // 4. Logout
        let logout_req = test::TestRequest::post()
            .uri("/api/auth/logout")
            .header("Authorization", format!("Bearer {}", token))
            .to_request();

        let logout_resp = test::call_service(&app, logout_req).await;
        assert_eq!(logout_resp.status(), StatusCode::OK);

        // 5. Try accessing protected endpoint after logout (should fail)
        let protected_req_after_logout = test::TestRequest::get()
            .uri("/api/users/me")
            .header("Authorization", format!("Bearer {}", token))
            .to_request();

        let protected_resp_after_logout = test::call_service(&app, protected_req_after_logout).await;
        assert_eq!(protected_resp_after_logout.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn test_invalid_login_attempts() {
        // Setup test app
        let app = setup_test_app().await;

        // 1. Try login with non-existent user
        let login_data = json!({
            "username_or_email": "nonexistent@example.com",
            "password": "Password123"
        });

        let login_req = test::TestRequest::post()
            .uri("/api/auth/login")
            .set_json(&login_data)
            .to_request();

        let login_resp = test::call_service(&app, login_req).await;
        assert_eq!(login_resp.status(), StatusCode::UNAUTHORIZED);

        // 2. Try login with invalid password format
        let login_data = json!({
            "username_or_email": "user@example.com",
            "password": "12" // Too short
        });

        let login_req = test::TestRequest::post()
            .uri("/api/auth/login")
            .set_json(&login_data)
            .to_request();

        let login_resp = test::call_service(&app, login_req).await;
        assert_eq!(login_resp.status(), StatusCode::BAD_REQUEST);

        // 3. Try login with invalid email format
        let login_data = json!({
            "username_or_email": "not-an-email",
            "password": "Password123"
        });

        let login_req = test::TestRequest::post()
            .uri("/api/auth/login")
            .set_json(&login_data)
            .to_request();

        let login_resp = test::call_service(&app, login_req).await;
        // This might be OK or BAD_REQUEST depending on validation approach
        assert!(login_resp.status() == StatusCode::UNAUTHORIZED ||
            login_resp.status() == StatusCode::BAD_REQUEST);
    }
}

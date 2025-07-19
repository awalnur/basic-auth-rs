// Route configuration for API
// This file contains definitions for all API routes

use std::sync::Arc;
use actix_web::{web, FromRequest, HttpResponse, Responder, dev::Payload, HttpRequest, get, post, put, delete, scope, App};
use crate::application::dtos::auth_dto::{LoginRequestDto, RegisterUserDto};
use crate::interfaces::api::controllers::auth_controller::AuthController;
use crate::interfaces::api::controllers::user_controller::UserController;
use crate::interfaces::api::middlewares::auth_middleware::{AuthMiddleware, AuthUserExtractor};
use crate::common::models::response::ApiResponse;

/// Configures all API routes
///
/// # Arguments
///
/// * `cfg` - Service config from Actix Web
/// * `auth_controller` - Controller for authentication
/// * `user_controller` - Controller for user management
/// * `auth_middleware` - Authentication middleware
pub fn configure_routes(
    cfg: &mut web::ServiceConfig,
    auth_controller: web::Data<AuthController>,
    user_controller: web::Data<UserController>,
    auth_middleware: Arc<AuthMiddleware>,
) {
    // Health check endpoint
    cfg.service(health_check);

    // API routes
    cfg.service(
        web::scope("/api")
            .service(health_check)
            // Authentication routes (public)
            .service(
                web::scope("/auth")
                    .app_data(auth_controller.clone()) // Add auth controller data
                    .service(login) // Health check endpoint
                    .route("/register", web::post().to(register))
                    .route("/logout", web::post().to(logout))
            )
            .service(
                web::scope("/users")
                    .wrap(auth_middleware.clone()) // Apply authentication middleware
                    .app_data(user_controller.clone())
                // .route("/me", web::get().to(get_current_user))
            )
        //         .app_data(user_controller.clone())
        //         .route("/me", web::get().to(get_current_user))
        //         .route("", web::post().to(create_user))
        //     // Uncomment these routes when the controller methods are implemented
        //     // .route("/{id}", web::get().to(get_user_by_id))
        //     // .route("/{id}", web::put().to(update_user))
        //     // .route("/{id}", web::delete().to(delete_user))
        // )
    );
}

/// Health check endpoint
///
/// Used for monitoring and readiness/liveness probes
#[get("/health")]
async fn health_check() -> impl Responder {
    let response = ApiResponse::with_message(
        serde_json::json!({
            "version": env!("CARGO_PKG_VERSION")
        }),
        "Service is healthy",
    );

    HttpResponse::Ok().json(response)
}

// Auth Controller Route Handlers


/// Custom JSON extractor that handles deserialization errors
pub struct SafeJson<T>(pub T);

impl<T> FromRequest for SafeJson<T>
where
    T: serde::de::DeserializeOwned + 'static,
{
    type Error = actix_web::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output=Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let json_fut = web::Json::<T>::from_request(req, payload);

        Box::pin(async move {
            match json_fut.await {
                Ok(json) => Ok(SafeJson(json.into_inner())),
                Err(e) => {
                    Err(actix_web::error::ErrorBadRequest("Invalid JSON format"))
                }
            }
        })
    }
}
#[post("/login")] /// Login handler that passes the request to the auth controller
async fn login(
    req: SafeJson<LoginRequestDto>,
    auth_ctrl: web::Data<AuthController>,
) -> impl Responder {
    let auth_controller = auth_ctrl.get_ref();

    // println!("hehe {:?}", req);
    // // // Extract the auth controller from the web::Data wrapper
    // let auth_controller = auth_ctrl.get_ref();
    let req_json = web::Json(req.0); // Extract the inner value from SafeJson
    auth_controller.login(req_json).await
    // let response = ApiResponse::with_message(
    //     serde_json::json!({
    //         "version": env!("CARGO_PKG_VERSION")
    //     }),
    //     "Service is healthy",
    // );
    //
    // HttpResponse::Ok().json(response)
}
/// Register handler that passes the request to the auth controller
async fn register(
    req: web::Json<RegisterUserDto>,
    auth_ctrl: web::Data<AuthController>,
) -> impl Responder {
    let auth_controller = auth_ctrl.get_ref();
    auth_controller.register(req).await
}

/// Logout handler that passes the request to the auth controller
async fn logout(
    req: HttpRequest,
    auth_ctrl: web::Data<AuthController>,
) -> impl Responder {
    let auth_controller = auth_ctrl.get_ref();
    auth_controller.logout(req).await
}


// Get current user handler that passes the request to the user controller
// async fn get_current_user(
//     req: HttpRequest,
//     user_ctrl: web::Data<UserController>,
// ) -> impl Responder {
//     let user_controller = user_ctrl.get_ref();
//     user_controller.get_current_user().await
// }
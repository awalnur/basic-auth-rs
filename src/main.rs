// Application entry point
// Sets up and runs the web server

use actix_web::{web, App, HttpServer, middleware::Logger};
use basic_auth::infrastructure::config::dependency_injection::init_dependencies;
use basic_auth::interfaces::api::routes::configure_routes;
use dotenv::dotenv;
use std::env;
use log::info;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize environment
    dotenv().ok();

    // Initialize logger
    env_logger::init();

    // Initialize all dependencies
    let dependencies = init_dependencies();

    // Get server configuration from environment
    let host = env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("SERVER_PORT").unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>().expect("SERVER_PORT must be a number");

    info!("Starting server at http://{}:{}", host, port);

    // Start HTTP server
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(dependencies.auth_controller.clone())
            .app_data(dependencies.user_controller.clone())
            .app_data(dependencies.auth_middleware.clone())
            .configure(|cfg| configure_routes(
                cfg,
                dependencies.auth_controller.clone(),
                dependencies.user_controller.clone(),
                dependencies.auth_middleware.clone(),
            ))
    })
        .bind((host, port))?
        .run()
        .await
}

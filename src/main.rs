mod infrastructure;
mod config;
mod utils;

use ::actix_web::{App, HttpServer, get, Responder, HttpResponse};
use actix_web::middleware::Logger;
use json;
use dotenv::dotenv;

#[get("/")]
async fn index() -> impl Responder {
    // This is the handler for the root path
    let response_body = json::object! {
        message: "Hello, world!"
    };
    HttpResponse::Ok().body(response_body.dump())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {

    // Set the logging level to debug
    unsafe { std::env::set_var("RUST_LOG", "debug") }

    env_logger::init();


    let database_pool = match config::database::init_pool() {
        Ok(pool) => Some(pool),
        Err(e) => {
            eprintln!("Failed to create database pool: {}", e);
            None
        }
    };
    // Initialize the logger
    // Start the HTTP server

    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .service(index)
    })
        .bind(("0.0.0.0", 8082))?.run().await
}

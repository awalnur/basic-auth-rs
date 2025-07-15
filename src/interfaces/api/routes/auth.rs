use actix_web::{web};

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .service(web::resource("/token").route(web::post().to(generate_token)))
    );
}
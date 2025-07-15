// Middlewares module
// Contains all middleware implementations for the API layer

pub mod auth_middleware;

pub use auth_middleware::{AuthMiddleware, AuthenticatedUser, AuthUserExtractor};

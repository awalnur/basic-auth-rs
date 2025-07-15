// filepath: /Users/development/RUST/auth/basic-auth/src/interfaces/api/models/response.rs
// This file now re-exports the common response models for API use
// This avoids duplication while maintaining the logical separation between layers

pub use crate::common::models::response::{
    ApiResponse,
    ApiErrorResponse,
    ErrorToResponse,
};

// API-specific response extensions can be added here if needed

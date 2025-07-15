// DTO (Data Transfer Object) for authentication request and response
// DTOs are used to transfer data between layers

use serde::{Deserialize, Serialize};
use validator::Validate;

/// DTO for login request
///
/// Used to send login credentials from
/// interface layer to application layer.
#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequestDto {
    /// Username or email of the user
    #[validate(length(min = 3, message = "Username/email must be at least 3 characters"))]
    pub username_or_email: String,

    /// User password (plaintext)
    #[validate(length(min = 6, message = "Password must be at least 6 characters"))]
    pub password: String,
}

/// DTO for successful login response
///
/// Sent back to client after successful login
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponseDto {
    /// User ID in UUID string format
    pub user_id: String,

    /// Username
    pub username: String,

    /// Authentication token (JWT or other)
    pub token: String,

    /// Token expiration time (Unix timestamp)
    pub token_expires_at: i64,
}

/// DTO for new user registration request
///
/// Contains data required to create a new user
#[derive(Debug, Deserialize, Validate)]
pub struct RegisterUserDto {
    /// Desired username
    #[validate(length(min = 3, max = 50, message = "Username must be between 3-50 characters"))]
    pub username: String,

    /// User email address
    #[validate(email(message = "Invalid email format"))]
    pub email: String,

    /// Password in plaintext
    #[validate(length(min = 8, message = "Password must be at least 8 characters"),
        regex(
            path = "STRONG_PASSWORD_REGEX",
            message = "Password must contain uppercase, lowercase, and number"
        ))]
    pub password: String,
}

/// DTO for registration response or user data
///
/// Contains user information returned to client
#[derive(Debug, Serialize)]
pub struct UserDto {
    /// User ID in UUID string format
    pub id: String,

    /// Username
    pub username: String,

    /// User email address
    pub email: String,

    /// User active status
    pub is_active: bool,

    /// Email verification status
    pub email_verified: bool,

    /// Account creation time (Unix timestamp)
    pub created_at: i64,
}

/// Regex for strong password validation
///
/// Password must contain:
/// - At least one uppercase letter
/// - At least one lowercase letter
/// - At least one number
lazy_static::lazy_static! {
    static ref STRONG_PASSWORD_REGEX: regex::Regex = regex::Regex::new(
        r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$"
    ).expect("Failed to compile password regex");
}

/// Implementation of conversion from domain Entity to DTO
impl From<crate::domain::entities::user::User> for UserDto {
    fn from(user: crate::domain::entities::user::User) -> Self {
        Self {
            id: user.id.to_string(),
            username: user.username,
            email: user.email,
            is_active: user.is_active,
            email_verified: user.email_verified,
            created_at: user.created_at.timestamp(),
        }
    }
}

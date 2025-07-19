// Domain entities representing core business objects
// Independent from infrastructure and framework

use chrono::{NaiveDateTime, Utc};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

/// Entity `User` represents a user in the authentication system
///
/// User is an aggregate root that encompasses user identity, credentials,
/// and status in the system. This entity contains business logic related to
/// user state management.
///
/// # Examples
///
/// ```rust
/// use basic_auth::domain::entities::user::User;
///
/// let user = User::new(
///     "johndoe".to_string(),
///     "john@example.com".to_string(),
///     "hashed_password".to_string()
/// );
/// ```
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub email_verified: bool,
    pub is_active: bool,
    pub created_at: NaiveDateTime,
    pub updated_at: Option<NaiveDateTime>,
}

impl User {
    /// Creates a new User instance with default values for other properties
    ///
    /// # Arguments
    ///
    /// * `username` - Unique username for the user
    /// * `email` - User's email address
    /// * `password_hash` - Hashed password (not plaintext)
    ///
    /// # Returns
    ///
    /// New User instance with generated UUID and current timestamp
    pub fn new(username: String, email: String, password_hash: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            username,
            email,
            password_hash,
            email_verified: false,
            is_active: true,
            created_at: Default::default(),
            updated_at: None,
        }
    }

    /// Verifies the user's email address
    ///
    /// # Side Effects
    ///
    /// * Changes `email_verified` status to `true`
    /// * Updates `updated_at` to current time
    pub fn verify_email(&mut self) {
        self.email_verified = true;
        self.updated_at = Some(Utc::now().naive_utc());
    }

    /// Deactivates the user account
    ///
    /// # Side Effects
    ///
    /// * Changes `is_active` status to `false`
    /// * Updates `updated_at` to current time
    pub fn deactivate(&mut self) {
        self.is_active = false;
        self.updated_at = Some(Utc::now().naive_utc());
    }

    /// Activates the user account
    ///
    /// # Side Effects
    ///
    /// * Changes `is_active` status to `true`
    /// * Updates `updated_at` to current time
    pub fn activate(&mut self) {
        self.is_active = true;
        self.updated_at = Some(Utc::now().naive_utc());
    }

    /// Changes the user's email address and resets verification status
    ///
    /// # Arguments
    ///
    /// * `new_email` - New email address
    ///
    /// # Side Effects
    ///
    /// * Changes `email` to new value
    /// * Resets `email_verified` to `false`
    /// * Updates `updated_at` to current time
    pub fn change_email(&mut self, new_email: String) {
        self.email = new_email;
        self.email_verified = false;
        self.updated_at = Some(Utc::now().naive_utc());
    }
}

// User aggregate root for authentication domain

use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::collections::HashMap;

use crate::domain::entities::user::User;
use crate::domain::value_objects::email::Email;
use crate::domain::errors::domain_error::DomainError;

/// Domain events that can be published by the User aggregate
#[derive(Debug, Clone)]
pub enum UserDomainEvent {
    /// User was created
    UserCreated {
        user_id: Uuid,
        email: String,
        created_at: DateTime<Utc>,
    },
    /// User email was verified
    EmailVerified {
        user_id: Uuid,
        email: String,
        verified_at: DateTime<Utc>,
    },
    /// User password was changed
    PasswordChanged {
        user_id: Uuid,
        changed_at: DateTime<Utc>,
    },
    /// User was deactivated
    UserDeactivated {
        user_id: Uuid,
        reason: String,
        deactivated_at: DateTime<Utc>,
    },
    /// User login attempt recorded
    LoginAttempted {
        user_id: Uuid,
        success: bool,
        ip_address: Option<String>,
        attempted_at: DateTime<Utc>,
    },
}

/// User aggregate root that encapsulates user-related business logic
///
/// This aggregate manages the user entity and enforces business rules
/// around user operations like registration, authentication, and profile management.
///
/// # Example
///
/// ```rust
/// use crate::domain::aggregates::user_aggregate::UserAggregate;
/// use crate::domain::value_objects::email::Email;
///
/// let email = Email::new("user@example.com")?;
/// let mut user_aggregate = UserAggregate::create_new_user(
///     "John Doe".to_string(),
///     email,
///     "hashed_password".to_string(),
/// )?;
///
/// // Verify email
/// user_aggregate.verify_email()?;
///
/// // Get pending events
/// let events = user_aggregate.take_events();
/// ```
#[derive(Debug)]
pub struct UserAggregate {
    /// The user entity (aggregate root)
    user: User,
    /// Domain events pending publication
    pending_events: Vec<UserDomainEvent>,
    /// Business rule violations tracking
    rule_violations: Vec<String>,
}

impl UserAggregate {
    /// Creates a new user aggregate with a new user
    ///
    /// # Arguments
    ///
    /// * `name` - User's full name
    /// * `email` - User's email address
    /// * `password_hash` - Hashed password
    ///
    /// # Returns
    ///
    /// * `Result<UserAggregate, DomainError>` - New user aggregate or error
    ///
    /// # Business Rules
    ///
    /// * Email must be unique (enforced at repository level)
    /// * Password must be properly hashed
    /// * User starts as unverified
    pub fn create_new_user(
        name: String,
        email: Email,
        password_hash: String,
    ) -> Result<Self, DomainError> {
        // Validate business rules
        if name.trim().is_empty() {
            return Err(DomainError::validation_failed("name", "cannot be empty"));
        }

        if password_hash.is_empty() {
            return Err(DomainError::validation_failed("password", "cannot be empty"));
        }

        let user_id = Uuid::new_v4();
        let now = Utc::now();

        let user = User::new(
            user_id,
            name,
            email.clone(),
            password_hash,
            false, // email_verified
            true,  // is_active
            now,   // created_at
            now,   // updated_at
        );

        let user_created_event = UserDomainEvent::UserCreated {
            user_id,
            email: email.value().to_string(),
            created_at: now,
        };

        Ok(Self {
            user,
            pending_events: vec![user_created_event],
            rule_violations: Vec::new(),
        })
    }

    /// Reconstructs user aggregate from existing user entity
    ///
    /// # Arguments
    ///
    /// * `user` - Existing user entity
    ///
    /// # Returns
    ///
    /// * `UserAggregate` - Reconstructed aggregate
    pub fn from_existing_user(user: User) -> Self {
        Self {
            user,
            pending_events: Vec::new(),
            rule_violations: Vec::new(),
        }
    }

    /// Verifies user's email address
    ///
    /// # Returns
    ///
    /// * `Result<(), DomainError>` - Success or error
    ///
    /// # Business Rules
    ///
    /// * User must be active
    /// * Email must not already be verified
    pub fn verify_email(&mut self) -> Result<(), DomainError> {
        if !self.user.is_active() {
            return Err(DomainError::business_rule_violated(
                "Cannot verify email for inactive user"
            ));
        }

        if self.user.is_email_verified() {
            return Err(DomainError::business_rule_violated(
                "Email is already verified"
            ));
        }

        self.user.set_email_verified(true);
        self.user.set_updated_at(Utc::now());

        let event = UserDomainEvent::EmailVerified {
            user_id: self.user.id(),
            email: self.user.email().value().to_string(),
            verified_at: Utc::now(),
        };

        self.pending_events.push(event);
        Ok(())
    }

    /// Changes user's password
    ///
    /// # Arguments
    ///
    /// * `new_password_hash` - New hashed password
    ///
    /// # Returns
    ///
    /// * `Result<(), DomainError>` - Success or error
    ///
    /// # Business Rules
    ///
    /// * User must be active
    /// * New password must be different from current
    pub fn change_password(&mut self, new_password_hash: String) -> Result<(), DomainError> {
        if !self.user.is_active() {
            return Err(DomainError::business_rule_violated(
                "Cannot change password for inactive user"
            ));
        }

        if new_password_hash.is_empty() {
            return Err(DomainError::validation_failed("password", "cannot be empty"));
        }

        if self.user.password_hash() == &new_password_hash {
            return Err(DomainError::business_rule_violated(
                "New password must be different from current password"
            ));
        }

        self.user.set_password_hash(new_password_hash);
        self.user.set_updated_at(Utc::now());

        let event = UserDomainEvent::PasswordChanged {
            user_id: self.user.id(),
            changed_at: Utc::now(),
        };

        self.pending_events.push(event);
        Ok(())
    }

    /// Deactivates the user account
    ///
    /// # Arguments
    ///
    /// * `reason` - Reason for deactivation
    ///
    /// # Returns
    ///
    /// * `Result<(), DomainError>` - Success or error
    ///
    /// # Business Rules
    ///
    /// * User must currently be active
    /// * Reason must be provided
    pub fn deactivate(&mut self, reason: String) -> Result<(), DomainError> {
        if !self.user.is_active() {
            return Err(DomainError::business_rule_violated(
                "User is already inactive"
            ));
        }

        if reason.trim().is_empty() {
            return Err(DomainError::validation_failed("reason", "cannot be empty"));
        }

        self.user.set_active(false);
        self.user.set_updated_at(Utc::now());

        let event = UserDomainEvent::UserDeactivated {
            user_id: self.user.id(),
            reason,
            deactivated_at: Utc::now(),
        };

        self.pending_events.push(event);
        Ok(())
    }

    /// Records a login attempt
    ///
    /// # Arguments
    ///
    /// * `success` - Whether login was successful
    /// * `ip_address` - Optional IP address of the attempt
    ///
    /// # Returns
    ///
    /// * `Result<(), DomainError>` - Success or error
    ///
    /// # Business Rules
    ///
    /// * User must be active to have successful login
    /// * Failed attempts are recorded even for inactive users
    pub fn record_login_attempt(
        &mut self,
        success: bool,
        ip_address: Option<String>,
    ) -> Result<(), DomainError> {
        if success && !self.user.is_active() {
            return Err(DomainError::business_rule_violated(
                "Inactive user cannot have successful login"
            ));
        }

        if success && !self.user.is_email_verified() {
            return Err(DomainError::business_rule_violated(
                "User with unverified email cannot login"
            ));
        }

        let event = UserDomainEvent::LoginAttempted {
            user_id: self.user.id(),
            success,
            ip_address,
            attempted_at: Utc::now(),
        };

        self.pending_events.push(event);
        Ok(())
    }

    /// Validates business rules and returns violations
    ///
    /// # Returns
    ///
    /// * `Vec<String>` - List of business rule violations
    pub fn validate_business_rules(&self) -> Vec<String> {
        let mut violations = Vec::new();

        // Rule: Active users must have verified emails for certain operations
        if self.user.is_active() && !self.user.is_email_verified() {
            violations.push("Active user should have verified email".to_string());
        }

        // Rule: User name should not be empty
        if self.user.name().trim().is_empty() {
            violations.push("User name cannot be empty".to_string());
        }

        violations
    }

    /// Takes all pending domain events and clears the internal list
    ///
    /// # Returns
    ///
    /// * `Vec<UserDomainEvent>` - Pending domain events
    pub fn take_events(&mut self) -> Vec<UserDomainEvent> {
        std::mem::take(&mut self.pending_events)
    }

    /// Gets reference to the user entity
    ///
    /// # Returns
    ///
    /// * `&User` - Reference to user entity
    pub fn user(&self) -> &User {
        &self.user
    }

    /// Gets mutable reference to the user entity
    ///
    /// # Returns
    ///
    /// * `&mut User` - Mutable reference to user entity
    pub fn user_mut(&mut self) -> &mut User {
        &mut self.user
    }

    /// Checks if aggregate has pending events
    ///
    /// # Returns
    ///
    /// * `bool` - True if there are pending events
    pub fn has_pending_events(&self) -> bool {
        !self.pending_events.is_empty()
    }

    /// Gets count of pending events
    ///
    /// # Returns
    ///
    /// * `usize` - Number of pending events
    pub fn pending_events_count(&self) -> usize {
        self.pending_events.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::value_objects::email::Email;

    #[test]
    fn test_create_new_user_success() {
        let email = Email::new("test@example.com").unwrap();
        let result = UserAggregate::create_new_user(
            "John Doe".to_string(),
            email,
            "hashed_password".to_string(),
        );

        assert!(result.is_ok());
        let aggregate = result.unwrap();
        assert_eq!(aggregate.user().name(), "John Doe");
        assert!(!aggregate.user().is_email_verified());
        assert!(aggregate.user().is_active());
        assert_eq!(aggregate.pending_events_count(), 1);
    }

    #[test]
    fn test_verify_email_success() {
        let email = Email::new("test@example.com").unwrap();
        let mut aggregate = UserAggregate::create_new_user(
            "John Doe".to_string(),
            email,
            "hashed_password".to_string(),
        ).unwrap();

        let result = aggregate.verify_email();
        assert!(result.is_ok());
        assert!(aggregate.user().is_email_verified());
        assert_eq!(aggregate.pending_events_count(), 2); // Created + Verified
    }

    #[test]
    fn test_verify_email_already_verified() {
        let email = Email::new("test@example.com").unwrap();
        let mut aggregate = UserAggregate::create_new_user(
            "John Doe".to_string(),
            email,
            "hashed_password".to_string(),
        ).unwrap();

        aggregate.verify_email().unwrap();
        let result = aggregate.verify_email();
        assert!(result.is_err());
    }

    #[test]
    fn test_change_password_success() {
        let email = Email::new("test@example.com").unwrap();
        let mut aggregate = UserAggregate::create_new_user(
            "John Doe".to_string(),
            email,
            "old_password".to_string(),
        ).unwrap();

        let result = aggregate.change_password("new_password".to_string());
        assert!(result.is_ok());
        assert_eq!(aggregate.user().password_hash(), "new_password");
    }

    #[test]
    fn test_change_password_same_password() {
        let email = Email::new("test@example.com").unwrap();
        let mut aggregate = UserAggregate::create_new_user(
            "John Doe".to_string(),
            email,
            "password".to_string(),
        ).unwrap();

        let result = aggregate.change_password("password".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_deactivate_user() {
        let email = Email::new("test@example.com").unwrap();
        let mut aggregate = UserAggregate::create_new_user(
            "John Doe".to_string(),
            email,
            "password".to_string(),
        ).unwrap();

        let result = aggregate.deactivate("Policy violation".to_string());
        assert!(result.is_ok());
        assert!(!aggregate.user().is_active());
    }

    #[test]
    fn test_record_login_attempt() {
        let email = Email::new("test@example.com").unwrap();
        let mut aggregate = UserAggregate::create_new_user(
            "John Doe".to_string(),
            email,
            "password".to_string(),
        ).unwrap();

        aggregate.verify_email().unwrap(); // Need verified email for successful login

        let result = aggregate.record_login_attempt(true, Some("192.168.1.1".to_string()));
        assert!(result.is_ok());
    }

    #[test]
    fn test_business_rules_validation() {
        let email = Email::new("test@example.com").unwrap();
        let aggregate = UserAggregate::create_new_user(
            "John Doe".to_string(),
            email,
            "password".to_string(),
        ).unwrap();

        let violations = aggregate.validate_business_rules();
        assert!(!violations.is_empty()); // Should have violation for unverified email
    }
}

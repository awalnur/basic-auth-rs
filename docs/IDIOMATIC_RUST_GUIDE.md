# 🦀 Idiomatic Rust Guide - Authentication System

## Table of Contents

- [Overview](#overview)
- [Error Handling](#error-handling)
- [Option and Result Types](#option-and-result-types)
- [Ownership and Borrowing](#ownership-and-borrowing)
- [Pattern Matching](#pattern-matching)
- [Iterator Patterns](#iterator-patterns)
- [Struct and Enum Design](#struct-and-enum-design)
- [Trait Implementation](#trait-implementation)
- [Memory Management](#memory-management)
- [Concurrency Patterns](#concurrency-patterns)
- [Testing Patterns](#testing-patterns)
- [Documentation Patterns](#documentation-patterns)
- [Performance Optimizations](#performance-optimizations)
- [Security-Focused Patterns](#security-focused-patterns)
- [Advanced Patterns](#advanced-patterns)
- [Anti-Patterns to Avoid](#anti-patterns-to-avoid)
- [Migration Strategies](#migration-strategies)

## Overview

Idiomatic Rust mengutamakan:

- **Safety**: Memory safety dan thread safety tanpa overhead runtime
- **Performance**: Zero-cost abstractions yang compile-time optimized
- **Expressiveness**: Clear dan concise code yang self-documenting
- **Reliability**: Compile-time error prevention dengan strong type system
- **Composability**: Modular dan reusable components dengan traits

### Rust Philosophy: "Move fast and don't break things"

Rust memungkinkan rapid development tanpa mengorbankan reliability. Compiler bertindak sebagai "pair programmer" yang mencegah bugs umum sebelum production.

### Key Principles

1. **Explicit over Implicit**: Rust lebih suka explicit handling daripada hidden behavior
2. **Zero-Cost Abstractions**: High-level constructs compile to efficient machine code
3. **Ownership Model**: Memory management tanpa garbage collector atau manual malloc/free
4. **Fearless Concurrency**: Safe concurrent programming dengan compile-time guarantees

## Error Handling

### Why Error Handling Matters

Dalam authentication systems, error handling yang baik adalah kritis untuk:
- **Security**: Preventing information leakage through error messages
- **User Experience**: Providing clear feedback without revealing system internals
- **Reliability**: Graceful degradation instead of crashes
- **Debugging**: Comprehensive error context for troubleshooting

### ❌ Non-Idiomatic: Panic dan Unwrap

```rust
// BAD: Using panic! and unwrap() everywhere
pub fn authenticate_user(username: &str, password: &str) -> User {
    let user = find_user_by_username(username).unwrap(); // Can panic!

    if !verify_password(password, &user.password_hash).unwrap() {
        panic!("Invalid password!"); // Very bad!
    }

    user
}

pub fn get_user_by_id(id: i32) -> User {
    database_query(id).expect("Database error") // Will crash the server
}

// BAD: Silent failures
pub fn update_last_login(user_id: i32) {
    if let Err(_) = database_update_last_login(user_id) {
        // Silently ignore errors - data inconsistency risk
    }
}

// BAD: String-based error handling
pub fn validate_password(password: &str) -> Result<(), String> {
    if password.len() < 8 {
        return Err("Password too short".to_string()); // Not type-safe
    }
    Ok(())
}
```

### ✅ Idiomatic: Comprehensive Error Handling

```rust
use thiserror::Error;
use std::fmt;

/// Authenticates a user with username and password credentials.
///
/// This function performs several security checks:
/// 1. Validates input format and length
/// 2. Checks if the account is locked or suspended
/// 3. Verifies password using secure hashing
/// 4. Updates login attempt counters
/// 5. Logs authentication events for security monitoring
///
/// # Arguments
///
/// * `credentials` - The user credentials containing username, password, and optional 2FA token
/// * `client_info` - Information about the client making the request (IP, User-Agent, etc.)
///
/// # Returns
///
/// * `Ok(AuthenticatedUser)` - Successfully authenticated user with session info
/// * `Err(AuthError)` - Authentication failed for various reasons:
///   - `UserNotFound` - No user exists with the given username
///   - `InvalidCredentials` - Password verification failed
///   - `AccountLocked` - Account is temporarily locked due to failed attempts
///   - `TwoFactorRequired` - Valid credentials but 2FA token needed
///   - `RateLimitExceeded` - Too many attempts from this IP/user
///
/// # Security Considerations
///
/// - Failed attempts are logged and may trigger account lockout
/// - Sensitive information is not leaked in error messages
/// - Timing attacks are mitigated through constant-time operations
/// - Rate limiting is applied per IP and per user
///
/// # Examples
///
/// ```rust
/// use crate::auth::{Credentials, ClientInfo, authenticate_user};
///
/// let credentials = Credentials::new("alice", "secure_password123");
/// let client_info = ClientInfo {
///     ip_address: "192.168.1.100".parse().unwrap(),
///     user_agent: "Mozilla/5.0...".to_string(),
///     request_id: Some("req_123".to_string()),
/// };
///
/// match authenticate_user(&credentials, &client_info).await {
///     Ok(authenticated_user) => {
///         println!("Welcome, {}!", authenticated_user.username);
///     },
///     Err(AuthError::TwoFactorRequired { .. }) => {
///         println!("Please enter your 2FA code");
///     },
///     Err(e) => {
///         eprintln!("Authentication failed: {}", e);
///     }
/// }
/// ```
///
/// # Panics
///
/// This function does not panic under normal circumstances. However, it may
/// panic if the system clock is set to a time before the Unix epoch.
///
/// # Performance
///
/// Typical authentication takes 50-100ms due to password hashing overhead.
/// Consider caching authenticated sessions to avoid repeated authentication.
pub async fn authenticate_user(
    credentials: &Credentials,
    client_info: &ClientInfo,
) -> AuthResult<AuthenticatedUser> {
    // Implementation...
    todo!()
}

/// Configuration for the authentication system.
///
/// This struct contains all the configurable parameters for authentication
/// behavior, security policies, and performance tuning.
///
/// # Thread Safety
///
/// This struct is thread-safe and can be shared across multiple threads
/// using `Arc<AuthConfig>`.
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
/// use crate::auth::AuthConfig;
///
/// let config = AuthConfig::builder()
///     .password_min_length(12)
///     .session_timeout(Duration::from_hours(8))
///     .max_failed_attempts(3)
///     .lockout_duration(Duration::from_minutes(15))
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Minimum required password length (default: 8)
    pub password_min_length: usize,

    /// Maximum session duration before requiring re-authentication
    pub session_timeout: Duration,

    /// Number of failed login attempts before account lockout
    pub max_failed_attempts: u32,

    /// Duration to lock account after max failed attempts
    pub lockout_duration: Duration,

    /// Whether to require two-factor authentication for admin users
    pub require_2fa_for_admins: bool,

    /// Rate limiting: maximum requests per minute per IP
    pub rate_limit_per_ip: u32,

    /// Rate limiting: maximum login attempts per minute per user
    pub rate_limit_per_user: u32,
}

impl Default for AuthConfig {
    /// Creates a new `AuthConfig` with secure default values.
    ///
    /// Default configuration prioritizes security over convenience:
    /// - 8 character minimum password length
    /// - 24 hour session timeout
    /// - 5 failed attempts before lockout
    /// - 30 minute lockout duration
    /// - 2FA required for admin users
    /// - Rate limiting: 60 requests/minute per IP, 10 login attempts/minute per user
    fn default() -> Self {
        Self {
            password_min_length: 8,
            session_timeout: Duration::from_secs(24 * 60 * 60), // 24 hours
            max_failed_attempts: 5,
            lockout_duration: Duration::from_secs(30 * 60), // 30 minutes
            require_2fa_for_admins: true,
            rate_limit_per_ip: 60,
            rate_limit_per_user: 10,
        }
    }
}

/// Represents different types of authentication errors.
///
/// This enum provides structured error handling for authentication operations,
/// allowing callers to handle different failure scenarios appropriately.
///
/// # Error Handling Strategy
///
/// - Security-sensitive errors (like `InvalidCredentials`) provide minimal
///   information to prevent information leakage
/// - User-actionable errors (like `TwoFactorRequired`) provide helpful context
/// - System errors (like `DatabaseError`) are logged internally but shown
///   generically to users
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("User not found")]
    UserNotFound,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Account is locked until {until}")]
    AccountLocked { until: chrono::DateTime<chrono::Utc> },

    #[error("Account requires email verification")]
    EmailVerificationRequired,

    #[error("Password does not meet security requirements: {requirements}")]
    WeakPassword { requirements: Vec<String> },

    #[error("Rate limit exceeded. Try again in {retry_after} seconds")]
    RateLimitExceeded { retry_after: u64 },

    #[error("Two-factor authentication required")]
    TwoFactorRequired { backup_codes_available: bool },

    #[error("Database error: {0}")]
    DatabaseError(#[from] diesel::result::Error),

    #[error("Password hashing error: {0}")]
    HashingError(#[from] argon2::password_hash::Error),

    #[error("Validation error: {field} - {message}")]
    ValidationError { field: String, message: String },

    #[error("Internal server error")]
    InternalError,
}

// GOOD: Custom result type for consistency
pub type AuthResult<T> = Result<T, AuthError>;

// GOOD: Proper error propagation with context
pub fn authenticate_user(credentials: &Credentials) -> AuthResult<AuthenticatedUser> {
    // Validate input first
    credentials.validate()
        .map_err(|e| AuthError::ValidationError {
            field: "credentials".to_string(),
            message: e.to_string()
        })?;

    // Find user with proper error handling
    let user = find_user_by_username(&credentials.username)?
        .ok_or(AuthError::UserNotFound)?;

    // Check account status
    match user.status {
        AccountStatus::Locked { until } if until > chrono::Utc::now() => {
            return Err(AuthError::AccountLocked { until });
        },
        AccountStatus::PendingVerification => {
            return Err(AuthError::EmailVerificationRequired);
        },
        AccountStatus::Active => {},
        _ => return Err(AuthError::InternalError),
    }

    // Verify password with detailed error handling
    let is_valid = verify_password(&credentials.password, &user.password_hash)
        .map_err(AuthError::HashingError)?;

    if !is_valid {
        // Log failed attempt for security monitoring
        log_failed_login_attempt(&user.id, &credentials.client_info);
        return Err(AuthError::InvalidCredentials);
    }

    // Check if 2FA is required
    if user.two_factor_enabled && !credentials.two_factor_token.is_some() {
        let backup_codes_available = user.backup_codes.len() > 0;
        return Err(AuthError::TwoFactorRequired { backup_codes_available });
    }

    // Create authenticated user session
    Ok(AuthenticatedUser::new(user, chrono::Utc::now()))
}

// GOOD: Error recovery strategies
pub fn authenticate_with_fallback(credentials: &Credentials) -> AuthResult<AuthenticatedUser> {
    // Try primary authentication
    authenticate_user(credentials)
        .or_else(|primary_err| {
            log::warn!("Primary auth failed for {}: {}", credentials.username, primary_err);
            authenticate_user_legacy(credentials.username, credentials.password)
        })
        .or_else(|legacy_err| {
            log::warn!("Legacy auth failed for {}: {}", credentials.username, legacy_err);
            authenticate_user_ldap(credentials.username, credentials.password)
        })
        .map_err(|final_err| {
            log::error!("All auth methods failed for {}: {}", credentials.username, final_err);
            AuthError::InvalidCredentials // Don't leak internal error details
        })
}

// GOOD: Error aggregation for batch operations
pub fn bulk_authenticate_users(
    credentials_list: &[Credentials]
) -> (Vec<AuthenticatedUser>, Vec<(usize, AuthError)>) {
    let mut successes = Vec::new();
    let mut failures = Vec::new();

    for (index, credentials) in credentials_list.iter().enumerate() {
        match authenticate_user(credentials) {
            Ok(authenticated_user) => successes.push(authenticated_user),
            Err(error) => failures.push((index, error)),
        }
    }

    (successes, failures)
}
```

### Error Context dan Chain

```rust
use anyhow::{Context, Result, bail};

// GOOD: Adding rich context to errors
pub fn load_user_profile(user_id: i32) -> Result<UserProfile> {
    let user = get_user_by_id(user_id)
        .with_context(|| format!("Failed to load user with ID: {}", user_id))?;

    let profile = get_user_profile(user_id)
        .with_context(|| "Failed to load user profile data")?;

    let permissions = get_user_permissions(user_id)
        .with_context(|| "Failed to load user permissions")?;

    // Validate profile completeness
    if profile.email.is_none() && user.role == UserRole::Admin {
        bail!("Admin users must have email addresses");
    }

    Ok(UserProfile {
        user,
        profile,
        permissions,
        loaded_at: chrono::Utc::now(),
    })
}

// GOOD: Custom error context for debugging
#[derive(Debug)]
pub struct ErrorContext {
    pub operation: String,
    pub user_id: Option<i32>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub request_id: Option<String>,
}

impl fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Operation: {}, User: {:?}, Time: {}, Request: {:?}", 
               self.operation, self.user_id, self.timestamp, self.request_id)
    }
}

pub fn with_context<T, E>(
    result: Result<T, E>,
    context: ErrorContext
) -> Result<T, (E, ErrorContext)>
where
    E: std::error::Error,
{
    result.map_err(|e| (e, context))
}
```

## Option and Result Types

### Understanding Option vs Result

- **Option<T>**: Represents presence or absence of a value (null safety)
- **Result<T, E>**: Represents success or failure of an operation (error handling)

### ❌ Non-Idiomatic: Null Checking Patterns

```rust
// BAD: Using sentinel values
pub fn find_user_by_email(email: &str) -> User {
    // Returns empty User if not found - confusing!
    User::default()
}

// BAD: Boolean + out parameter pattern
pub fn get_session(token: &str, session: &mut Session) -> bool {
    // Modifies session parameter, returns success flag
    false
}

// BAD: Using magic values
pub fn get_user_age(user_id: i32) -> i32 {
    // Returns -1 if user not found - error prone
    if let Some(user) = find_user(user_id) {
        calculate_age(user.birth_date)
    } else {
        -1 // Magic value indicating error
    }
}

// BAD: Nested if-let without combinators
pub fn get_user_display_name(user_id: i32) -> String {
    if let Some(user) = find_user_by_id(user_id) {
        if let Some(first_name) = user.first_name {
            if let Some(last_name) = user.last_name {
                format!("{} {}", first_name, last_name)
            } else {
                first_name
            }
        } else {
            user.username
        }
    } else {
        "Unknown User".to_string()
    }
}
```

### ✅ Idiomatic: Option dan Result Usage

```rust
// GOOD: Clear Option usage with semantic meaning
pub fn find_user_by_email(email: &str) -> Option<User> {
    // Clearly indicates user might not exist
    database_query("SELECT * FROM users WHERE email = $1", email)
        .optional()
        .unwrap_or(None)
}

// GOOD: Result for operations that can fail
pub fn get_active_session(token: &str) -> AuthResult<Session> {
    let session = find_session_by_token(token)?
        .ok_or(AuthError::InvalidSession)?;

    if session.is_expired() {
        return Err(AuthError::SessionExpired);
    }

    if session.is_revoked {
        return Err(AuthError::SessionRevoked);
    }

    Ok(session)
}

// GOOD: Combining Option and Result elegantly
pub fn validate_user_access(user_id: i32, resource: &str) -> AuthResult<AccessLevel> {
    let user = find_user_by_id(user_id)?
        .ok_or(AuthError::UserNotFound)?;

    let access_level = user.permissions
        .as_ref() // Option<Vec<Permission>> -> Option<&Vec<Permission>>
        .and_then(|perms| perms.iter().find(|p| p.resource == resource))
        .map(|perm| perm.access_level)
        .unwrap_or(AccessLevel::None);

    Ok(access_level)
}

// GOOD: Using combinators for cleaner code
pub fn get_user_display_name(user_id: i32) -> String {
    find_user_by_id(user_id)
        .ok()
        .and_then(|user| {
            // Try full name first
            user.first_name.zip(user.last_name)
                .map(|(first, last)| format!("{} {}", first, last))
                .or_else(|| user.first_name.clone()) // Then first name only
                .or_else(|| Some(user.username.clone())) // Finally username
        })
        .unwrap_or_else(|| format!("User #{}", user_id))
}

// GOOD: Error recovery patterns with detailed logging
pub fn authenticate_with_fallback(username: &str, password: &str) -> AuthResult<User> {
    authenticate_user(username, password)
        .or_else(|primary_err| {
            log::warn!("Primary auth failed for {}: {}", username, primary_err);
            authenticate_user_legacy(username, password)
        })
        .or_else(|legacy_err| {
            log::warn!("Legacy auth failed for {}: {}", username, legacy_err);
            authenticate_user_ldap(username, password)
        })
        .map_err(|final_err| {
            log::error!("All auth methods failed for {}: {}", username, final_err);
            AuthError::InvalidCredentials // Don't leak internal error details
        })
}
```

### Advanced Option/Result Patterns

```rust
// GOOD: Transpose for converting Option<Result<T, E>> to Result<Option<T>, E>
pub fn maybe_update_user_profile(
    user_id: Option<i32>, 
    profile_data: &ProfileData
) -> AuthResult<Option<UserProfile>> {
    user_id
        .map(|id| update_user_profile(id, profile_data)) // Option<Result<UserProfile, AuthError>>
        .transpose() // Result<Option<UserProfile>, AuthError>
}

// GOOD: Working with collections of Options/Results
pub fn load_user_batch(user_ids: &[i32]) -> AuthResult<Vec<User>> {
    user_ids.iter()
        .map(|&id| find_user_by_id(id).ok_or(AuthError::UserNotFound))
        .collect::<Result<Vec<_>, _>>() // Fail fast on first error
}

// GOOD: Partial success handling
pub fn load_user_batch_partial(user_ids: &[i32]) -> (Vec<User>, Vec<i32>) {
    let (users, failed_ids): (Vec<_>, Vec<_>) = user_ids.iter()
        .filter_map(|&id| {
            match find_user_by_id(id) {
                Ok(Some(user)) => Some(Ok(user)),
                Ok(None) => Some(Err(id)),
                Err(_) => Some(Err(id)),
            }
        })
        .partition_result(); // Separate successes from failures

    (users, failed_ids)
}

// GOOD: Option chaining for complex validation
pub fn validate_user_session_chain(
    token: &str,
    ip_address: &str,
    user_agent: &str
) -> Option<ValidatedSession> {
    find_session_by_token(token)?
        .filter(|s| !s.is_expired())?
        .filter(|s| !s.is_revoked)?
        .filter(|s| s.ip_address.as_ref().map_or(true, |ip| ip == ip_address))?
        .filter(|s| s.user_agent.as_ref().map_or(true, |ua| ua == user_agent))?
        .into()
}
```

## Ownership and Borrowing

### Understanding Ownership Rules

1. **Each value has a single owner**
2. **When owner goes out of scope, value is dropped**
3. **Ownership can be moved or borrowed**
4. **Borrowing rules ensure memory safety**

### ❌ Non-Idiomatic: Unnecessary Cloning

```rust
// BAD: Cloning everything
pub fn process_users(users: Vec<User>) -> Vec<String> {
    let mut result = Vec::new();
    for user in users {
        let cloned_user = user.clone(); // Unnecessary clone!
        result.push(format!("User: {}", cloned_user.username.clone())); // More cloning!
    }
    result
}

// BAD: Taking ownership when borrowing is sufficient
pub fn validate_password(password: String) -> bool { // Should be &str
    password.len() >= 8
}

// BAD: Cloning in hot paths
pub fn format_user_list(users: &[User]) -> String {
    let mut result = String::new();
    for user in users {
        let user_copy = user.clone(); // Expensive clone in loop!
        result.push_str(&format!("{}\n", user_copy.username));
    }
    result
}

// BAD: Unnecessary Vec allocation
pub fn get_admin_usernames(users: &[User]) -> Vec<String> {
    let admin_users: Vec<User> = users.iter()
        .filter(|u| u.role == UserRole::Admin)
        .cloned() // Cloning entire User structs
        .collect();
    
    admin_users.iter()
        .map(|u| u.username.clone())
        .collect()
}
```

### ✅ Idiomatic: Smart Borrowing

```rust
// GOOD: Using references efficiently
pub fn process_users(users: &[User]) -> Vec<String> {
    users.iter()
        .map(|user| format!("User: {}", user.username))
        .collect()
}

// GOOD: Borrowing when possible, clear function signatures
pub fn validate_password(password: &str) -> ValidationResult {
    let mut issues = Vec::new();
    
    if password.len() < 8 {
        issues.push("Password must be at least 8 characters");
    }
    
    if !password.chars().any(|c| c.is_uppercase()) {
        issues.push("Password must contain uppercase letters");
    }
    
    if !password.chars().any(|c| c.is_lowercase()) {
        issues.push("Password must contain lowercase letters");
    }
    
    if !password.chars().any(|c| c.is_numeric()) {
        issues.push("Password must contain numbers");
    }
    
    if issues.is_empty() {
        ValidationResult::Valid
    } else {
        ValidationResult::Invalid(issues)
    }
}

// GOOD: Strategic cloning only when necessary
pub fn create_user_session(user: &User) -> Session {
    Session {
        id: SessionId::new(),
        user_id: user.id,
        username: user.username.clone(), // Only clone what's needed
        role: user.role, // Copy for enum
        created_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
        ip_address: None, // Will be set by middleware
        user_agent: None, // Will be set by middleware
    }
}

// GOOD: Iterator chains avoid intermediate allocations
pub fn get_admin_usernames(users: &[User]) -> Vec<&str> {
    users.iter()
        .filter(|user| user.role == UserRole::Admin) // No cloning
        .map(|user| user.username.as_str()) // Borrow string slice
        .collect()
}

// GOOD: Using iterator adaptors for zero-copy processing
pub fn find_users_by_roles<'a>(
    users: &'a [User], 
    target_roles: &[UserRole]
) -> impl Iterator<Item = &'a User> {
    users.iter()
        .filter(move |user| target_roles.contains(&user.role))
}
```

### Lifetime Management

```rust
// GOOD: Explicit lifetimes when needed
pub struct AuthContext<'a> {
    pub user: &'a User,
    pub permissions: &'a [Permission],
    pub session: &'a Session,
    pub request_metadata: RequestMetadata // Owned data
}

impl<'a> AuthContext<'a> {
    pub fn new(
        user: &'a User, 
        permissions: &'a [Permission], 
        session: &'a Session,
        request_metadata: RequestMetadata,
    ) -> Self {
        Self { user, permissions, session, request_metadata }
    }
    
    pub fn has_permission(&self, resource: &str, action: Action) -> bool {
        self.permissions.iter()
            .any(|perm| perm.resource == resource && perm.action == action)
    }
    
    pub fn is_admin(&self) -> bool {
        self.user.role == UserRole::Admin
    }
    
    // Method that returns data with same lifetime as context
    pub fn get_user_permissions(&self) -> &'a [Permission] {
        self.permissions
    }
}

// GOOD: Using Cow for flexible string handling
use std::borrow::Cow;

pub fn sanitize_username(username: &str, strict_mode: bool) -> Cow<str> {
    if strict_mode {
        // Strict mode: only alphanumeric and underscore
        if username.chars().all(|c| c.is_alphanumeric() || c == '_') {
            Cow::Borrowed(username) // No allocation needed
        } else {
            Cow::Owned(
                username.chars()
                    .filter(|c| c.is_alphanumeric() || *c == '_')
                    .collect()
            ) // Allocate only when necessary
        }
    } else {
        // Permissive mode: allow more characters
        if username.chars().all(|c| c.is_alphanumeric() || "_-.@".contains(c)) {
            Cow::Borrowed(username)
        } else {
            Cow::Owned(
                username.chars()
                    .filter(|c| c.is_alphanumeric() || "_-.@".contains(*c))
                    .collect()
            )
        }
    }
}

// GOOD: Multiple lifetime parameters
pub fn compare_user_sessions<'u, 's>(
    user: &'u User,
    current_session: &'s Session,
    previous_session: &'s Session,
) -> SessionComparison<'u, 's> {
    SessionComparison {
        user,
        current_session,
        previous_session,
        comparison_time: chrono::Utc::now(),
    }
}

// GOOD: Lifetime elision works in most cases
pub fn get_user_display_info(user: &User) -> UserDisplayInfo { // 'a elided
    UserDisplayInfo {
        username: &user.username,
        role: user.role,
        last_login: user.last_login,
        is_active: user.is_active,
    }
}
```

### Advanced Ownership Patterns

```rust
// GOOD: Phantom types for compile-time guarantees
use std::marker::PhantomData;

pub struct Unvalidated;
pub struct Validated;

/// A user input that tracks its validation state at the type level.
///
/// This prevents using unvalidated data accidentally and ensures
/// validation happens exactly once.
pub struct UserInput<State = Unvalidated> {
    data: String,
    _state: PhantomData<State>,
}

impl UserInput<Unvalidated> {
    pub fn new(data: String) -> Self {
        Self {
            data,
            _state: PhantomData,
        }
    }
    
    /// Validates the input and returns a validated version.
    ///
    /// This consumes the unvalidated input, preventing reuse.
    pub fn validate(self) -> Result<UserInput<Validated>, ValidationError> {
        if self.data.is_empty() {
            return Err(ValidationError::EmptyInput);
        }
        
        if self.data.len() > 1000 {
            return Err(ValidationError::TooLong);
        }
        
        // Additional validation logic...
        
        Ok(UserInput {
            data: self.data,
            _state: PhantomData,
        })
    }
}

impl UserInput<Validated> {
    /// Returns the validated data.
    ///
    /// This method is only available on validated inputs.
    pub fn data(&self) -> &str {
        &self.data
    }
    
    /// Converts to a trusted string that can be used safely.
    pub fn into_trusted_string(self) -> TrustedString {
        TrustedString(self.data)
    }
}

// GOOD: Session state machine with type safety
pub struct LoggedOut;
pub struct LoggedIn;
pub struct TwoFactorPending;

pub struct UserSession<State> {
    session_id: SessionId,
    user_id: Option<UserId>,
    created_at: DateTime<Utc>,
    _state: PhantomData<State>,
}

impl UserSession<LoggedOut> {
    pub fn new() -> Self {
        Self {
            session_id: SessionId::generate(),
            user_id: None,
            created_at: Utc::now(),
            _state: PhantomData,
        }
    }
    
    pub fn login(
        self, 
        user_id: UserId, 
        requires_2fa: bool
    ) -> Result<UserSession<LoggedIn>, UserSession<TwoFactorPending>> {
        if requires_2fa {
            Err(UserSession {
                session_id: self.session_id,
                user_id: Some(user_id),
                created_at: self.created_at,
                _state: PhantomData,
            })
        } else {
            Ok(UserSession {
                session_id: self.session_id,
                user_id: Some(user_id),
                created_at: self.created_at,
                _state: PhantomData,
            })
        }
    }
}

impl UserSession<TwoFactorPending> {
    pub fn complete_2fa(self, token: &str) -> Result<UserSession<LoggedIn>, AuthError> {
        // Verify 2FA token
        if verify_2fa_token(self.user_id.unwrap(), token)? {
            Ok(UserSession {
                session_id: self.session_id,
                user_id: self.user_id,
                created_at: self.created_at,
                _state: PhantomData,
            })
        } else {
            Err(AuthError::Invalid2FA)
        }
    }
}

impl UserSession<LoggedIn> {
    pub fn user_id(&self) -> UserId {
        self.user_id.unwrap() // Safe because LoggedIn state guarantees user_id exists
    }
    
    pub fn logout(self) -> UserSession<LoggedOut> {
        UserSession {
            session_id: self.session_id,
            user_id: None,
            created_at: self.created_at,
            _state: PhantomData,
        }
    }
}
```

## Documentation Patterns

### Why Documentation Matters in Rust

Rust's documentation system is integrated into the language and toolchain:
- **rustdoc**: Generates beautiful HTML documentation
- **Cargo**: Built-in documentation testing with `cargo test`
- **docs.rs**: Automatic documentation hosting
- **IntraDoc Links**: Link between items in your crate

### ❌ Non-Idiomatic: Poor Documentation

```rust
// BAD: No documentation
pub fn auth(u: &str, p: &str) -> bool {
    // Implementation without any explanation
    true
}

// BAD: Outdated or misleading documentation
/// This function checks if user exists
/// Returns true if password is correct
pub fn authenticate_user(username: &str, password: &str) -> AuthResult<User> {
    // Actually returns User struct, not boolean!
    unimplemented!()
}

// BAD: Documentation that doesn't add value
/// Gets the user
pub fn get_user() -> User {
    // Comment just restates the function name
    unimplemented!()
}
```

### ✅ Idiomatic: Comprehensive Documentation

```rust
/// Authenticates a user with username and password credentials.
///
/// This function performs several security checks:
/// 1. Validates input format and length
/// 2. Checks if the account is locked or suspended
/// 3. Verifies password using secure hashing
/// 4. Updates login attempt counters
/// 5. Logs authentication events for security monitoring
///
/// # Arguments
///
/// * `credentials` - The user credentials containing username, password, and optional 2FA token
/// * `client_info` - Information about the client making the request (IP, User-Agent, etc.)
///
/// # Returns
///
/// * `Ok(AuthenticatedUser)` - Successfully authenticated user with session info
/// * `Err(AuthError)` - Authentication failed for various reasons:
///   - `UserNotFound` - No user exists with the given username
///   - `InvalidCredentials` - Password verification failed
///   - `AccountLocked` - Account is temporarily locked due to failed attempts
///   - `TwoFactorRequired` - Valid credentials but 2FA token needed
///   - `RateLimitExceeded` - Too many attempts from this IP/user
///
/// # Security Considerations
///
/// - Failed attempts are logged and may trigger account lockout
/// - Sensitive information is not leaked in error messages
/// - Timing attacks are mitigated through constant-time operations
/// - Rate limiting is applied per IP and per user
///
/// # Examples
///
/// ```rust
/// use crate::auth::{Credentials, ClientInfo, authenticate_user};
///
/// let credentials = Credentials::new("alice", "secure_password123");
/// let client_info = ClientInfo {
///     ip_address: "192.168.1.100".parse().unwrap(),
///     user_agent: "Mozilla/5.0...".to_string(),
///     request_id: Some("req_123".to_string()),
/// };
///
/// match authenticate_user(&credentials, &client_info).await {
///     Ok(authenticated_user) => {
///         println!("Welcome, {}!", authenticated_user.username);
///     },
///     Err(AuthError::TwoFactorRequired { .. }) => {
///         println!("Please enter your 2FA code");
///     },
///     Err(e) => {
///         eprintln!("Authentication failed: {}", e);
///     }
/// }
/// ```
///
/// # Panics
///
/// This function does not panic under normal circumstances. However, it may
/// panic if the system clock is set to a time before the Unix epoch.
///
/// # Performance
///
/// Typical authentication takes 50-100ms due to password hashing overhead.
/// Consider caching authenticated sessions to avoid repeated authentication.
pub async fn authenticate_user(
    credentials: &Credentials,
    client_info: &ClientInfo,
) -> AuthResult<AuthenticatedUser> {
    // Implementation...
    todo!()
}

/// Configuration for the authentication system.
///
/// This struct contains all the configurable parameters for authentication
/// behavior, security policies, and performance tuning.
///
/// # Thread Safety
///
/// This struct is thread-safe and can be shared across multiple threads
/// using `Arc<AuthConfig>`.
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
/// use crate::auth::AuthConfig;
///
/// let config = AuthConfig::builder()
///     .password_min_length(12)
///     .session_timeout(Duration::from_hours(8))
///     .max_failed_attempts(3)
///     .lockout_duration(Duration::from_minutes(15))
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Minimum required password length (default: 8)
    pub password_min_length: usize,

    /// Maximum session duration before requiring re-authentication
    pub session_timeout: Duration,

    /// Number of failed login attempts before account lockout
    pub max_failed_attempts: u32,

    /// Duration to lock account after max failed attempts
    pub lockout_duration: Duration,

    /// Whether to require two-factor authentication for admin users
    pub require_2fa_for_admins: bool,

    /// Rate limiting: maximum requests per minute per IP
    pub rate_limit_per_ip: u32,

    /// Rate limiting: maximum login attempts per minute per user
    pub rate_limit_per_user: u32,
}

impl Default for AuthConfig {
    /// Creates a new `AuthConfig` with secure default values.
    ///
    /// Default configuration prioritizes security over convenience:
    /// - 8 character minimum password length
    /// - 24 hour session timeout
    /// - 5 failed attempts before lockout
    /// - 30 minute lockout duration
    /// - 2FA required for admin users
    /// - Rate limiting: 60 requests/minute per IP, 10 login attempts/minute per user
    fn default() -> Self {
        Self {
            password_min_length: 8,
            session_timeout: Duration::from_secs(24 * 60 * 60), // 24 hours
            max_failed_attempts: 5,
            lockout_duration: Duration::from_secs(30 * 60), // 30 minutes
            require_2fa_for_admins: true,
            rate_limit_per_ip: 60,
            rate_limit_per_user: 10,
        }
    }
}

/// Represents different types of authentication errors.
///
/// This enum provides structured error handling for authentication operations,
/// allowing callers to handle different failure scenarios appropriately.
///
/// # Error Handling Strategy
///
/// - Security-sensitive errors (like `InvalidCredentials`) provide minimal
///   information to prevent information leakage
/// - User-actionable errors (like `TwoFactorRequired`) provide helpful context
/// - System errors (like `DatabaseError`) are logged internally but shown
///   generically to users
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("User not found")]
    UserNotFound,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Account is locked until {until}")]
    AccountLocked { until: chrono::DateTime<chrono::Utc> },

    #[error("Account requires email verification")]
    EmailVerificationRequired,

    #[error("Password does not meet security requirements: {requirements}")]
    WeakPassword { requirements: Vec<String> },

    #[error("Rate limit exceeded. Try again in {retry_after} seconds")]
    RateLimitExceeded { retry_after: u64 },

    #[error("Two-factor authentication required")]
    TwoFactorRequired { backup_codes_available: bool },

    #[error("Database error: {0}")]
    DatabaseError(#[from] diesel::result::Error),

    #[error("Password hashing error: {0}")]
    HashingError(#[from] argon2::password_hash::Error),

    #[error("Validation error: {field} - {message}")]
    ValidationError { field: String, message: String },

    #[error("Internal server error")]
    InternalError,
}

// GOOD: Custom result type for consistency
pub type AuthResult<T> = Result<T, AuthError>;

// GOOD: Proper error propagation with context
pub fn authenticate_user(credentials: &Credentials) -> AuthResult<AuthenticatedUser> {
    // Validate input first
    credentials.validate()
        .map_err(|e| AuthError::ValidationError {
            field: "credentials".to_string(),
            message: e.to_string()
        })?;

    // Find user with proper error handling
    let user = find_user_by_username(&credentials.username)?
        .ok_or(AuthError::UserNotFound)?;

    // Check account status
    match user.status {
        AccountStatus::Locked { until } if until > chrono::Utc::now() => {
            return Err(AuthError::AccountLocked { until });
        },
        AccountStatus::PendingVerification => {
            return Err(AuthError::EmailVerificationRequired);
        },
        AccountStatus::Active => {},
        _ => return Err(AuthError::InternalError),
    }

    // Verify password with detailed error handling
    let is_valid = verify_password(&credentials.password, &user.password_hash)
        .map_err(AuthError::HashingError)?;

    if !is_valid {
        // Log failed attempt for security monitoring
        log_failed_login_attempt(&user.id, &credentials.client_info);
        return Err(AuthError::InvalidCredentials);
    }

    // Check if 2FA is required
    if user.two_factor_enabled && !credentials.two_factor_token.is_some() {
        let backup_codes_available = user.backup_codes.len() > 0;
        return Err(AuthError::TwoFactorRequired { backup_codes_available });
    }

    // Create authenticated user session
    Ok(AuthenticatedUser::new(user, chrono::Utc::now()))
}

// GOOD: Error recovery strategies
pub fn authenticate_with_fallback(credentials: &Credentials) -> AuthResult<AuthenticatedUser> {
    // Try primary authentication
    authenticate_user(credentials)
        .or_else(|primary_err| {
            log::warn!("Primary auth failed for {}: {}", credentials.username, primary_err);
            authenticate_user_legacy(credentials.username, credentials.password)
        })
        .or_else(|legacy_err| {
            log::warn!("Legacy auth failed for {}: {}", credentials.username, legacy_err);
            authenticate_user_ldap(credentials.username, credentials.password)
        })
        .map_err(|final_err| {
            log::error!("All auth methods failed for {}: {}", credentials.username, final_err);
            AuthError::InvalidCredentials // Don't leak internal error details
        })
}

// GOOD: Error aggregation for batch operations
pub fn bulk_authenticate_users(
    credentials_list: &[Credentials]
) -> (Vec<AuthenticatedUser>, Vec<(usize, AuthError)>) {
    let mut successes = Vec::new();
    let mut failures = Vec::new();

    for (index, credentials) in credentials_list.iter().enumerate() {
        match authenticate_user(credentials) {
            Ok(authenticated_user) => successes.push(authenticated_user),
            Err(error) => failures.push((index, error)),
        }
    }

    (successes, failures)
}
```

### Error Context dan Chain

```rust
use anyhow::{Context, Result, bail};

// GOOD: Adding rich context to errors
pub fn load_user_profile(user_id: i32) -> Result<UserProfile> {
    let user = get_user_by_id(user_id)
        .with_context(|| format!("Failed to load user with ID: {}", user_id))?;

    let profile = get_user_profile(user_id)
        .with_context(|| "Failed to load user profile data")?;

    let permissions = get_user_permissions(user_id)
        .with_context(|| "Failed to load user permissions")?;

    // Validate profile completeness
    if profile.email.is_none() && user.role == UserRole::Admin {
        bail!("Admin users must have email addresses");
    }

    Ok(UserProfile {
        user,
        profile,
        permissions,
        loaded_at: chrono::Utc::now(),
    })
}

// GOOD: Custom error context for debugging
#[derive(Debug)]
pub struct ErrorContext {
    pub operation: String,
    pub user_id: Option<i32>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub request_id: Option<String>,
}

impl fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Operation: {}, User: {:?}, Time: {}, Request: {:?}", 
               self.operation, self.user_id, self.timestamp, self.request_id)
    }
}

pub fn with_context<T, E>(
    result: Result<T, E>,
    context: ErrorContext
) -> Result<T, (E, ErrorContext)>
where
    E: std::error::Error,
{
    result.map_err(|e| (e, context))
}
```

## Option and Result Types

### Understanding Option vs Result

- **Option<T>**: Represents presence or absence of a value (null safety)
- **Result<T, E>**: Represents success or failure of an operation (error handling)

### ❌ Non-Idiomatic: Null Checking Patterns

```rust
// BAD: Using sentinel values
pub fn find_user_by_email(email: &str) -> User {
    // Returns empty User if not found - confusing!
    User::default()
}

// BAD: Boolean + out parameter pattern
pub fn get_session(token: &str, session: &mut Session) -> bool {
    // Modifies session parameter, returns success flag
    false
}

// BAD: Using magic values
pub fn get_user_age(user_id: i32) -> i32 {
    // Returns -1 if user not found - error prone
    if let Some(user) = find_user(user_id) {
        calculate_age(user.birth_date)
    } else {
        -1 // Magic value indicating error
    }
}

// BAD: Nested if-let without combinators
pub fn get_user_display_name(user_id: i32) -> String {
    if let Some(user) = find_user_by_id(user_id) {
        if let Some(first_name) = user.first_name {
            if let Some(last_name) = user.last_name {
                format!("{} {}", first_name, last_name)
            } else {
                first_name
            }
        } else {
            user.username
        }
    } else {
        "Unknown User".to_string()
    }
}
```

### ✅ Idiomatic: Option dan Result Usage

```rust
// GOOD: Clear Option usage with semantic meaning
pub fn find_user_by_email(email: &str) -> Option<User> {
    // Clearly indicates user might not exist
    database_query("SELECT * FROM users WHERE email = $1", email)
        .optional()
        .unwrap_or(None)
}

// GOOD: Result for operations that can fail
pub fn get_active_session(token: &str) -> AuthResult<Session> {
    let session = find_session_by_token(token)?
        .ok_or(AuthError::InvalidSession)?;

    if session.is_expired() {
        return Err(AuthError::SessionExpired);
    }

    if session.is_revoked {
        return Err(AuthError::SessionRevoked);
    }

    Ok(session)
}

// GOOD: Combining Option and Result elegantly
pub fn validate_user_access(user_id: i32, resource: &str) -> AuthResult<AccessLevel> {
    let user = find_user_by_id(user_id)?
        .ok_or(AuthError::UserNotFound)?;

    let access_level = user.permissions
        .as_ref() // Option<Vec<Permission>> -> Option<&Vec<Permission>>
        .and_then(|perms| perms.iter().find(|p| p.resource == resource))
        .map(|perm| perm.access_level)
        .unwrap_or(AccessLevel::None);

    Ok(access_level)
}

// GOOD: Using combinators for cleaner code
pub fn get_user_display_name(user_id: i32) -> String {
    find_user_by_id(user_id)
        .ok()
        .and_then(|user| {
            // Try full name first
            user.first_name.zip(user.last_name)
                .map(|(first, last)| format!("{} {}", first, last))
                .or_else(|| user.first_name.clone()) // Then first name only
                .or_else(|| Some(user.username.clone())) // Finally username
        })
        .unwrap_or_else(|| format!("User #{}", user_id))
}

// GOOD: Error recovery patterns with detailed logging
pub fn authenticate_with_fallback(username: &str, password: &str) -> AuthResult<User> {
    authenticate_user(username, password)
        .or_else(|primary_err| {
            log::warn!("Primary auth failed for {}: {}", username, primary_err);
            authenticate_user_legacy(username, password)
        })
        .or_else(|legacy_err| {
            log::warn!("Legacy auth failed for {}: {}", username, legacy_err);
            authenticate_user_ldap(username, password)
        })
        .map_err(|final_err| {
            log::error!("All auth methods failed for {}: {}", username, final_err);
            AuthError::InvalidCredentials // Don't leak internal error details
        })
}
```

### Advanced Option/Result Patterns

```rust
// GOOD: Transpose for converting Option<Result<T, E>> to Result<Option<T>, E>
pub fn maybe_update_user_profile(
    user_id: Option<i32>, 
    profile_data: &ProfileData
) -> AuthResult<Option<UserProfile>> {
    user_id
        .map(|id| update_user_profile(id, profile_data)) // Option<Result<UserProfile, AuthError>>
        .transpose() // Result<Option<UserProfile>, AuthError>
}

// GOOD: Working with collections of Options/Results
pub fn load_user_batch(user_ids: &[i32]) -> AuthResult<Vec<User>> {
    user_ids.iter()
        .map(|&id| find_user_by_id(id).ok_or(AuthError::UserNotFound))
        .collect::<Result<Vec<_>, _>>() // Fail fast on first error
}

// GOOD: Partial success handling
pub fn load_user_batch_partial(user_ids: &[i32]) -> (Vec<User>, Vec<i32>) {
    let (users, failed_ids): (Vec<_>, Vec<_>) = user_ids.iter()
        .filter_map(|&id| {
            match find_user_by_id(id) {
                Ok(Some(user)) => Some(Ok(user)),
                Ok(None) => Some(Err(id)),
                Err(_) => Some(Err(id)),
            }
        })
        .partition_result(); // Separate successes from failures

    (users, failed_ids)
}

// GOOD: Option chaining for complex validation
pub fn validate_user_session_chain(
    token: &str,
    ip_address: &str,
    user_agent: &str
) -> Option<ValidatedSession> {
    find_session_by_token(token)?
        .filter(|s| !s.is_expired())?
        .filter(|s| !s.is_revoked)?
        .filter(|s| s.ip_address.as_ref().map_or(true, |ip| ip == ip_address))?
        .filter(|s| s.user_agent.as_ref().map_or(true, |ua| ua == user_agent))?
        .into()
}
```

## Ownership and Borrowing

### Understanding Ownership Rules

1. **Each value has a single owner**
2. **When owner goes out of scope, value is dropped**
3. **Ownership can be moved or borrowed**
4. **Borrowing rules ensure memory safety**

### ❌ Non-Idiomatic: Unnecessary Cloning

```rust
// BAD: Cloning everything
pub fn process_users(users: Vec<User>) -> Vec<String> {
    let mut result = Vec::new();
    for user in users {
        let cloned_user = user.clone(); // Unnecessary clone!
        result.push(format!("User: {}", cloned_user.username.clone())); // More cloning!
    }
    result
}

// BAD: Taking ownership when borrowing is sufficient
pub fn validate_password(password: String) -> bool { // Should be &str
    password.len() >= 8
}

// BAD: Cloning in hot paths
pub fn format_user_list(users: &[User]) -> String {
    let mut result = String::new();
    for user in users {
        let user_copy = user.clone(); // Expensive clone in loop!
        result.push_str(&format!("{}\n", user_copy.username));
    }
    result
}

// BAD: Unnecessary Vec allocation
pub fn get_admin_usernames(users: &[User]) -> Vec<String> {
    let admin_users: Vec<User> = users.iter()
        .filter(|u| u.role == UserRole::Admin)
        .cloned() // Cloning entire User structs
        .collect();
    
    admin_users.iter()
        .map(|u| u.username.clone())
        .collect()
}
```

### ✅ Idiomatic: Smart Borrowing

```rust
// GOOD: Using references efficiently
pub fn process_users(users: &[User]) -> Vec<String> {
    users.iter()
        .map(|user| format!("User: {}", user.username))
        .collect()
}

// GOOD: Borrowing when possible, clear function signatures
pub fn validate_password(password: &str) -> ValidationResult {
    let mut issues = Vec::new();
    
    if password.len() < 8 {
        issues.push("Password must be at least 8 characters");
    }
    
    if !password.chars().any(|c| c.is_uppercase()) {
        issues.push("Password must contain uppercase letters");
    }
    
    if !password.chars().any(|c| c.is_lowercase()) {
        issues.push("Password must contain lowercase letters");
    }
    
    if !password.chars().any(|c| c.is_numeric()) {
        issues.push("Password must contain numbers");
    }
    
    if issues.is_empty() {
        ValidationResult::Valid
    } else {
        ValidationResult::Invalid(issues)
    }
}

// GOOD: Strategic cloning only when necessary
pub fn create_user_session(user: &User) -> Session {
    Session {
        id: SessionId::new(),
        user_id: user.id,
        username: user.username.clone(), // Only clone what's needed
        role: user.role, // Copy for enum
        created_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
        ip_address: None, // Will be set by middleware
        user_agent: None, // Will be set by middleware
    }
}

// GOOD: Iterator chains avoid intermediate allocations
pub fn get_admin_usernames(users: &[User]) -> Vec<&str> {
    users.iter()
        .filter(|user| user.role == UserRole::Admin) // No cloning
        .map(|user| user.username.as_str()) // Borrow string slice
        .collect()
}

// GOOD: Using iterator adaptors for zero-copy processing
pub fn find_users_by_roles<'a>(
    users: &'a [User], 
    target_roles: &[UserRole]
) -> impl Iterator<Item = &'a User> {
    users.iter()
        .filter(move |user| target_roles.contains(&user.role))
}
```

### Lifetime Management

```rust
// GOOD: Explicit lifetimes when needed
pub struct AuthContext<'a> {
    pub user: &'a User,
    pub permissions: &'a [Permission],
    pub session: &'a Session,
    pub request_metadata: RequestMetadata // Owned data
}

impl<'a> AuthContext<'a> {
    pub fn new(
        user: &'a User, 
        permissions: &'a [Permission], 
        session: &'a Session,
        request_metadata: RequestMetadata,
    ) -> Self {
        Self { user, permissions, session, request_metadata }
    }
    
    pub fn has_permission(&self, resource: &str, action: Action) -> bool {
        self.permissions.iter()
            .any(|perm| perm.resource == resource && perm.action == action)
    }
    
    pub fn is_admin(&self) -> bool {
        self.user.role == UserRole::Admin
    }
    
    // Method that returns data with same lifetime as context
    pub fn get_user_permissions(&self) -> &'a [Permission] {
        self.permissions
    }
}

// GOOD: Using Cow for flexible string handling
use std::borrow::Cow;

pub fn sanitize_username(username: &str, strict_mode: bool) -> Cow<str> {
    if strict_mode {
        // Strict mode: only alphanumeric and underscore
        if username.chars().all(|c| c.is_alphanumeric() || c == '_') {
            Cow::Borrowed(username) // No allocation needed
        } else {
            Cow::Owned(
                username.chars()
                    .filter(|c| c.is_alphanumeric() || *c == '_')
                    .collect()
            ) // Allocate only when necessary
        }
    } else {
        // Permissive mode: allow more characters
        if username.chars().all(|c| c.is_alphanumeric() || "_-.@".contains(c)) {
            Cow::Borrowed(username)
        } else {
            Cow::Owned(
                username.chars()
                    .filter(|c| c.is_alphanumeric() || "_-.@".contains(*c))
                    .collect()
            )
        }
    }
}

// GOOD: Multiple lifetime parameters
pub fn compare_user_sessions<'u, 's>(
    user: &'u User,
    current_session: &'s Session,
    previous_session: &'s Session,
) -> SessionComparison<'u, 's> {
    SessionComparison {
        user,
        current_session,
        previous_session,
        comparison_time: chrono::Utc::now(),
    }
}

// GOOD: Lifetime elision works in most cases
pub fn get_user_display_info(user: &User) -> UserDisplayInfo { // 'a elided
    UserDisplayInfo {
        username: &user.username,
        role: user.role,
        last_login: user.last_login,
        is_active: user.is_active,
    }
}
```

### Advanced Ownership Patterns

```rust
// GOOD: Phantom types for compile-time guarantees
use std::marker::PhantomData;

pub struct Unvalidated;
pub struct Validated;

/// A user input that tracks its validation state at the type level.
///
/// This prevents using unvalidated data accidentally and ensures
/// validation happens exactly once.
pub struct UserInput<State = Unvalidated> {
    data: String,
    _state: PhantomData<State>,
}

impl UserInput<Unvalidated> {
    pub fn new(data: String) -> Self {
        Self {
            data,
            _state: PhantomData,
        }
    }
    
    /// Validates the input and returns a validated version.
    ///
    /// This consumes the unvalidated input, preventing reuse.
    pub fn validate(self) -> Result<UserInput<Validated>, ValidationError> {
        if self.data.is_empty() {
            return Err(ValidationError::EmptyInput);
        }
        
        if self.data.len() > 1000 {
            return Err(ValidationError::TooLong);
        }
        
        // Additional validation logic...
        
        Ok(UserInput {
            data: self.data,
            _state: PhantomData,
        })
    }
}

impl UserInput<Validated> {
    /// Returns the validated data.
    ///
    /// This method is only available on validated inputs.
    pub fn data(&self) -> &str {
        &self.data
    }
    
    /// Converts to a trusted string that can be used safely.
    pub fn into_trusted_string(self) -> TrustedString {
        TrustedString(self.data)
    }
}

// GOOD: Session state machine with type safety
pub struct LoggedOut;
pub struct LoggedIn;
pub struct TwoFactorPending;

pub struct UserSession<State> {
    session_id: SessionId,
    user_id: Option<UserId>,
    created_at: DateTime<Utc>,
    _state: PhantomData<State>,
}

impl UserSession<LoggedOut> {
    pub fn new() -> Self {
        Self {
            session_id: SessionId::generate(),
            user_id: None,
            created_at: Utc::now(),
            _state: PhantomData,
        }
    }
    
    pub fn login(
        self, 
        user_id: UserId, 
        requires_2fa: bool
    ) -> Result<UserSession<LoggedIn>, UserSession<TwoFactorPending>> {
        if requires_2fa {
            Err(UserSession {
                session_id: self.session_id,
                user_id: Some(user_id),
                created_at: self.created_at,
                _state: PhantomData,
            })
        } else {
            Ok(UserSession {
                session_id: self.session_id,
                user_id: Some(user_id),
                created_at: self.created_at,
                _state: PhantomData,
            })
        }
    }
}

impl UserSession<TwoFactorPending> {
    pub fn complete_2fa(self, token: &str) -> Result<UserSession<LoggedIn>, AuthError> {
        // Verify 2FA token
        if verify_2fa_token(self.user_id.unwrap(), token)? {
            Ok(UserSession {
                session_id: self.session_id,
                user_id: self.user_id,
                created_at: self.created_at,
                _state: PhantomData,
            })
        } else {
            Err(AuthError::Invalid2FA)
        }
    }
}

impl UserSession<LoggedIn> {
    pub fn user_id(&self) -> UserId {
        self.user_id.unwrap() // Safe because LoggedIn state guarantees user_id exists
    }
    
    pub fn logout(self) -> UserSession<LoggedOut> {
        UserSession {
            session_id: self.session_id,
            user_id: None,
            created_at: self.created_at,
            _state: PhantomData,
        }
    }
}
```

## Migration Strategies

### Migrating from Non-Idiomatic to Idiomatic Rust

```rust
// STEP 1: Introduce proper error types gradually
#[derive(Error, Debug)]
pub enum LegacyAuthError {
    #[error("Legacy error: {0}")]
    Legacy(String),
    #[error(transparent)]
    Modern(#[from] AuthError),
}

pub fn migrate_auth_function(username: &str, password: &str) -> Result<User, LegacyAuthError> {
    // First, wrap old string-based errors
    old_auth_function(username, password)
        .map_err(|e| LegacyAuthError::Legacy(e))
        .or_else(|_| {
            // Gradually replace with new implementation
            new_auth_function(username, password)
                .map_err(LegacyAuthError::Modern)
        })
}

// STEP 2: Introduce type safety incrementally
pub enum UserIdCompat {
    Legacy(i32),
    Modern(UserId),
}

impl From<i32> for UserIdCompat {
    fn from(id: i32) -> Self {
        Self::Legacy(id)
    }
}

impl From<UserId> for UserIdCompat {
    fn from(id: UserId) -> Self {
        Self::Modern(id)
    }
}

// STEP 3: Feature flags for gradual rollout
#[cfg(feature = "new-auth")]
pub use new_auth::*;

#[cfg(not(feature = "new-auth"))]
pub use legacy_auth::*;
```

### Performance Migration Guide

```rust
// BEFORE: Allocating strings unnecessarily
pub fn old_format_user_list(users: &[User]) -> Vec<String> {
    let mut result = Vec::new();
    for user in users {
        result.push(format!("User: {} ({})", user.username, user.email));
    }
    result
}

// AFTER: Using iterator for better performance
pub fn new_format_user_list(users: &[User]) -> impl Iterator<Item = String> + '_ {
    users.iter().map(|user| format!("User: {} ({})", user.username, user.email))
}

// MIGRATION: Provide both APIs during transition
pub fn format_user_list_compat(users: &[User], lazy: bool) -> Either<Vec<String>, Box<dyn Iterator<Item = String> + '_>> {
    if lazy {
        Either::Right(Box::new(new_format_user_list(users)))
    } else {
        Either::Left(old_format_user_list(users))
    }
}
```

---

## Conclusion

### The Idiomatic Rust Journey

Writing idiomatic Rust is a journey, not a destination. The patterns in this guide represent:

1. ⚡ **Performance**: Zero-cost abstractions dan efficient memory usage
2. 🛡️ **Safety**: Compile-time guarantees dan memory safety
3. 🔧 **Maintainability**: Clear code structure dan error handling
4. 🧪 **Testability**: Dependency injection dan mockable interfaces
5. 🚀 **Scalability**: Async programming dan concurrent processing
6. 🔒 **Security**: Safe handling of sensitive data dan input validation

### Progressive Improvement Strategy

1. **Start with Safety**: Focus on proper error handling and type safety
2. **Add Performance**: Use iterators and avoid unnecessary allocations
3. **Improve Testability**: Introduce dependency injection and traits
4. **Enhance Documentation**: Add comprehensive docs with examples
5. **Optimize for Production**: Profile and optimize hot paths
6. **Security Hardening**: Implement security-focused patterns

### Key Takeaways

- **Use the type system** untuk prevent bugs at compile time
- **Embrace ownership** untuk memory safety without garbage collection
- **Prefer composition** over inheritance dengan traits
- **Handle errors explicitly** dengan Result dan Option
- **Use iterators** untuk functional programming patterns
- **Design for testing** dengan dependency injection
- **Profile before optimizing** dan focus pada algorithmic improvements
- **Secure by design** dengan proper data handling
- **Document thoroughly** dengan examples dan tests
- **Migrate incrementally** when improving existing code

### Resources for Continuous Learning

- **The Rust Book**: Official guide to Rust fundamentals
- **Rust by Example**: Practical examples of Rust patterns
- **The Rustonomicon**: Advanced unsafe Rust patterns
- **Rust API Guidelines**: Official API design guidelines
- **This Week in Rust**: Stay updated with community developments

Dengan mengikuti patterns ini, code Anda akan lebih idiomatik, aman, dan maintainable sesuai dengan Rust community standards. Remember: good Rust code is not just correct, it's also clear, efficient, and secure.

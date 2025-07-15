# Panduan Lengkap Idiomatic Rust

## Daftar Isi

- [Pendahuluan](#pendahuluan)
- [Prinsip Dasar Rust](#prinsip-dasar-rust)
- [Ownership dan Borrowing](#ownership-dan-borrowing)
- [Error Handling](#error-handling)
- [Pattern Matching](#pattern-matching)
- [Traits dan Generics](#traits-dan-generics)
- [Collections](#collections)
- [Concurrency](#concurrency)
- [Testing](#testing)
- [Performance Patterns](#performance-patterns)
- [Security Patterns](#security-patterns)
- [Code Organization](#code-organization)
- [Best Practices](#best-practices)
- [Anti-Patterns](#anti-patterns)
- [Real-World Examples](#real-world-examples)

## Pendahuluan

Rust adalah bahasa pemrograman systems yang mengutamakan safety, speed, dan concurrency. Idiomatic Rust mengacu pada
cara penulisan kode yang memanfaatkan fitur-fitur bahasa secara optimal dan mengikuti konvensi komunitas.

### Filosofi Rust

- **Memory Safety**: Mencegah segmentation faults, buffer overflows, dan data races
- **Zero-Cost Abstractions**: Abstraksi high-level tanpa overhead runtime
- **Ownership**: Model kepemilikan unik yang mengelola memory tanpa GC
- **Fearless Concurrency**: Concurrent programming yang aman secara compile-time

## Prinsip Dasar Rust

### 1. Explicit over Implicit

```rust
// ❌ Tidak idiomatis - implicit conversion
fn process_data(data: &str) {
    let number = data.parse::<i32>().unwrap(); // Panic jika gagal
}

// ✅ Idiomatis - explicit error handling
fn process_data(data: &str) -> Result<i32, std::num::ParseIntError> {
    data.parse::<i32>()
}
```

### 2. Move Semantics

```rust
// ❌ Tidak efisien - unnecessary cloning
fn process_string(s: String) -> String {
    let mut result = s.clone();
    result.push_str(" processed");
    result
}

// ✅ Idiomatis - take ownership
fn process_string(mut s: String) -> String {
    s.push_str(" processed");
    s
}
```

### 3. Borrowing vs Ownership

```rust
// ✅ Borrow untuk read-only access
fn get_length(s: &str) -> usize {
    s.len()
}

// ✅ Mutable borrow untuk modification
fn capitalize(s: &mut String) {
    s.make_ascii_uppercase();
}

// ✅ Take ownership untuk transformation
fn into_uppercase(s: String) -> String {
    s.to_uppercase()
}
```

## Ownership dan Borrowing

### Ownership Rules

1. Setiap value memiliki satu owner
2. Ketika owner keluar dari scope, value akan di-drop
3. Tidak boleh ada multiple mutable references atau mutable + immutable references bersamaan

```rust
// ✅ Idiomatis ownership patterns
struct User {
    name: String,
    email: String,
}

impl User {
    // Constructor mengambil ownership
    pub fn new(name: String, email: String) -> Self {
        Self { name, email }
    }

    // Getter mengembalikan reference
    pub fn name(&self) -> &str {
        &self.name
    }

    // Method yang mengubah state
    pub fn update_email(&mut self, new_email: String) {
        self.email = new_email;
    }

    // Method yang mengkonsumsi self
    pub fn into_name(self) -> String {
        self.name
    }
}
```

### Lifetime Annotations

```rust
// ✅ Explicit lifetime untuk complex scenarios
struct UserSession<'a> {
    user: &'a User,
    token: String,
    expires_at: std::time::SystemTime,
}

impl<'a> UserSession<'a> {
    pub fn new(user: &'a User, token: String) -> Self {
        Self {
            user,
            token,
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        }
    }

    pub fn is_valid(&self) -> bool {
        std::time::SystemTime::now() < self.expires_at
    }
}
```

## Error Handling

### Result Type

```rust
use std::fs;
use std::io;

// ✅ Idiomatis error handling dengan custom error types
#[derive(Debug)]
pub enum ConfigError {
    Io(io::Error),
    Parse(serde_json::Error),
    Validation(String),
}

impl From<io::Error> for ConfigError {
    fn from(err: io::Error) -> Self {
        ConfigError::Io(err)
    }
}

impl From<serde_json::Error> for ConfigError {
    fn from(err: serde_json::Error) -> Self {
        ConfigError::Parse(err)
    }
}

pub fn load_config(path: &str) -> Result<Config, ConfigError> {
    let content = fs::read_to_string(path)?;
    let config: Config = serde_json::from_str(&content)?;

    if config.port == 0 {
        return Err(ConfigError::Validation("Port cannot be zero".to_string()));
    }

    Ok(config)
}
```

### Error Propagation dengan ?

```rust
// ✅ Menggunakan ? operator untuk error propagation
async fn authenticate_user(credentials: &Credentials) -> Result<User, AuthError> {
    let user = database::find_user(&credentials.username).await?;
    let is_valid = password::verify(&credentials.password, &user.password_hash)?;

    if !is_valid {
        return Err(AuthError::InvalidCredentials);
    }

    Ok(user)
}
```

### Option Type

```rust
// ✅ Idiomatis penggunaan Option
impl User {
    pub fn find_by_email(email: &str) -> Option<User> {
        // Database lookup logic
        todo!()
    }

    pub fn get_profile_picture(&self) -> Option<&str> {
        self.profile_picture.as_deref()
    }
}

// ✅ Pattern matching dengan Option
fn process_user(email: &str) -> Result<String, &'static str> {
    match User::find_by_email(email) {
        Some(user) => Ok(format!("Welcome, {}", user.name)),
        None => Err("User not found"),
    }
}

// ✅ Menggunakan combinator methods
fn get_user_display_name(email: &str) -> String {
    User::find_by_email(email)
        .map(|user| user.name)
        .unwrap_or_else(|| "Guest".to_string())
}
```

## Pattern Matching

### Match Expressions

```rust
// ✅ Comprehensive pattern matching
enum AuthResult {
    Success(User),
    InvalidCredentials,
    AccountLocked { until: std::time::SystemTime },
    TwoFactorRequired { token: String },
}

fn handle_auth_result(result: AuthResult) -> String {
    match result {
        AuthResult::Success(user) => {
            format!("Welcome, {}!", user.name)
        }
        AuthResult::InvalidCredentials => {
            "Invalid username or password".to_string()
        }
        AuthResult::AccountLocked { until } => {
            format!("Account locked until {:?}", until)
        }
        AuthResult::TwoFactorRequired { token } => {
            format!("Please enter 2FA code. Token: {}", token)
        }
    }
}
```

### If Let dan While Let

```rust
// ✅ Menggunakan if let untuk single pattern matching
fn process_optional_data(data: Option<String>) {
    if let Some(content) = data {
        println!("Processing: {}", content);
    }
}

// ✅ While let untuk iterating dengan pattern matching
fn process_queue(mut queue: Vec<Task>) {
    while let Some(task) = queue.pop() {
        task.execute();
    }
}
```

### Destructuring

```rust
// ✅ Destructuring structs dan tuples
struct Point {
    x: i32,
    y: i32
}

fn analyze_point(point: Point) {
    match point {
        Point { x: 0, y: 0 } => println!("Origin"),
        Point { x: 0, y } => println!("On Y-axis at y={}", y),
        Point { x, y: 0 } => println!("On X-axis at x={}", x),
        Point { x, y } => println!("Point at ({}, {})", x, y),
    }
}

// ✅ Destructuring dalam function parameters
fn calculate_distance((x1, y1): (f64, f64), (x2, y2): (f64, f64)) -> f64 {
    ((x2 - x1).powi(2) + (y2 - y1).powi(2)).sqrt()
}
```

## Traits dan Generics

### Trait Definitions

```rust
// ✅ Well-designed trait dengan associated types
trait Repository<T> {
    type Error;
    type Id;

    async fn find_by_id(&self, id: Self::Id) -> Result<Option<T>, Self::Error>;
    async fn save(&self, entity: &T) -> Result<Self::Id, Self::Error>;
    async fn delete(&self, id: Self::Id) -> Result<(), Self::Error>;
}

// ✅ Default implementations
trait Authenticatable {
    fn hash_password(password: &str) -> String {
        // Default bcrypt implementation
        bcrypt::hash(password, bcrypt::DEFAULT_COST).unwrap()
    }

    fn verify_password(&self, password: &str, hash: &str) -> bool;
    fn is_account_locked(&self) -> bool {
        false // Default: not locked
    }
}
```

### Generic Constraints

```rust
use std::fmt::Debug;
use serde::{Serialize, Deserialize};

// ✅ Meaningful generic constraints
fn log_and_serialize<T>(item: &T) -> Result<String, serde_json::Error>
where
    T: Debug + Serialize,
{
    println!("Serializing: {:?}", item);
    serde_json::to_string(item)
}

// ✅ Associated types untuk cleaner APIs
trait Iterator {
    type Item;

    fn next(&mut self) -> Option<Self::Item>;

    // Default implementations using associated type
    fn collect<B: FromIterator<Self::Item>>(self) -> B
    where
        Self: Sized,
    {
        FromIterator::from_iter(self)
    }
}
```

### Trait Objects

```rust
// ✅ Trait objects untuk dynamic dispatch
trait EventHandler: Send + Sync {
    fn handle(&self, event: &Event) -> Result<(), Box<dyn std::error::Error>>;
}

struct EventBus {
    handlers: Vec<Box<dyn EventHandler>>,
}

impl EventBus {
    pub fn register<H: EventHandler + 'static>(&mut self, handler: H) {
        self.handlers.push(Box::new(handler));
    }

    pub fn publish(&self, event: &Event) {
        for handler in &self.handlers {
            if let Err(e) = handler.handle(event) {
                eprintln!("Handler error: {}", e);
            }
        }
    }
}
```

## Collections

### Vec

```rust
// ✅ Efficient Vec operations
fn process_numbers(numbers: Vec<i32>) -> Vec<i32> {
    numbers
        .into_iter()
        .filter(|&n| n > 0)
        .map(|n| n * 2)
        .collect()
}

// ✅ Pre-allocate capacity when size is known
fn generate_sequence(n: usize) -> Vec<i32> {
    let mut result = Vec::with_capacity(n);
    for i in 0..n {
        result.push(i as i32);
    }
    result
}
```

### HashMap

```rust
use std::collections::HashMap;

// ✅ Idiomatis HashMap usage
fn count_words(text: &str) -> HashMap<String, usize> {
    let mut counts = HashMap::new();

    for word in text.split_whitespace() {
        *counts.entry(word.to_lowercase()).or_insert(0) += 1;
    }

    counts
}

// ✅ Custom key types dengan Hash + Eq
#[derive(Hash, Eq, PartialEq, Debug)]
struct UserId(u64);

type UserCache = HashMap<UserId, User>;
```

### Iterators

```rust
// ✅ Chaining iterator adaptors
fn process_user_emails(users: &[User]) -> Vec<String> {
    users
        .iter()
        .filter(|user| user.is_active)
        .filter_map(|user| user.email.as_ref())
        .map(|email| email.to_lowercase())
        .collect()
}

// ✅ Custom iterator implementation
struct Counter {
    current: usize,
    max: usize,
}

impl Counter {
    fn new(max: usize) -> Counter {
        Counter { current: 0, max }
    }
}

impl Iterator for Counter {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current < self.max {
            let current = self.current;
            self.current += 1;
            Some(current)
        } else {
            None
        }
    }
}
```

## Concurrency

### Async/Await

```rust
use tokio;
use std::time::Duration;

// ✅ Idiomatis async functions
async fn fetch_user_data(user_id: u64) -> Result<UserData, ApiError> {
    let client = reqwest::Client::new();

    let response = client
        .get(&format!("https://api.example.com/users/{}", user_id))
        .timeout(Duration::from_secs(30))
        .send()
        .await?;

    let user_data = response.json::<UserData>().await?;
    Ok(user_data)
}

// ✅ Concurrent execution dengan join!
async fn load_user_profile(user_id: u64) -> Result<UserProfile, ProfileError> {
    let (user_data, preferences, activities) = tokio::try_join!(
        fetch_user_data(user_id),
        fetch_user_preferences(user_id),
        fetch_user_activities(user_id)
    )?;

    Ok(UserProfile {
        data: user_data,
        preferences,
        activities,
    })
}
```

### Channels

```rust
use tokio::sync::{mpsc, oneshot};

// ✅ Using channels untuk communication
async fn worker_pool_example() {
    let (tx, mut rx) = mpsc::channel::<Task>(100);

    // Spawn workers
    for _ in 0..4 {
        let mut task_rx = rx.clone();
        tokio::spawn(async move {
            while let Some(task) = task_rx.recv().await {
                task.execute().await;
            }
        });
    }

    // Send tasks
    for i in 0..10 {
        let task = Task::new(i);
        tx.send(task).await.unwrap();
    }
}
```

### Shared State

```rust
use std::sync::Arc;
use tokio::sync::RwLock;

// ✅ Thread-safe shared state
#[derive(Clone)]
struct AppState {
    users: Arc<RwLock<HashMap<UserId, User>>>,
    config: Arc<Config>,
}

impl AppState {
    async fn get_user(&self, id: UserId) -> Option<User> {
        let users = self.users.read().await;
        users.get(&id).cloned()
    }

    async fn update_user(&self, id: UserId, user: User) {
        let mut users = self.users.write().await;
        users.insert(id, user);
    }
}
```

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_validation() {
        assert!(is_valid_password("StrongP@ssw0rd"));
        assert!(!is_valid_password("weak"));
        assert!(!is_valid_password(""));
    }

    #[test]
    #[should_panic]
    fn test_invalid_configuration() {
        Config::new("", 0); // Should panic
    }

    // ✅ Property-based testing dengan quickcheck
    #[quickcheck]
    fn prop_hash_verify_roundtrip(password: String) -> bool {
        if password.is_empty() {
            return true; // Skip empty passwords
        }

        let hash = hash_password(&password);
        verify_password(&password, &hash)
    }
}
```

### Integration Tests

```rust
// tests/integration_test.rs
use basic_auth::*;
use tokio_test;

#[tokio::test]
async fn test_full_authentication_flow() {
    let mut app = create_test_app().await;

    // Register user
    let user_data = UserRegistration {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "SecurePassword123!".to_string(),
    };

    let user = app.register_user(user_data).await.expect("Registration failed");
    assert_eq!(user.username, "testuser");

    // Authenticate
    let credentials = Credentials {
        username: "testuser".to_string(),
        password: "SecurePassword123!".to_string(),
    };

    let auth_result = app.authenticate(credentials).await.expect("Auth failed");
    assert!(matches!(auth_result, AuthResult::Success(_)));
}
```

### Mocking

```rust
// ✅ Trait-based mocking
#[async_trait]
trait UserRepository {
    async fn find_by_username(&self, username: &str) -> Result<Option<User>, DbError>;
    async fn save(&self, user: &User) -> Result<(), DbError>;
}

// Production implementation
struct PostgresUserRepository {
    pool: sqlx::PgPool,
}

// Test implementation
struct MockUserRepository {
    users: HashMap<String, User>,
}

#[async_trait]
impl UserRepository for MockUserRepository {
    async fn find_by_username(&self, username: &str) -> Result<Option<User>, DbError> {
        Ok(self.users.get(username).cloned())
    }

    async fn save(&self, user: &User) -> Result<(), DbError> {
        // Mock implementation
        Ok(())
    }
}
```

## Performance Patterns

### Zero-Copy Operations

```rust
// ✅ Avoiding unnecessary allocations
fn parse_headers(input: &str) -> HashMap<&str, &str> {
    input
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(2, ':');
            match (parts.next(), parts.next()) {
                (Some(key), Some(value)) => Some((key.trim(), value.trim())),
                _ => None,
            }
        })
        .collect()
}

// ✅ Using Cow untuk conditional ownership
use std::borrow::Cow;

fn process_text(input: &str) -> Cow<str> {
    if input.contains("sensitive") {
        Cow::Owned(input.replace("sensitive", "[REDACTED]"))
    } else {
        Cow::Borrowed(input)
    }
}
```

### Memory Pool Pattern

```rust
// ✅ Object pooling untuk high-performance scenarios
use std::sync::Mutex;

struct ConnectionPool<T> {
    connections: Mutex<Vec<T>>,
    factory: Box<dyn Fn() -> T + Send + Sync>,
}

impl<T> ConnectionPool<T> {
    pub fn new<F>(size: usize, factory: F) -> Self
    where
        F: Fn() -> T + Send + Sync + 'static,
    {
        let mut connections = Vec::with_capacity(size);
        for _ in 0..size {
            connections.push(factory());
        }

        Self {
            connections: Mutex::new(connections),
            factory: Box::new(factory),
        }
    }

    pub fn get(&self) -> PooledConnection<T> {
        let connection = self.connections
            .lock()
            .unwrap()
            .pop()
            .unwrap_or_else(|| (self.factory)());

        PooledConnection {
            connection: Some(connection),
            pool: self,
        }
    }
}
```

## Security Patterns

### Secure String Handling

```rust
use zeroize::Zeroize;

// ✅ Secure password handling
#[derive(Zeroize)]
#[zeroize(drop)]
struct SecureString {
    data: Vec<u8>,
}

impl SecureString {
    pub fn new(s: String) -> Self {
        Self {
            data: s.into_bytes(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

// ✅ Constant-time comparison
fn verify_token(provided: &str, expected: &str) -> bool {
    use subtle::ConstantTimeEq;
    provided.as_bytes().ct_eq(expected.as_bytes()).into()
}
```

### Input Validation

```rust
// ✅ Comprehensive input validation
#[derive(Debug)]
pub struct ValidatedEmail(String);

impl ValidatedEmail {
    pub fn new(email: String) -> Result<Self, ValidationError> {
        if email.is_empty() {
            return Err(ValidationError::Empty);
        }

        if !email.contains('@') {
            return Err(ValidationError::InvalidFormat);
        }

        if email.len() > 254 {
            return Err(ValidationError::TooLong);
        }

        // Additional validation...

        Ok(ValidatedEmail(email))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ✅ Use validated types in APIs
pub fn send_notification(email: ValidatedEmail, message: &str) -> Result<(), NotificationError> {
    // Safe to use email.as_str() here - it's already validated
    todo!()
}
```

## Code Organization

### Module Structure

```rust
// lib.rs
pub mod auth {
    pub mod service;
    pub mod repository;
    pub mod models;
}

pub mod config;
pub mod error;
pub mod utils;

// Re-export important types
pub use auth::models::{User, Credentials};
pub use auth::service::AuthService;
pub use error::{AuthError, Result};
```

### Feature Gates

```rust
// Cargo.toml
[features]
default = ["sqlite"]
sqlite = ["sqlx/sqlite"]
postgres = ["sqlx/postgres"]
redis-cache = ["redis"]

// lib.rs
#[cfg(feature = "redis-cache")]
pub mod cache;

#[cfg(feature = "postgres")]
mod postgres_repository;

#[cfg(feature = "sqlite")]
mod sqlite_repository;
```

## Best Practices

### 1. Prefer Composition over Inheritance

```rust
// ✅ Composition dengan traits
trait Hashable {
    fn hash(&self, password: &str) -> String;
}

trait Validator {
    fn validate(&self, input: &str) -> Result<(), ValidationError>;
}

struct AuthService<H, V> {
    hasher: H,
    validator: V,
}

impl<H: Hashable, V: Validator> AuthService<H, V> {
    pub fn new(hasher: H, validator: V) -> Self {
        Self { hasher, validator }
    }

    pub fn register(&self, credentials: &Credentials) -> Result<User, AuthError> {
        self.validator.validate(&credentials.password)?;
        let hash = self.hasher.hash(&credentials.password);
        // Create user...
        todo!()
    }
}
```

### 2. Use Type-Driven Development

```rust
// ✅ Express business rules through types
#[derive(Debug)]
pub struct UnverifiedUser {
    pub email: ValidatedEmail,
    pub username: String,
    verification_token: String,
}

#[derive(Debug)]
pub struct VerifiedUser {
    pub email: ValidatedEmail,
    pub username: String,
    pub created_at: DateTime<Utc>,
}

impl UnverifiedUser {
    pub fn verify(self, token: &str) -> Result<VerifiedUser, VerificationError> {
        if self.verification_token != token {
            return Err(VerificationError::InvalidToken);
        }

        Ok(VerifiedUser {
            email: self.email,
            username: self.username,
            created_at: Utc::now(),
        })
    }
}
```

### 3. Minimize Public APIs

```rust
// ✅ Clear public interface
pub struct UserService {
    repository: Box<dyn UserRepository>,
    hasher: Box<dyn PasswordHasher>,
}

impl UserService {
    // Public constructor
    pub fn new(
        repository: Box<dyn UserRepository>,
        hasher: Box<dyn PasswordHasher>,
    ) -> Self {
        Self { repository, hasher }
    }

    // Public methods
    pub async fn register_user(&self, data: UserRegistration) -> Result<User, ServiceError> {
        self.validate_registration(&data)?;
        let user = self.create_user(data).await?;
        self.repository.save(&user).await?;
        Ok(user)
    }

    // Private helper methods
    fn validate_registration(&self, data: &UserRegistration) -> Result<(), ValidationError> {
        // Validation logic
        todo!()
    }

    async fn create_user(&self, data: UserRegistration) -> Result<User, ServiceError> {
        // User creation logic
        todo!()
    }
}
```

## Anti-Patterns

### 1. Excessive Cloning

```rust
// ❌ Avoid unnecessary cloning
fn bad_example(users: Vec<User>) -> Vec<String> {
    let mut names = Vec::new();
    for user in users {
        names.push(user.name.clone()); // Unnecessary clone
    }
    names
}

// ✅ Use references atau move semantics
fn good_example(users: Vec<User>) -> Vec<String> {
    users.into_iter().map(|user| user.name).collect()
}
```

### 2. Unwrap() dalam Production Code

```rust
// ❌ Avoid unwrap() in production
fn bad_parse(input: &str) -> i32 {
    input.parse().unwrap() // Will panic on invalid input
}

// ✅ Proper error handling
fn good_parse(input: &str) -> Result<i32, std::num::ParseIntError> {
    input.parse()
}
```

### 3. Stringly Typed Programming

```rust
// ❌ Using strings for everything
fn bad_user_status(status: &str) -> bool {
    status == "active" // Prone to typos
}

// ✅ Use enums untuk distinct states
#[derive(Debug, PartialEq)]
enum UserStatus {
    Active,
    Inactive,
    Suspended,
}

fn good_user_status(status: UserStatus) -> bool {
    status == UserStatus::Active
}
```

## Real-World Examples

### Complete Authentication Service

```rust
use async_trait::async_trait;
use bcrypt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

// Domain types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub is_active: bool,
}

#[derive(Debug, Deserialize)]
pub struct UserRegistration {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginCredentials {
    pub username: String,
    pub password: String,
}

// Error types
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("Database error: {0}")]
    Database(String),
    #[error("Validation error: {0}")]
    Validation(String),
}

// Repository trait
#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_by_username(&self, username: &str) -> Result<Option<User>, AuthError>;
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError>;
    async fn save(&self, user: &User) -> Result<(), AuthError>;
}

// Service implementation
pub struct AuthService<R: UserRepository> {
    repository: R,
}

impl<R: UserRepository> AuthService<R> {
    pub fn new(repository: R) -> Self {
        Self { repository }
    }

    pub async fn register(&self, registration: UserRegistration) -> Result<User, AuthError> {
        // Validate input
        self.validate_registration(&registration)?;

        // Check if user already exists
        if let Some(_) = self.repository.find_by_username(&registration.username).await? {
            return Err(AuthError::UserAlreadyExists);
        }

        if let Some(_) = self.repository.find_by_email(&registration.email).await? {
            return Err(AuthError::UserAlreadyExists);
        }

        // Create user
        let password_hash = bcrypt::hash(&registration.password, bcrypt::DEFAULT_COST)
            .map_err(|e| AuthError::Database(e.to_string()))?;

        let user = User {
            id: Uuid::new_v4(),
            username: registration.username,
            email: registration.email,
            password_hash,
            is_active: true,
        };

        // Save to repository
        self.repository.save(&user).await?;

        Ok(user)
    }

    pub async fn login(&self, credentials: LoginCredentials) -> Result<User, AuthError> {
        let user = self.repository
            .find_by_username(&credentials.username)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        if !user.is_active {
            return Err(AuthError::InvalidCredentials);
        }

        let is_valid = bcrypt::verify(&credentials.password, &user.password_hash)
            .map_err(|e| AuthError::Database(e.to_string()))?;

        if !is_valid {
            return Err(AuthError::InvalidCredentials);
        }

        Ok(user)
    }

    fn validate_registration(&self, registration: &UserRegistration) -> Result<(), AuthError> {
        if registration.username.len() < 3 {
            return Err(AuthError::Validation("Username too short".to_string()));
        }

        if !registration.email.contains('@') {
            return Err(AuthError::Validation("Invalid email format".to_string()));
        }

        if registration.password.len() < 8 {
            return Err(AuthError::Validation("Password too short".to_string()));
        }

        Ok(())
    }
}

// In-memory repository for testing
pub struct InMemoryUserRepository {
    users: std::sync::RwLock<HashMap<String, User>>,
}

impl InMemoryUserRepository {
    pub fn new() -> Self {
        Self {
            users: std::sync::RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl UserRepository for InMemoryUserRepository {
    async fn find_by_username(&self, username: &str) -> Result<Option<User>, AuthError> {
        let users = self.users.read().unwrap();
        Ok(users.get(username).cloned())
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
        let users = self.users.read().unwrap();
        Ok(users.values().find(|u| u.email == email).cloned())
    }

    async fn save(&self, user: &User) -> Result<(), AuthError> {
        let mut users = self.users.write().unwrap();
        users.insert(user.username.clone(), user.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_user_registration_and_login() {
        let repository = InMemoryUserRepository::new();
        let auth_service = AuthService::new(repository);

        // Register user
        let registration = UserRegistration {
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password: "securepassword123".to_string(),
        };

        let user = auth_service.register(registration).await.unwrap();
        assert_eq!(user.username, "testuser");
        assert_eq!(user.email, "test@example.com");

        // Login
        let credentials = LoginCredentials {
            username: "testuser".to_string(),
            password: "securepassword123".to_string(),
        };

        let logged_in_user = auth_service.login(credentials).await.unwrap();
        assert_eq!(logged_in_user.id, user.id);
    }

    #[tokio::test]
    async fn test_duplicate_registration() {
        let repository = InMemoryUserRepository::new();
        let auth_service = AuthService::new(repository);

        let registration = UserRegistration {
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password: "securepassword123".to_string(),
        };

        // First registration should succeed
        auth_service.register(registration.clone()).await.unwrap();

        // Second registration should fail
        let result = auth_service.register(registration).await;
        assert!(matches!(result, Err(AuthError::UserAlreadyExists)));
    }
}
```

## Kesimpulan

Idiomatic Rust mengutamakan:

1. **Safety**: Gunakan type system untuk mencegah bugs
2. **Performance**: Zero-cost abstractions dan efficient memory usage
3. **Clarity**: Code yang self-documenting dan explicit
4. **Composability**: Modular design dengan traits
5. **Testing**: Comprehensive testing strategy

Kunci untuk menulis idiomatic Rust adalah memahami ownership model, memanfaatkan type system secara optimal, dan
mengikuti konvensi komunitas. Dengan practice yang konsisten, Anda akan mengembangkan intuisi untuk patterns yang
efektif dan aman.

---

*Panduan ini mencakup aspek fundamental sampai advanced dari idiomatic Rust. Untuk implementasi production, selalu
pertimbangkan security, performance, dan maintainability sesuai dengan requirement spesifik aplikasi Anda.*

# Complete Rust Idiomatic Programming Guide 🦀

> **Idiomatic Rust** = Menulis kode yang natural, aman, efisien, dan mengikuti konvensi komunitas Rust

## Table of Contents

1. [Naming Conventions](#naming-conventions)
2. [Error Handling](#error-handling)
3. [Iterators](#iterators)
4. [Ownership & Borrowing](#ownership--borrowing)
5. [Option & Result Patterns](#option--result-patterns)
6. [Struct & Enum Patterns](#struct--enum-patterns)
7. [Traits & Generics](#traits--generics)
8. [Collections & Data Structures](#collections--data-structures)
9. [String Handling](#string-handling)
10. [Modules & Visibility](#modules--visibility)
11. [Documentation](#documentation)
12. [Testing](#testing)
13. [Async Patterns](#async-patterns)
14. [Performance Idioms](#performance-idioms)
15. [Cargo & Project Structure](#cargo--project-structure)
16. [Memory Management](#memory-management)
17. [Concurrency Patterns](#concurrency-patterns)
18. [Functional Programming](#functional-programming)
19. [Type Safety](#type-safety)
20. [Macro Usage](#macro-usage)

---

## Naming Conventions

### General Rules

```rust
// ✅ Good: snake_case for variables, functions, modules
let user_name = "john_doe";
fn calculate_total() -> u32 { 100 }
mod user_service;

// ✅ Good: PascalCase for types, structs, enums, traits
struct UserAccount;
enum PaymentStatus;
trait DatabaseConnection;

// ✅ Good: SCREAMING_SNAKE_CASE for constants
const MAX_RETRY_ATTEMPTS: u32 = 3;
const DATABASE_URL: &str = "postgresql://localhost/mydb";

// ❌ Bad: Mixed conventions
let userName = "john"; // Should be user_name
struct userAccount; // Should be UserAccount
const maxRetries: u32 = 3; // Should be MAX_RETRIES
```

### Specific Patterns

```rust
// ✅ Good: Type conversions: from/into/to/as patterns
impl From<String> for UserId {
    fn from(s: String) -> Self {
        UserId(s)
    }
}

// ✅ Good: Boolean methods: is_/has_/can_/should_
impl User {
    fn is_active(&self) -> bool { self.status == Status::Active }
    fn has_permissions(&self) -> bool { !self.permissions.is_empty() }
    fn can_edit(&self) -> bool { self.role == Role::Admin }
}

// ✅ Good: Getter methods: omit "get_" prefix
impl User {
    fn name(&self) -> &str { &self.name } // Not get_name()
    fn email(&self) -> &str { &self.email } // Not get_email()
}

// ❌ Bad: Inconsistent method naming
impl User {
    fn getName(&self) -> &str { &self.name } // Should be name()
    fn get_email(&self) -> &str { &self.email } // Should be email()
    fn IsActive(&self) -> bool { self.status == Status::Active } // Should be is_active()
}
```

### Naming Comparisons with Other Languages

| Concept         | Rust (Idiomatic)    | Java/C#            | JavaScript/TypeScript | Python              |
|-----------------|---------------------|--------------------|-----------------------|---------------------|
| Variables       | `user_name`         | `userName`         | `userName`            | `user_name`         |
| Functions       | `calculate_total()` | `calculateTotal()` | `calculateTotal()`    | `calculate_total()` |
| Types/Classes   | `UserAccount`       | `UserAccount`      | `UserAccount`         | `UserAccount`       |
| Constants       | `MAX_ATTEMPTS`      | `MAX_ATTEMPTS`     | `MAX_ATTEMPTS`        | `MAX_ATTEMPTS`      |
| Modules         | `user_service`      | `UserService`      | `userService`         | `user_service`      |
| Boolean methods | `is_valid()`        | `isValid()`        | `isValid()`           | `is_valid()`        |

### Module and File Naming

```rust
// ✅ Good: Module name matches file name
// In user_service.rs
pub mod user_service {
    // Module contents...
}

// ✅ Good: Module structure matches directory structure
// In models/user.rs
pub struct User {
    /* ... */
}

// In main.rs or lib.rs
mod models; // This will look for models/mod.rs or models/*.rs files

// ❌ Bad: Mismatched file and module names
// In user_service
pub mod user_service { // Doesn't match file name
    // Module contents...
}
```

### Type Parameters and Generics

```rust
// ✅ Good: Single uppercase letter for simple generics
fn identity<T>(value: T) -> T {
    value
}

// ✅ Good: Descriptive names for complex generic parameters
struct Cache<Backend, Item>
where
    Backend: Storage,
    Item: Serialize + Deserialize,
{
    backend: Backend,
    items: Vec<Item>,
}

// ❌ Bad: Lowercase or non-descriptive generic names
fn process<data, errorType>(input: data) -> Result<data, errorType> {
    // Should be Data and ErrorType or just T and E
}
```

---

## Error Handling

### Use Result<T, E> for Recoverable Errors

```rust
use std::fs::File;
use std::io::{self, Read};

// ✅ Good: Return Result for operations that can fail
fn read_config_file(path: &str) -> Result<String, io::Error> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

// ✅ Good: Custom error types
#[derive(Debug)]
enum ConfigError {
    IoError(io::Error),
    ParseError(String),
    ValidationError(String),
}

impl From<io::Error> for ConfigError {
    fn from(error: io::Error) -> Self {
        ConfigError::IoError(error)
    }
}

// ❌ Bad: Using panic or unwrap in production code
fn read_config_bad(path: &str) -> String {
    let mut file = File::open(path).unwrap(); // Panics if file doesn't exist
    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("Failed to read file");
    contents
}

// ❌ Bad: Using generic error types
fn process_data(data: &str) -> Result<ProcessedData, String> {
    // String error types provide limited context and are not composable
    if data.is_empty() {
        return Err("Data is empty".to_string());
    }
    // ...process data...
    Ok(ProcessedData {})
}
```

### Error Propagation Patterns

```rust
// ✅ Good: Use ? operator for error propagation
fn process_user_data(id: u32) -> Result<User, DatabaseError> {
    let raw_data = fetch_user_from_db(id)?;
    let parsed_data = parse_user_data(&raw_data)?;
    let validated_user = validate_user(parsed_data)?;
    Ok(validated_user)
}

// ✅ Good: Chain operations with and_then
fn get_user_email(id: u32) -> Result<String, Error> {
    find_user(id)
        .and_then(|user| validate_user(&user))
        .map(|user| user.email)
}

// ✅ Good: Use map_err for error transformation
fn save_user(user: &User) -> Result<(), ServiceError> {
    database::save(user)
        .map_err(|e| ServiceError::DatabaseError(e))?;
    Ok(())
}

// ❌ Bad: Manual error propagation with match
fn process_user_data_bad(id: u32) -> Result<User, DatabaseError> {
    let raw_data = match fetch_user_from_db(id) {
        Ok(data) => data,
        Err(e) => return Err(e),
    };

    let parsed_data = match parse_user_data(&raw_data) {
        Ok(data) => data,
        Err(e) => return Err(e),
    };

    match validate_user(parsed_data) {
        Ok(user) => Ok(user),
        Err(e) => Err(e),
    }
}
```

### Early Returns and Error Context

```rust
// ✅ Good: Early returns with context
fn authenticate_user(token: &str) -> Result<User, AuthError> {
    if token.is_empty() {
        return Err(AuthError::MissingToken);
    }

    let claims = decode_jwt(token)
        .map_err(|_| AuthError::InvalidToken)?;

    let user = find_user_by_id(claims.user_id)
        .ok_or(AuthError::UserNotFound)?;

    if !user.is_active {
        return Err(AuthError::UserDeactivated);
    }

    Ok(user)
}
```

### Modern Error Handling with thiserror and anyhow

```rust
// ✅ Good: Using thiserror for error definition
use thiserror::Error;

#[derive(Error, Debug)]
enum ServiceError {
    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Authentication error: {0}")]
    Auth(#[from] AuthError),

    #[error("Rate limit exceeded: {max_requests} requests per {time_window} seconds")]
    RateLimit { max_requests: u32, time_window: u32 },
}

// ✅ Good: Using anyhow for applications
use anyhow::{Context, Result};

fn process_config_file(path: &str) -> Result<Config> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path))?;

    let config: Config = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse config file: {}", path))?;

    Ok(config)
}
```

### Error Handling Comparison with Other Languages

| Concept           | Rust              | Go                                  | Java/C#                  | JavaScript/TypeScript          | Python                    |
|-------------------|-------------------|-------------------------------------|--------------------------|--------------------------------|---------------------------|
| Error Type        | `Result<T, E>`    | Multiple return values with error   | Exceptions               | Exceptions / Promise rejection | Exceptions                |
| Error Propagation | `?` operator      | `if err != nil { return nil, err }` | `try/catch` with rethrow | `try/catch` or promise chains  | `try/except` with reraise |
| Custom Errors     | Enum variants     | Custom error types                  | Exception subclasses     | Custom Error classes           | Exception subclasses      |
| Type Safety       | Compiler enforced | Partial                             | Not enforced             | Optional with TypeScript       | Not enforced              |

---

## Iterators

### Prefer Iterator Methods Over Manual Loops

```rust
// ✅ Good: Use iterator methods
let numbers = vec![1, 2, 3, 4, 5];

// Filter and transform
let even_squares: Vec<i32> = numbers
.iter()
.filter( | & & x| x % 2 == 0)
.map( | & x| x * x)
.collect();

// Find operations
let first_large = numbers
.iter()
.find( | & & x| x > 3);

// Aggregations
let sum: i32 = numbers.iter().sum();
let product: i32 = numbers.iter().product();

// ❌ Bad: Manual loop implementation
let mut even_squares_bad = Vec::new();
for x in & numbers {
if x % 2 == 0 {
even_squares_bad.push(x * x);
}
}

// ❌ Bad: Inefficient loops with multiple iterations
let mut filtered = Vec::new();
for x in & numbers {
if x % 2 == 0 {
filtered.push( * x);
}
}

let mut squares = Vec::new();
for x in & filtered {
squares.push(x * x);
}
```

### Advanced Iterator Patterns

```rust
// ✅ Good: Chain iterators
let users = vec![
    User { name: "Alice".to_string(), age: 30 },
    User { name: "Bob".to_string(), age: 25 },
];

let names: Vec<String> = users
.iter()
.filter( | user| user.age > = 25)
.map( | user| user.name.clone())
.chain(std::iter::once("Admin".to_string()))
.collect();

// ✅ Good: Use enumerate for index access
for (index, item) in items.iter().enumerate() {
println ! ("Item {} at position {}", item, index);
}

// ✅ Good: Partition data
let (adults, minors): (Vec<_ >, Vec<_ > ) = people
.into_iter()
.partition( | person| person.age > = 18);

// ❌ Bad: Manual index tracking
let mut index = 0;
for item in & items {
println!("Item {} at position {}", item, index);
index += 1;
}
```

### Iterator Adapters and Consumers

```rust
// ✅ Good: Lazy evaluation with adapters
let numbers = vec![1, 2, 3, 4, 5];

// These operations don't execute until collected
let iter = numbers
.iter()
.map( | x| {
println ! ("Processing: {}", x); // Will not print until collected
x * 2
})
.filter( | x| x % 2 == 0);

// Consumption triggers evaluation
let results: Vec<_ > = iter.collect();

// ✅ Good: Short-circuiting operations
let has_even = numbers.iter().any( | & x| {
println ! ("Checking {}", x); // Only prints until first even number
x % 2 == 0
});

// ✅ Good: Using zip to pair iterators
let a = [1, 2, 3];
let b = [4, 5, 6];
let pairs: Vec<_ > = a.iter().zip(b.iter()).collect(); // [(1, 4), (2, 5), (3, 6)]
```

### Custom Iterators

```rust
// ✅ Good: Implement Iterator trait
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

// Usage
for num in Counter::new(5) {
println ! ("{}", num); // Prints 0, 1, 2, 3, 4
}

// ✅ Good: Creating iterators with itertools
use itertools::Itertools;

// Combinations
let items = vec![1, 2, 3];
for combo in items.iter().combinations(2) {
println ! ("{:?}", combo); // [1, 2], [1, 3], [2, 3]
}

// Windowing
let values = vec![1, 2, 3, 4, 5];
for window in values.windows(3) {
println ! ("{:?}", window); // [1, 2, 3], [2, 3, 4], [3, 4, 5]
}
```

### Iterators vs. Loops Comparison

| Operation             | Iterator Approach             | Loop Approach                 | Benefits of Iterators         |
|-----------------------|-------------------------------|-------------------------------|-------------------------------|
| Filtering             | `.filter(condition)`          | `if condition { ... }`        | Composable, declarative, lazy |
| Transformation        | `.map(transform)`             | Manual push to new collection | Cleaner intent, chainable     |
| Aggregation           | `.fold(init, op)` or `.sum()` | Manual accumulation           | Declarative, less error-prone |
| Finding items         | `.find(predicate)`            | Loop with early return        | Clearer intent, reusable      |
| Combining collections | `.chain(other)`               | Multiple loops                | Seamless composition          |
| Parallel processing   | `.par_iter()` (with rayon)    | Complex thread management     | Simple parallelism            |

### Iterators in Other Languages Comparison

| Feature          | Rust                     | C++                            | Java                      | JavaScript          | Python              |
|------------------|--------------------------|--------------------------------|---------------------------|---------------------|---------------------|
| Lazy evaluation  | Yes                      | Yes (C++20)                    | Sometimes                 | Yes                 | Yes                 |
| Method chaining  | `.iter().map().filter()` | `.begin() ... end()` or ranges | `stream().map().filter()` | `.map().filter()`   | No native chaining  |
| Performance      | Zero-cost abstraction    | Template-based, efficient      | Boxing overhead           | Dynamic, slower     | Dynamic, slower     |
| Short-circuiting | Automatic                | Manual                         | Yes with streams          | Yes                 | Yes                 |
| Custom iterators | `impl Iterator`          | Iterator classes               | `Iterator` interface      | Generator functions | Generator functions |

---

## Ownership & Borrowing

### Borrowing Best Practices

```rust
// ✅ Good: Take references when you don't need ownership
fn print_user_info(user: &User) {
    println!("Name: {}, Email: {}", user.name, user.email);
}

// ✅ Good: Return borrowed data when possible
fn get_first_name<'a>(full_name: &'a str) -> &'a str {
    full_name.split_whitespace().next().unwrap_or("")
}

// ✅ Good: Use mutable references for in-place modifications
fn normalize_email(email: &mut String) {
    *email = email.to_lowercase();
}

// ❌ Bad: Taking ownership when a reference would suffice
fn print_user_info_bad(user: User) { // Takes ownership unnecessarily
    println!("Name: {}, Email: {}", user.name, user.email);
}

// ❌ Bad: Cloning when borrowing would work
fn get_username(user: &User) -> String {
    user.name.clone() // Unnecessary clone if caller just needs to read the name
}
```

### Ownership Transfer Patterns

```rust
// ✅ Good: Builder pattern with ownership transfer
struct User {
    name: String,
    email: String,
    age: Option<u32>,
}

impl User {
    fn new(name: String, email: String) -> Self {
        User { name, email, age: None }
    }

    fn with_age(mut self, age: u32) -> Self {
        self.age = Some(age);
        self
    }
}

// Usage
let user = User::new("Alice".to_string(), "alice@example.com".to_string())
.with_age(30);

// ✅ Good: Clone when necessary, but prefer borrowing
fn process_users(users: &[User]) -> Vec<String> {
    users.iter()
        .map(|user| user.name.clone()) // Clone only the needed part
        .collect()
}

// ❌ Bad: Inefficient ownership transfer
fn extract_usernames_bad(users: Vec<User>) -> Vec<String> { // Takes ownership of the entire Vec
    let mut names = Vec::with_capacity(users.len());
    for user in users { // Consumes users
        names.push(user.name);
    }
    names
}

// ✅ Better: Preserve original collection with borrowing
fn extract_usernames_good(users: &[User]) -> Vec<String> {
    users.iter()
        .map(|user| user.name.clone())
        .collect()
}
```

### Move Semantics

```rust
// ✅ Good: Understanding move semantics
let s1 = String::from("hello");
let s2 = s1; // s1 is moved to s2, s1 is no longer valid

// ✅ Good: Explicit cloning when a copy is needed
let s1 = String::from("hello");
let s2 = s1.clone(); // Now both s1 and s2 are valid

// ❌ Bad: Trying to use moved values
let s1 = String::from("hello");
let s2 = s1;
println!("{}", s1); // Error: value used here after move

// ✅ Good: Copy types don't move
let x = 5;
let y = x; // x is copied, not moved
println!("x = {}, y = {}", x, y); // Both are valid
```

### Lifetime Annotations

```rust
// ✅ Good: Explicit lifetimes when needed
struct UserSession<'a> {
    user: &'a User,
    expires_at: SystemTime,
}

impl<'a> UserSession<'a> {
    fn new(user: &'a User, duration: Duration) -> Self {
        UserSession {
            user,
            expires_at: SystemTime::now() + duration,
        }
    }

    fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }
}

// ✅ Good: Multiple lifetime parameters
fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() > y.len() { x } else { y }
}

// ❌ Bad: Unnecessarily complex lifetimes
fn simple_function<'a, 'b>(x: &'a str, y: &'b str) -> &'a str {
    // When you're just returning the first parameter
    // there's no need for two lifetime parameters
    x
}

// ✅ Better: Simplified lifetimes
fn simple_function_better<'a>(x: &'a str, _y: &str) -> &'a str {
    x
}
```

### RAII (Resource Acquisition Is Initialization)

```rust
// ✅ Good: Resources are cleaned up when they go out of scope
fn process_file() -> Result<(), io::Error> {
    let file = File::open("data.txt")?;
    // file is automatically closed when it goes out of scope

    // Even with early returns, cleanup still happens
    if some_condition() {
        return Ok(());
    }

    Ok(())
}

// ✅ Good: Custom drop behavior
struct Database {
    connection: Connection,
}

impl Drop for Database {
    fn drop(&mut self) {
        // Cleanup code runs when Database goes out of scope
        self.connection.close();
        println!("Database connection closed");
    }
}

// Usage
{
let db = Database::new();
// Use db...
} // db is dropped here, connection is closed automatically
```

### Ownership Patterns with Smart Pointers

```rust
// ✅ Good: Using Box<T> for heap allocation
struct LargeData {
    data: [u8; 1_000_000],
}

fn process_large_data() {
    // Allocated on the heap to avoid stack overflow
    let boxed_data = Box::new(LargeData { data: [0; 1_000_000] });

    // Use boxed_data...
} // boxed_data is dropped, memory is freed

// ✅ Good: Shared ownership with Rc<T>
use std::rc::Rc;

fn shared_ownership() {
    let data = Rc::new(String::from("Shared data"));

    let reference1 = Rc::clone(&data); // Increments reference count
    let reference2 = Rc::clone(&data); // Increments reference count again

    println!("Reference count: {}", Rc::strong_count(&data)); // Prints 3
} // All Rc references are dropped, memory is freed when count reaches 0
```

### Ownership Model Comparison with Other Languages

| Concept              | Rust                            | C/C++                    | Java/C#                        | JavaScript/TypeScript  | Python                 |
|----------------------|---------------------------------|--------------------------|--------------------------------|------------------------|------------------------|
| Ownership model      | Ownership with borrowing        | Manual memory management | Garbage collection             | Garbage collection     | Garbage collection     |
| Memory safety        | Compile-time checking           | Manual (unsafe)          | Runtime safety                 | Runtime safety         | Runtime safety         |
| Resource management  | RAII (deterministic)            | RAII in C++              | Finalizers (non-deterministic) | Non-deterministic      | Context managers       |
| Move semantics       | Move by default, explicit clone | Move constructors (C++)  | Reference semantics            | Reference semantics    | Reference semantics    |
| Memory allocation    | Stack by default, explicit heap | Mixed, manual            | Heap for objects               | Heap                   | Heap                   |
| Performance overhead | Minimal                         | None                     | GC pauses                      | GC pauses              | GC pauses              |
| Concurrency safety   | Enforced by compiler            | Manual synchronization   | Manual synchronization         | Manual synchronization | Manual synchronization |

---

## Option & Result Patterns

### Option Handling

```rust
// ✅ Good: Use combinators instead of match
fn get_user_display_name(user: &User) -> String {
    user.nickname
        .as_ref()
        .unwrap_or(&user.name)
        .to_string()
}

// ✅ Good: Chain Option operations
fn process_config(config: &Config) -> Option<ProcessedConfig> {
    config.database_url
        .as_ref()
        .and_then(|url| parse_database_url(url))
        .map(|parsed| ProcessedConfig::new(parsed))
}

// ✅ Good: Use ok_or for Option to Result conversion
fn find_user_by_email(email: &str) -> Result<User, UserError> {
    users_database
        .find_by_email(email)
        .ok_or(UserError::NotFound)
}

// ❌ Bad: Excessive unwrapping
fn process_config_bad(config: &Config) -> Option<ProcessedConfig> {
    if config.database_url.is_none() {
        return None;
    }

    let url = config.database_url.as_ref().unwrap();
    let parsed = parse_database_url(url);

    if parsed.is_none() {
        return None;
    }

    Some(ProcessedConfig::new(parsed.unwrap()))
}

// ❌ Bad: Using unwrap in production code
fn get_admin_email() -> String {
    let admin = users_database.find_by_role("admin").unwrap(); // Panics if no admin
    admin.email
}
```

### Option Patterns

```rust
// ✅ Good: Pattern matching with Option
fn describe_number(n: Option<i32>) -> String {
    match n {
        None => "No number provided".to_string(),
        Some(0) => "Zero".to_string(),
        Some(n) if n > 0 => "Positive".to_string(),
        Some(_) => "Negative".to_string(),
    }
}

// ✅ Good: if let for simple cases
fn process_positive_number(n: Option<i32>) -> Option<i32> {
    if let Some(val) = n {
        if val > 0 {
            return Some(val * 2);
        }
    }
    None
}

// ✅ Good: Use map_or and map_or_else for default values
fn get_display_name(user: &User) -> String {
    user.nickname.as_ref().map_or_else(
        || format!("{} {}", user.first_name, user.last_name),
        |nick| nick.to_string()
    )
}
```

### Advanced Option Combinators

```rust
// ✅ Good: Combine multiple Options
fn full_name(first: Option<&str>, last: Option<&str>) -> Option<String> {
    Some(format!("{} {}", first?, last?))
}

// ✅ Good: Fallbacks with or_else
fn get_configuration() -> Option<Config> {
    get_config_from_env()
        .or_else(|| get_config_from_file("config.json"))
        .or_else(|| get_config_from_file("default.json"))
}

// ✅ Good: Collection operations on Option
fn process_optional_values(values: &[Option<i32>]) -> i32 {
    values
        .iter()
        .filter_map(|opt| opt.map(|val| val * 2))
        .sum()
}

// ✅ Good: Use Option methods instead of reimplementing them
fn first_even_squared(numbers: &[i32]) -> Option<i32> {
    numbers.iter()
        .find(|&&n| n % 2 == 0)
        .map(|&n| n * n)
}
```

### Result Combinators

```rust
// ✅ Good: Chain Result operations
fn authenticate_and_authorize(token: &str, resource: &str) -> Result<User, AuthError> {
    validate_token(token)
        .and_then(|claims| find_user(claims.user_id))
        .and_then(|user| authorize_access(&user, resource).map(|_| user))
}

// ✅ Good: Use map for transformations
fn get_user_age_category(user_id: u32) -> Result<AgeCategory, UserError> {
    find_user(user_id)
        .map(|user| match user.age {
            0..=17 => AgeCategory::Minor,
            18..=64 => AgeCategory::Adult,
            _ => AgeCategory::Senior,
        })
}

// ✅ Good: Combine multiple Results
fn create_user_profile(name: String, email: String, age: u32) -> Result<UserProfile, ValidationError> {
    let validated_name = validate_name(&name)?;
    let validated_email = validate_email(&email)?;
    let validated_age = validate_age(age)?;

    Ok(UserProfile {
        name: validated_name,
        email: validated_email,
        age: validated_age,
    })
}

// ❌ Bad: Manual Result handling
fn authenticate_and_authorize_bad(token: &str, resource: &str) -> Result<User, AuthError> {
    let claims = match validate_token(token) {
        Ok(c) => c,
        Err(e) => return Err(e),
    };

    let user = match find_user(claims.user_id) {
        Ok(u) => u,
        Err(e) => return Err(e),
    };

    match authorize_access(&user, resource) {
        Ok(_) => Ok(user),
        Err(e) => Err(e),
    }
}
```

### Error Conversion Patterns

```rust
// ✅ Good: Using the ? operator with different error types
fn process_user_input(input: &str) -> Result<ProcessedData, ProcessError> {
    let parsed = parse_input(input)
        .map_err(|e| ProcessError::ParseError(e.to_string()))?;

    let validated = validate_data(&parsed)
        .map_err(|e| ProcessError::ValidationError(e))?;

    let result = transform_data(validated)
        .map_err(ProcessError::TransformError)?;

    Ok(result)
}

// ✅ Good: Using From trait for automatic error conversion
#[derive(Debug)]
enum AppError {
    Database(DatabaseError),
    Validation(ValidationError),
    External(ExternalApiError),
}

impl From<DatabaseError> for AppError {
    fn from(error: DatabaseError) -> Self {
        AppError::Database(error)
    }
}

impl From<ValidationError> for AppError {
    fn from(error: ValidationError) -> Self {
        AppError::Validation(error)
    }
}

// Usage with ? operator - automatic conversion happens
fn process_data() -> Result<Data, AppError> {
    let record = database::fetch_record()?; // DatabaseError -> AppError
    let validated = validation::validate(record)?; // ValidationError -> AppError
    Ok(validated)
}
```

### Option & Result Interoperation

```rust
// ✅ Good: Converting between Option and Result
fn find_user(id: UserId) -> Result<User, UserError> {
    // Convert Option to Result with custom error
    database.get_user(id).ok_or(UserError::UserNotFound)
}

fn get_admin() -> Option<User> {
    // Convert Result to Option, discarding the error
    find_user_by_role("admin").ok()
}

// ✅ Good: Collecting Results
fn validate_all_users(users: Vec<User>) -> Result<Vec<ValidUser>, ValidationError> {
    users.into_iter()
        .map(validate_user)
        .collect() // Collects into Result<Vec<_>, _>
}

// ✅ Good: Fallbacks with or and or_else
fn get_setting(key: &str) -> Result<String, ConfigError> {
    get_from_environment(key)
        .or_else(|_| get_from_config_file(key))
        .or_else(|_| get_default(key))
}
```

### Option & Result Comparison with Other Languages

| Concept          | Rust                               | C++                       | Java                          | JavaScript/TypeScript               | Python                 |
|------------------|------------------------------------|---------------------------|-------------------------------|-------------------------------------|------------------------|
| Optional values  | `Option<T>`                        | `std::optional<T>`        | `Optional<T>`                 | `T \| null \| undefined`            | `None` or special case |
| Error handling   | `Result<T, E>`                     | Exceptions or error codes | Exceptions                    | Exceptions, Promise rejection       | Exceptions             |
| Composition      | Combinators like `map`, `and_then` | Limited                   | `map`, `flatMap` in Optional  | Promise chaining, Optional chaining | Limited                |
| Null safety      | Compile-time enforced              | Manual (unsafe)           | Runtime safety                | Runtime safety                      | Runtime safety         |
| Pattern matching | Full support                       | Limited (C++17)           | Switch expressions (Java 17+) | Limited                             | Limited                |

### Nullability Comparison: `Option<T>` vs. `null` in Other Languages

| Feature         | Rust's `Option<T>`         | Null References (Other Languages)         |
|-----------------|----------------------------|-------------------------------------------|
| Compiler checks | Yes, must handle None case | No, can forget null checks                |
| Type safety     | Explicit in type signature | Often implicit                            |
| Default values  | Explicit via `unwrap_or`   | Often error-prone                         |
| Composition     | Rich combinator API        | Limited, prone to null pointer exceptions |
| Documentation   | Self-documenting API       | Often needs comments                      |
| Performance     | Zero overhead abstraction  | Often requires runtime checks             |

---

## Struct & Enum Patterns

### Struct Design

```rust
// ✅ Good: Use builder pattern for complex construction
#[derive(Debug, Clone)]
struct DatabaseConfig {
    host: String,
    port: u16,
    database: String,
    username: String,
    password: String,
    pool_size: u32,
    timeout: Duration,
}

impl DatabaseConfig {
    fn builder() -> DatabaseConfigBuilder {
        DatabaseConfigBuilder::default()
    }
}

#[derive(Default)]
struct DatabaseConfigBuilder {
    host: Option<String>,
    port: Option<u16>,
    database: Option<String>,
    username: Option<String>,
    password: Option<String>,
    pool_size: Option<u32>,
    timeout: Option<Duration>,
}

impl DatabaseConfigBuilder {
    fn host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    fn build(self) -> Result<DatabaseConfig, String> {
        Ok(DatabaseConfig {
            host: self.host.ok_or("Host is required")?,
            port: self.port.unwrap_or(5432),
            database: self.database.ok_or("Database name is required")?,
            username: self.username.ok_or("Username is required")?,
            password: self.password.ok_or("Password is required")?,
            pool_size: self.pool_size.unwrap_or(10),
            timeout: self.timeout.unwrap_or(Duration::from_secs(30)),
        })
    }
}

// ❌ Bad: Complex constructor with many parameters
impl DatabaseConfig {
    fn new_bad(
        host: String,
        port: u16,
        database: String,
        username: String,
        password: String,
        pool_size: u32,
        timeout: Duration,
    ) -> Self {
        DatabaseConfig {
            host,
            port,
            database,
            username,
            password,
            pool_size,
            timeout,
        }
    }
}
```

### Struct Composition

```rust
// ✅ Good: Composition over inheritance
struct User {
    id: UserId,
    name: String,
    email: Email,
    address: Address,
    preferences: UserPreferences,
}

struct Address {
    street: String,
    city: String,
    country: String,
    postal_code: String,
}

struct UserPreferences {
    theme: Theme,
    notifications_enabled: bool,
    language: Language,
}

// ✅ Good: Newtype pattern for type safety
struct UserId(String);
struct Email(String);

impl Email {
    fn new(email: String) -> Result<Self, ValidationError> {
        if !is_valid_email(&email) {
            return Err(ValidationError::InvalidEmail);
        }
        Ok(Email(email))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

// ❌ Bad: Exposing implementation details
struct UserBad {
    id_str: String, // Should use UserId type
    raw_email: String, // Should use Email type with validation
    street_address: String, // Should compose with Address type
    city: String,
    country: String,
    postal_code: String,
    theme: String, // Should use enum
    notifications: bool,
    language_code: String, // Should use enum
}
```

### Field Visibility and Methods

```rust
// ✅ Good: Private fields with public accessors
pub struct BankAccount {
    id: AccountId,
    owner: UserId,
    balance: Decimal,
    account_type: AccountType,
    created_at: DateTime<Utc>,
    // Private field - not accessible outside the module
    transaction_count: u32,
}

impl BankAccount {
    // Public constructor
    pub fn new(id: AccountId, owner: UserId, account_type: AccountType) -> Self {
        BankAccount {
            id,
            owner,
            balance: Decimal::ZERO,
            account_type,
            created_at: Utc::now(),
            transaction_count: 0,
        }
    }

    // Public accessor
    pub fn balance(&self) -> Decimal {
        self.balance
    }

    // Public method with validation
    pub fn deposit(&mut self, amount: Decimal) -> Result<(), AccountError> {
        if amount <= Decimal::ZERO {
            return Err(AccountError::InvalidAmount);
        }

        self.balance += amount;
        self.transaction_count += 1;
        Ok(())
    }
}

// ❌ Bad: Public fields that should be private
pub struct BankAccountBad {
    pub id: AccountId,
    pub owner: UserId,
    pub balance: Decimal, // Should be private with accessor
    pub account_type: AccountType,
    pub created_at: DateTime<Utc>,
    pub transaction_count: u32, // Should be private
}
```

### Enum Patterns

```rust
// ✅ Good: Use enums for state management
#[derive(Debug, Clone, PartialEq)]
enum OrderStatus {
    Pending,
    Processing { started_at: SystemTime },
    Shipped { tracking_number: String, carrier: String },
    Delivered { delivered_at: SystemTime },
    Cancelled { reason: String },
}

impl OrderStatus {
    fn is_active(&self) -> bool {
        !matches!(self, OrderStatus::Delivered { .. } | OrderStatus::Cancelled { .. })
    }

    fn can_be_cancelled(&self) -> bool {
        matches!(self, OrderStatus::Pending | OrderStatus::Processing { .. })
    }
}

// ✅ Good: Use enums for error types
#[derive(Debug, thiserror::Error)]
enum PaymentError {
    #[error("Insufficient funds: required {required}, available {available}")]
    InsufficientFunds { required: Decimal, available: Decimal },

    #[error("Invalid payment method: {method}")]
    InvalidPaymentMethod { method: String },

    #[error("Payment processor error: {0}")]
    ProcessorError(String),

    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),
}

// ❌ Bad: String constants instead of enums
struct OrderBad {
    status: String, // "pending", "processing", "shipped", "delivered", "cancelled"
    // ... other fields
}

// Hard to enforce valid status values, easy to make typos
fn is_order_active_bad(order: &OrderBad) -> bool {
    order.status != "delivered" && order.status != "cancelled"
}
```

### Pattern Matching with Enums

```rust
// ✅ Good: Exhaustive pattern matching
fn describe_order_status(status: &OrderStatus) -> String {
    match status {
        OrderStatus::Pending => "Your order is pending".to_string(),
        OrderStatus::Processing { started_at } => {
            format!("Your order is being processed since {}", humanize_time(started_at))
        }
        OrderStatus::Shipped { tracking_number, carrier } => {
            format!("Your order has been shipped via {}. Tracking number: {}",
                    carrier, tracking_number)
        }
        OrderStatus::Delivered { delivered_at } => {
            format!("Your order was delivered at {}", humanize_time(delivered_at))
        }
        OrderStatus::Cancelled { reason } => {
            format!("Your order was cancelled. Reason: {}", reason)
        }
    }
}

// ✅ Good: Combine match with if guards
fn get_order_status_color(status: &OrderStatus) -> Color {
    match status {
        OrderStatus::Pending => Color::BLUE,
        OrderStatus::Processing { started_at } if started_at.elapsed().as_hours() > 24 => {
            // Processing for more than 24 hours
            Color::ORANGE
        }
        OrderStatus::Processing { .. } => Color::GREEN,
        OrderStatus::Shipped { .. } => Color::PURPLE,
        OrderStatus::Delivered { .. } => Color::GREEN,
        OrderStatus::Cancelled { .. } => Color::RED,
    }
}

// ❌ Bad: Non-exhaustive pattern matching without catch-all
fn describe_order_status_bad(status: &OrderStatus) -> String {
    match status {
        OrderStatus::Pending => "Your order is pending".to_string(),
        OrderStatus::Delivered { .. } => "Your order was delivered".to_string(),
        // Missing other variants - will fail to compile without `_` arm
    }
}
```

### Tagged Unions vs. Class Hierarchies

```rust
// ✅ Good: Enum as a tagged union
enum Shape {
    Circle { radius: f64 },
    Rectangle { width: f64, height: f64 },
    Triangle { base: f64, height: f64 },
}

impl Shape {
    fn area(&self) -> f64 {
        match self {
            Shape::Circle { radius } => std::f64::consts::PI * radius * radius,
            Shape::Rectangle { width, height } => width * height,
            Shape::Triangle { base, height } => 0.5 * base * height,
        }
    }

    fn perimeter(&self) -> f64 {
        match self {
            Shape::Circle { radius } => 2.0 * std::f64::consts::PI * radius,
            Shape::Rectangle { width, height } => 2.0 * (width + height),
            Shape::Triangle { .. } => {
                // For simplicity, we're not calculating triangle perimeter here
                unimplemented!("Triangle perimeter not implemented")
            }
        }
    }
}

// Usage
let shapes = vec![
    Shape::Circle { radius: 5.0 },
    Shape::Rectangle { width: 4.0, height: 3.0 },
    Shape::Triangle { base: 4.0, height: 3.0 },
];

for shape in & shapes {
println!("Area: {}", shape.area());
}
```

### Struct & Enum Comparison with Other Languages

| Feature          | Rust                     | C/C++                           | Java/C#                     | JavaScript/TypeScript    | Python            |
|------------------|--------------------------|---------------------------------|-----------------------------|--------------------------|-------------------|
| Data structures  | Struct (value semantics) | Struct/Class                    | Class (reference semantics) | Class/Object (reference) | Class (reference) |
| Enums            | Rich, data-carrying      | Simple (C) or class-based (C++) | Simple or class-based       | Limited (TypeScript)     | Limited           |
| Pattern matching | Exhaustive, powerful     | Limited                         | Switch, instanceof          | Limited                  | Limited           |
| Null safety      | Option<T>                | Nullable references             | Nullable references         | null/undefined           | None              |
| Immutability     | Default for variables    | const                           | final                       | const/readonly           | Limited           |
| Inheritance      | No, composition instead  | Yes                             | Yes                         | Yes                      | Yes               |
| Methods          | impl blocks              | Inside class/struct             | Inside class                | Inside class             | Inside class      |

### Data Modeling Approaches: Rust vs. Object-Oriented Languages

| Concept          | Rust Approach                         | OOP Approach                     |
|------------------|---------------------------------------|----------------------------------|
| Type hierarchies | Enums with variants                   | Class inheritance                |
| Polymorphism     | Trait objects, enums                  | Virtual methods, interfaces      |
| Encapsulation    | Module system, privacy                | Private fields and methods       |
| Extension        | Trait implementation                  | Inheritance or extension methods |
| Composition      | Struct fields                         | Object composition               |
| Immutability     | Immutable by default                  | Mutable by default               |
| Method dispatch  | Static by default, dynamic via traits | Often dynamic by default         |
| State management | Explicit state enums                  | Often implicit state via fields  |

---


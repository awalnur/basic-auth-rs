// Common utility functions and helpers

use chrono::{DateTime, Utc, Duration};
use regex::Regex;
use std::collections::HashMap;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

// Using OnceLock instead of lazy_static for better performance and no external dependency
static EMAIL_REGEX: OnceLock<Regex> = OnceLock::new();
static PASSWORD_PATTERNS: OnceLock<HashMap<&'static str, Regex>> = OnceLock::new();
static USERNAME_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_email_regex() -> &'static Regex {
    EMAIL_REGEX.get_or_init(|| {
        Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap()
    })
}

fn get_password_patterns() -> &'static HashMap<&'static str, Regex> {
    PASSWORD_PATTERNS.get_or_init(|| {
        let mut patterns = HashMap::new();
        patterns.insert("uppercase", Regex::new(r"[A-Z]").unwrap());
        patterns.insert("lowercase", Regex::new(r"[a-z]").unwrap());
        patterns.insert("digit", Regex::new(r"\d").unwrap());
        patterns.insert("special", Regex::new("[!@#$%^&*(),.?\":{}|<>]").unwrap());
        patterns
    })
}

fn get_username_regex() -> &'static Regex {
    USERNAME_REGEX.get_or_init(|| {
        Regex::new(r"^[a-zA-Z0-9_]{3,30}$").unwrap()
    })
}

/// String validation utilities
pub mod validation {
    use super::*;

    /// Validates email format
    ///
    /// # Arguments
    ///
    /// * `email` - Email string to validate
    ///
    /// # Returns
    ///
    /// * `bool` - True if email format is valid
    ///
    /// # Example
    ///
    /// ```rust
    /// use basic_auth::common::utils::validation::is_valid_email;
    ///
    /// assert!(is_valid_email("user@example.com"));
    /// assert!(!is_valid_email("invalid-email"));
    /// ```
    pub fn is_valid_email(email: &str) -> bool {
        if email.is_empty() || email.len() > 254 {
            return false;
        }
        get_email_regex().is_match(email)
    }

    /// Validates username format
    ///
    /// # Arguments
    ///
    /// * `username` - Username string to validate
    ///
    /// # Returns
    ///
    /// * `bool` - True if username format is valid
    pub fn is_valid_username(username: &str) -> bool {
        get_username_regex().is_match(username)
    }

    /// Password strength assessment
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum PasswordStrength {
        Weak,
        Fair,
        Good,
        Strong,
        VeryStrong,
    }

    impl PasswordStrength {
        /// Gets numeric score for the strength level
        pub fn score(&self) -> u32 {
            match self {
                PasswordStrength::Weak => 1,
                PasswordStrength::Fair => 2,
                PasswordStrength::Good => 3,
                PasswordStrength::Strong => 4,
                PasswordStrength::VeryStrong => 5,
            }
        }

        /// Gets color code for UI display
        pub fn color(&self) -> &'static str {
            match self {
                PasswordStrength::Weak => "#e74c3c",      // Red
                PasswordStrength::Fair => "#f39c12",      // Orange
                PasswordStrength::Good => "#f1c40f",      // Yellow
                PasswordStrength::Strong => "#2ecc71",    // Green
                PasswordStrength::VeryStrong => "#27ae60", // Dark Green
            }
        }
    }

    /// Password validation result
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PasswordValidation {
        pub is_valid: bool,
        pub strength: PasswordStrength,
        pub score: u32,
        pub feedback: Vec<String>,
        pub requirements_met: HashMap<String, bool>,
        pub estimated_crack_time: String,
    }

    /// Validates password strength and requirements
    ///
    /// # Arguments
    ///
    /// * `password` - Password to validate
    /// * `min_length` - Minimum required length (default: 8)
    ///
    /// # Returns
    ///
    /// * `PasswordValidation` - Detailed validation result
    ///
    /// # Example
    ///
    /// ```rust
    /// use basic_auth::common::utils::validation::validate_password;
    ///
    /// let result = validate_password("MySecureP@ss123", 8);
    /// assert!(result.is_valid);
    /// ```
    pub fn validate_password(password: &str, min_length: usize) -> PasswordValidation {
        let mut score = 0u32;
        let mut feedback = Vec::new();
        let mut requirements = HashMap::new();

        // Length check
        let length_ok = password.len() >= min_length;
        requirements.insert("min_length".to_string(), length_ok);
        if length_ok {
            score += 25;
        } else {
            feedback.push(format!("Password must be at least {} characters long", min_length));
        }

        // Character type checks
        for (name, pattern) in get_password_patterns().iter() {
            let has_pattern = pattern.is_match(password);
            requirements.insert(name.to_string(), has_pattern);
            if has_pattern {
                score += 15;
            } else {
                let requirement = match *name {
                    "uppercase" => "at least one uppercase letter",
                    "lowercase" => "at least one lowercase letter",
                    "digit" => "at least one digit",
                    "special" => "at least one special character",
                    _ => "unknown requirement",
                };
                feedback.push(format!("Password must contain {}", requirement));
            }
        }

        // Length bonus
        if password.len() >= 12 {
            score += 10;
        }
        if password.len() >= 16 {
            score += 10;
        }

        // Complexity bonus
        let unique_chars = password.chars().collect::<std::collections::HashSet<_>>().len();
        if unique_chars >= 8 {
            score += 5;
        }

        // Common password penalty
        if is_common_password(password) {
            score = score.saturating_sub(30);
            feedback.push("This is a commonly used password".to_string());
        }

        // Determine strength
        let strength = match score {
            0..=30 => PasswordStrength::Weak,
            31..=50 => PasswordStrength::Fair,
            51..=70 => PasswordStrength::Good,
            71..=90 => PasswordStrength::Strong,
            _ => PasswordStrength::VeryStrong,
        };

        let estimated_crack_time = estimate_crack_time(password, &strength);
        let is_valid = score >= 60 && length_ok; // Require at least "Good" strength

        PasswordValidation {
            is_valid,
            strength,
            score,
            feedback,
            requirements_met: requirements,
            estimated_crack_time,
        }
    }

    /// Checks if password is in common password list
    fn is_common_password(password: &str) -> bool {
        const COMMON_PASSWORDS: &[&str] = &[
            "password", "123456", "123456789", "qwerty", "abc123",
            "password123", "admin", "letmein", "welcome", "monkey",
            "1234567890", "password1", "123123", "test", "user"
        ];

        let lower_password = password.to_lowercase();
        COMMON_PASSWORDS.iter().any(|&common| lower_password.contains(common))
    }

    /// Estimates password crack time based on strength
    fn estimate_crack_time(password: &str, strength: &PasswordStrength) -> String {
        let charset_size = calculate_charset_size(password);
        // println!("Charset size: {} {}", charset_size, password.len());
        // let combinations = charset_size.powi(password.len() as u32);
        let password_length = password.len();

        println!("Charset size: {} {}", charset_size, password_length);

        // Hitung jumlah kombinasi secara bertahap agar aman dari overflow
        let mut combinations: f64 = 1.0;
        for _ in 0..password_length {
            combinations *= charset_size as f64;
        }


        // Assume 1 billion guesses per second
        let seconds = combinations / 2.0 / 1_000_000_000.0;

        match strength {
            PasswordStrength::Weak => "Less than 1 hour".to_string(),
            PasswordStrength::Fair => format!("{} hours", (seconds / 3600.0).ceil() as u64),
            PasswordStrength::Good => format!("{} days", (seconds / 86400.0).ceil() as u64),
            PasswordStrength::Strong => format!("{} years", (seconds / 31_536_000.0).ceil() as u64),
            PasswordStrength::VeryStrong => "Centuries".to_string(),
        }
    }

    /// Calculates charset size for password
    fn calculate_charset_size(password: &str) -> u32 {
        let mut size = 0;

        if password.chars().any(|c| c.is_ascii_lowercase()) {
            size += 26;
        }
        if password.chars().any(|c| c.is_ascii_uppercase()) {
            size += 26;
        }
        if password.chars().any(|c| c.is_ascii_digit()) {
            size += 10;
        }
        if password.chars().any(|c| "!@#$%^&*(),.?\":{}|<>".contains(c)) {
            size += 22;
        }

        size.max(1) // Ensure at least 1
    }
}

/// Date and time utilities
pub mod datetime {
    use super::*;

    /// Gets current UTC timestamp
    pub fn now_utc() -> DateTime<Utc> {
        Utc::now()
    }

    /// Adds duration to timestamp
    pub fn add_duration(timestamp: DateTime<Utc>, duration: Duration) -> DateTime<Utc> {
        timestamp + duration
    }

    /// Checks if timestamp is expired (before now)
    pub fn is_expired(timestamp: DateTime<Utc>) -> bool {
        timestamp < Utc::now()
    }

    /// Gets duration until expiry
    pub fn time_until_expiry(expiry: DateTime<Utc>) -> Option<Duration> {
        let now = Utc::now();
        if expiry > now {
            Some(expiry - now)
        } else {
            None
        }
    }

    /// Formats timestamp for logging/display
    pub fn format_timestamp(timestamp: DateTime<Utc>) -> String {
        timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    }

    /// Creates timestamp from unix seconds
    pub fn from_unix_timestamp(seconds: i64) -> Option<DateTime<Utc>> {
        DateTime::from_timestamp(seconds, 0)
    }

    /// Converts timestamp to unix seconds
    pub fn to_unix_timestamp(timestamp: DateTime<Utc>) -> i64 {
        timestamp.timestamp()
    }

    /// Creates expiry timestamp (now + duration)
    pub fn create_expiry(duration: Duration) -> DateTime<Utc> {
        Utc::now() + duration
    }

    /// Common durations for convenience
    pub mod durations {
        use super::Duration;

        pub fn minutes(mins: i64) -> Duration {
            Duration::minutes(mins)
        }

        pub fn hours(hours: i64) -> Duration {
            Duration::hours(hours)
        }

        pub fn days(days: i64) -> Duration {
            Duration::days(days)
        }

        pub fn weeks(weeks: i64) -> Duration {
            Duration::weeks(weeks)
        }

        // Common auth-related durations
        pub fn access_token_duration() -> Duration {
            Duration::minutes(15) // 15 minutes
        }

        pub fn refresh_token_duration() -> Duration {
            Duration::days(30) // 30 days
        }

        pub fn email_verification_duration() -> Duration {
            Duration::hours(24) // 24 hours
        }

        pub fn password_reset_duration() -> Duration {
            Duration::hours(1) // 1 hour
        }
    }
}

/// ID generation utilities
pub mod ids {
    use super::*;

    /// Generates a new UUID v4
    pub fn generate_uuid() -> Uuid {
        Uuid::new_v4()
    }

    /// Generates a new UUID as string
    pub fn generate_uuid_string() -> String {
        Uuid::new_v4().to_string()
    }

    /// Generates a random alphanumeric string of specified length
    pub fn generate_random_string(length: usize) -> String {
        use rand::{distributions::Alphanumeric, Rng};
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect()
    }

    /// Generates a numeric code of specified length
    pub fn generate_numeric_code(length: usize) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..length)
            .map(|_| rng.gen_range(0..10).to_string())
            .collect()
    }

    /// Generates a secure token for password reset, email verification, etc.
    pub fn generate_secure_token() -> String {
        use rand::{distributions::Alphanumeric, Rng};
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect()
    }

    /// Validates UUID format
    pub fn is_valid_uuid(uuid_str: &str) -> bool {
        Uuid::parse_str(uuid_str).is_ok()
    }
}

/// String manipulation utilities
pub mod strings {
    use regex::Regex;

    /// Truncates string to max length with ellipsis
    pub fn truncate_with_ellipsis(s: &str, max_len: usize) -> String {
        if s.len() <= max_len {
            s.to_string()
        } else if max_len <= 3 {
            "...".to_string()
        } else {
            format!("{}...", &s[..max_len - 3])
        }
    }

    /// Sanitizes string for safe logging (removes sensitive patterns)
    pub fn sanitize_for_logging(s: &str) -> String {
        let mut sanitized = s.to_string();

        // Email addresses
        if let Ok(email_regex) = Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b") {
            sanitized = email_regex.replace_all(&sanitized, "[EMAIL]").to_string();
        }

        // Potential passwords (8+ chars with mixed case and numbers)
        // Look for word boundaries or whitespace to isolate potential passwords
        if let Ok(password_regex) = Regex::new(r"\b[A-Za-z\d#@$!%*?&]{8,}\b") {
            sanitized = password_regex.replace_all(&sanitized, |caps: &regex::Captures| {
                let pw = &caps[0];
                let has_upper = pw.chars().any(|c| c.is_ascii_uppercase());
                let has_lower = pw.chars().any(|c| c.is_ascii_lowercase());
                let has_digit = pw.chars().any(|c| c.is_ascii_digit());
                if has_upper && has_lower && has_digit {
                    "[PASSWORD]".to_string()
                } else {
                    pw.to_string()
                }
            }).to_string();
        }
        // UUIDs
        if let Ok(uuid_regex) = Regex::new(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b") {
            sanitized = uuid_regex.replace_all(&sanitized, "[UUID]").to_string();
        }

        // Credit card numbers (basic pattern)
        if let Ok(cc_regex) = Regex::new(r"\b(?:\d{4}[-\s]?){3}\d{4}\b") {
            sanitized = cc_regex.replace_all(&sanitized, "[CREDIT_CARD]").to_string();
        }

        // Social Security Numbers (US format)
        if let Ok(ssn_regex) = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b") {
            sanitized = ssn_regex.replace_all(&sanitized, "[SSN]").to_string();
        }

        sanitized
    }

    /// Converts string to title case
    pub fn to_title_case(s: &str) -> String {
        s.split_whitespace()
            .map(|word| {
                let mut chars = word.chars();
                match chars.next() {
                    None => String::new(),
                    Some(first) => first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase(),
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Removes extra whitespace and normalizes spacing
    pub fn normalize_whitespace(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Converts string to slug format (lowercase, hyphens, no special chars)
    pub fn to_slug(s: &str) -> String {
        s.to_lowercase()
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '-' })
            .collect::<String>()
            .split('-')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Masks sensitive data showing only first and last few characters
    pub fn mask_sensitive_data(s: &str, show_chars: usize) -> String {
        if s.len() <= show_chars * 2 {
            "*".repeat(s.len())
        } else {
            format!(
                "{}{}{}",
                &s[..show_chars],
                "*".repeat(s.len() - show_chars * 2),
                &s[s.len() - show_chars..]
            )
        }
    }
}

/// Collection utilities
pub mod collections {
    use std::collections::HashMap;
    use std::hash::Hash;

    /// Groups items by a key function
    pub fn group_by<T, K, F>(items: Vec<T>, key_fn: F) -> HashMap<K, Vec<T>>
    where
        K: Hash + Eq,
        F: Fn(&T) -> K,
    {
        let mut groups: HashMap<K, Vec<T>> = HashMap::new();
        for item in items {
            let key = key_fn(&item);
            groups.entry(key).or_insert_with(Vec::new).push(item);
        }
        groups
    }

    /// Checks if all items in collection satisfy a predicate
    pub fn all<T, F>(items: &[T], predicate: F) -> bool
    where
        F: Fn(&T) -> bool,
    {
        items.iter().all(predicate)
    }

    /// Checks if any item in collection satisfies a predicate
    pub fn any<T, F>(items: &[T], predicate: F) -> bool
    where
        F: Fn(&T) -> bool,
    {
        items.iter().any(predicate)
    }

    /// Finds the first item that satisfies a predicate
    pub fn find_first<T, F>(items: &[T], predicate: F) -> Option<&T>
    where
        F: Fn(&T) -> bool,
    {
        items.iter().find(|&item| predicate(item))
    }

    /// Partitions collection into two based on predicate
    pub fn partition<T, F>(items: Vec<T>, predicate: F) -> (Vec<T>, Vec<T>)
    where
        F: Fn(&T) -> bool,
    {
        let mut left = Vec::new();
        let mut right = Vec::new();

        for item in items {
            if predicate(&item) {
                left.push(item);
            } else {
                right.push(item);
            }
        }

        (left, right)
    }

    /// Deduplicates items while preserving order
    pub fn deduplicate<T>(items: Vec<T>) -> Vec<T>
    where
        T: PartialEq + Clone,
    {
        let mut result = Vec::new();
        for item in items {
            if !result.contains(&item) {
                result.push(item);
            }
        }
        result
    }
}

/// Configuration and environment utilities
pub mod config {
    use std::env;
    use std::str::FromStr;

    /// Gets environment variable with default value
    pub fn get_env_or_default(key: &str, default: &str) -> String {
        env::var(key).unwrap_or_else(|_| default.to_string())
    }

    /// Gets required environment variable or panics with helpful message
    pub fn get_required_env(key: &str) -> String {
        env::var(key).unwrap_or_else(|_| {
            panic!(
                "Required environment variable '{}' not set. Please check your .env file or environment configuration.",
                key
            )
        })
    }

    /// Gets environment variable as integer with default
    pub fn get_env_as_int(key: &str, default: i32) -> i32 {
        env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    /// Gets environment variable as boolean with default
    pub fn get_env_as_bool(key: &str, default: bool) -> bool {
        env::var(key)
            .ok()
            .and_then(|v| match v.to_lowercase().as_str() {
                "true" | "1" | "yes" | "on" | "enabled" => Some(true),
                "false" | "0" | "no" | "off" | "disabled" => Some(false),
                _ => None,
            })
            .unwrap_or(default)
    }

    /// Gets environment variable as generic type with default
    pub fn get_env_as<T>(key: &str, default: T) -> T
    where
        T: FromStr,
    {
        env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    /// Checks if running in development mode
    pub fn is_development() -> bool {
        matches!(
            get_env_or_default("ENVIRONMENT", "development").as_str(),
            "development" | "dev"
        )
    }

    /// Checks if running in production mode
    pub fn is_production() -> bool {
        matches!(
            get_env_or_default("ENVIRONMENT", "development").as_str(),
            "production" | "prod"
        )
    }

    /// Checks if running in test mode
    pub fn is_test() -> bool {
        matches!(
            get_env_or_default("ENVIRONMENT", "development").as_str(),
            "test" | "testing"
        )
    }

    /// Gets database URL with fallback logic
    pub fn get_database_url() -> String {
        // Try DATABASE_URL first, then construct from components
        if let Ok(url) = env::var("DATABASE_URL") {
            return url;
        }

        let host = get_env_or_default("DB_HOST", "localhost");
        let port = get_env_or_default("DB_PORT", "5432");
        let database = get_env_or_default("DB_NAME", "auth_db");
        let username = get_env_or_default("DB_USER", "postgres");
        let password = get_env_or_default("DB_PASSWORD", "password");

        format!("postgres://{}:{}@{}:{}/{}", username, password, host, port, database)
    }
}

/// Rate limiting utilities
pub mod rate_limit {
    use std::collections::HashMap;
    use std::time::{Duration, Instant};
    use std::sync::{Arc, Mutex};

    /// Simple in-memory rate limiter
    #[derive(Debug)]
    pub struct RateLimiter {
        requests: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
        max_requests: usize,
        window: Duration,
    }

    impl RateLimiter {
        /// Creates a new rate limiter
        pub fn new(max_requests: usize, window: Duration) -> Self {
            Self {
                requests: Arc::new(Mutex::new(HashMap::new())),
                max_requests,
                window,
            }
        }

        /// Checks if request is allowed for given key (e.g., IP address, user ID)
        pub fn is_allowed(&self, key: &str) -> bool {
            let mut requests = self.requests.lock().unwrap();
            let now = Instant::now();

            // Clean up old entries for this key
            let entry = requests.entry(key.to_string()).or_insert_with(Vec::new);
            entry.retain(|&timestamp| now.duration_since(timestamp) <= self.window);

            // Check if under limit
            if entry.len() < self.max_requests {
                entry.push(now);
                true
            } else {
                false
            }
        }

        /// Gets remaining requests for a key
        pub fn remaining_requests(&self, key: &str) -> usize {
            let mut requests = self.requests.lock().unwrap();
            let now = Instant::now();

            let entry = requests.entry(key.to_string()).or_insert_with(Vec::new);
            entry.retain(|&timestamp| now.duration_since(timestamp) <= self.window);

            self.max_requests.saturating_sub(entry.len())
        }

        /// Gets time until next request is allowed
        pub fn time_until_reset(&self, key: &str) -> Option<Duration> {
            let requests = self.requests.lock().unwrap();

            if let Some(entry) = requests.get(key) {
                if let Some(&oldest) = entry.first() {
                    let now = Instant::now();
                    let elapsed = now.duration_since(oldest);
                    if elapsed < self.window {
                        return Some(self.window - elapsed);
                    }
                }
            }

            None
        }
    }
}

/// Cryptographic utilities
pub mod crypto {
    /// Generates a cryptographically secure random token
    pub fn generate_crypto_token(length: usize) -> String {
        use rand::{rngs::OsRng, RngCore};

        let mut bytes = vec![0u8; length];
        OsRng.fill_bytes(&mut bytes);

        // Convert to base64url (URL-safe base64)
        base64::encode(bytes)
    }

    /// Generates a secure session ID
    pub fn generate_session_id() -> String {
        generate_crypto_token(32) // 256-bit entropy
    }

    /// Generates a CSRF token
    pub fn generate_csrf_token() -> String {
        generate_crypto_token(32)
    }

    /// Constant-time string comparison to prevent timing attacks
    pub fn constant_time_eq(a: &str, b: &str) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let a_bytes = a.as_bytes();
        let b_bytes = b.as_bytes();

        let mut result = 0u8;
        for i in 0..a_bytes.len() {
            result |= a_bytes[i] ^ b_bytes[i];
        }

        result == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_validation() {
        assert!(validation::is_valid_email("test@example.com"));
        assert!(validation::is_valid_email("user.name@domain.co.uk"));
        assert!(!validation::is_valid_email("invalid-email"));
        assert!(!validation::is_valid_email("@domain.com"));
        assert!(!validation::is_valid_email("user@"));
        assert!(!validation::is_valid_email("")); // Empty email
        assert!(!validation::is_valid_email(&"a".repeat(255))); // Too long
    }

    #[test]
    fn test_username_validation() {
        assert!(validation::is_valid_username("user123"));
        assert!(validation::is_valid_username("test_user"));
        assert!(!validation::is_valid_username("ab")); // too short
        assert!(!validation::is_valid_username("user-name")); // dash not allowed
        assert!(!validation::is_valid_username("user name")); // space not allowed
    }

    #[test]
    fn test_enhanced_password_validation() {
        let result = validation::validate_password("MySecureP@ss123", 8);
        assert!(result.is_valid);
        assert!(matches!(
            result.strength,
            validation::PasswordStrength::Strong | validation::PasswordStrength::VeryStrong
        ));
        assert!(!result.estimated_crack_time.is_empty());

        let weak_result = validation::validate_password("password", 8);
        assert!(!weak_result.is_valid);
        assert_eq!(weak_result.strength, validation::PasswordStrength::Weak);
    }

    #[test]
    fn test_string_utilities() {
        assert_eq!(strings::truncate_with_ellipsis("hello world", 8), "hello...");
        assert_eq!(strings::truncate_with_ellipsis("short", 10), "short");

        assert_eq!(strings::to_title_case("hello world"), "Hello World");
        assert_eq!(strings::normalize_whitespace("  hello   world  "), "hello world");
        assert_eq!(strings::to_slug("Hello World!"), "hello-world");

        assert_eq!(strings::mask_sensitive_data("1234567890", 2), "12******90");
    }

    #[test]
    fn test_sensitive_data_sanitization() {
        let input = "User1234@ email is john@example.com and password is SecurePass123";
        let sanitized = strings::sanitize_for_logging(input);
        println!("Sanitized: {}", sanitized);
        assert!(sanitized.contains("[EMAIL]"));
        assert!(sanitized.contains("[PASSWORD]"));
    }

    #[test]
    fn test_datetime_utilities() {
        let now = datetime::now_utc();
        let future = datetime::add_duration(now, datetime::durations::hours(1));

        assert!(!datetime::is_expired(future));
        assert!(datetime::time_until_expiry(future).is_some());

        let past = datetime::add_duration(now, datetime::durations::hours(-1));
        assert!(datetime::is_expired(past));
        assert!(datetime::time_until_expiry(past).is_none());
    }

    #[test]
    fn test_collections_utilities() {
        let numbers = vec![1, 2, 3, 4, 5, 3, 2];

        assert!(collections::all(&numbers, |&n| n > 0));
        assert!(!collections::all(&numbers, |&n| n > 3));

        assert!(collections::any(&numbers, |&n| n > 4));
        assert!(!collections::any(&numbers, |&n| n > 10));

        assert_eq!(collections::find_first(&numbers, |&n| n > 3), Some(&4));
        assert_eq!(collections::find_first(&numbers, |&n| n > 10), None);

        let deduped = collections::deduplicate(numbers);
        assert_eq!(deduped, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_rate_limiter() {
        use std::time::Duration;

        let limiter = rate_limit::RateLimiter::new(3, Duration::from_secs(60));

        // Should allow first 3 requests
        assert!(limiter.is_allowed("user1"));
        assert!(limiter.is_allowed("user1"));
        assert!(limiter.is_allowed("user1"));

        // Should deny 4th request
        assert!(!limiter.is_allowed("user1"));

        // Different user should be allowed
        assert!(limiter.is_allowed("user2"));
    }

    #[test]
    fn test_crypto_utilities() {
        let token1 = crypto::generate_crypto_token(32);
        let token2 = crypto::generate_crypto_token(32);

        assert_ne!(token1, token2);
        assert!(!token1.is_empty());

        let session_id = crypto::generate_session_id();
        assert!(!session_id.is_empty());

        // Test constant time comparison
        assert!(crypto::constant_time_eq("hello", "hello"));
        assert!(!crypto::constant_time_eq("hello", "world"));
        assert!(!crypto::constant_time_eq("hello", "hello2"));
    }
}

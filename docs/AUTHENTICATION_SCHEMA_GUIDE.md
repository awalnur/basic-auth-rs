# 🔐 Comprehensive Authentication Schema Guide

## Table of Contents

- [Overview](#overview)
- [Database Schema](#database-schema)
- [Authentication Flows](#authentication-flows)
- [Role-Based Access Control](#role-based-access-control)
- [Security Features](#security-features)
- [API Authentication](#api-authentication)
- [Social Login Integration](#social-login-integration)
- [Session Management](#session-management)
- [Security Scenarios](#security-scenarios)
- [Implementation Examples](#implementation-examples)
- [Best Practices](#best-practices)

## Overview

This authentication system provides a comprehensive, enterprise-grade user authentication and authorization solution
with multiple authentication methods, role-based access control, and advanced security features.

### Key Features

- 🔑 Multi-factor Authentication (2FA)
- 👥 Role-Based Access Control (RBAC)
- 🌐 Social Login Integration
- 📱 Session Management
- 🔒 Advanced Security Policies
- 📊 Comprehensive Audit Logging
- 🔌 API Key Management
- 🚨 Brute Force Protection

## Database Schema

### Core Tables

#### 1. Users Table (Extended)

```sql
-- Base user information
users
:
  - id (Primary Key)
  - username (Unique)
  - email (Unique)
  - password_hash
  - email_verified (Boolean)
  - is_active (Boolean)
  - created_at, updated_at
```

#### 2. User Profiles

```sql
-- Extended user information
user_profiles
:
  - id (Primary Key)
  - user_id (Foreign Key to users)
  - first_name, last_name
  - phone, date_of_birth
  - avatar_url, bio
  - timezone, language
  - created_at, updated_at
```

#### 3. Roles & Permissions System

```sql
-- Role definitions
roles
:
  - id (Primary Key)
  - name (Unique)
  - description
  - is_system_role (Boolean)
  - created_at, updated_at

-- Permission definitions
permissions:
  - id (Primary Key)
  - name (Unique)
  - description
  - resource, action
  - created_at

-- Role-Permission mapping
role_permissions:
  - role_id, permission_id
  - granted_at, granted_by

-- User-Role mapping
user_roles:
  - user_id, role_id
  - assigned_at, assigned_by
  - expires_at, is_active
```

#### 4. Security Tables

```sql
-- Account security settings
account_security
:
  - user_id (Foreign Key)
  - two_factor_enabled, two_factor_secret
  - backup_codes[]
  - account_locked, locked_until
  - failed_login_attempts
  - last_password_change, password_expires_at
  - force_password_change

-- Password history (prevent reuse)
password_history:
  - user_id, password_hash
  - created_at

-- Login attempt tracking
login_attempts:
  - email, ip_address, user_agent
  - success, failure_reason
  - attempted_at, user_id
```

## Authentication Flows

### 1. Standard Login Flow

```mermaid
graph TD
    A[User Enters Credentials] --> B{Validate Email/Password}
    B -->|Valid| C{Account Active?}
    B -->|Invalid| D[Log Failed Attempt]
    C -->|Yes| E{2FA Enabled?}
    C -->|No| F[Account Disabled Error]
    E -->|Yes| G[Request 2FA Code]
    E -->|No| H[Create Session]
    G --> I{Valid 2FA?}
    I -->|Yes| H
    I -->|No| D
    H --> J[Return JWT/Session Token]
    D --> K{Too Many Attempts?}
    K -->|Yes| L[Lock Account]
    K -->|No| M[Return Error]
```

**Detailed Steps:**

1. **Credential Validation**
   ```sql
   -- Check user credentials
   SELECT u.*, as.* FROM users u
   JOIN account_security as ON u.id = as.user_id
   WHERE u.email = $1 AND u.is_active = true;
   
   -- Verify password hash
   verify_password(input_password, stored_hash)
   ```

2. **Security Checks**
   ```sql
   -- Check if account is locked
   SELECT account_locked, locked_until FROM account_security
   WHERE user_id = $1 AND (account_locked = false OR locked_until < NOW());
   ```

3. **Session Creation**
   ```sql
   -- Create new session
   INSERT INTO user_sessions (user_id, session_token, refresh_token, 
                             ip_address, user_agent, expires_at)
   VALUES ($1, $2, $3, $4, $5, $6);
   ```

### 2. Two-Factor Authentication Flow

```mermaid
graph TD
    A[Primary Auth Success] --> B[Generate TOTP Secret]
    B --> C[Send 2FA Code]
    C --> D[User Enters Code]
    D --> E{Verify TOTP?}
    E -->|Valid| F[Complete Login]
    E -->|Invalid| G{Backup Code?}
    G -->|Yes| H{Valid Backup?}
    G -->|No| I[2FA Failed]
    H -->|Yes| J[Mark Backup Used]
    H -->|No| I
    J --> F
```

**Implementation:**

```sql
-- Enable 2FA for user
UPDATE account_security
SET two_factor_enabled = true,
    two_factor_secret  = $1,
    backup_codes       = $2
WHERE user_id = $3;

-- Verify 2FA during login
SELECT two_factor_secret, backup_codes
FROM account_security
WHERE user_id = $1
  AND two_factor_enabled = true;
```

### 3. Social Login Flow (OAuth)

```mermaid
graph TD
    A[User Clicks Social Login] --> B[Redirect to Provider]
    B --> C[User Authorizes]
    C --> D[Provider Returns Code]
    D --> E[Exchange Code for Token]
    E --> F[Fetch User Info]
    F --> G{User Exists?}
    G -->|Yes| H[Link Accounts]
    G -->|No| I[Create New User]
    H --> J[Create Session]
    I --> J
```

**OAuth Configuration:**

```sql
-- OAuth provider setup
INSERT INTO oauth_providers (name, client_id, client_secret,
                             authorization_url, token_url, user_info_url)
VALUES ('google', 'client_id', 'client_secret',
        'https://accounts.google.com/o/oauth2/v2/auth',
        'https://oauth2.googleapis.com/token',
        'https://www.googleapis.com/oauth2/v2/userinfo');

-- Link user account
INSERT INTO user_oauth_connections (user_id, provider_id, provider_user_id,
                                    access_token, refresh_token)
VALUES ($1, $2, $3, $4, $5);
```

## Role-Based Access Control

### Default Roles Hierarchy

```
super_admin (All Permissions)
├── admin (System Management)
├── moderator (Content Management)
├── editor (Content Creation)
├── support (User Support)
├── api_client (API Access)
├── user (Basic Access)
└── guest (Read-only)
```

### Permission Categories

#### 1. User Management

```sql
-- User permissions
'users.create'     -- Create new users
'users.read'       -- View user information
'users.update'     -- Update user information
'users.delete'     -- Delete users
'users.list'       -- List all users
'users.activate'   -- Activate/deactivate users
'users.impersonate' -- Impersonate other users
```

#### 2. Content Management

```sql
-- Content permissions
'content.create'   -- Create content
'content.read'     -- Read content
'content.update'   -- Update content
'content.delete'   -- Delete content
'content.publish'  -- Publish content
'content.moderate' -- Moderate content
```

#### 3. System Administration

```sql
-- System permissions
'system.admin'     -- System administration
'system.backup'    -- Perform backups
'system.settings'  -- Manage settings
'system.maintenance' -- Maintenance mode
'system.logs'      -- Access system logs
```

#### 4. API Access

```sql
-- API permissions
'api.access'       -- Basic API access
'api.keys.create'  -- Create API keys
'api.keys.manage'  -- Manage API keys
'api.users.read'   -- API: Read user data
'api.users.write'  -- API: Write user data
```

### Permission Checking

```sql
-- Check if user has permission
SELECT COUNT(*) > 0 as has_permission
FROM users u
         JOIN user_roles ur ON u.id = ur.user_id
         JOIN role_permissions rp ON ur.role_id = rp.role_id
         JOIN permissions p ON rp.permission_id = p.id
WHERE u.id = $1
  AND p.name = $2
  AND ur.is_active = true;
```

## Security Features

### 1. Account Lockout Policy

```sql
-- Increment failed attempts
UPDATE account_security
SET failed_login_attempts = failed_login_attempts + 1
WHERE user_id = $1;

-- Lock account after threshold
UPDATE account_security
SET account_locked = true,
    locked_until   = NOW() + INTERVAL '30 minutes'
WHERE user_id = $1 AND failed_login_attempts >= 5;
```

### 2. Password Policy

- Minimum 8 characters
- Must contain uppercase, lowercase, numbers
- Cannot reuse last 5 passwords
- Expires every 90 days (configurable)

```sql
-- Store password in history
INSERT INTO password_history (user_id, password_hash)
VALUES ($1, $2);

-- Check password reuse
SELECT COUNT(*)
FROM password_history
WHERE user_id = $1
  AND password_hash = $2;
```

### 3. Session Security

- JWT tokens with short expiration
- Refresh token rotation
- Device fingerprinting
- IP address validation

```sql
-- Session validation
SELECT *
FROM user_sessions
WHERE session_token = $1
  AND is_active = true
  AND expires_at > NOW()
  AND ip_address = $2;
```

## API Authentication

### 1. JWT Bearer Tokens

```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 2. API Keys

```sql
-- Create API key
INSERT INTO api_keys (user_id, name, key_hash, permissions, expires_at)
VALUES ($1, $2, $3, $4, $5);

-- Validate API key
SELECT ak.*, u.*
FROM api_keys ak
         JOIN users u ON ak.user_id = u.id
WHERE ak.key_hash = $1
  AND ak.is_active = true
  AND ak.expires_at > NOW();
```

### 3. Rate Limiting

Based on user role and API key permissions:

- **guest**: 100 requests/hour
- **user**: 1000 requests/hour
- **api_client**: 10000 requests/hour
- **admin**: Unlimited

## Social Login Integration

### Supported Providers

1. **Google OAuth 2.0**
2. **GitHub OAuth**
3. **Facebook Login**
4. **LinkedIn OAuth**

### Implementation Flow

```rust
// Example OAuth flow
async fn handle_oauth_callback(provider: String, code: String) -> Result<User> {
    // 1. Exchange code for access token
    let token = exchange_code_for_token(provider, code).await?;

    // 2. Fetch user info from provider
    let user_info = fetch_user_info(provider, token.access_token).await?;

    // 3. Find or create user
    let user = find_or_create_user(user_info).await?;

    // 4. Create session
    let session = create_session(user.id).await?;

    Ok(user)
}
```

## Session Management

### Session Types

1. **Web Sessions** - Browser-based with cookies
2. **Mobile Sessions** - Long-lived JWT tokens
3. **API Sessions** - Short-lived tokens with refresh

### Session Data

```sql
-- Session information stored
user_sessions
:
  - session_token (Primary identifier)
  - refresh_token (For token renewal)
  - ip_address (Security validation)
  - user_agent (Device identification)
  - device_fingerprint (Additional security)
  - last_activity (For cleanup)
  - expires_at (Token expiration)
```

### Session Operations

```sql
-- Refresh session
UPDATE user_sessions
SET last_activity = NOW(),
    expires_at    = NOW() + INTERVAL '24 hours'
WHERE session_token = $1;

-- Terminate session
UPDATE user_sessions
SET is_active = false
WHERE user_id = $1
  AND id = $2;

-- Cleanup expired sessions
DELETE
FROM user_sessions
WHERE expires_at < NOW() - INTERVAL '7 days';
```

## Security Scenarios

### 1. Brute Force Attack

**Detection:**

```sql
-- Monitor failed attempts
SELECT COUNT(*) as attempts
FROM login_attempts
WHERE ip_address = $1
  AND attempted_at > NOW() - INTERVAL '1 hour'
  AND success = false;
```

**Response:**

- Temporary IP blocking
- Account lockout
- Email notification
- CAPTCHA requirement

### 2. Account Takeover

**Prevention:**

- 2FA requirement for sensitive actions
- Email verification for changes
- Device recognition
- Suspicious activity alerts

### 3. Session Hijacking

**Protection:**

- IP address validation
- User agent verification
- Session token rotation
- Concurrent session limits

### 4. Password Attacks

**Mitigation:**

- Strong password requirements
- Password history tracking
- Regular password expiration
- Breach monitoring integration

## Implementation Examples

### 1. User Registration

```rust
pub async fn register_user(
    username: String,
    email: String,
    password: String,
) -> Result<User> {
    // 1. Validate input
    validate_registration_data(&username, &email, &password)?;

    // 2. Check if user exists
    if user_exists(&email).await? {
        return Err("User already exists");
    }

    // 3. Hash password
    let password_hash = hash_password(&password)?;

    // 4. Create user
    let user = create_user(username, email, password_hash).await?;

    // 5. Send verification email
    send_verification_email(&user).await?;

    // 6. Log audit event
    log_audit_event("user.registered", user.id, None).await?;

    Ok(user)
}
```

### 2. Login with 2FA

```rust
pub async fn login_with_2fa(
    email: String,
    password: String,
    totp_code: Option<String>,
) -> Result<Session> {
    // 1. Validate credentials
    let user = validate_credentials(&email, &password).await?;

    // 2. Check if 2FA is enabled
    let security = get_account_security(user.id).await?;

    if security.two_factor_enabled {
        // 3. Verify TOTP code
        let code = totp_code.ok_or("2FA code required")?;
        verify_totp_code(&security.two_factor_secret, &code)?;
    }

    // 4. Create session
    let session = create_session(user.id).await?;

    // 5. Reset failed attempts
    reset_failed_login_attempts(user.id).await?;

    // 6. Log successful login
    log_login_attempt(email, true, None).await?;

    Ok(session)
}
```

### 3. Permission Checking Middleware

```rust
pub async fn check_permission(
    user_id: i32,
    required_permission: &str,
) -> Result<bool> {
    let has_permission = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) > 0 as has_permission
        FROM users u
        JOIN user_roles ur ON u.id = ur.user_id
        JOIN role_permissions rp ON ur.role_id = rp.role_id
        JOIN permissions p ON rp.permission_id = p.id
        WHERE u.id = $1 AND p.name = $2 AND ur.is_active = true
        "#,
        user_id,
        required_permission
    )
        .fetch_one(&pool)
        .await?;

    Ok(has_permission.unwrap_or(false))
}
```

## Best Practices

### 1. API Security Best Practices

#### 🔐 Authentication & Authorization

```rust
// Always validate API keys/tokens
async fn validate_api_request(req: &Request) -> Result<User> {
    let auth_header = req.headers().get("Authorization")
        .ok_or("Missing Authorization header")?;

    if let Some(token) = auth_header.strip_prefix("Bearer ") {
        validate_jwt_token(token).await
    } else if let Some(api_key) = auth_header.strip_prefix("ApiKey ") {
        validate_api_key(api_key).await
    } else {
        Err("Invalid authorization format")
    }
}
```

**Best Practices:**

- ✅ **Always use HTTPS** - Never transmit credentials over HTTP
- ✅ **Implement proper token validation** - Verify signature, expiration, and issuer
- ✅ **Use short-lived access tokens** - 15-30 minutes max
- ✅ **Implement refresh token rotation** - Generate new refresh tokens on use
- ✅ **Validate API keys securely** - Hash API keys, never store plain text

#### 🚦 Rate Limiting & Throttling

```rust
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::time::{SystemTime, Duration};

pub struct RateLimiter {
    requests: RwLock<HashMap<String, Vec<SystemTime>>>,
    limits: HashMap<String, (u32, Duration)>, // (requests, window)
}

impl RateLimiter {
    pub async fn check_rate_limit(&self, identifier: &str, role: &str) -> Result<bool> {
        let (limit, window) = self.limits.get(role)
            .unwrap_or(&(100, Duration::from_secs(3600))); // Default: 100/hour

        let mut requests = self.requests.write().await;
        let now = SystemTime::now();

        // Clean old requests
        let user_requests = requests.entry(identifier.to_string())
            .or_insert_with(Vec::new);
        user_requests.retain(|&time| now.duration_since(time).unwrap() < *window);

        if user_requests.len() >= *limit as usize {
            return Ok(false); // Rate limit exceeded
        }

        user_requests.push(now);
        Ok(true)
    }
}

// Rate limits by role
const RATE_LIMITS: &[(&str, u32, u64)] = &[
    ("guest", 50, 3600),        // 50 requests/hour
    ("user", 1000, 3600),       // 1000 requests/hour
    ("premium", 5000, 3600),    // 5000 requests/hour
    ("api_client", 10000, 3600), // 10000 requests/hour
    ("admin", 50000, 3600),     // 50000 requests/hour
];
```

**Rate Limiting Strategy:**

- ✅ **Different limits per role** - Higher limits for premium users
- ✅ **Multiple time windows** - Per minute, hour, day limits
- ✅ **IP-based limiting** - Prevent abuse from single IP
- ✅ **Graceful degradation** - Return 429 with retry-after header

#### 🛡️ Input Validation & Sanitization

```rust
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

#[derive(Debug, Deserialize, Validate)]
pub struct CreateUserRequest {
    #[validate(length(min = 3, max = 50))]
    #[validate(regex = "USERNAME_REGEX")]
    pub username: String,

    #[validate(email)]
    pub email: String,

    #[validate(length(min = 8, max = 128))]
    #[validate(custom = "validate_password_strength")]
    pub password: String,

    #[validate(length(max = 100))]
    pub first_name: Option<String>,
}

fn validate_password_strength(password: &str) -> Result<(), ValidationError> {
    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_digit(10));
    let has_special = password.chars().any(|c| "!@#$%^&*()".contains(c));

    if has_uppercase && has_lowercase && has_digit && has_special {
        Ok(())
    } else {
        Err(ValidationError::new("weak_password"))
    }
}

// Middleware for input validation
async fn validate_input<T: Validate>(payload: Json<T>) -> Result<Json<T>, ApiError> {
    payload.validate().map_err(|e| ApiError::ValidationError(e))?;
    Ok(payload)
}
```

**Input Validation Rules:**

- ✅ **Validate all inputs** - Never trust client data
- ✅ **Use strong typing** - Leverage Rust's type system
- ✅ **Sanitize HTML/SQL** - Prevent injection attacks
- ✅ **Limit payload size** - Prevent DoS attacks
- ✅ **Validate file uploads** - Check file types and sizes

#### 🔍 Security Headers

```rust
use axum::response::Response;
use axum::http::HeaderMap;

async fn security_headers_middleware(
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    // Security headers
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());
    headers.insert("X-XSS-Protection", "1; mode=block".parse().unwrap());
    headers.insert("Strict-Transport-Security",
                   "max-age=31536000; includeSubDomains".parse().unwrap());
    headers.insert("Content-Security-Policy",
                   "default-src 'self'".parse().unwrap());
    headers.insert("Referrer-Policy", "strict-origin-when-cross-origin".parse().unwrap());

    // API-specific headers
    headers.insert("X-API-Version", "v1".parse().unwrap());
    headers.insert("X-RateLimit-Limit", "1000".parse().unwrap());
    headers.insert("X-RateLimit-Remaining", "999".parse().unwrap());

    response
}
```

#### 🗃️ Data Protection & Privacy

```rust
use serde_json::Value;

// Response filtering to hide sensitive data
pub fn filter_sensitive_data(user_role: &str, mut data: Value) -> Value {
    match user_role {
        "admin" | "super_admin" => data, // Full access
        "user" => {
            // Remove sensitive fields for regular users
            if let Value::Object(ref mut map) = data {
                map.remove("password_hash");
                map.remove("two_factor_secret");
                map.remove("backup_codes");
                map.remove("internal_notes");
            }
            data
        }
        "guest" => {
            // Very limited data for guests
            if let Value::Object(ref mut map) = data {
                let allowed_fields = vec!["id", "username", "created_at"];
                map.retain(|k, _| allowed_fields.contains(&k.as_str()));
            }
            data
        }
        _ => Value::Null, // Unknown role, return nothing
    }
}

// Data encryption for sensitive fields
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};

pub struct DataEncryption {
    cipher: Aes256Gcm,
}

impl DataEncryption {
    pub fn new(key: &[u8; 32]) -> Self {
        let key = Key::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        Self { cipher }
    }

    pub fn encrypt(&self, data: &str) -> Result<String, Box<dyn std::error::Error>> {
        let nonce = Nonce::from_slice(b"unique nonce"); // Use random nonce in production
        let ciphertext = self.cipher.encrypt(nonce, data.as_bytes())?;
        Ok(base64::encode(ciphertext))
    }

    pub fn decrypt(&self, encrypted_data: &str) -> Result<String, Box<dyn std::error::Error>> {
        let nonce = Nonce::from_slice(b"unique nonce");
        let ciphertext = base64::decode(encrypted_data)?;
        let plaintext = self.cipher.decrypt(nonce, ciphertext.as_ref())?;
        Ok(String::from_utf8(plaintext)?)
    }
}
```

#### 📊 API Monitoring & Logging

```rust
use tracing::{info, warn, error};
use serde_json::json;

// Comprehensive API logging
pub async fn api_logging_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let start_time = std::time::Instant::now();
    let method = request.method().clone();
    let uri = request.uri().clone();
    let user_agent = request.headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    // Extract user info if authenticated
    let user_id = extract_user_id(&request).await.unwrap_or(-1);

    let response = next.run(request).await;
    let status = response.status();
    let duration = start_time.elapsed();

    // Log API access
    info!(
        target: "api_access",
        method = %method,
        uri = %uri,
        status = %status.as_u16(),
        duration_ms = duration.as_millis(),
        user_id = user_id,
        ip_address = %addr.ip(),
        user_agent = user_agent,
        "API request processed"
    );

    // Log suspicious activities
    if status.as_u16() >= 400 {
        warn!(
            target: "api_security",
            method = %method,
            uri = %uri,
            status = %status.as_u16(),
            ip_address = %addr.ip(),
            user_id = user_id,
            "API error response"
        );
    }

    // Store in audit log for critical endpoints
    if is_critical_endpoint(&uri) {
        store_audit_log(AuditLog {
            user_id: Some(user_id),
            action: format!("{} {}", method, uri),
            ip_address: Some(addr.ip()),
            user_agent: Some(user_agent.to_string()),
            status_code: status.as_u16(),
            duration_ms: duration.as_millis() as i64,
        }).await;
    }

    response
}

// Alert on suspicious patterns
pub fn detect_suspicious_activity(logs: &[ApiLog]) -> Vec<SecurityAlert> {
    let mut alerts = Vec::new();

    // High error rate from single IP
    let error_rate = logs.iter()
        .filter(|log| log.status_code >= 400)
        .count() as f64 / logs.len() as f64;

    if error_rate > 0.5 {
        alerts.push(SecurityAlert {
            alert_type: "high_error_rate".to_string(),
            severity: "medium".to_string(),
            message: format!("High error rate detected: {:.2}%", error_rate * 100.0),
        });
    }

    // Brute force detection
    let failed_logins = logs.iter()
        .filter(|log| log.uri.contains("/login") && log.status_code == 401)
        .count();

    if failed_logins > 10 {
        alerts.push(SecurityAlert {
            alert_type: "brute_force_attempt".to_string(),
            severity: "high".to_string(),
            message: format!("Possible brute force attack: {} failed login attempts", failed_logins),
        });
    }

    alerts
}
```

#### 🔒 API Key Management

```rust
use rand::Rng;
use sha2::{Sha256, Digest};

pub struct ApiKeyManager {
    db: Database,
}

impl ApiKeyManager {
    // Generate secure API key
    pub fn generate_api_key() -> (String, String) {
        let key: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        (key, hash) // Return (plain_key, hashed_key)
    }

    // Create API key with permissions
    pub async fn create_api_key(
        &self,
        user_id: i32,
        name: String,
        permissions: Vec<String>,
        expires_days: Option<i32>,
    ) -> Result<String> {
        let (plain_key, key_hash) = Self::generate_api_key();
        let expires_at = expires_days.map(|days|
            chrono::Utc::now() + chrono::Duration::days(days as i64)
        );

        sqlx::query!(
            r#"
            INSERT INTO api_keys (user_id, name, key_hash, permissions, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            user_id,
            name,
            key_hash,
            &permissions,
            expires_at
        )
            .execute(&self.db.pool)
            .await?;

        Ok(plain_key) // Return only once, never store plain key
    }

    // Validate API key with permissions
    pub async fn validate_api_key(
        &self,
        key: &str,
        required_permission: &str,
    ) -> Result<Option<User>> {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let key_hash = format!("{:x}", hasher.finalize());

        let result = sqlx::query!(
            r#"
            SELECT ak.user_id, ak.permissions, u.username, u.email
            FROM api_keys ak
            JOIN users u ON ak.user_id = u.id
            WHERE ak.key_hash = $1 
              AND ak.is_active = true 
              AND (ak.expires_at IS NULL OR ak.expires_at > NOW())
              AND u.is_active = true
            "#,
            key_hash
        )
            .fetch_optional(&self.db.pool)
            .await?;

        if let Some(row) = result {
            // Check if API key has required permission
            if row.permissions.contains(&required_permission.to_string()) {
                // Update last used timestamp
                sqlx::query!(
                    "UPDATE api_keys SET last_used_at = NOW() WHERE key_hash = $1",
                    key_hash
                )
                    .execute(&self.db.pool)
                    .await?;

                return Ok(Some(User {
                    id: row.user_id,
                    username: row.username,
                    email: row.email,
                }));
            }
        }

        Ok(None)
    }
}
```

#### 🧪 API Testing & Security Validation

```rust
#[cfg(test)]
mod security_tests {
    use super::*;

    #[tokio::test]
    async fn test_sql_injection_protection() {
        let malicious_input = "'; DROP TABLE users; --";
        let result = get_user_by_email(malicious_input).await;

        // Should not cause SQL injection
        assert!(result.is_err() || result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let limiter = RateLimiter::new();
        let identifier = "test_user";

        // Should allow normal usage
        for _ in 0..50 {
            assert!(limiter.check_rate_limit(identifier, "user").await.unwrap());
        }

        // Should block after limit
        for _ in 0..1000 {
            limiter.check_rate_limit(identifier, "user").await.unwrap();
        }

        assert!(!limiter.check_rate_limit(identifier, "user").await.unwrap());
    }

    #[tokio::test]
    async fn test_authentication_bypass() {
        let client = TestClient::new();

        // Should reject requests without authentication
        let response = client.get("/api/users").await;
        assert_eq!(response.status(), 401);

        // Should reject invalid tokens
        let response = client
            .get("/api/users")
            .header("Authorization", "Bearer invalid_token")
            .await;
        assert_eq!(response.status(), 401);
    }
}
```

### 2. Production Security Checklist

#### 🚀 Deployment Security

- [ ] **Environment Variables** - Never hardcode secrets
- [ ] **HTTPS Everywhere** - Use TLS 1.3 minimum
- [ ] **Security Headers** - Implement all security headers
- [ ] **CORS Configuration** - Restrict origins appropriately
- [ ] **Database Security** - Use connection pooling and encryption
- [ ] **Container Security** - Scan images for vulnerabilities
- [ ] **Network Security** - Use VPCs and security groups

#### 📋 Regular Security Audits

```bash
# Dependency vulnerability scanning
cargo audit

# Static analysis
cargo clippy -- -W clippy::all

# Security-focused linting
cargo deny check

# Runtime security monitoring
# - Monitor for unusual API patterns
# - Track authentication failures
# - Alert on privilege escalations
# - Monitor data access patterns
```

#### 🔄 Incident Response Plan

1. **Detection** - Automated monitoring and alerting
2. **Assessment** - Determine scope and impact
3. **Containment** - Isolate affected systems
4. **Eradication** - Remove threats and vulnerabilities
5. **Recovery** - Restore normal operations
6. **Lessons Learned** - Document and improve

### 3. API Documentation Security

```yaml
# OpenAPI security documentation
openapi: 3.0.0
security:
  - BearerAuth: [ ]
  - ApiKeyAuth: [ ]

components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
    ApiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key

paths:
  /api/users:
    get:
      security:
        - BearerAuth: [ ]
      parameters:
        - name: limit
          in: query
          schema:
            type: integer
            minimum: 1
            maximum: 100
      responses:
        '200':
          description: Success
        '401':
          description: Unauthorized
        '429':
          description: Rate limit exceeded
```

## Default Credentials

**⚠️ CRITICAL SECURITY WARNING: Change these immediately in production!**

### Development/Testing Credentials

- **Email**: `admin@example.com`
- **Username**: `admin`
- **Default Password Hash**: `$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewMw1xD5Nk6LxbSG`
- **Plain Password**: `admin123!` (for development only)
- **Role**: `super_admin`
- **Permissions**: All permissions granted (full system access)

### First Login Security Requirements

```sql
-- The admin account is configured to force password change
SELECT force_password_change
FROM account_security
WHERE user_id = 1;
-- Returns: true
```

**Required Actions After First Login:**

1. ✅ Change default password immediately
2. ✅ Enable two-factor authentication (2FA)
3. ✅ Update profile information
4. ✅ Review and configure system settings
5. ✅ Create additional admin users if needed
6. ✅ Disable or delete default account after creating new admins

### Production Setup Instructions

#### Step 1: Create New Super Admin

```bash
# Example using your API
curl -X POST https://your-api.com/api/admin/users \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "your_admin_username",
    "email": "your_admin@company.com",
    "password": "SecurePassword123!@#",
    "role": "super_admin"
  }'
```

#### Step 2: Secure Default Account

```sql
-- Option 1: Disable default account
UPDATE users
SET is_active = false
WHERE email = 'admin@example.com';

-- Option 2: Delete default account (after creating new admin)
DELETE
FROM users
WHERE email = 'admin@example.com';
```

#### Step 3: Configure 2FA for All Admins

```rust
// Enable 2FA programmatically
async fn enable_2fa_for_user(user_id: i32) -> Result<String> {
    let secret = generate_totp_secret();
    let backup_codes = generate_backup_codes(10);

    sqlx::query!(
        "UPDATE account_security SET 
         two_factor_enabled = true, 
         two_factor_secret = $1, 
         backup_codes = $2 
         WHERE user_id = $3",
        secret,
        &backup_codes,
        user_id
    ).execute(&pool).await?;

    Ok(secret)
}
```

## Advanced Configuration Guide

### 1. Environment Variables Setup

Create a `.env` file with production values:

```bash
# Database Configuration
DATABASE_URL=postgresql://username:password@localhost:5432/auth_db

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-minimum-32-characters
JWT_EXPIRATION=1800  # 30 minutes
REFRESH_TOKEN_EXPIRATION=604800  # 7 days

# Security Configuration
BCRYPT_ROUNDS=12
RATE_LIMIT_WINDOW=3600  # 1 hour
RATE_LIMIT_MAX_REQUESTS=1000

# Email Configuration (for verification/reset)
SMTP_HOST=smtp.your-provider.com
SMTP_PORT=587
SMTP_USERNAME=your-email@company.com
SMTP_PASSWORD=your-email-password
FROM_EMAIL=noreply@your-company.com

# OAuth Providers (replace with your credentials)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Security Headers
ALLOWED_ORIGINS=https://your-frontend.com,https://your-app.com
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_SAME_SITE=strict

# Monitoring & Logging
LOG_LEVEL=info
ENABLE_AUDIT_LOGGING=true
SECURITY_ALERT_EMAIL=security@your-company.com
```

### 2. Production Database Setup

#### Database Performance Optimization

```sql
-- Create additional indexes for better performance
CREATE INDEX CONCURRENTLY idx_users_active_email ON users(email) WHERE is_active = true;
CREATE INDEX CONCURRENTLY idx_sessions_user_active ON user_sessions(user_id, is_active, expires_at);
CREATE INDEX CONCURRENTLY idx_login_attempts_recent ON login_attempts(ip_address, attempted_at)
    WHERE attempted_at > NOW() - INTERVAL '24 hours';

-- Partitioning for large audit logs (optional)
CREATE TABLE audit_logs_2025 PARTITION OF audit_logs
    FOR VALUES FROM
(
    '2025-01-01'
) TO
(
    '2026-01-01'
);
```

#### Database Backup Strategy

```bash
#!/bin/bash
# automated_backup.sh - Add to cron job

DB_NAME="auth_db"
BACKUP_DIR="/backups/auth"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup
pg_dump -h localhost -U postgres $DB_NAME > "$BACKUP_DIR/auth_backup_$DATE.sql"

# Compress backup
gzip "$BACKUP_DIR/auth_backup_$DATE.sql"

# Keep only last 30 days of backups
find $BACKUP_DIR -name "auth_backup_*.sql.gz" -mtime +30 -delete

# Upload to cloud storage (optional)
aws s3 cp "$BACKUP_DIR/auth_backup_$DATE.sql.gz" s3://your-backup-bucket/
```

### 3. Monitoring & Alerting Setup

#### Health Check Endpoints

```rust
// Health check with authentication system status
#[derive(Serialize)]
pub struct HealthStatus {
    pub status: String,
    pub database: String,
    pub redis: String,
    pub authentication: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub version: String,
}

pub async fn health_check() -> Json<HealthStatus> {
    let db_status = check_database_connection().await;
    let redis_status = check_redis_connection().await;
    let auth_status = check_authentication_service().await;

    Json(HealthStatus {
        status: if db_status && redis_status && auth_status {
            "healthy".to_string()
        } else {
            "unhealthy".to_string()
        },
        database: if db_status { "connected" } else { "disconnected" }.to_string(),
        redis: if redis_status { "connected" } else { "disconnected" }.to_string(),
        authentication: if auth_status { "operational" } else { "degraded" }.to_string(),
        timestamp: chrono::Utc::now(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}
```

#### Prometheus Metrics

```rust
use prometheus::{Counter, Histogram, Gauge, register_counter, register_histogram, register_gauge};

lazy_static! {
    static ref LOGIN_ATTEMPTS: Counter = register_counter!(
        "auth_login_attempts_total", "Total number of login attempts"
    ).unwrap();
    
    static ref LOGIN_FAILURES: Counter = register_counter!(
        "auth_login_failures_total", "Total number of failed login attempts"
    ).unwrap();
    
    static ref ACTIVE_SESSIONS: Gauge = register_gauge!(
        "auth_active_sessions", "Number of currently active sessions"
    ).unwrap();
    
    static ref REQUEST_DURATION: Histogram = register_histogram!(
        "auth_request_duration_seconds", "Time spent processing authentication requests"
    ).unwrap();
}

// Usage in your handlers
pub async fn login_handler(/* params */) -> Result<Response> {
    let _timer = REQUEST_DURATION.start_timer();
    LOGIN_ATTEMPTS.inc();

    match authenticate_user(credentials).await {
        Ok(user) => {
            ACTIVE_SESSIONS.inc();
            // ... success logic
        }
        Err(_) => {
            LOGIN_FAILURES.inc();
            // ... failure logic
        }
    }
}
```

### 4. Security Hardening Checklist

#### Application Security

- [ ] **Input Validation**: All user inputs validated and sanitized
- [ ] **SQL Injection Protection**: Using parameterized queries only
- [ ] **XSS Prevention**: Proper output encoding and CSP headers
- [ ] **CSRF Protection**: CSRF tokens on state-changing operations
- [ ] **File Upload Security**: Type validation, size limits, virus scanning
- [ ] **Dependency Security**: Regular vulnerability scanning with `cargo audit`

#### Infrastructure Security

- [ ] **Network Security**: Private subnets, security groups, firewalls
- [ ] **TLS Configuration**: TLS 1.3 minimum, strong cipher suites
- [ ] **Server Hardening**: OS updates, unnecessary services disabled
- [ ] **Access Control**: SSH key authentication, no root access
- [ ] **Monitoring**: Intrusion detection, log analysis, alerting
- [ ] **Backup Security**: Encrypted backups, tested recovery procedures

#### Compliance & Governance

- [ ] **GDPR Compliance**: Data privacy controls, right to deletion
- [ ] **SOC 2 Requirements**: Access controls, monitoring, incident response
- [ ] **Password Policy**: Complexity, expiration, history tracking
- [ ] **Audit Logging**: Complete audit trail, log retention policies
- [ ] **Incident Response**: Documented procedures, regular testing
- [ ] **Security Training**: Team awareness, secure coding practices

### 5. Troubleshooting Guide

#### Common Issues & Solutions

**Issue 1: High Login Failure Rate**

```sql
-- Investigate failed login patterns
SELECT ip_address,
       COUNT(*)          as attempts,
       MIN(attempted_at) as first_attempt,
       MAX(attempted_at) as last_attempt
FROM login_attempts
WHERE success = false
  AND attempted_at > NOW() - INTERVAL '1 hour'
GROUP BY ip_address
ORDER BY attempts DESC;
```

**Solution**: Implement IP-based rate limiting and CAPTCHA

**Issue 2: Session Performance Problems**

```sql
-- Clean up expired sessions
DELETE
FROM user_sessions
WHERE expires_at < NOW() - INTERVAL '7 days';

-- Monitor session table size
SELECT schemaname,
       tablename,
       attname,
       n_distinct,
       most_common_vals
FROM pg_stats
WHERE tablename = 'user_sessions';
```

**Solution**: Implement session cleanup job and consider Redis for session storage

**Issue 3: Database Connection Issues**

```rust
// Connection pool monitoring
pub async fn check_db_pool_health(pool: &PgPool) -> bool {
    match sqlx::query("SELECT 1").fetch_one(pool).await {
        Ok(_) => true,
        Err(e) => {
            error!("Database health check failed: {}", e);
            false
        }
    }
}
```

**Solution**: Configure proper connection pool settings and implement retry logic

### 6. Performance Optimization

#### Database Query Optimization

```sql
-- Analyze slow queries
SELECT query,
       calls,
       total_time,
       mean_time, rows
FROM pg_stat_statements
ORDER BY mean_time DESC
    LIMIT 10;

-- Optimize frequently used queries
EXPLAIN
ANALYZE
SELECT u.*, p.first_name, p.last_name
FROM users u
         LEFT JOIN user_profiles p ON u.id = p.user_id
WHERE u.email = 'user@example.com';
```

#### Caching Strategy

```rust
use redis::AsyncCommands;

pub struct AuthCache {
    redis: redis::Client,
}

impl AuthCache {
    // Cache user permissions for faster authorization
    pub async fn cache_user_permissions(&self, user_id: i32, permissions: Vec<String>) -> Result<()> {
        let mut conn = self.redis.get_async_connection().await?;
        let key = format!("user:{}:permissions", user_id);
        let value = serde_json::to_string(&permissions)?;

        conn.setex(key, 300, value).await?; // Cache for 5 minutes
        Ok(())
    }

    pub async fn get_cached_permissions(&self, user_id: i32) -> Result<Option<Vec<String>>> {
        let mut conn = self.redis.get_async_connection().await?;
        let key = format!("user:{}:permissions", user_id);

        match conn.get::<_, String>(key).await {
            Ok(value) => Ok(Some(serde_json::from_str(&value)?)),
            Err(_) => Ok(None),
        }
    }
}
```

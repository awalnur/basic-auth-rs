# 🛡️ Security Guide - Authentication System

## Table of Contents

- [Overview](#overview)
- [Security Threats & Mitigations](#security-threats--mitigations)
- [Password Security](#password-security)
- [Session Security](#session-security)
- [Multi-Factor Authentication (MFA)](#multi-factor-authentication-mfa)
- [Brute Force Protection](#brute-force-protection)
- [API Security](#api-security)
- [Data Protection](#data-protection)
- [Audit & Monitoring](#audit--monitoring)
- [Security Configuration](#security-configuration)
- [Security Testing](#security-testing)
- [Incident Response](#incident-response)
- [Compliance & Standards](#compliance--standards)

## Overview

Sistem autentikasi ini dirancang dengan prinsip **Defense in Depth** - multiple layers of security untuk melindungi dari
berbagai jenis serangan. Dokumen ini menjelaskan setiap aspek keamanan dan cara implementasinya.

### Security Principles

- **Least Privilege**: User hanya mendapat akses minimum yang diperlukan
- **Zero Trust**: Verifikasi setiap request, tidak ada yang dipercaya secara default
- **Data Minimization**: Hanya collect dan store data yang benar-benar diperlukan
- **Fail Secure**: Sistem gagal ke mode yang aman, bukan terbuka

## Security Threats & Mitigations

### 1. 🔓 Brute Force Attacks

**Threat**: Attacker mencoba berbagai kombinasi password untuk masuk ke akun

**Mitigations**:

- Rate limiting per IP dan per user
- Account lockout setelah failed attempts
- CAPTCHA setelah beberapa kali gagal
- Progressive delays (exponential backoff)
- Monitoring dan alerting untuk suspicious activities

```rust
// Example implementation in account_security table
pub struct AccountSecurity {
    pub failed_login_attempts: Option<i32>,    // Counter untuk failed attempts
    pub account_locked: Option<bool>,          // Status lock account
    pub locked_until: Option<NaiveDateTime>,   // Waktu unlock otomatis
}
```

### 2. 🎭 Password Attacks

**Threats**:

- Dictionary attacks
- Rainbow table attacks
- Credential stuffing
- Password spraying

**Mitigations**:

- Strong password hashing (Argon2, bcrypt, scrypt)
- Salt untuk setiap password
- Password complexity requirements
- Password history tracking
- Regular password expiration
- Breach password checking

### 3. 🕵️ Session Hijacking

**Threats**:

- Session token theft
- Session fixation
- Cross-site scripting (XSS)

**Mitigations**:

- Secure session tokens (cryptographically random)
- HttpOnly dan Secure cookies
- Session regeneration setelah login
- Session timeout
- IP address validation
- User agent validation

### 4. 🌐 Cross-Site Request Forgery (CSRF)

**Threats**: Attacker membuat user melakukan action tanpa sepengetahuan mereka

**Mitigations**:

- CSRF tokens
- SameSite cookie attributes
- Origin header validation
- Double submit cookies

### 5. 💉 SQL Injection

**Threats**: Attacker inject malicious SQL code

**Mitigations**:

- Parameterized queries (Diesel ORM provides this)
- Input validation
- Least privilege database accounts
- Database query monitoring

## Password Security

### Password Hashing Strategy

```rust
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(hash)?;
    Ok(Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok())
}
```

### Password Policy Requirements

- **Minimum Length**: 12 characters
- **Complexity**:
    - Uppercase letters
    - Lowercase letters
    - Numbers
    - Special characters
- **No Common Passwords**: Check against breach databases
- **No Personal Information**: Username, email, nama tidak boleh ada dalam password
- **Password History**: Tidak boleh reuse 12 password terakhir

### Password Storage Security

```sql
-- Tabel untuk track password history
CREATE TABLE password_history (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Session Security

### Session Token Generation

```rust
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;

pub fn generate_session_token() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}
```

### Session Validation

```rust
pub fn validate_session(token: &str, ip: &str, user_agent: &str) -> Result<bool, SessionError> {
    // 1. Check if session exists and not expired
    // 2. Validate IP address (optional, untuk high security)
    // 3. Validate user agent
    // 4. Check for suspicious patterns
    // 5. Update last_activity timestamp
}
```

### Session Security Headers

```rust
use actix_web::HttpResponse;

pub fn set_secure_session_cookie(response: &mut HttpResponse, token: &str) {
    response.cookie(
        actix_web::cookie::Cookie::build("session_token", token)
            .secure(true)      // HTTPS only
            .http_only(true)   // No JavaScript access
            .same_site(actix_web::cookie::SameSite::Strict)
            .max_age(actix_web::cookie::time::Duration::hours(24))
            .finish()
    );
}
```

## Multi-Factor Authentication (MFA)

### TOTP (Time-based One-Time Password)

```rust
use totp_rs::{Algorithm, TOTP, Secret};

pub fn generate_totp_secret() -> String {
    Secret::generate_secret().to_string()
}

pub fn verify_totp(secret: &str, token: &str) -> bool {
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,      // 6 digit codes
        1,      // 1 step
        30,     // 30 second validity
        secret.as_bytes().to_vec(),
    ).unwrap();
    
    totp.check_current(token).unwrap()
}
```

### Backup Codes

```rust
pub fn generate_backup_codes() -> Vec<String> {
    (0..10)
        .map(|_| {
            thread_rng()
                .sample_iter(&Alphanumeric)
                .take(8)
                .map(char::from)
                .collect()
        })
        .collect()
}
```

## Brute Force Protection

### Rate Limiting Strategy

```rust
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    attempts: HashMap<String, Vec<Instant>>,
    max_attempts: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn check_rate_limit(&mut self, identifier: &str) -> bool {
        let now = Instant::now();
        let attempts = self.attempts.entry(identifier.to_string()).or_insert_with(Vec::new);

        // Remove old attempts outside the window
        attempts.retain(|&attempt_time| now.duration_since(attempt_time) < self.window);

        if attempts.len() >= self.max_attempts {
            false // Rate limit exceeded
        } else {
            attempts.push(now);
            true // Allow attempt
        }
    }
}
```

### Progressive Delays

```rust
pub fn calculate_delay(failed_attempts: i32) -> Duration {
    match failed_attempts {
        0..=2 => Duration::from_secs(0),
        3..=5 => Duration::from_secs(1),
        6..=10 => Duration::from_secs(5),
        11..=20 => Duration::from_secs(30),
        _ => Duration::from_secs(300), // 5 minutes for excessive attempts
    }
}
```

## API Security

### API Key Management

```rust
use sha2::{Digest, Sha256};

pub fn generate_api_key() -> (String, String) {
    let key = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect::<String>();
    
    let hash = Sha256::digest(key.as_bytes());
    let hash_hex = format!("{:x}", hash);
    
    (key, hash_hex)
}

pub fn validate_api_key(provided_key: &str, stored_hash: &str) -> bool {
    let hash = Sha256::digest(provided_key.as_bytes());
    let hash_hex = format!("{:x}", hash);
    hash_hex == stored_hash
}
```

### JWT Security

```rust
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};

pub struct JWTManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl JWTManager {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
        }
    }

    pub fn create_token(&self, claims: &Claims) -> Result<String, jsonwebtoken::errors::Error> {
        encode(&Header::new(Algorithm::HS256), claims, &self.encoding_key)
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        let validation = Validation::new(Algorithm::HS256);
        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)?;
        Ok(token_data.claims)
    }
}
```

## Data Protection

### Encryption at Rest

```rust
use aes_gcm::{Aes256Gcm, Key, Nonce, NewAead, Aead};

pub struct DataEncryption {
    cipher: Aes256Gcm,
}

impl DataEncryption {
    pub fn new(key: &[u8; 32]) -> Self {
        let key = Key::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        Self { cipher }
    }

    pub fn encrypt(&self, data: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>, aes_gcm::Error> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher.encrypt(nonce, data)
    }

    pub fn decrypt(&self, encrypted_data: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>, aes_gcm::Error> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher.decrypt(nonce, encrypted_data)
    }
}
```

### PII (Personally Identifiable Information) Protection

- **Data Classification**: Klasifikasi data berdasarkan sensitivity
- **Data Masking**: Mask sensitive data dalam logs
- **Data Retention**: Automatic deletion setelah periode tertentu
- **Access Logging**: Log semua akses ke PII data

## Audit & Monitoring

### Security Event Logging

```rust
use serde_json::json;

pub fn log_security_event(event_type: &str, user_id: Option<i32>, details: serde_json::Value) {
    let log_entry = json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "event_type": event_type,
        "user_id": user_id,
        "details": details,
        "severity": classify_severity(event_type)
    });
    
    // Log to audit_logs table dan external SIEM system
    info!("SECURITY_EVENT: {}", log_entry);
}

fn classify_severity(event_type: &str) -> &'static str {
    match event_type {
        "login_failed" => "medium",
        "account_locked" => "high",
        "password_changed" => "medium",
        "mfa_disabled" => "high",
        "api_key_compromised" => "critical",
        _ => "low",
    }
}
```

### Real-time Monitoring

```rust
pub struct SecurityMonitor {
    alert_thresholds: HashMap<String, i32>,
}

impl SecurityMonitor {
    pub fn check_anomalies(&self, event: &SecurityEvent) -> Vec<Alert> {
        let mut alerts = Vec::new();
        
        // Check for unusual login patterns
        if self.is_unusual_login_pattern(event) {
            alerts.push(Alert::new("unusual_login_pattern", event));
        }
        
        // Check for privilege escalation attempts
        if self.is_privilege_escalation_attempt(event) {
            alerts.push(Alert::new("privilege_escalation", event));
        }
        
        // Check for data exfiltration patterns
        if self.is_data_exfiltration_pattern(event) {
            alerts.push(Alert::new("data_exfiltration", event));
        }
        
        alerts
    }
}
```

## Security Configuration

### Environment Variables

```bash
# .env file
DATABASE_URL=postgresql://user:pass@localhost/auth_db
JWT_SECRET=your-super-secret-jwt-key-min-256-bits
ENCRYPTION_KEY=your-32-byte-encryption-key
SESSION_SECRET=your-session-secret-key
RATE_LIMIT_MAX_ATTEMPTS=5
RATE_LIMIT_WINDOW_SECONDS=300
ACCOUNT_LOCKOUT_DURATION_MINUTES=30
SESSION_TIMEOUT_HOURS=24
PASSWORD_MIN_LENGTH=12
MFA_ISSUER=YourAppName
```

### Security Headers

```rust
use actix_web::middleware::DefaultHeaders;

pub fn security_headers() -> DefaultHeaders {
    DefaultHeaders::new()
        .add(("X-Content-Type-Options", "nosniff"))
        .add(("X-Frame-Options", "DENY"))
        .add(("X-XSS-Protection", "1; mode=block"))
        .add(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
        .add(("Content-Security-Policy", "default-src 'self'; script-src 'self'"))
        .add(("Referrer-Policy", "strict-origin-when-cross-origin"))
}
```

## Security Testing

### Penetration Testing Checklist

- [ ] **Authentication Bypass**: Test untuk bypass mechanisms
- [ ] **Authorization Flaws**: Test untuk privilege escalation
- [ ] **Session Management**: Test session handling
- [ ] **Input Validation**: Test SQL injection, XSS, command injection
- [ ] **Cryptographic Issues**: Test weak encryption, key management
- [ ] **Business Logic Flaws**: Test workflow dan business rules
- [ ] **Information Disclosure**: Test untuk data leaks
- [ ] **DoS Attacks**: Test rate limiting dan resource exhaustion

### Automated Security Testing

```rust
#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let password = "test_password_123!";
        let hash = hash_password(password).unwrap();
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_rate_limiting() {
        let mut limiter = RateLimiter::new(3, Duration::from_secs(60));
        let ip = "192.168.1.1";
        
        assert!(limiter.check_rate_limit(ip));
        assert!(limiter.check_rate_limit(ip));
        assert!(limiter.check_rate_limit(ip));
        assert!(!limiter.check_rate_limit(ip)); // Should be rate limited
    }

    #[test]
    fn test_session_token_randomness() {
        let token1 = generate_session_token();
        let token2 = generate_session_token();
        assert_ne!(token1, token2);
        assert_eq!(token1.len(), 64);
    }
}
```

## Incident Response

### Security Incident Classification

| Level        | Description                 | Response Time | Examples                                       |
|--------------|-----------------------------|---------------|------------------------------------------------|
| **Critical** | Immediate threat to system  | < 15 minutes  | Data breach, system compromise                 |
| **High**     | Significant security impact | < 1 hour      | Account takeover, privilege escalation         |
| **Medium**   | Moderate security concern   | < 4 hours     | Brute force attacks, policy violations         |
| **Low**      | Minor security issue        | < 24 hours    | Failed login attempts, minor policy violations |

### Incident Response Procedures

1. **Detection & Analysis**
    - Monitor security alerts
    - Analyze incident scope dan impact
    - Document timeline dan evidence

2. **Containment**
    - Isolate affected systems
    - Revoke compromised credentials
    - Block malicious IP addresses

3. **Eradication**
    - Remove malware atau unauthorized access
    - Patch vulnerabilities
    - Update security controls

4. **Recovery**
    - Restore systems dari clean backups
    - Implement additional monitoring
    - Validate system integrity

5. **Lessons Learned**
    - Document incident details
    - Update security procedures
    - Improve detection capabilities

## Compliance & Standards

### Security Standards Compliance

- **OWASP Top 10**: Address semua vulnerabilities
- **ISO 27001**: Information security management
- **SOC 2**: Security, availability, dan confidentiality
- **GDPR**: Data protection dan privacy
- **PCI DSS**: Payment card data security (if applicable)

### Security Audit Requirements

```sql
-- Audit log retention untuk compliance
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id INTEGER,
    old_values JSONB,
    new_values JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index untuk efficient audit queries
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
```

## Security Maintenance

### Regular Security Tasks

**Daily:**

- [ ] Review security alerts
- [ ] Monitor failed login attempts
- [ ] Check system resource usage

**Weekly:**

- [ ] Review audit logs
- [ ] Update threat intelligence
- [ ] Backup security configurations

**Monthly:**

- [ ] Security patch updates
- [ ] Access review dan cleanup
- [ ] Vulnerability scans

**Quarterly:**

- [ ] Penetration testing
- [ ] Security training
- [ ] Incident response drills

**Annually:**

- [ ] Security architecture review
- [ ] Policy updates
- [ ] Compliance audits

---

## Quick Security Checklist

### Pre-Production Security Checklist

- [ ] All passwords hashed dengan strong algorithm (Argon2/bcrypt)
- [ ] Rate limiting implemented
- [ ] Session management secure
- [ ] HTTPS enforced
- [ ] Security headers configured
- [ ] Input validation implemented
- [ ] Error handling doesn't leak information
- [ ] Audit logging enabled
- [ ] Backup dan recovery procedures tested
- [ ] Security monitoring configured

### Production Security Monitoring

- [ ] Failed login attempts monitoring
- [ ] Unusual access patterns detection
- [ ] Database query monitoring
- [ ] File integrity monitoring
- [ ] Network traffic analysis
- [ ] Security event correlation
- [ ] Automated threat response
- [ ] Regular security metrics reporting

---

**Remember**: Security adalah ongoing process, bukan satu-kali setup. Regular updates, monitoring, dan testing adalah
kunci untuk maintain security posture yang kuat.

For implementation details, lihat file-file lainnya dalam proyek ini dan referensi ke AUTHENTICATION_SCHEMA_GUIDE.md
untuk database schema details.

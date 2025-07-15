-- Complex Authentication Schema
-- This schema provides comprehensive user management, role-based access control,
-- session management, security features, and audit logging

-- 1. User Profiles Table (Extended user information)
CREATE TABLE IF NOT EXISTS user_profiles
(
    id            SERIAL PRIMARY KEY,
    user_id       UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    first_name    VARCHAR(50),
    last_name     VARCHAR(50),
    phone         VARCHAR(20),
    date_of_birth DATE,
    avatar_url    VARCHAR(500),
    bio           TEXT,
    timezone      VARCHAR(50) DEFAULT 'UTC',
    language      VARCHAR(10) DEFAULT 'en',
    created_at    TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id)
);

-- 2. Roles Table
CREATE TABLE IF NOT EXISTS roles
(
    id             SERIAL PRIMARY KEY,
    name           VARCHAR(50) NOT NULL UNIQUE,
    description    TEXT,
    is_system_role BOOLEAN     DEFAULT FALSE,
    created_at     TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 3. Permissions Table
CREATE TABLE IF NOT EXISTS permissions
(
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    resource    VARCHAR(50)  NOT NULL,
    action      VARCHAR(50)  NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 4. Role Permissions (Many-to-Many)
CREATE TABLE IF NOT EXISTS role_permissions
(
    id            SERIAL PRIMARY KEY,
    role_id       INTEGER NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions (id) ON DELETE CASCADE,
    granted_at    TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    granted_by    UUID REFERENCES users (id),
    UNIQUE (role_id, permission_id)
);

-- 5. User Roles (Many-to-Many)
CREATE TABLE IF NOT EXISTS user_roles
(
    id          SERIAL PRIMARY KEY,
    user_id     UUID    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id     INTEGER NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    assigned_by UUID REFERENCES users (id),
    expires_at  TIMESTAMP,
    is_active   BOOLEAN     DEFAULT TRUE,
    UNIQUE (user_id, role_id)
);

-- 6. User Sessions Table
CREATE TABLE IF NOT EXISTS user_sessions
(
    id                 SERIAL PRIMARY KEY,
    user_id            UUID         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    session_token      VARCHAR(255) NOT NULL UNIQUE,
    refresh_token      VARCHAR(255) UNIQUE,
    ip_address         INET,
    user_agent         TEXT,
    device_fingerprint VARCHAR(255),
    is_active          BOOLEAN     DEFAULT TRUE,
    expires_at         TIMESTAMPTZ  NOT NULL,
    last_activity      TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    created_at         TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 7. Password History (Prevent password reuse)
CREATE TABLE IF NOT EXISTS password_history
(
    id            SERIAL PRIMARY KEY,
    user_id       UUID         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    password_hash VARCHAR(255) NOT NULL,
    created_at    TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 8. Login Attempts (Security tracking)
CREATE TABLE IF NOT EXISTS login_attempts
(
    id             SERIAL PRIMARY KEY,
    email          VARCHAR(100),
    ip_address     INET    NOT NULL,
    user_agent     TEXT,
    success        BOOLEAN NOT NULL,
    failure_reason VARCHAR(100),
    attempted_at   TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    user_id        UUID REFERENCES users (id)
);

-- 9. Account Security Settings
CREATE TABLE IF NOT EXISTS account_security
(
    id                    SERIAL PRIMARY KEY,
    user_id               UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    two_factor_enabled    BOOLEAN     DEFAULT FALSE,
    two_factor_secret     VARCHAR(32),
    backup_codes          TEXT[], -- Array of backup codes
    account_locked        BOOLEAN     DEFAULT FALSE,
    locked_until          TIMESTAMP,
    failed_login_attempts INTEGER     DEFAULT 0,
    last_password_change  TIMESTAMP,
    password_expires_at   TIMESTAMP,
    force_password_change BOOLEAN     DEFAULT FALSE,
    created_at            TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at            TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id)
);

-- 10. OAuth Providers (Social login)
CREATE TABLE IF NOT EXISTS oauth_providers
(
    id                SERIAL PRIMARY KEY,
    name              VARCHAR(50)  NOT NULL UNIQUE,
    client_id         VARCHAR(255) NOT NULL,
    client_secret     VARCHAR(255) NOT NULL,
    authorization_url VARCHAR(500) NOT NULL,
    token_url         VARCHAR(500) NOT NULL,
    user_info_url     VARCHAR(500) NOT NULL,
    scope             VARCHAR(255),
    is_active         BOOLEAN     DEFAULT TRUE,
    created_at        TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 11. User OAuth Connections
CREATE TABLE IF NOT EXISTS user_oauth_connections
(
    id               SERIAL PRIMARY KEY,
    user_id          UUID         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider_id      INTEGER      NOT NULL REFERENCES oauth_providers (id) ON DELETE CASCADE,
    provider_user_id VARCHAR(255) NOT NULL,
    access_token     TEXT,
    refresh_token    TEXT,
    token_expires_at TIMESTAMP,
    connected_at     TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_used_at     TIMESTAMP,
    UNIQUE (user_id, provider_id),
    UNIQUE (provider_id, provider_user_id)
);

-- 12. Password Reset Tokens
CREATE TABLE IF NOT EXISTS password_reset_tokens
(
    id         SERIAL PRIMARY KEY,
    user_id    UUID         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token      VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ  NOT NULL,
    used       BOOLEAN     DEFAULT FALSE,
    used_at    TIMESTAMP,
    ip_address INET,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 13. Email Verification Tokens
CREATE TABLE IF NOT EXISTS email_verification_tokens
(
    id          SERIAL PRIMARY KEY,
    user_id     UUID         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token       VARCHAR(255) NOT NULL UNIQUE,
    email       VARCHAR(100) NOT NULL,
    expires_at  TIMESTAMPTZ  NOT NULL,
    verified    BOOLEAN     DEFAULT FALSE,
    verified_at TIMESTAMP,
    created_at  TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 14. Audit Log (Track all important actions)
CREATE TABLE IF NOT EXISTS audit_logs
(
    id            SERIAL PRIMARY KEY,
    user_id       UUID REFERENCES users (id),
    action        VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id   UUID,
    old_values    JSONB,
    new_values    JSONB,
    ip_address    INET,
    user_agent    TEXT,
    created_at    TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 15. API Keys (For API access)
CREATE TABLE IF NOT EXISTS api_keys
(
    id           SERIAL PRIMARY KEY,
    user_id      UUID         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name         VARCHAR(100) NOT NULL,
    key_hash     VARCHAR(255) NOT NULL UNIQUE,
    permissions  TEXT[], -- Array of permission names
    last_used_at TIMESTAMP,
    expires_at   TIMESTAMP,
    is_active    BOOLEAN     DEFAULT TRUE,
    created_at   TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_user_profiles_user_id ON user_profiles (user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles (user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles (role_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions (session_token);
CREATE INDEX IF NOT EXISTS idx_user_sessions_active ON user_sessions (is_active, expires_at);
CREATE INDEX IF NOT EXISTS idx_login_attempts_email ON login_attempts (email);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts (ip_address);
CREATE INDEX IF NOT EXISTS idx_login_attempts_time ON login_attempts (attempted_at);
CREATE INDEX IF NOT EXISTS idx_account_security_user_id ON account_security (user_id);
CREATE INDEX IF NOT EXISTS idx_password_history_user_id ON password_history (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs (action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_time ON audit_logs (created_at);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys (user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys (key_hash);

-- Insert default roles
INSERT INTO roles (name, description, is_system_role)
VALUES ('admin', 'System Administrator with full access', TRUE),
       ('moderator', 'Content moderator with limited admin access', TRUE),
       ('user', 'Regular user with basic permissions', TRUE),
       ('guest', 'Guest user with read-only access', TRUE)
ON CONFLICT (name) DO NOTHING;

-- Insert additional roles for more granular access control
INSERT INTO roles (name, description, is_system_role)
VALUES ('super_admin', 'Super Administrator with unrestricted access', TRUE),
       ('editor', 'Content editor with publishing permissions', FALSE),
       ('viewer', 'Read-only access to most resources', FALSE),
       ('api_client', 'Dedicated role for API-only access', FALSE),
       ('support', 'Customer support with limited user management', FALSE)
ON CONFLICT (name) DO NOTHING;

-- Insert default permissions
INSERT INTO permissions (name, description, resource, action)
VALUES ('users.create', 'Create new users', 'users', 'create'),
       ('users.read', 'View user information', 'users', 'read'),
       ('users.update', 'Update user information', 'users', 'update'),
       ('users.delete', 'Delete users', 'users', 'delete'),
       ('roles.manage', 'Manage user roles', 'roles', 'manage'),
       ('system.admin', 'System administration access', 'system', 'admin'),
       ('content.moderate', 'Moderate content', 'content', 'moderate'),
       ('api.access', 'Access API endpoints', 'api', 'access')
ON CONFLICT (name) DO NOTHING;

-- Insert comprehensive permissions for different resources
INSERT INTO permissions (name, description, resource, action)
VALUES
-- User management permissions
('users.list', 'List all users', 'users', 'list'),
('users.profile.update', 'Update own profile', 'users', 'profile_update'),
('users.password.change', 'Change own password', 'users', 'password_change'),
('users.activate', 'Activate/deactivate users', 'users', 'activate'),
('users.impersonate', 'Impersonate other users', 'users', 'impersonate'),

-- Role and permission management
('roles.create', 'Create new roles', 'roles', 'create'),
('roles.read', 'View roles', 'roles', 'read'),
('roles.update', 'Update roles', 'roles', 'update'),
('roles.delete', 'Delete roles', 'roles', 'delete'),
('permissions.manage', 'Manage permissions', 'permissions', 'manage'),

-- Session management
('sessions.manage', 'Manage user sessions', 'sessions', 'manage'),
('sessions.terminate', 'Terminate user sessions', 'sessions', 'terminate'),

-- Security and audit
('security.audit', 'View audit logs', 'security', 'audit'),
('security.settings', 'Manage security settings', 'security', 'settings'),
('security.2fa.manage', 'Manage two-factor authentication', 'security', '2fa_manage'),

-- API and integration
('api.keys.create', 'Create API keys', 'api', 'keys_create'),
('api.keys.manage', 'Manage API keys', 'api', 'keys_manage'),
('api.oauth.manage', 'Manage OAuth connections', 'api', 'oauth_manage'),

-- Content management
('content.create', 'Create content', 'content', 'create'),
('content.read', 'Read content', 'content', 'read'),
('content.update', 'Update content', 'content', 'update'),
('content.delete', 'Delete content', 'content', 'delete'),
('content.publish', 'Publish content', 'content', 'publish'),

-- System administration
('system.backup', 'Perform system backups', 'system', 'backup'),
('system.settings', 'Manage system settings', 'system', 'settings'),
('system.maintenance', 'System maintenance mode', 'system', 'maintenance'),
('system.logs', 'Access system logs', 'system', 'logs')
ON CONFLICT (name) DO NOTHING;

-- Assign permissions to default roles
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r,
     permissions p
WHERE r.name = 'admin'
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r,
     permissions p
WHERE r.name = 'moderator'
  AND p.name IN ('users.read', 'content.moderate', 'api.access')
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r,
     permissions p
WHERE r.name = 'user'
  AND p.name IN ('users.read', 'api.access')
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r,
     permissions p
WHERE r.name = 'guest'
  AND p.name = 'users.read'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Assign permissions to super_admin (all permissions)
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r,
     permissions p
WHERE r.name = 'super_admin'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Assign permissions to editor role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r,
     permissions p
WHERE r.name = 'editor'
  AND p.name IN (
                 'users.read', 'users.profile.update', 'users.password.change',
                 'content.create', 'content.read', 'content.update', 'content.delete', 'content.publish',
                 'api.access'
    )
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Assign permissions to viewer role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r,
     permissions p
WHERE r.name = 'viewer'
  AND p.name IN (
                 'users.read', 'users.profile.update', 'users.password.change',
                 'content.read', 'roles.read'
    )
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Assign permissions to api_client role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r,
     permissions p
WHERE r.name = 'api_client'
  AND p.name IN (
                 'api.access', 'api.keys.create', 'api.keys.manage',
                 'users.read', 'content.read'
    )
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Assign permissions to support role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r,
     permissions p
WHERE r.name = 'support'
  AND p.name IN (
                 'users.read', 'users.list', 'users.activate',
                 'sessions.manage', 'sessions.terminate',
                 'security.audit', 'api.access'
    )
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Update user role permissions to include profile management
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r,
     permissions p
WHERE r.name = 'user'
  AND p.name IN ('users.profile.update', 'users.password.change')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Insert default OAuth providers (popular social login providers)
INSERT INTO oauth_providers (name, client_id, client_secret, authorization_url, token_url, user_info_url, scope,
                             is_active)
VALUES ('google', 'your-google-client-id', 'your-google-client-secret',
        'https://accounts.google.com/o/oauth2/v2/auth',
        'https://oauth2.googleapis.com/token',
        'https://www.googleapis.com/oauth2/v2/userinfo',
        'openid email profile', FALSE),

       ('github', 'your-github-client-id', 'your-github-client-secret',
        'https://github.com/login/oauth/authorize',
        'https://github.com/login/oauth/access_token',
        'https://api.github.com/user',
        'user:email', FALSE),

       ('facebook', 'your-facebook-app-id', 'your-facebook-app-secret',
        'https://www.facebook.com/v18.0/dialog/oauth',
        'https://graph.facebook.com/v18.0/oauth/access_token',
        'https://graph.facebook.com/v18.0/me',
        'email,public_profile', FALSE),

       ('linkedin', 'your-linkedin-client-id', 'your-linkedin-client-secret',
        'https://www.linkedin.com/oauth/v2/authorization',
        'https://www.linkedin.com/oauth/v2/accessToken',
        'https://api.linkedin.com/v2/people/~',
        'r_liteprofile r_emailaddress', FALSE)
ON CONFLICT (name) DO NOTHING;

-- Create default admin user (password should be changed immediately)
-- Note: This is for demo purposes - in production, create admin users securely
INSERT INTO users (username, email, password_hash, email_verified, is_active, created_at)
VALUES ('admin', 'admin@example.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewMw1xD5Nk6LxbSG', TRUE, TRUE,
        CURRENT_TIMESTAMP)
ON CONFLICT (email) DO NOTHING;

-- Assign super_admin role to default admin user
INSERT INTO user_roles (user_id, role_id, assigned_at, is_active)
SELECT u.id, r.id, CURRENT_TIMESTAMP, TRUE
FROM users u,
     roles r
WHERE u.email = 'admin@example.com'
  AND r.name = 'super_admin'
ON CONFLICT (user_id, role_id) DO NOTHING;

-- Create default admin profile
INSERT INTO user_profiles (user_id, first_name, last_name, timezone, language)
SELECT u.id, 'System', 'Administrator', 'UTC', 'en'
FROM users u
WHERE u.email = 'admin@example.com'
ON CONFLICT (user_id) DO NOTHING;

-- Create default security settings for admin user
INSERT INTO account_security (user_id, two_factor_enabled, account_locked, failed_login_attempts, last_password_change,
                              force_password_change)
SELECT u.id, FALSE, FALSE, 0, CURRENT_TIMESTAMP, TRUE
FROM users u
WHERE u.email = 'admin@example.com'
ON CONFLICT (user_id) DO NOTHING;

-- Insert audit log entry for default admin creation
INSERT INTO audit_logs (user_id, action, resource_type, resource_id, new_values, ip_address, created_at)
SELECT u.id,
       'user.created',
       'users',
       u.id,
       jsonb_build_object('email', u.email, 'role', 'super_admin', 'created_by', 'system'),
       '127.0.0.1'::inet,
       CURRENT_TIMESTAMP
FROM users u
WHERE u.email = 'admin@example.com';

-- Create some sample API permissions for demonstration
INSERT INTO permissions (name, description, resource, action)
VALUES ('api.users.read', 'API: Read user data', 'api', 'users_read'),
       ('api.users.write', 'API: Create/update user data', 'api', 'users_write'),
       ('api.content.read', 'API: Read content data', 'api', 'content_read'),
       ('api.content.write', 'API: Create/update content data', 'api', 'content_write'),
       ('api.analytics.read', 'API: Read analytics data', 'api', 'analytics_read')
ON CONFLICT (name) DO NOTHING;

-- Assign API permissions to appropriate roles
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r,
     permissions p
WHERE r.name = 'api_client'
  AND p.name LIKE 'api.%'
ON CONFLICT (role_id, permission_id) DO NOTHING;

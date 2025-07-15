-- This file should undo anything in `up.sql`

-- Rollback complex authentication schema
-- Drop tables in reverse order to handle foreign key dependencies

DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS email_verification_tokens;
DROP TABLE IF EXISTS password_reset_tokens;
DROP TABLE IF EXISTS user_oauth_connections;
DROP TABLE IF EXISTS oauth_providers;
DROP TABLE IF EXISTS account_security;
DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS password_history;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS user_profiles;

// @generated automatically by Diesel CLI.

diesel::table! {
    account_security (id) {
        id -> Int4,
        user_id -> Uuid,
        two_factor_enabled -> Nullable<Bool>,
        #[max_length = 32]
        two_factor_secret -> Nullable<Varchar>,
        backup_codes -> Nullable<Array<Nullable<Text>>>,
        account_locked -> Nullable<Bool>,
        locked_until -> Nullable<Timestamp>,
        failed_login_attempts -> Nullable<Int4>,
        last_password_change -> Nullable<Timestamp>,
        password_expires_at -> Nullable<Timestamp>,
        force_password_change -> Nullable<Bool>,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    api_keys (id) {
        id -> Int4,
        user_id -> Uuid,
        #[max_length = 100]
        name -> Varchar,
        #[max_length = 255]
        key_hash -> Varchar,
        permissions -> Nullable<Array<Nullable<Text>>>,
        last_used_at -> Nullable<Timestamp>,
        expires_at -> Nullable<Timestamp>,
        is_active -> Nullable<Bool>,
        created_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    audit_logs (id) {
        id -> Int4,
        user_id -> Nullable<Uuid>,
        #[max_length = 100]
        action -> Varchar,
        #[max_length = 50]
        resource_type -> Nullable<Varchar>,
        resource_id -> Nullable<Uuid>,
        old_values -> Nullable<Jsonb>,
        new_values -> Nullable<Jsonb>,
        ip_address -> Nullable<Inet>,
        user_agent -> Nullable<Text>,
        created_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    email_verification_tokens (id) {
        id -> Int4,
        user_id -> Uuid,
        #[max_length = 255]
        token -> Varchar,
        #[max_length = 100]
        email -> Varchar,
        expires_at -> Timestamptz,
        verified -> Nullable<Bool>,
        verified_at -> Nullable<Timestamp>,
        created_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    login_attempts (id) {
        id -> Int4,
        #[max_length = 100]
        email -> Nullable<Varchar>,
        ip_address -> Inet,
        user_agent -> Nullable<Text>,
        success -> Bool,
        #[max_length = 100]
        failure_reason -> Nullable<Varchar>,
        attempted_at -> Nullable<Timestamptz>,
        user_id -> Nullable<Uuid>,
    }
}

diesel::table! {
    oauth_providers (id) {
        id -> Int4,
        #[max_length = 50]
        name -> Varchar,
        #[max_length = 255]
        client_id -> Varchar,
        #[max_length = 255]
        client_secret -> Varchar,
        #[max_length = 500]
        authorization_url -> Varchar,
        #[max_length = 500]
        token_url -> Varchar,
        #[max_length = 500]
        user_info_url -> Varchar,
        #[max_length = 255]
        scope -> Nullable<Varchar>,
        is_active -> Nullable<Bool>,
        created_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    password_history (id) {
        id -> Int4,
        user_id -> Uuid,
        #[max_length = 255]
        password_hash -> Varchar,
        created_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    password_reset_tokens (id) {
        id -> Int4,
        user_id -> Uuid,
        #[max_length = 255]
        token -> Varchar,
        expires_at -> Timestamptz,
        used -> Nullable<Bool>,
        used_at -> Nullable<Timestamp>,
        ip_address -> Nullable<Inet>,
        created_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    permissions (id) {
        id -> Int4,
        #[max_length = 100]
        name -> Varchar,
        description -> Nullable<Text>,
        #[max_length = 50]
        resource -> Varchar,
        #[max_length = 50]
        action -> Varchar,
        created_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    role_permissions (id) {
        id -> Int4,
        role_id -> Int4,
        permission_id -> Int4,
        granted_at -> Nullable<Timestamptz>,
        granted_by -> Nullable<Uuid>,
    }
}

diesel::table! {
    roles (id) {
        id -> Int4,
        #[max_length = 50]
        name -> Varchar,
        description -> Nullable<Text>,
        is_system_role -> Nullable<Bool>,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    user_oauth_connections (id) {
        id -> Int4,
        user_id -> Uuid,
        provider_id -> Int4,
        #[max_length = 255]
        provider_user_id -> Varchar,
        access_token -> Nullable<Text>,
        refresh_token -> Nullable<Text>,
        token_expires_at -> Nullable<Timestamp>,
        connected_at -> Nullable<Timestamptz>,
        last_used_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    user_profiles (id) {
        id -> Int4,
        user_id -> Uuid,
        #[max_length = 50]
        first_name -> Nullable<Varchar>,
        #[max_length = 50]
        last_name -> Nullable<Varchar>,
        #[max_length = 20]
        phone -> Nullable<Varchar>,
        date_of_birth -> Nullable<Date>,
        #[max_length = 500]
        avatar_url -> Nullable<Varchar>,
        bio -> Nullable<Text>,
        #[max_length = 50]
        timezone -> Nullable<Varchar>,
        #[max_length = 10]
        language -> Nullable<Varchar>,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    user_roles (id) {
        id -> Int4,
        user_id -> Uuid,
        role_id -> Int4,
        assigned_at -> Nullable<Timestamptz>,
        assigned_by -> Nullable<Uuid>,
        expires_at -> Nullable<Timestamp>,
        is_active -> Nullable<Bool>,
    }
}

diesel::table! {
    user_sessions (id) {
        id -> Int4,
        user_id -> Uuid,
        #[max_length = 255]
        session_token -> Varchar,
        #[max_length = 255]
        refresh_token -> Nullable<Varchar>,
        ip_address -> Nullable<Inet>,
        user_agent -> Nullable<Text>,
        #[max_length = 255]
        device_fingerprint -> Nullable<Varchar>,
        is_active -> Nullable<Bool>,
        expires_at -> Timestamptz,
        last_activity -> Nullable<Timestamptz>,
        created_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        #[max_length = 50]
        username -> Varchar,
        #[max_length = 100]
        email -> Varchar,
        #[max_length = 255]
        password_hash -> Varchar,
        email_verified -> Bool,
        is_active -> Bool,
        created_at -> Timestamptz,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::joinable!(account_security -> users (user_id));
diesel::joinable!(api_keys -> users (user_id));
diesel::joinable!(audit_logs -> users (user_id));
diesel::joinable!(email_verification_tokens -> users (user_id));
diesel::joinable!(login_attempts -> users (user_id));
diesel::joinable!(password_history -> users (user_id));
diesel::joinable!(password_reset_tokens -> users (user_id));
diesel::joinable!(role_permissions -> permissions (permission_id));
diesel::joinable!(role_permissions -> roles (role_id));
diesel::joinable!(role_permissions -> users (granted_by));
diesel::joinable!(user_oauth_connections -> oauth_providers (provider_id));
diesel::joinable!(user_oauth_connections -> users (user_id));
diesel::joinable!(user_profiles -> users (user_id));
diesel::joinable!(user_roles -> roles (role_id));
diesel::joinable!(user_sessions -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    account_security,
    api_keys,
    audit_logs,
    email_verification_tokens,
    login_attempts,
    oauth_providers,
    password_history,
    password_reset_tokens,
    permissions,
    role_permissions,
    roles,
    user_oauth_connections,
    user_profiles,
    user_roles,
    user_sessions,
    users,
);

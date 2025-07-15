use basic_auth::infrastructure::persistence::repositories::user_repository_impl::UserRepositoryImpl;
use basic_auth::domain::repositories::user_repository::UserRepository;
use basic_auth::domain::entities::user::User;
use basic_auth::infrastructure::persistence::models::user_model::UserModel;
use uuid::Uuid;
use std::sync::Arc;
use std::env;

#[cfg(test)]
#[cfg(feature = "integration_tests")]
mod user_repository_integration_tests {
    use super::*;
    use crate::common::test_helpers;

    #[tokio::test]
    async fn test_find_by_id() {
        // Setup
        let pool = test_helpers::setup_test_db().await;
        let repo = Arc::new(UserRepositoryImpl::new(Arc::new(pool.clone())));

        // Clean up before test
        test_helpers::clean_database(&pool).await;

        // Create test user
        let user = test_helpers::create_test_user(
            None,
            None,
            None,
            true,
            false,
        );

        // Save user to database
        let saved_user = repo.save(&user).await.expect("Failed to save user");

        // Test find by ID
        let found_user = repo.find_by_id(saved_user.id).await.expect("Repository error");
        assert!(found_user.is_some());
        let found_user = found_user.unwrap();
        assert_eq!(found_user.username, user.username);
        assert_eq!(found_user.email, user.email);

        // Clean up after test
        test_helpers::clean_database(&pool).await;
    }

    #[tokio::test]
    async fn test_find_by_email() {
        // Setup
        let pool = test_helpers::setup_test_db().await;
        let repo = Arc::new(UserRepositoryImpl::new(Arc::new(pool.clone())));

        // Clean up before test
        test_helpers::clean_database(&pool).await;

        // Create test user with random email
        let email = test_helpers::random_email();
        let user = test_helpers::create_test_user(
            None,
            Some(email.clone()),
            None,
            true,
            false,
        );

        // Save user to database
        repo.save(&user).await.expect("Failed to save user");

        // Test find by email
        let found_user = repo.find_by_email(&email).await.expect("Repository error");
        assert!(found_user.is_some());
        let found_user = found_user.unwrap();
        assert_eq!(found_user.email, email);

        // Test non-existent email
        let not_found = repo.find_by_email("nonexistent@example.com").await.expect("Repository error");
        assert!(not_found.is_none());

        // Clean up after test
        test_helpers::clean_database(&pool).await;
    }

    #[tokio::test]
    async fn test_update_user() {
        // Setup
        let pool = test_helpers::setup_test_db().await;
        let repo = Arc::new(UserRepositoryImpl::new(Arc::new(pool.clone())));

        // Clean up before test
        test_helpers::clean_database(&pool).await;

        // Create and save test user
        let mut user = test_helpers::create_test_user(None, None, None, true, false);
        let saved_user = repo.save(&user).await.expect("Failed to save user");

        // Update user
        let mut updated_user = saved_user.clone();
        updated_user.verify_email();
        updated_user.username = "updated_username".to_string();

        repo.update(&updated_user).await.expect("Failed to update user");

        // Verify update
        let found_user = repo.find_by_id(updated_user.id).await.expect("Repository error").unwrap();
        assert_eq!(found_user.username, "updated_username");
        assert_eq!(found_user.email_verified, true);

        // Clean up after test
        test_helpers::clean_database(&pool).await;
    }

    #[tokio::test]
    async fn test_delete_user() {
        // Setup
        let pool = test_helpers::setup_test_db().await;
        let repo = Arc::new(UserRepositoryImpl::new(Arc::new(pool.clone())));

        // Clean up before test
        test_helpers::clean_database(&pool).await;

        // Create and save test user
        let user = test_helpers::create_test_user(None, None, None, true, false);
        let saved_user = repo.save(&user).await.expect("Failed to save user");

        // Verify user exists
        let found_before = repo.find_by_id(saved_user.id).await.expect("Repository error");
        assert!(found_before.is_some());

        // Delete user
        repo.delete(saved_user.id).await.expect("Failed to delete user");

        // Verify user no longer exists
        let found_after = repo.find_by_id(saved_user.id).await.expect("Repository error");
        assert!(found_after.is_none());

        // Clean up after test
        test_helpers::clean_database(&pool).await;
    }

    #[tokio::test]
    async fn test_find_active_users() {
        // Setup
        let pool = test_helpers::setup_test_db().await;
        let repo = Arc::new(UserRepositoryImpl::new(Arc::new(pool.clone())));

        // Clean up before test
        test_helpers::clean_database(&pool).await;

        // Create 3 users: 2 active, 1 inactive
        let active_user1 = test_helpers::create_test_user(
            Some("active1".to_string()),
            Some(test_helpers::random_email()),
            None,
            true,
            false,
        );

        let active_user2 = test_helpers::create_test_user(
            Some("active2".to_string()),
            Some(test_helpers::random_email()),
            None,
            true,
            false,
        );

        let inactive_user = test_helpers::create_test_user(
            Some("inactive".to_string()),
            Some(test_helpers::random_email()),
            None,
            false, // inactive
            false,
        );

        // Save all users
        repo.save(&active_user1).await.expect("Failed to save user");
        repo.save(&active_user2).await.expect("Failed to save user");
        repo.save(&inactive_user).await.expect("Failed to save user");

        // Test find active users
        let active_users = repo.find_active_users().await.expect("Repository error");
        assert_eq!(active_users.len(), 2);

        // Verify all returned users are active
        for user in active_users {
            assert_eq!(user.is_active, true);
        }

        // Clean up after test
        test_helpers::clean_database(&pool).await;
    }
}

// Common module exports

pub mod errors;
pub mod logging;
pub mod utils;

pub mod models;
// Re-export commonly used types for convenience
pub use errors::{AppError, AppResult, ErrorContext, ContextualError};
pub use logging::{AppLogger, LogLevel, LogEntry, PerformanceMonitor};
pub use utils::validation::{is_valid_email, validate_password, PasswordValidation};
pub use utils::datetime;
pub use utils::ids;

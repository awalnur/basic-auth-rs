// Common logging utilities and structured logging support

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn, error, debug, trace};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Log levels for structured logging
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl From<LogLevel> for tracing::Level {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Trace => tracing::Level::TRACE,
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Warn => tracing::Level::WARN,
            LogLevel::Error => tracing::Level::ERROR,
        }
    }
}

/// Structured log entry for consistent logging across the application
#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    /// Log level
    pub level: LogLevel,
    /// Log message
    pub message: String,
    /// Timestamp when log was created
    pub timestamp: DateTime<Utc>,
    /// Request ID for tracking requests across services
    pub request_id: Option<String>,
    /// User ID associated with the operation
    pub user_id: Option<Uuid>,
    /// Operation being performed
    pub operation: Option<String>,
    /// Additional structured data
    pub fields: HashMap<String, serde_json::Value>,
    /// Error information if applicable
    pub error: Option<ErrorInfo>,
}

/// Error information for structured logging
#[derive(Debug, Clone, Serialize)]
pub struct ErrorInfo {
    /// Error type/category
    pub error_type: String,
    /// Error message
    pub message: String,
    /// Error code if applicable
    pub code: Option<String>,
    /// Stack trace or additional debug info
    pub details: Option<String>,
}

impl LogEntry {
    /// Creates a new log entry with the specified level and message
    pub fn new(level: LogLevel, message: String) -> Self {
        Self {
            level,
            message,
            timestamp: Utc::now(),
            request_id: None,
            user_id: None,
            operation: None,
            fields: HashMap::new(),
            error: None,
        }
    }

    /// Adds request ID to the log entry
    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }

    /// Adds user ID to the log entry
    pub fn with_user_id(mut self, user_id: Uuid) -> Self {
        self.user_id = Some(user_id);
        self
    }

    /// Adds operation context to the log entry
    pub fn with_operation(mut self, operation: String) -> Self {
        self.operation = Some(operation);
        self
    }

    /// Adds a custom field to the log entry
    pub fn with_field<T: Serialize>(mut self, key: &str, value: T) -> Self {
        if let Ok(json_value) = serde_json::to_value(value) {
            self.fields.insert(key.to_string(), json_value);
        }
        self
    }

    /// Adds error information to the log entry
    pub fn with_error(mut self, error_info: ErrorInfo) -> Self {
        self.error = Some(error_info);
        self
    }

    /// Logs the entry using tracing
    pub fn log(self) {
        let json_fields = serde_json::to_string(&self.fields).unwrap_or_default();

        match self.level {
            LogLevel::Trace => trace!(
                request_id = ?self.request_id,
                user_id = ?self.user_id,
                operation = ?self.operation,
                fields = %json_fields,
                error = ?self.error,
                "{}",
                self.message
            ),
            LogLevel::Debug => debug!(
                request_id = ?self.request_id,
                user_id = ?self.user_id,
                operation = ?self.operation,
                fields = %json_fields,
                error = ?self.error,
                "{}",
                self.message
            ),
            LogLevel::Info => info!(
                request_id = ?self.request_id,
                user_id = ?self.user_id,
                operation = ?self.operation,
                fields = %json_fields,
                error = ?self.error,
                "{}",
                self.message
            ),
            LogLevel::Warn => warn!(
                request_id = ?self.request_id,
                user_id = ?self.user_id,
                operation = ?self.operation,
                fields = %json_fields,
                error = ?self.error,
                "{}",
                self.message
            ),
            LogLevel::Error => error!(
                request_id = ?self.request_id,
                user_id = ?self.user_id,
                operation = ?self.operation,
                fields = %json_fields,
                error = ?self.error,
                "{}",
                self.message
            ),
        }
    }
}

impl ErrorInfo {
    /// Creates error info from an error
    pub fn from_error<E: std::error::Error>(error: &E) -> Self {
        Self {
            error_type: std::any::type_name::<E>().to_string(),
            message: error.to_string(),
            code: None,
            details: error.source().map(|s| s.to_string()),
        }
    }

    /// Creates error info with custom type and message
    pub fn new(error_type: &str, message: &str) -> Self {
        Self {
            error_type: error_type.to_string(),
            message: message.to_string(),
            code: None,
            details: None,
        }
    }

    /// Adds error code
    pub fn with_code(mut self, code: &str) -> Self {
        self.code = Some(code.to_string());
        self
    }

    /// Adds error details
    pub fn with_details(mut self, details: &str) -> Self {
        self.details = Some(details.to_string());
        self
    }
}

/// Logger wrapper for consistent application logging
pub struct AppLogger {
    /// Default request ID for this logger instance
    request_id: Option<String>,
    /// Default user ID for this logger instance
    user_id: Option<Uuid>,
    /// Default operation context
    operation: Option<String>,
}

impl AppLogger {
    /// Creates a new logger instance
    pub fn new() -> Self {
        Self {
            request_id: None,
            user_id: None,
            operation: None,
        }
    }

    /// Creates logger with request context
    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }

    /// Creates logger with user context
    pub fn with_user_id(mut self, user_id: Uuid) -> Self {
        self.user_id = Some(user_id);
        self
    }

    /// Creates logger with operation context
    pub fn with_operation(mut self, operation: String) -> Self {
        self.operation = Some(operation);
        self
    }

    /// Creates a log entry with current context
    fn create_entry(&self, level: LogLevel, message: String) -> LogEntry {
        let mut entry = LogEntry::new(level, message);

        if let Some(ref request_id) = self.request_id {
            entry = entry.with_request_id(request_id.clone());
        }

        if let Some(user_id) = self.user_id {
            entry = entry.with_user_id(user_id);
        }

        if let Some(ref operation) = self.operation {
            entry = entry.with_operation(operation.clone());
        }

        entry
    }

    /// Logs info message
    pub fn info(&self, message: &str) {
        self.create_entry(LogLevel::Info, message.to_string()).log();
    }

    /// Logs warning message
    pub fn warn(&self, message: &str) {
        self.create_entry(LogLevel::Warn, message.to_string()).log();
    }

    /// Logs error message
    pub fn error(&self, message: &str) {
        self.create_entry(LogLevel::Error, message.to_string()).log();
    }

    /// Logs debug message
    pub fn debug(&self, message: &str) {
        self.create_entry(LogLevel::Debug, message.to_string()).log();
    }

    /// Logs trace message
    pub fn trace(&self, message: &str) {
        self.create_entry(LogLevel::Trace, message.to_string()).log();
    }

    /// Logs error with error information
    pub fn error_with_details<E: std::error::Error>(&self, message: &str, error: &E) {
        self.create_entry(LogLevel::Error, message.to_string())
            .with_error(ErrorInfo::from_error(error))
            .log();
    }

    /// Logs info with custom fields
    pub fn info_with_fields<T: Serialize>(&self, message: &str, fields: &HashMap<&str, T>) {
        let mut entry = self.create_entry(LogLevel::Info, message.to_string());
        for (key, value) in fields {
            entry = entry.with_field(key, value);
        }
        entry.log();
    }

    /// Logs operation start
    pub fn log_operation_start(&self, operation: &str) {
        self.create_entry(LogLevel::Info, format!("Starting operation: {}", operation))
            .with_operation(operation.to_string())
            .log();
    }

    /// Logs operation success
    pub fn log_operation_success(&self, operation: &str, duration_ms: u64) {
        self.create_entry(LogLevel::Info, format!("Operation completed successfully: {}", operation))
            .with_operation(operation.to_string())
            .with_field("duration_ms", duration_ms)
            .log();
    }

    /// Logs operation failure
    pub fn log_operation_failure<E: std::error::Error>(&self, operation: &str, error: &E, duration_ms: u64) {
        self.create_entry(LogLevel::Error, format!("Operation failed: {}", operation))
            .with_operation(operation.to_string())
            .with_field("duration_ms", duration_ms)
            .with_error(ErrorInfo::from_error(error))
            .log();
    }
}

impl Default for AppLogger {
    fn default() -> Self {
        Self::new()
    }
}

/// Macro for easy structured logging
#[macro_export]
macro_rules! log_info {
    ($msg:expr) => {
        $crate::common::logging::AppLogger::new().info($msg);
    };
    ($msg:expr, $($key:expr => $value:expr),+) => {
        {
            let mut fields = std::collections::HashMap::new();
            $(
                fields.insert($key, $value);
            )+
            $crate::common::logging::AppLogger::new().info_with_fields($msg, &fields);
        }
    };
}

#[macro_export]
macro_rules! log_error {
    ($msg:expr) => {
        $crate::common::logging::AppLogger::new().error($msg);
    };
    ($msg:expr, $error:expr) => {
        $crate::common::logging::AppLogger::new().error_with_details($msg, $error);
    };
}

/// Performance monitoring utilities
pub struct PerformanceMonitor {
    operation: String,
    start_time: std::time::Instant,
    logger: AppLogger,
}

impl PerformanceMonitor {
    /// Starts monitoring an operation
    pub fn start(operation: &str) -> Self {
        let logger = AppLogger::new().with_operation(operation.to_string());
        logger.log_operation_start(operation);

        Self {
            operation: operation.to_string(),
            start_time: std::time::Instant::now(),
            logger,
        }
    }

    /// Starts monitoring with context
    pub fn start_with_context(operation: &str, request_id: Option<String>, user_id: Option<Uuid>) -> Self {
        let mut logger = AppLogger::new().with_operation(operation.to_string());

        if let Some(req_id) = request_id {
            logger = logger.with_request_id(req_id);
        }

        if let Some(uid) = user_id {
            logger = logger.with_user_id(uid);
        }

        logger.log_operation_start(operation);

        Self {
            operation: operation.to_string(),
            start_time: std::time::Instant::now(),
            logger,
        }
    }

    /// Finishes monitoring with success
    pub fn finish_success(self) {
        let duration = self.start_time.elapsed().as_millis() as u64;
        self.logger.log_operation_success(&self.operation, duration);
    }

    /// Finishes monitoring with error
    pub fn finish_error<E: std::error::Error>(self, error: &E) {
        let duration = self.start_time.elapsed().as_millis() as u64;
        self.logger.log_operation_failure(&self.operation, error, duration);
    }

    /// Gets current operation duration
    pub fn duration_ms(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_entry_creation() {
        let entry = LogEntry::new(LogLevel::Info, "Test message".to_string())
            .with_request_id("req-123".to_string())
            .with_user_id(Uuid::new_v4())
            .with_operation("test_operation".to_string())
            .with_field("test_field", "test_value");

        assert_eq!(entry.level as u8, LogLevel::Info as u8);
        assert_eq!(entry.message, "Test message");
        assert!(entry.request_id.is_some());
        assert!(entry.user_id.is_some());
        assert!(entry.operation.is_some());
        assert!(entry.fields.contains_key("test_field"));
    }

    #[test]
    fn test_error_info_creation() {
        let error_info = ErrorInfo::new("ValidationError", "Invalid input")
            .with_code("VAL001")
            .with_details("Field 'email' is required");

        assert_eq!(error_info.error_type, "ValidationError");
        assert_eq!(error_info.message, "Invalid input");
        assert_eq!(error_info.code, Some("VAL001".to_string()));
        assert!(error_info.details.is_some());
    }

    #[test]
    fn test_app_logger() {
        let logger = AppLogger::new()
            .with_request_id("req-123".to_string())
            .with_user_id(Uuid::new_v4())
            .with_operation("test_op".to_string());

        // These should not panic
        logger.info("Test info message");
        logger.warn("Test warning message");
        logger.error("Test error message");
        logger.debug("Test debug message");
        logger.trace("Test trace message");
    }

    #[test]
    fn test_performance_monitor() {
        let monitor = PerformanceMonitor::start("test_operation");
        std::thread::sleep(std::time::Duration::from_millis(10));

        assert!(monitor.duration_ms() >= 10);
        monitor.finish_success();
    }
}

from .conversation import get_file_names_regex, get_urls
from .lang import SUPPORTED_LANGUAGE_MAP

# New production-grade utilities
from .security import (
    PasswordHasher,
    hash_password,
    verify_password,
    RateLimiter,
    RateLimitConfig,
    login_rate_limiter,
    api_rate_limiter,
    upload_rate_limiter,
    InputSanitizer,
    sanitizer,
    CSRFProtection,
    SessionTokenManager,
    session_manager,
)

from .validation import (
    FileValidator,
    document_validator,
    image_validator,
    PathValidator,
    ConfigValidator,
    URLValidator,
    url_validator,
    SchemaValidator,
)

from .audit import (
    AuditLogger,
    AuditEvent,
    AuditEventType,
    AuditSeverity,
    audit_logger,
    audit_action,
)

from .file_utils import (
    SafeArchiveExtractor,
    safe_extract_zip,
    safe_extract_archive,
    TempFileManager,
    temp_file,
    temp_directory,
    compute_file_hash,
    verify_file_hash,
    safe_write_file,
)

from .http_client import (
    HTTPClient,
    HTTPClientConfig,
    APIClient,
    CircuitBreaker,
    CircuitBreakerConfig,
    retry_with_backoff,
    RetryConfig,
    OutboundRateLimiter,
)

from .health import (
    HealthChecker,
    HealthStatus,
    ComponentHealth,
    SystemHealth,
    MetricsCollector,
    get_health_checker,
    get_metrics_collector,
    create_database_check,
    create_disk_space_check,
    create_memory_check,
)

from .llm_safety import (
    PromptInjectionDetector,
    InjectionRiskLevel,
    detect_injection,
    is_safe_input,
    RAGContentSanitizer,
    sanitize_rag_content,
    SafePromptFormatter,
    LLMOutputValidator,
    validate_llm_output,
    redact_sensitive_output,
)

from .config import (
    AppConfig,
    DatabaseConfig,
    SecurityConfig,
    LLMConfig,
    StorageConfig,
    FeatureFlags,
    ConfigManager,
    get_config,
    get_secrets,
    get_env,
    require_env,
)

__all__ = [
    # Original exports
    "SUPPORTED_LANGUAGE_MAP",
    "get_file_names_regex",
    "get_urls",

    # Security utilities
    "PasswordHasher",
    "hash_password",
    "verify_password",
    "RateLimiter",
    "RateLimitConfig",
    "login_rate_limiter",
    "api_rate_limiter",
    "upload_rate_limiter",
    "InputSanitizer",
    "sanitizer",
    "CSRFProtection",
    "SessionTokenManager",
    "session_manager",

    # Validation utilities
    "FileValidator",
    "document_validator",
    "image_validator",
    "PathValidator",
    "ConfigValidator",
    "URLValidator",
    "url_validator",
    "SchemaValidator",

    # Audit logging
    "AuditLogger",
    "AuditEvent",
    "AuditEventType",
    "AuditSeverity",
    "audit_logger",
    "audit_action",

    # File utilities
    "SafeArchiveExtractor",
    "safe_extract_zip",
    "safe_extract_archive",
    "TempFileManager",
    "temp_file",
    "temp_directory",
    "compute_file_hash",
    "verify_file_hash",
    "safe_write_file",

    # HTTP client
    "HTTPClient",
    "HTTPClientConfig",
    "APIClient",
    "CircuitBreaker",
    "CircuitBreakerConfig",
    "retry_with_backoff",
    "RetryConfig",
    "OutboundRateLimiter",

    # Health monitoring
    "HealthChecker",
    "HealthStatus",
    "ComponentHealth",
    "SystemHealth",
    "MetricsCollector",
    "get_health_checker",
    "get_metrics_collector",
    "create_database_check",
    "create_disk_space_check",
    "create_memory_check",

    # LLM safety
    "PromptInjectionDetector",
    "InjectionRiskLevel",
    "detect_injection",
    "is_safe_input",
    "RAGContentSanitizer",
    "sanitize_rag_content",
    "SafePromptFormatter",
    "LLMOutputValidator",
    "validate_llm_output",
    "redact_sensitive_output",

    # Configuration
    "AppConfig",
    "DatabaseConfig",
    "SecurityConfig",
    "LLMConfig",
    "StorageConfig",
    "FeatureFlags",
    "ConfigManager",
    "get_config",
    "get_secrets",
    "get_env",
    "require_env",
]

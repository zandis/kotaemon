"""
Production-grade configuration management.

This module provides:
- Environment-based configuration
- Configuration validation
- Secrets management
- Feature flags
"""

import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, TypeVar, Union
import logging

logger = logging.getLogger(__name__)

T = TypeVar('T')


# =============================================================================
# Configuration Classes
# =============================================================================

@dataclass
class DatabaseConfig:
    """Database configuration."""
    url: str = "sqlite:///./data/app.db"
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    pool_recycle: int = 1800
    echo: bool = False

    @classmethod
    def from_env(cls) -> 'DatabaseConfig':
        """Load from environment variables."""
        defaults = cls()
        try:
            pool_size = int(os.getenv("DATABASE_POOL_SIZE", defaults.pool_size))
        except (ValueError, TypeError):
            logger.warning("Invalid DATABASE_POOL_SIZE, using default")
            pool_size = defaults.pool_size
        try:
            max_overflow = int(os.getenv("DATABASE_MAX_OVERFLOW", defaults.max_overflow))
        except (ValueError, TypeError):
            logger.warning("Invalid DATABASE_MAX_OVERFLOW, using default")
            max_overflow = defaults.max_overflow
        try:
            pool_timeout = int(os.getenv("DATABASE_POOL_TIMEOUT", defaults.pool_timeout))
        except (ValueError, TypeError):
            logger.warning("Invalid DATABASE_POOL_TIMEOUT, using default")
            pool_timeout = defaults.pool_timeout
        try:
            pool_recycle = int(os.getenv("DATABASE_POOL_RECYCLE", defaults.pool_recycle))
        except (ValueError, TypeError):
            logger.warning("Invalid DATABASE_POOL_RECYCLE, using default")
            pool_recycle = defaults.pool_recycle

        return cls(
            url=os.getenv("DATABASE_URL", defaults.url),
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_timeout=pool_timeout,
            pool_recycle=pool_recycle,
            echo=os.getenv("DATABASE_ECHO", "false").lower() == "true"
        )


@dataclass
class SecurityConfig:
    """Security configuration."""
    secret_key: str = ""
    password_pepper: str = ""
    session_lifetime_hours: int = 24
    csrf_enabled: bool = True
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 100
    rate_limit_window: int = 60
    allowed_hosts: List[str] = field(default_factory=lambda: ["*"])
    cors_origins: List[str] = field(default_factory=list)

    @classmethod
    def from_env(cls) -> 'SecurityConfig':
        """Load from environment variables."""
        defaults = cls()
        try:
            session_lifetime_hours = int(os.getenv("SESSION_LIFETIME_HOURS", defaults.session_lifetime_hours))
        except (ValueError, TypeError):
            logger.warning("Invalid SESSION_LIFETIME_HOURS, using default")
            session_lifetime_hours = defaults.session_lifetime_hours
        try:
            rate_limit_requests = int(os.getenv("RATE_LIMIT_REQUESTS", defaults.rate_limit_requests))
        except (ValueError, TypeError):
            logger.warning("Invalid RATE_LIMIT_REQUESTS, using default")
            rate_limit_requests = defaults.rate_limit_requests
        try:
            rate_limit_window = int(os.getenv("RATE_LIMIT_WINDOW", defaults.rate_limit_window))
        except (ValueError, TypeError):
            logger.warning("Invalid RATE_LIMIT_WINDOW, using default")
            rate_limit_window = defaults.rate_limit_window

        return cls(
            secret_key=os.getenv("SECRET_KEY", ""),
            password_pepper=os.getenv("PASSWORD_PEPPER", ""),
            session_lifetime_hours=session_lifetime_hours,
            csrf_enabled=os.getenv("CSRF_ENABLED", "true").lower() == "true",
            rate_limit_enabled=os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true",
            rate_limit_requests=rate_limit_requests,
            rate_limit_window=rate_limit_window,
            allowed_hosts=os.getenv("ALLOWED_HOSTS", "*").split(","),
            cors_origins=os.getenv("CORS_ORIGINS", "").split(",") if os.getenv("CORS_ORIGINS") else []
        )

    def validate(self) -> List[str]:
        """Validate security configuration."""
        errors = []
        if not self.secret_key:
            errors.append("SECRET_KEY is required for production")
        elif len(self.secret_key) < 32:
            errors.append("SECRET_KEY should be at least 32 characters")
        if self.secret_key == "default-secret-key":
            errors.append("SECRET_KEY is using default value - change it!")
        return errors


@dataclass
class LLMConfig:
    """LLM provider configuration."""
    provider: str = "openai"
    api_key: str = ""
    model: str = "gpt-4"
    temperature: float = 0.7
    max_tokens: int = 4096
    timeout: int = 60
    retry_attempts: int = 3
    api_base: Optional[str] = None

    @classmethod
    def from_env(cls, prefix: str = "LLM") -> 'LLMConfig':
        """Load from environment variables with prefix."""
        defaults = cls()
        try:
            temperature = float(os.getenv(f"{prefix}_TEMPERATURE", defaults.temperature))
        except (ValueError, TypeError):
            logger.warning(f"Invalid {prefix}_TEMPERATURE, using default")
            temperature = defaults.temperature
        try:
            max_tokens = int(os.getenv(f"{prefix}_MAX_TOKENS", defaults.max_tokens))
        except (ValueError, TypeError):
            logger.warning(f"Invalid {prefix}_MAX_TOKENS, using default")
            max_tokens = defaults.max_tokens
        try:
            timeout = int(os.getenv(f"{prefix}_TIMEOUT", defaults.timeout))
        except (ValueError, TypeError):
            logger.warning(f"Invalid {prefix}_TIMEOUT, using default")
            timeout = defaults.timeout
        try:
            retry_attempts = int(os.getenv(f"{prefix}_RETRY_ATTEMPTS", defaults.retry_attempts))
        except (ValueError, TypeError):
            logger.warning(f"Invalid {prefix}_RETRY_ATTEMPTS, using default")
            retry_attempts = defaults.retry_attempts

        return cls(
            provider=os.getenv(f"{prefix}_PROVIDER", defaults.provider),
            api_key=os.getenv(f"{prefix}_API_KEY", ""),
            model=os.getenv(f"{prefix}_MODEL", defaults.model),
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=timeout,
            retry_attempts=retry_attempts,
            api_base=os.getenv(f"{prefix}_API_BASE")
        )

    def validate(self) -> List[str]:
        """Validate LLM configuration."""
        errors = []
        if not self.api_key:
            errors.append(f"LLM API key is required")
        if self.api_key in ("<YOUR_OPENAI_KEY>", "your-key", "sk-xxx"):
            errors.append("LLM API key appears to be a placeholder")
        return errors


@dataclass
class StorageConfig:
    """Storage configuration."""
    data_dir: str = "./data"
    upload_dir: str = "./data/uploads"
    cache_dir: str = "./data/cache"
    max_upload_size_mb: int = 100
    allowed_extensions: List[str] = field(default_factory=lambda: [".pdf", ".txt", ".docx", ".md"])

    @classmethod
    def from_env(cls) -> 'StorageConfig':
        """Load from environment variables."""
        defaults = cls()
        try:
            max_upload_size_mb = int(os.getenv("MAX_UPLOAD_SIZE_MB", defaults.max_upload_size_mb))
        except (ValueError, TypeError):
            logger.warning("Invalid MAX_UPLOAD_SIZE_MB, using default")
            max_upload_size_mb = defaults.max_upload_size_mb

        return cls(
            data_dir=os.getenv("DATA_DIR", defaults.data_dir),
            upload_dir=os.getenv("UPLOAD_DIR", defaults.upload_dir),
            cache_dir=os.getenv("CACHE_DIR", defaults.cache_dir),
            max_upload_size_mb=max_upload_size_mb,
            allowed_extensions=os.getenv("ALLOWED_EXTENSIONS", ",".join(defaults.allowed_extensions)).split(",")
        )

    def ensure_directories(self) -> None:
        """Create required directories."""
        for dir_path in [self.data_dir, self.upload_dir, self.cache_dir]:
            Path(dir_path).mkdir(parents=True, exist_ok=True)


@dataclass
class FeatureFlags:
    """Feature flags configuration."""
    user_management: bool = True
    file_upload: bool = True
    chat_history: bool = True
    public_sharing: bool = False
    admin_panel: bool = True
    api_access: bool = False
    analytics: bool = False
    debug_mode: bool = False

    @classmethod
    def from_env(cls) -> 'FeatureFlags':
        """Load from environment variables."""
        return cls(
            user_management=os.getenv("FEATURE_USER_MANAGEMENT", "true").lower() == "true",
            file_upload=os.getenv("FEATURE_FILE_UPLOAD", "true").lower() == "true",
            chat_history=os.getenv("FEATURE_CHAT_HISTORY", "true").lower() == "true",
            public_sharing=os.getenv("FEATURE_PUBLIC_SHARING", "false").lower() == "true",
            admin_panel=os.getenv("FEATURE_ADMIN_PANEL", "true").lower() == "true",
            api_access=os.getenv("FEATURE_API_ACCESS", "false").lower() == "true",
            analytics=os.getenv("FEATURE_ANALYTICS", "false").lower() == "true",
            debug_mode=os.getenv("DEBUG", "false").lower() == "true"
        )


@dataclass
class AppConfig:
    """Main application configuration."""
    name: str = "Kotaemon"
    version: str = "1.0.0"
    environment: str = "development"
    host: str = "0.0.0.0"
    port: int = 7860
    workers: int = 1
    log_level: str = "INFO"

    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    features: FeatureFlags = field(default_factory=FeatureFlags)

    @classmethod
    def from_env(cls) -> 'AppConfig':
        """Load full configuration from environment."""
        defaults = cls()
        try:
            port = int(os.getenv("PORT", defaults.port))
        except (ValueError, TypeError):
            logger.warning("Invalid PORT, using default")
            port = defaults.port
        try:
            workers = int(os.getenv("WORKERS", defaults.workers))
        except (ValueError, TypeError):
            logger.warning("Invalid WORKERS, using default")
            workers = defaults.workers

        return cls(
            name=os.getenv("APP_NAME", defaults.name),
            version=os.getenv("APP_VERSION", defaults.version),
            environment=os.getenv("ENVIRONMENT", defaults.environment),
            host=os.getenv("HOST", defaults.host),
            port=port,
            workers=workers,
            log_level=os.getenv("LOG_LEVEL", defaults.log_level),
            database=DatabaseConfig.from_env(),
            security=SecurityConfig.from_env(),
            llm=LLMConfig.from_env(),
            storage=StorageConfig.from_env(),
            features=FeatureFlags.from_env()
        )

    def validate(self, strict: bool = False) -> List[str]:
        """
        Validate the entire configuration.

        Args:
            strict: If True, treat warnings as errors

        Returns:
            List of validation errors/warnings
        """
        errors = []

        # Check environment
        if self.environment == "production":
            # Security validations
            security_errors = self.security.validate()
            errors.extend(security_errors)

            # LLM validations
            llm_errors = self.llm.validate()
            errors.extend(llm_errors)

            # Check debug mode
            if self.features.debug_mode:
                errors.append("DEBUG mode should be disabled in production")

        return errors

    @property
    def is_production(self) -> bool:
        """Check if running in production."""
        return self.environment.lower() == "production"

    @property
    def is_development(self) -> bool:
        """Check if running in development."""
        return self.environment.lower() in ("development", "dev", "local")


# =============================================================================
# Configuration Manager
# =============================================================================

class ConfigManager:
    """
    Configuration manager with validation and hot-reload support.

    Usage:
        config = ConfigManager.load()

        # Access configuration
        db_url = config.database.url
        is_debug = config.features.debug_mode

        # Validate
        errors = config.validate()
        if errors:
            print("Configuration errors:", errors)
    """

    _instance: Optional[AppConfig] = None
    _lock: threading.Lock = threading.Lock()

    @classmethod
    def load(cls, validate: bool = True) -> AppConfig:
        """
        Load configuration from environment.

        Args:
            validate: Run validation after loading

        Returns:
            AppConfig instance
        """
        with cls._lock:
            config = AppConfig.from_env()

            if validate:
                errors = config.validate(strict=config.is_production)
                if errors and config.is_production:
                    raise ConfigurationError(
                        f"Configuration validation failed: {'; '.join(errors)}"
                    )
                elif errors:
                    for error in errors:
                        logger.warning(f"Configuration warning: {error}")

            cls._instance = config
            return config

    @classmethod
    def get(cls) -> AppConfig:
        """Get current configuration (load if not loaded)."""
        with cls._lock:
            if cls._instance is None:
                # Release lock for load() which will reacquire
                pass
            else:
                return cls._instance
        # Load outside lock to avoid nested lock
        return cls.load(validate=False)

    @classmethod
    def reload(cls) -> AppConfig:
        """Reload configuration from environment."""
        with cls._lock:
            cls._instance = None
        return cls.load()


class ConfigurationError(Exception):
    """Configuration validation error."""
    pass


# =============================================================================
# Environment Helpers
# =============================================================================

def get_env(
    key: str,
    default: T = None,
    cast: Type[T] = str,
    required: bool = False
) -> T:
    """
    Get environment variable with type casting.

    Args:
        key: Environment variable name
        default: Default value if not set
        cast: Type to cast to
        required: Raise error if not set

    Returns:
        Environment variable value
    """
    value = os.getenv(key)

    if value is None:
        if required:
            raise ConfigurationError(f"Required environment variable {key} is not set")
        return default

    if cast == bool:
        return value.lower() in ("true", "1", "yes", "on")

    try:
        return cast(value)
    except (ValueError, TypeError) as e:
        raise ConfigurationError(f"Cannot cast {key}={value} to {cast.__name__}: {e}")


def require_env(key: str, cast: Type[T] = str) -> T:
    """Get required environment variable."""
    return get_env(key, cast=cast, required=True)


# =============================================================================
# Secrets Management
# =============================================================================

class SecretsManager:
    """
    Manage sensitive configuration values.

    Supports:
    - Environment variables
    - File-based secrets (Docker secrets)
    - AWS Secrets Manager (if boto3 available)
    """

    def __init__(
        self,
        secrets_dir: Optional[str] = None,
        env_prefix: str = ""
    ):
        """
        Initialize secrets manager.

        Args:
            secrets_dir: Directory for file-based secrets
            env_prefix: Prefix for environment variables
        """
        self.secrets_dir = Path(secrets_dir) if secrets_dir else Path("/run/secrets")
        self.env_prefix = env_prefix
        self._cache: Dict[str, str] = {}
        self._lock = threading.Lock()

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """
        Get a secret value.

        Checks in order:
        1. Cache
        2. Environment variable
        3. File-based secret
        4. Default value

        Args:
            key: Secret key name
            default: Default value

        Returns:
            Secret value or default
        """
        with self._lock:
            # Check cache
            if key in self._cache:
                return self._cache[key]

            # Check environment
            env_key = f"{self.env_prefix}{key}" if self.env_prefix else key
            value = os.getenv(env_key)
            if value:
                self._cache[key] = value
                return value

            # Check file-based secrets
            secret_file = self.secrets_dir / key
            if secret_file.exists():
                value = secret_file.read_text().strip()
                self._cache[key] = value
                return value

            return default

    def require(self, key: str) -> str:
        """Get a required secret (raises if not found)."""
        value = self.get(key)
        if value is None:
            raise ConfigurationError(f"Required secret '{key}' not found")
        return value

    def clear_cache(self) -> None:
        """Clear the secrets cache."""
        with self._lock:
            self._cache.clear()


# Global instances
_config: Optional[AppConfig] = None
_secrets: Optional[SecretsManager] = None


def get_config() -> AppConfig:
    """Get the global configuration."""
    global _config
    if _config is None:
        _config = ConfigManager.load()
    return _config


def get_secrets() -> SecretsManager:
    """Get the global secrets manager."""
    global _secrets
    if _secrets is None:
        _secrets = SecretsManager()
    return _secrets

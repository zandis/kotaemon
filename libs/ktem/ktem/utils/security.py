"""
Security utilities for production-grade authentication and protection.

This module provides:
- Secure password hashing with bcrypt/argon2
- Rate limiting with sliding window
- Input sanitization
- CSRF token generation
- Session token management
"""

import hashlib
import hmac
import os
import re
import secrets
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import wraps
from html import escape as html_escape
from threading import Lock
from typing import Any, Callable, Optional, TypeVar
from urllib.parse import quote as url_quote

# Try to import bcrypt, fall back to hashlib with proper salting
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

# Type variable for generic decorators
F = TypeVar('F', bound=Callable[..., Any])


# =============================================================================
# Password Hashing
# =============================================================================

class PasswordHasher:
    """
    Secure password hashing using bcrypt with fallback to salted SHA256.

    Usage:
        hasher = PasswordHasher()
        hashed = hasher.hash("mypassword")
        is_valid = hasher.verify("mypassword", hashed)
    """

    # Cost factor for bcrypt (higher = slower but more secure)
    BCRYPT_ROUNDS = 12
    # Salt length for fallback
    SALT_LENGTH = 32
    # Pepper (application-level secret, should be in env var in production)
    _pepper: Optional[str] = None

    def __init__(self, pepper: Optional[str] = None):
        """
        Initialize password hasher.

        Args:
            pepper: Optional application-level secret to add to passwords
        """
        self._pepper = pepper or os.environ.get("PASSWORD_PEPPER", "")

    def hash(self, password: str) -> str:
        """
        Hash a password securely.

        Args:
            password: Plain text password

        Returns:
            Hashed password string (includes algorithm identifier)
        """
        if not password:
            raise ValueError("Password cannot be empty")

        # Add pepper to password
        peppered = self._pepper + password

        if BCRYPT_AVAILABLE:
            # Use bcrypt (recommended)
            salt = bcrypt.gensalt(rounds=self.BCRYPT_ROUNDS)
            hashed = bcrypt.hashpw(peppered.encode('utf-8'), salt)
            return f"bcrypt${hashed.decode('utf-8')}"
        else:
            # Fallback to salted SHA256 with multiple iterations
            salt = secrets.token_hex(self.SALT_LENGTH)
            iterations = 100000
            hashed = self._pbkdf2_hash(peppered, salt, iterations)
            return f"pbkdf2${iterations}${salt}${hashed}"

    def verify(self, password: str, hashed: str) -> bool:
        """
        Verify a password against a hash.

        Args:
            password: Plain text password to verify
            hashed: Previously hashed password

        Returns:
            True if password matches, False otherwise
        """
        if not password or not hashed:
            return False

        peppered = self._pepper + password

        try:
            if hashed.startswith("bcrypt$"):
                if not BCRYPT_AVAILABLE:
                    return False
                stored_hash = hashed[7:].encode('utf-8')
                return bcrypt.checkpw(peppered.encode('utf-8'), stored_hash)

            elif hashed.startswith("pbkdf2$"):
                parts = hashed.split("$")
                if len(parts) != 4:
                    return False
                iterations = int(parts[1])
                salt = parts[2]
                stored_hash = parts[3]
                computed = self._pbkdf2_hash(peppered, salt, iterations)
                return hmac.compare_digest(computed, stored_hash)

            else:
                # Legacy SHA256 hash (for migration)
                legacy_hash = hashlib.sha256(password.encode()).hexdigest()
                return hmac.compare_digest(legacy_hash, hashed)

        except Exception:
            return False

    def needs_rehash(self, hashed: str) -> bool:
        """
        Check if a hash needs to be upgraded to a better algorithm.

        Args:
            hashed: Previously hashed password

        Returns:
            True if rehashing is recommended
        """
        # Legacy hashes should be upgraded
        if not hashed.startswith(("bcrypt$", "pbkdf2$")):
            return True

        # If bcrypt is available but hash isn't bcrypt, upgrade
        if BCRYPT_AVAILABLE and not hashed.startswith("bcrypt$"):
            return True

        return False

    def _pbkdf2_hash(self, password: str, salt: str, iterations: int) -> str:
        """PBKDF2 hash implementation."""
        dk = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            iterations
        )
        return dk.hex()


# Global password hasher instance
password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Convenience function to hash a password."""
    return password_hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """Convenience function to verify a password."""
    return password_hasher.verify(password, hashed)


# =============================================================================
# Rate Limiting
# =============================================================================

@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    max_requests: int = 100
    window_seconds: int = 60
    block_seconds: int = 300  # How long to block after exceeding limit


@dataclass
class RateLimitEntry:
    """Track rate limit state for a single key."""
    requests: list = field(default_factory=list)
    blocked_until: Optional[float] = None


class RateLimiter:
    """
    Thread-safe sliding window rate limiter.

    Usage:
        limiter = RateLimiter(RateLimitConfig(max_requests=10, window_seconds=60))

        if limiter.is_allowed("user_123"):
            # Process request
        else:
            # Return 429 Too Many Requests
    """

    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self._entries: dict[str, RateLimitEntry] = defaultdict(RateLimitEntry)
        self._lock = Lock()

    def is_allowed(self, key: str) -> bool:
        """
        Check if a request is allowed for the given key.

        Args:
            key: Identifier (e.g., user ID, IP address)

        Returns:
            True if request is allowed, False if rate limited
        """
        with self._lock:
            now = time.time()
            entry = self._entries[key]

            # Check if currently blocked
            if entry.blocked_until and now < entry.blocked_until:
                return False

            # Clear block if expired
            if entry.blocked_until and now >= entry.blocked_until:
                entry.blocked_until = None
                entry.requests.clear()

            # Remove old requests outside the window
            window_start = now - self.config.window_seconds
            entry.requests = [t for t in entry.requests if t > window_start]

            # Check if under limit
            if len(entry.requests) < self.config.max_requests:
                entry.requests.append(now)
                return True

            # Rate limit exceeded - block the key
            entry.blocked_until = now + self.config.block_seconds
            return False

    def get_retry_after(self, key: str) -> Optional[int]:
        """
        Get seconds until the key can make requests again.

        Args:
            key: Identifier

        Returns:
            Seconds to wait, or None if not rate limited
        """
        with self._lock:
            entry = self._entries.get(key)
            if not entry or not entry.blocked_until:
                return None

            remaining = entry.blocked_until - time.time()
            return max(0, int(remaining)) if remaining > 0 else None

    def reset(self, key: str) -> None:
        """Reset rate limit state for a key."""
        with self._lock:
            if key in self._entries:
                del self._entries[key]

    def cleanup(self) -> None:
        """Remove expired entries to free memory."""
        with self._lock:
            now = time.time()
            window_start = now - self.config.window_seconds

            keys_to_remove = []
            for key, entry in self._entries.items():
                if entry.blocked_until and now >= entry.blocked_until:
                    if not entry.requests or max(entry.requests) < window_start:
                        keys_to_remove.append(key)

            for key in keys_to_remove:
                del self._entries[key]


# Pre-configured rate limiters
login_rate_limiter = RateLimiter(RateLimitConfig(
    max_requests=5,
    window_seconds=300,  # 5 attempts per 5 minutes
    block_seconds=900    # 15 minute lockout
))

api_rate_limiter = RateLimiter(RateLimitConfig(
    max_requests=100,
    window_seconds=60,   # 100 requests per minute
    block_seconds=60     # 1 minute cooldown
))

upload_rate_limiter = RateLimiter(RateLimitConfig(
    max_requests=20,
    window_seconds=3600, # 20 uploads per hour
    block_seconds=1800   # 30 minute cooldown
))


def rate_limit(limiter: RateLimiter, key_func: Callable[..., str]) -> Callable[[F], F]:
    """
    Decorator to apply rate limiting to a function.

    Args:
        limiter: RateLimiter instance to use
        key_func: Function to extract rate limit key from arguments

    Usage:
        @rate_limit(login_rate_limiter, lambda username, **kwargs: username)
        def login(username, password):
            ...
    """
    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args, **kwargs):
            key = key_func(*args, **kwargs)
            if not limiter.is_allowed(key):
                retry_after = limiter.get_retry_after(key)
                raise RateLimitExceeded(
                    f"Rate limit exceeded. Retry after {retry_after} seconds.",
                    retry_after=retry_after
                )
            return func(*args, **kwargs)
        return wrapper  # type: ignore
    return decorator


class RateLimitExceeded(Exception):
    """Exception raised when rate limit is exceeded."""

    def __init__(self, message: str, retry_after: Optional[int] = None):
        super().__init__(message)
        self.retry_after = retry_after


# =============================================================================
# Input Sanitization
# =============================================================================

class InputSanitizer:
    """
    Sanitize user input to prevent injection attacks.

    Provides methods for different contexts:
    - HTML content
    - SQL-like filters
    - File names
    - URLs
    - Shell commands
    """

    # Dangerous file name characters
    UNSAFE_FILENAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
    UNSAFE_FILENAME_PATTERNS = re.compile(r'^\.+$|^(CON|PRN|AUX|NUL|COM\d|LPT\d)$', re.I)

    # SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        re.compile(r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b)", re.I),
        re.compile(r"(--|#|/\*|\*/|;)"),
        re.compile(r"('|\"|`)")
    ]

    @staticmethod
    def html(value: str, allow_newlines: bool = False) -> str:
        """
        Sanitize string for HTML output.

        Args:
            value: Raw string
            allow_newlines: If True, convert newlines to <br>

        Returns:
            HTML-safe string
        """
        if not value:
            return ""

        # Escape HTML entities
        result = html_escape(str(value), quote=True)

        if allow_newlines:
            result = result.replace('\n', '<br>')

        return result

    @staticmethod
    def filename(value: str, max_length: int = 255) -> str:
        """
        Sanitize a filename to be safe for filesystem.

        Args:
            value: Raw filename
            max_length: Maximum allowed length

        Returns:
            Safe filename
        """
        if not value:
            return "unnamed"

        # Get just the filename part (no path)
        filename = os.path.basename(str(value))

        # Remove/replace unsafe characters
        filename = InputSanitizer.UNSAFE_FILENAME_CHARS.sub('_', filename)

        # Remove leading/trailing dots and spaces
        filename = filename.strip('. ')

        # Check for reserved names
        name_part = filename.rsplit('.', 1)[0] if '.' in filename else filename
        if InputSanitizer.UNSAFE_FILENAME_PATTERNS.match(name_part):
            filename = f"file_{filename}"

        # Truncate if too long
        if len(filename) > max_length:
            name, ext = os.path.splitext(filename)
            max_name_len = max_length - len(ext)
            filename = name[:max_name_len] + ext

        return filename or "unnamed"

    @staticmethod
    def path_component(value: str) -> str:
        """
        Sanitize a single path component (not full path).

        Args:
            value: Raw path component

        Returns:
            Safe path component
        """
        if not value:
            return ""

        # Remove any path separators
        result = str(value).replace('/', '').replace('\\', '').replace('\x00', '')

        # Remove parent directory references
        result = result.replace('..', '')

        return result.strip()

    @staticmethod
    def sql_identifier(value: str) -> str:
        """
        Sanitize a value for use in SQL-like queries (identifiers).

        Args:
            value: Raw value

        Returns:
            Safe identifier (alphanumeric and underscore only)
        """
        if not value:
            return ""

        # Only allow alphanumeric and underscore
        return re.sub(r'[^a-zA-Z0-9_]', '', str(value))

    @staticmethod
    def sql_string(value: str) -> str:
        """
        Escape a string for use in SQL-like queries.

        Note: Always prefer parameterized queries over string escaping.

        Args:
            value: Raw value

        Returns:
            Escaped string (quotes escaped)
        """
        if not value:
            return ""

        # Escape single quotes by doubling them
        return str(value).replace("'", "''")

    @staticmethod
    def url(value: str) -> str:
        """
        Sanitize a URL for safe output.

        Args:
            value: Raw URL

        Returns:
            URL-encoded safe string
        """
        if not value:
            return ""

        return url_quote(str(value), safe=':/?#[]@!$&()*+,;=')

    @staticmethod
    def strip_html_tags(value: str) -> str:
        """
        Remove HTML tags from a string.

        Args:
            value: String potentially containing HTML

        Returns:
            Plain text string
        """
        if not value:
            return ""

        # Remove HTML tags
        clean = re.sub(r'<[^>]+>', '', str(value))

        # Decode common entities
        clean = clean.replace('&nbsp;', ' ')
        clean = clean.replace('&amp;', '&')
        clean = clean.replace('&lt;', '<')
        clean = clean.replace('&gt;', '>')
        clean = clean.replace('&quot;', '"')

        return clean

    @staticmethod
    def detect_sql_injection(value: str) -> bool:
        """
        Detect potential SQL injection patterns.

        Args:
            value: String to check

        Returns:
            True if suspicious patterns found
        """
        if not value:
            return False

        for pattern in InputSanitizer.SQL_INJECTION_PATTERNS:
            if pattern.search(str(value)):
                return True

        return False


# Convenience instance
sanitizer = InputSanitizer()


# =============================================================================
# CSRF Protection
# =============================================================================

class CSRFProtection:
    """
    CSRF token generation and validation.

    Usage:
        csrf = CSRFProtection()
        token = csrf.generate_token(session_id)

        # Later, in form submission:
        if csrf.validate_token(session_id, submitted_token):
            # Process form
    """

    def __init__(self, secret_key: Optional[str] = None, token_lifetime: int = 3600):
        """
        Initialize CSRF protection.

        Args:
            secret_key: Secret key for signing tokens
            token_lifetime: Token validity in seconds
        """
        self._secret = secret_key or os.environ.get("CSRF_SECRET", secrets.token_hex(32))
        self._lifetime = token_lifetime
        self._tokens: dict[str, tuple[str, float]] = {}
        self._lock = Lock()

    def generate_token(self, session_id: str) -> str:
        """
        Generate a CSRF token for a session.

        Args:
            session_id: User's session identifier

        Returns:
            CSRF token string
        """
        with self._lock:
            # Create token
            random_part = secrets.token_hex(16)
            timestamp = time.time()

            # Sign the token
            message = f"{session_id}:{random_part}:{timestamp}"
            signature = hmac.new(
                self._secret.encode(),
                message.encode(),
                hashlib.sha256
            ).hexdigest()[:16]

            token = f"{random_part}:{signature}"

            # Store for validation
            self._tokens[session_id] = (token, timestamp)

            # Cleanup old tokens periodically
            self._cleanup()

            return token

    def validate_token(self, session_id: str, token: str) -> bool:
        """
        Validate a CSRF token.

        Args:
            session_id: User's session identifier
            token: Token to validate

        Returns:
            True if valid, False otherwise
        """
        if not session_id or not token:
            return False

        with self._lock:
            stored = self._tokens.get(session_id)
            if not stored:
                return False

            stored_token, timestamp = stored

            # Check expiration
            if time.time() - timestamp > self._lifetime:
                del self._tokens[session_id]
                return False

            # Constant-time comparison
            return hmac.compare_digest(stored_token, token)

    def _cleanup(self) -> None:
        """Remove expired tokens."""
        now = time.time()
        expired = [
            sid for sid, (_, ts) in self._tokens.items()
            if now - ts > self._lifetime
        ]
        for sid in expired:
            del self._tokens[sid]


# =============================================================================
# Session Token Management
# =============================================================================

class SessionTokenManager:
    """
    Secure session token generation and validation.

    Generates cryptographically secure tokens with optional
    expiration and refresh capabilities.
    """

    TOKEN_LENGTH = 32  # 256 bits

    def __init__(
        self,
        secret_key: Optional[str] = None,
        token_lifetime: int = 86400,  # 24 hours
        refresh_threshold: int = 3600  # Refresh if < 1 hour left
    ):
        self._secret = secret_key or os.environ.get("SESSION_SECRET", secrets.token_hex(32))
        self._lifetime = token_lifetime
        self._refresh_threshold = refresh_threshold
        self._sessions: dict[str, dict] = {}
        self._lock = Lock()

    def create_session(self, user_id: str, metadata: Optional[dict] = None) -> str:
        """
        Create a new session and return token.

        Args:
            user_id: User identifier
            metadata: Optional session metadata

        Returns:
            Session token
        """
        with self._lock:
            token = secrets.token_urlsafe(self.TOKEN_LENGTH)
            now = time.time()

            self._sessions[token] = {
                'user_id': user_id,
                'created_at': now,
                'expires_at': now + self._lifetime,
                'last_activity': now,
                'metadata': metadata or {}
            }

            return token

    def validate_session(self, token: str) -> Optional[dict]:
        """
        Validate a session token and return session data.

        Args:
            token: Session token

        Returns:
            Session data dict or None if invalid
        """
        if not token:
            return None

        with self._lock:
            session = self._sessions.get(token)
            if not session:
                return None

            now = time.time()

            # Check expiration
            if now > session['expires_at']:
                del self._sessions[token]
                return None

            # Update last activity
            session['last_activity'] = now

            return session.copy()

    def should_refresh(self, token: str) -> bool:
        """Check if token should be refreshed."""
        with self._lock:
            session = self._sessions.get(token)
            if not session:
                return False

            time_left = session['expires_at'] - time.time()
            return time_left < self._refresh_threshold

    def refresh_session(self, old_token: str) -> Optional[str]:
        """
        Refresh a session with a new token.

        Args:
            old_token: Current session token

        Returns:
            New token or None if session invalid
        """
        with self._lock:
            session = self._sessions.get(old_token)
            if not session:
                return None

            # Remove old session
            del self._sessions[old_token]

            # Create new token with same session data
            new_token = secrets.token_urlsafe(self.TOKEN_LENGTH)
            now = time.time()

            session['expires_at'] = now + self._lifetime
            session['last_activity'] = now
            self._sessions[new_token] = session

            return new_token

    def invalidate_session(self, token: str) -> bool:
        """
        Invalidate a session (logout).

        Args:
            token: Session token to invalidate

        Returns:
            True if session was found and invalidated
        """
        with self._lock:
            if token in self._sessions:
                del self._sessions[token]
                return True
            return False

    def invalidate_user_sessions(self, user_id: str) -> int:
        """
        Invalidate all sessions for a user.

        Args:
            user_id: User identifier

        Returns:
            Number of sessions invalidated
        """
        with self._lock:
            tokens_to_remove = [
                t for t, s in self._sessions.items()
                if s['user_id'] == user_id
            ]
            for token in tokens_to_remove:
                del self._sessions[token]
            return len(tokens_to_remove)

    def cleanup_expired(self) -> int:
        """Remove all expired sessions."""
        with self._lock:
            now = time.time()
            expired = [
                t for t, s in self._sessions.items()
                if now > s['expires_at']
            ]
            for token in expired:
                del self._sessions[token]
            return len(expired)


# Global session manager
session_manager = SessionTokenManager()

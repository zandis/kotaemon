"""
Validation utilities for production-grade input validation.

This module provides:
- File validation (type, size, content)
- Path validation (traversal prevention)
- Configuration validation
- Schema validation
- URL validation
"""

import hashlib
import io
import mimetypes
import os
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Callable, Optional, Union
from urllib.parse import urlparse

# =============================================================================
# File Validation
# =============================================================================

@dataclass
class FileTypeConfig:
    """Configuration for allowed file types."""
    extensions: set[str]
    mime_types: set[str]
    magic_bytes: list[tuple[bytes, int]]  # (magic bytes, offset)
    max_size_mb: float = 100.0


# Common file type configurations
ALLOWED_DOCUMENT_TYPES = FileTypeConfig(
    extensions={'.pdf', '.doc', '.docx', '.txt', '.md', '.rtf', '.odt'},
    mime_types={
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'text/plain',
        'text/markdown',
        'application/rtf',
        'application/vnd.oasis.opendocument.text'
    },
    magic_bytes=[
        (b'%PDF', 0),  # PDF
        (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 0),  # DOC/OLE
        (b'PK\x03\x04', 0),  # DOCX/ODT (ZIP-based)
    ],
    max_size_mb=50.0
)

ALLOWED_IMAGE_TYPES = FileTypeConfig(
    extensions={'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.tiff'},
    mime_types={
        'image/jpeg',
        'image/png',
        'image/gif',
        'image/webp',
        'image/bmp',
        'image/tiff'
    },
    magic_bytes=[
        (b'\xff\xd8\xff', 0),  # JPEG
        (b'\x89PNG\r\n\x1a\n', 0),  # PNG
        (b'GIF87a', 0),  # GIF87
        (b'GIF89a', 0),  # GIF89
        (b'RIFF', 0),  # WEBP (starts with RIFF...WEBP)
        (b'BM', 0),  # BMP
        (b'II*\x00', 0),  # TIFF (little endian)
        (b'MM\x00*', 0),  # TIFF (big endian)
    ],
    max_size_mb=20.0
)

ALLOWED_DATA_TYPES = FileTypeConfig(
    extensions={'.csv', '.json', '.xlsx', '.xls', '.xml', '.yaml', '.yml'},
    mime_types={
        'text/csv',
        'application/json',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/xml',
        'text/xml',
        'application/x-yaml',
        'text/yaml'
    },
    magic_bytes=[
        (b'PK\x03\x04', 0),  # XLSX (ZIP-based)
        (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 0),  # XLS (OLE)
    ],
    max_size_mb=100.0
)

ALLOWED_ARCHIVE_TYPES = FileTypeConfig(
    extensions={'.zip', '.tar', '.gz', '.bz2', '.7z', '.rar'},
    mime_types={
        'application/zip',
        'application/x-tar',
        'application/gzip',
        'application/x-bzip2',
        'application/x-7z-compressed',
        'application/x-rar-compressed'
    },
    magic_bytes=[
        (b'PK\x03\x04', 0),  # ZIP
        (b'\x1f\x8b', 0),  # GZIP
        (b'BZh', 0),  # BZIP2
        (b'7z\xbc\xaf\x27\x1c', 0),  # 7Z
        (b'Rar!\x1a\x07', 0),  # RAR
    ],
    max_size_mb=500.0
)


@dataclass
class FileValidationResult:
    """Result of file validation."""
    is_valid: bool
    error_message: Optional[str] = None
    detected_type: Optional[str] = None
    file_size: int = 0
    file_hash: Optional[str] = None


class FileValidator:
    """
    Comprehensive file validation with multiple checks.

    Validates:
    - File extension
    - MIME type
    - Magic bytes (file signature)
    - File size
    - Content safety

    Usage:
        validator = FileValidator(ALLOWED_DOCUMENT_TYPES)
        result = validator.validate(file_path)
        if not result.is_valid:
            print(f"Invalid: {result.error_message}")
    """

    def __init__(
        self,
        config: FileTypeConfig,
        compute_hash: bool = True,
        check_magic_bytes: bool = True
    ):
        """
        Initialize file validator.

        Args:
            config: File type configuration
            compute_hash: Whether to compute SHA256 hash
            check_magic_bytes: Whether to verify file signatures
        """
        self.config = config
        self.compute_hash = compute_hash
        self.check_magic_bytes = check_magic_bytes

    def validate(
        self,
        file_input: Union[str, Path, BinaryIO],
        filename: Optional[str] = None
    ) -> FileValidationResult:
        """
        Validate a file.

        Args:
            file_input: File path or file-like object
            filename: Optional filename (required if file_input is file-like)

        Returns:
            FileValidationResult with validation status
        """
        try:
            # Handle different input types
            if isinstance(file_input, (str, Path)):
                file_path = Path(file_input)
                if not file_path.exists():
                    return FileValidationResult(
                        is_valid=False,
                        error_message="File does not exist"
                    )
                filename = file_path.name
                file_size = file_path.stat().st_size
                with open(file_path, 'rb') as f:
                    content = f.read()
            else:
                if not filename:
                    return FileValidationResult(
                        is_valid=False,
                        error_message="Filename required for file-like objects"
                    )
                content = file_input.read()
                file_size = len(content)
                if hasattr(file_input, 'seek'):
                    file_input.seek(0)

            # Validate extension
            ext = os.path.splitext(filename)[1].lower()
            if ext not in self.config.extensions:
                return FileValidationResult(
                    is_valid=False,
                    error_message=f"File extension '{ext}' not allowed",
                    file_size=file_size
                )

            # Validate size
            max_size_bytes = int(self.config.max_size_mb * 1024 * 1024)
            if file_size > max_size_bytes:
                return FileValidationResult(
                    is_valid=False,
                    error_message=f"File too large ({file_size / 1024 / 1024:.1f}MB > {self.config.max_size_mb}MB)",
                    file_size=file_size
                )

            # Check MIME type
            mime_type, _ = mimetypes.guess_type(filename)
            if mime_type and mime_type not in self.config.mime_types:
                # Don't fail on MIME type alone, but note it
                pass

            # Validate magic bytes
            if self.check_magic_bytes and self.config.magic_bytes:
                magic_valid = False
                detected_type = None

                for magic, offset in self.config.magic_bytes:
                    if len(content) >= offset + len(magic):
                        if content[offset:offset + len(magic)] == magic:
                            magic_valid = True
                            detected_type = self._identify_type(magic)
                            break

                # For text files, magic bytes check is optional
                is_text_type = ext in {'.txt', '.md', '.csv', '.json', '.xml', '.yaml', '.yml'}

                if not magic_valid and not is_text_type:
                    return FileValidationResult(
                        is_valid=False,
                        error_message="File content does not match expected type",
                        file_size=file_size
                    )

            # Compute hash
            file_hash = None
            if self.compute_hash:
                file_hash = hashlib.sha256(content).hexdigest()

            return FileValidationResult(
                is_valid=True,
                detected_type=mime_type or ext,
                file_size=file_size,
                file_hash=file_hash
            )

        except Exception as e:
            return FileValidationResult(
                is_valid=False,
                error_message=f"Validation error: {str(e)}"
            )

    def _identify_type(self, magic: bytes) -> str:
        """Identify file type from magic bytes."""
        type_map = {
            b'%PDF': 'application/pdf',
            b'\xff\xd8\xff': 'image/jpeg',
            b'\x89PNG': 'image/png',
            b'GIF8': 'image/gif',
            b'PK\x03\x04': 'application/zip',
        }
        for key, value in type_map.items():
            if magic.startswith(key):
                return value
        return 'application/octet-stream'


# Pre-configured validators
document_validator = FileValidator(ALLOWED_DOCUMENT_TYPES)
image_validator = FileValidator(ALLOWED_IMAGE_TYPES)
data_validator = FileValidator(ALLOWED_DATA_TYPES)
archive_validator = FileValidator(ALLOWED_ARCHIVE_TYPES)


# =============================================================================
# Path Validation
# =============================================================================

class PathValidator:
    """
    Validate and sanitize file paths to prevent traversal attacks.

    Usage:
        validator = PathValidator(base_dir="/app/uploads")

        if validator.is_safe_path(user_provided_path):
            # Safe to use
            safe_path = validator.resolve_path(user_provided_path)
    """

    DANGEROUS_PATTERNS = [
        r'\.\.',           # Parent directory
        r'^~',             # Home directory expansion
        r'\$\{.*\}',       # Variable expansion
        r'\$\w+',          # Variable expansion
        r'%[a-zA-Z]+%',    # Windows environment variables
        r'\x00',           # Null bytes
    ]

    def __init__(self, base_dir: Union[str, Path], allow_symlinks: bool = False):
        """
        Initialize path validator.

        Args:
            base_dir: Base directory that all paths must be under
            allow_symlinks: Whether to allow symlinked paths
        """
        self.base_dir = Path(base_dir).resolve()
        self.allow_symlinks = allow_symlinks
        self._pattern = re.compile('|'.join(self.DANGEROUS_PATTERNS))

    def is_safe_path(self, path: Union[str, Path]) -> bool:
        """
        Check if a path is safe (no traversal attempts).

        Args:
            path: Path to validate

        Returns:
            True if path is safe
        """
        try:
            path_str = str(path)

            # Check for dangerous patterns
            if self._pattern.search(path_str):
                return False

            # Resolve the path
            resolved = self.resolve_path(path)
            if resolved is None:
                return False

            return True

        except Exception:
            return False

    def resolve_path(self, path: Union[str, Path]) -> Optional[Path]:
        """
        Safely resolve a path within the base directory.

        Args:
            path: Path to resolve

        Returns:
            Resolved Path or None if unsafe
        """
        try:
            path_str = str(path)

            # Check for dangerous patterns first
            if self._pattern.search(path_str):
                return None

            # Handle absolute vs relative paths
            if os.path.isabs(path_str):
                full_path = Path(path_str)
            else:
                full_path = self.base_dir / path_str

            # Resolve to absolute path
            if self.allow_symlinks:
                resolved = full_path.resolve()
            else:
                # Check for symlinks in path
                resolved = full_path.resolve()
                current = full_path
                while current != current.parent:
                    if current.is_symlink():
                        return None
                    current = current.parent

            # Ensure path is under base directory
            try:
                resolved.relative_to(self.base_dir)
            except ValueError:
                return None

            return resolved

        except Exception:
            return None

    def sanitize_filename(self, filename: str) -> str:
        """
        Sanitize a filename for safe storage.

        Args:
            filename: Raw filename

        Returns:
            Sanitized filename
        """
        # Get just the filename, no path
        name = os.path.basename(filename)

        # Remove dangerous characters
        name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name)

        # Remove leading/trailing dots and spaces
        name = name.strip('. ')

        # Limit length
        if len(name) > 255:
            base, ext = os.path.splitext(name)
            name = base[:255 - len(ext)] + ext

        return name or 'unnamed'

    def join_safe(self, *parts: str) -> Optional[Path]:
        """
        Safely join path parts under base directory.

        Args:
            *parts: Path components to join

        Returns:
            Joined path or None if result is unsafe
        """
        # Sanitize each part
        sanitized = [self.sanitize_filename(p) for p in parts]

        # Join and validate
        joined = '/'.join(sanitized)
        return self.resolve_path(joined)


# =============================================================================
# Configuration Validation
# =============================================================================

@dataclass
class ConfigValidationError:
    """Error details for configuration validation."""
    field: str
    message: str
    value: Any = None


class ConfigValidator:
    """
    Validate application configuration.

    Ensures required settings are present and valid.

    Usage:
        validator = ConfigValidator()
        validator.require("DATABASE_URL", pattern=r"^sqlite://")
        validator.require("API_KEY", min_length=32)

        errors = validator.validate(config_dict)
        if errors:
            for error in errors:
                print(f"{error.field}: {error.message}")
    """

    def __init__(self):
        self._rules: list[dict] = []

    def require(
        self,
        field: str,
        field_type: Optional[type] = None,
        pattern: Optional[str] = None,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
        min_value: Optional[float] = None,
        max_value: Optional[float] = None,
        choices: Optional[list] = None,
        custom_validator: Optional[Callable[[Any], bool]] = None,
        error_message: Optional[str] = None
    ) -> 'ConfigValidator':
        """
        Add a required field validation rule.

        Args:
            field: Configuration field name
            field_type: Expected type
            pattern: Regex pattern to match
            min_length: Minimum string length
            max_length: Maximum string length
            min_value: Minimum numeric value
            max_value: Maximum numeric value
            choices: List of allowed values
            custom_validator: Custom validation function
            error_message: Custom error message

        Returns:
            Self for chaining
        """
        self._rules.append({
            'field': field,
            'required': True,
            'type': field_type,
            'pattern': re.compile(pattern) if pattern else None,
            'min_length': min_length,
            'max_length': max_length,
            'min_value': min_value,
            'max_value': max_value,
            'choices': choices,
            'validator': custom_validator,
            'error_message': error_message
        })
        return self

    def optional(
        self,
        field: str,
        default: Any = None,
        **kwargs
    ) -> 'ConfigValidator':
        """Add an optional field validation rule."""
        self._rules.append({
            'field': field,
            'required': False,
            'default': default,
            **kwargs
        })
        return self

    def validate(self, config: dict) -> list[ConfigValidationError]:
        """
        Validate configuration against all rules.

        Args:
            config: Configuration dictionary

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        for rule in self._rules:
            field = rule['field']
            value = config.get(field, rule.get('default'))

            # Check required
            if rule.get('required', False):
                if value is None or value == '':
                    errors.append(ConfigValidationError(
                        field=field,
                        message=rule.get('error_message') or f"Required field '{field}' is missing",
                        value=value
                    ))
                    continue

            # Skip further validation if value is None/empty for optional fields
            if value is None or value == '':
                continue

            # Type check
            expected_type = rule.get('type')
            if expected_type and not isinstance(value, expected_type):
                errors.append(ConfigValidationError(
                    field=field,
                    message=f"Expected type {expected_type.__name__}, got {type(value).__name__}",
                    value=value
                ))
                continue

            # Pattern check
            pattern = rule.get('pattern')
            if pattern and isinstance(value, str):
                if not pattern.match(value):
                    errors.append(ConfigValidationError(
                        field=field,
                        message=rule.get('error_message') or f"Value does not match required pattern",
                        value=value
                    ))

            # Length checks
            if isinstance(value, str):
                if rule.get('min_length') and len(value) < rule['min_length']:
                    errors.append(ConfigValidationError(
                        field=field,
                        message=f"Value too short (min {rule['min_length']} characters)",
                        value=value
                    ))
                if rule.get('max_length') and len(value) > rule['max_length']:
                    errors.append(ConfigValidationError(
                        field=field,
                        message=f"Value too long (max {rule['max_length']} characters)",
                        value=value
                    ))

            # Value range checks
            if isinstance(value, (int, float)):
                if rule.get('min_value') is not None and value < rule['min_value']:
                    errors.append(ConfigValidationError(
                        field=field,
                        message=f"Value below minimum ({rule['min_value']})",
                        value=value
                    ))
                if rule.get('max_value') is not None and value > rule['max_value']:
                    errors.append(ConfigValidationError(
                        field=field,
                        message=f"Value above maximum ({rule['max_value']})",
                        value=value
                    ))

            # Choices check
            choices = rule.get('choices')
            if choices and value not in choices:
                errors.append(ConfigValidationError(
                    field=field,
                    message=f"Value must be one of: {choices}",
                    value=value
                ))

            # Custom validator
            custom = rule.get('validator')
            if custom and not custom(value):
                errors.append(ConfigValidationError(
                    field=field,
                    message=rule.get('error_message') or "Custom validation failed",
                    value=value
                ))

        return errors


# =============================================================================
# URL Validation
# =============================================================================

class URLValidator:
    """
    Validate URLs for safety and correctness.

    Checks:
    - Valid URL format
    - Allowed schemes
    - Allowed/blocked hosts
    - SSRF prevention

    Usage:
        validator = URLValidator(
            allowed_schemes=['https'],
            blocked_hosts=['localhost', '127.0.0.1']
        )

        if validator.is_safe(url):
            # Safe to fetch
    """

    # Private IP ranges for SSRF prevention
    PRIVATE_IP_PATTERNS = [
        r'^127\.',                    # Loopback
        r'^10\.',                     # Class A private
        r'^172\.(1[6-9]|2\d|3[01])\.', # Class B private
        r'^192\.168\.',               # Class C private
        r'^169\.254\.',               # Link-local
        r'^::1$',                     # IPv6 loopback
        r'^fe80:',                    # IPv6 link-local
        r'^fc00:',                    # IPv6 unique local
    ]

    def __init__(
        self,
        allowed_schemes: Optional[list[str]] = None,
        blocked_schemes: Optional[list[str]] = None,
        allowed_hosts: Optional[list[str]] = None,
        blocked_hosts: Optional[list[str]] = None,
        allow_private_ips: bool = False,
        max_length: int = 2048
    ):
        """
        Initialize URL validator.

        Args:
            allowed_schemes: Whitelist of allowed schemes (default: http, https)
            blocked_schemes: Blacklist of blocked schemes
            allowed_hosts: Whitelist of allowed hosts
            blocked_hosts: Blacklist of blocked hosts
            allow_private_ips: Whether to allow private/internal IPs
            max_length: Maximum URL length
        """
        self.allowed_schemes = set(allowed_schemes or ['http', 'https'])
        self.blocked_schemes = set(blocked_schemes or ['file', 'ftp', 'data', 'javascript'])
        self.allowed_hosts = set(allowed_hosts) if allowed_hosts else None
        self.blocked_hosts = set(blocked_hosts or ['localhost', '127.0.0.1', '0.0.0.0', '::1'])
        self.allow_private_ips = allow_private_ips
        self.max_length = max_length
        self._private_patterns = [re.compile(p) for p in self.PRIVATE_IP_PATTERNS]

    def is_safe(self, url: str) -> bool:
        """
        Check if a URL is safe to fetch.

        Args:
            url: URL to validate

        Returns:
            True if URL is safe
        """
        result = self.validate(url)
        return result.is_valid

    def validate(self, url: str) -> 'URLValidationResult':
        """
        Validate a URL and return detailed result.

        Args:
            url: URL to validate

        Returns:
            URLValidationResult with details
        """
        if not url or not isinstance(url, str):
            return URLValidationResult(False, "Invalid URL")

        # Length check
        if len(url) > self.max_length:
            return URLValidationResult(False, f"URL too long (max {self.max_length})")

        try:
            parsed = urlparse(url)

            # Scheme validation
            scheme = parsed.scheme.lower()
            if scheme in self.blocked_schemes:
                return URLValidationResult(False, f"Blocked scheme: {scheme}")

            if scheme not in self.allowed_schemes:
                return URLValidationResult(False, f"Scheme not allowed: {scheme}")

            # Host validation
            host = parsed.hostname
            if not host:
                return URLValidationResult(False, "No host in URL")

            host_lower = host.lower()

            # Check blocked hosts
            if host_lower in self.blocked_hosts:
                return URLValidationResult(False, f"Blocked host: {host}")

            # Check allowed hosts whitelist
            if self.allowed_hosts and host_lower not in self.allowed_hosts:
                return URLValidationResult(False, f"Host not in allowed list: {host}")

            # SSRF protection - block private IPs
            if not self.allow_private_ips:
                for pattern in self._private_patterns:
                    if pattern.match(host):
                        return URLValidationResult(False, "Private IP addresses not allowed")

            return URLValidationResult(
                True,
                parsed_url=parsed,
                scheme=scheme,
                host=host,
                port=parsed.port,
                path=parsed.path
            )

        except Exception as e:
            return URLValidationResult(False, f"URL parsing error: {str(e)}")


@dataclass
class URLValidationResult:
    """Result of URL validation."""
    is_valid: bool
    error_message: Optional[str] = None
    parsed_url: Any = None
    scheme: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    path: Optional[str] = None


# Default URL validator
url_validator = URLValidator()


# =============================================================================
# Schema Validation
# =============================================================================

class SchemaValidator:
    """
    Simple schema validation for dictionaries.

    Usage:
        schema = {
            'name': {'type': str, 'required': True, 'min_length': 1},
            'age': {'type': int, 'required': False, 'min': 0, 'max': 150},
            'email': {'type': str, 'pattern': r'^[\w.-]+@[\w.-]+\.\w+$'}
        }

        validator = SchemaValidator(schema)
        errors = validator.validate(data)
    """

    def __init__(self, schema: dict):
        """
        Initialize schema validator.

        Args:
            schema: Schema definition dictionary
        """
        self.schema = schema

    def validate(self, data: dict) -> list[ConfigValidationError]:
        """
        Validate data against schema.

        Args:
            data: Data dictionary to validate

        Returns:
            List of validation errors
        """
        errors = []

        for field, rules in self.schema.items():
            value = data.get(field)

            # Required check
            if rules.get('required', False) and value is None:
                errors.append(ConfigValidationError(
                    field=field,
                    message="Required field missing"
                ))
                continue

            if value is None:
                continue

            # Type check
            expected_type = rules.get('type')
            if expected_type and not isinstance(value, expected_type):
                errors.append(ConfigValidationError(
                    field=field,
                    message=f"Expected {expected_type.__name__}",
                    value=value
                ))
                continue

            # String validations
            if isinstance(value, str):
                if rules.get('min_length') and len(value) < rules['min_length']:
                    errors.append(ConfigValidationError(
                        field=field,
                        message=f"Too short (min {rules['min_length']})",
                        value=value
                    ))
                if rules.get('max_length') and len(value) > rules['max_length']:
                    errors.append(ConfigValidationError(
                        field=field,
                        message=f"Too long (max {rules['max_length']})",
                        value=value
                    ))
                if rules.get('pattern'):
                    if not re.match(rules['pattern'], value):
                        errors.append(ConfigValidationError(
                            field=field,
                            message="Does not match pattern",
                            value=value
                        ))

            # Numeric validations
            if isinstance(value, (int, float)):
                if rules.get('min') is not None and value < rules['min']:
                    errors.append(ConfigValidationError(
                        field=field,
                        message=f"Below minimum ({rules['min']})",
                        value=value
                    ))
                if rules.get('max') is not None and value > rules['max']:
                    errors.append(ConfigValidationError(
                        field=field,
                        message=f"Above maximum ({rules['max']})",
                        value=value
                    ))

            # Enum/choices validation
            if rules.get('choices') and value not in rules['choices']:
                errors.append(ConfigValidationError(
                    field=field,
                    message=f"Must be one of: {rules['choices']}",
                    value=value
                ))

        return errors

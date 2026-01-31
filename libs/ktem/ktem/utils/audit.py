"""
Audit logging system for security and compliance.

This module provides:
- Structured audit logging
- Event tracking (login, file access, data changes)
- Log rotation and retention
- Export functionality

Designed for compliance with SOC 2, GDPR, and security best practices.
"""

import json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional, Union
from functools import wraps


# =============================================================================
# Audit Event Types
# =============================================================================

class AuditEventType(str, Enum):
    """Categories of audit events."""

    # Authentication events
    AUTH_LOGIN_SUCCESS = "auth.login.success"
    AUTH_LOGIN_FAILURE = "auth.login.failure"
    AUTH_LOGOUT = "auth.logout"
    AUTH_PASSWORD_CHANGE = "auth.password.change"
    AUTH_PASSWORD_RESET = "auth.password.reset"
    AUTH_SESSION_CREATED = "auth.session.created"
    AUTH_SESSION_EXPIRED = "auth.session.expired"
    AUTH_MFA_SUCCESS = "auth.mfa.success"
    AUTH_MFA_FAILURE = "auth.mfa.failure"

    # User management events
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    USER_ROLE_CHANGED = "user.role.changed"
    USER_LOCKED = "user.locked"
    USER_UNLOCKED = "user.unlocked"

    # Data access events
    DATA_READ = "data.read"
    DATA_CREATED = "data.created"
    DATA_UPDATED = "data.updated"
    DATA_DELETED = "data.deleted"
    DATA_EXPORTED = "data.exported"
    DATA_SHARED = "data.shared"

    # File events
    FILE_UPLOADED = "file.uploaded"
    FILE_DOWNLOADED = "file.downloaded"
    FILE_DELETED = "file.deleted"
    FILE_ACCESSED = "file.accessed"
    FILE_SHARED = "file.shared"

    # Conversation events
    CONVERSATION_CREATED = "conversation.created"
    CONVERSATION_DELETED = "conversation.deleted"
    CONVERSATION_SHARED = "conversation.shared"
    CONVERSATION_ACCESSED = "conversation.accessed"

    # System events
    SYSTEM_CONFIG_CHANGED = "system.config.changed"
    SYSTEM_STARTUP = "system.startup"
    SYSTEM_SHUTDOWN = "system.shutdown"
    SYSTEM_ERROR = "system.error"

    # Security events
    SECURITY_RATE_LIMITED = "security.rate_limited"
    SECURITY_INVALID_INPUT = "security.invalid_input"
    SECURITY_UNAUTHORIZED = "security.unauthorized"
    SECURITY_SUSPICIOUS_ACTIVITY = "security.suspicious"


class AuditSeverity(str, Enum):
    """Severity levels for audit events."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


# =============================================================================
# Audit Event Data Classes
# =============================================================================

@dataclass
class AuditEvent:
    """
    Structured audit event.

    Contains all information needed for security analysis and compliance.
    """
    event_type: AuditEventType
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    severity: AuditSeverity = AuditSeverity.INFO

    # Actor information
    user_id: Optional[str] = None
    username: Optional[str] = None
    user_role: Optional[str] = None
    session_id: Optional[str] = None

    # Request information
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    request_path: Optional[str] = None
    request_method: Optional[str] = None

    # Resource information
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None

    # Event details
    action: Optional[str] = None
    status: str = "success"
    message: Optional[str] = None
    details: dict = field(default_factory=dict)

    # Change tracking (for updates)
    old_value: Optional[Any] = None
    new_value: Optional[Any] = None

    # Error information
    error_code: Optional[str] = None
    error_message: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert event to dictionary for serialization."""
        data = asdict(self)
        data['event_type'] = self.event_type.value
        data['severity'] = self.severity.value
        return data

    def to_json(self) -> str:
        """Convert event to JSON string."""
        return json.dumps(self.to_dict(), default=str)


# =============================================================================
# Audit Logger
# =============================================================================

class AuditLogger:
    """
    Production-grade audit logging system.

    Features:
    - Structured JSON logging
    - Multiple output destinations
    - Log rotation
    - Async/buffered writes
    - Export functionality

    Usage:
        audit = AuditLogger()

        # Log an event
        audit.log(AuditEvent(
            event_type=AuditEventType.AUTH_LOGIN_SUCCESS,
            user_id="123",
            username="john",
            ip_address="192.168.1.1"
        ))

        # Or use convenience methods
        audit.log_login_success(user_id="123", username="john", ip="192.168.1.1")
    """

    def __init__(
        self,
        log_dir: Optional[Union[str, Path]] = None,
        log_name: str = "audit",
        max_file_size_mb: int = 100,
        backup_count: int = 10,
        enable_console: bool = False,
        buffer_size: int = 100,
        flush_interval: float = 5.0
    ):
        """
        Initialize audit logger.

        Args:
            log_dir: Directory for log files (default: ./logs/audit)
            log_name: Base name for log files
            max_file_size_mb: Max size before rotation
            backup_count: Number of backup files to keep
            enable_console: Also log to console
            buffer_size: Number of events to buffer before flush
            flush_interval: Seconds between automatic flushes
        """
        self.log_dir = Path(log_dir or "./logs/audit")
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.log_name = log_name
        self.max_file_size = max_file_size_mb * 1024 * 1024
        self.backup_count = backup_count
        self.enable_console = enable_console
        self.buffer_size = buffer_size
        self.flush_interval = flush_interval

        # Event buffer for async writes
        self._buffer: list[AuditEvent] = []
        self._buffer_lock = threading.Lock()
        self._last_flush = time.time()

        # Set up Python logger
        self._setup_logger()

        # Start background flush thread
        self._stop_event = threading.Event()
        self._flush_thread = threading.Thread(target=self._background_flush, daemon=True)
        self._flush_thread.start()

    def _setup_logger(self) -> None:
        """Configure the underlying Python logger."""
        self._logger = logging.getLogger(f"audit.{self.log_name}")
        self._logger.setLevel(logging.DEBUG)
        self._logger.handlers.clear()

        # Rotating file handler
        from logging.handlers import RotatingFileHandler
        log_file = self.log_dir / f"{self.log_name}.json"
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=self.max_file_size,
            backupCount=self.backup_count
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter('%(message)s'))
        self._logger.addHandler(file_handler)

        # Console handler (optional)
        if self.enable_console:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(logging.Formatter(
                '%(asctime)s - AUDIT - %(message)s'
            ))
            self._logger.addHandler(console_handler)

    def log(self, event: AuditEvent) -> None:
        """
        Log an audit event.

        Args:
            event: AuditEvent to log
        """
        with self._buffer_lock:
            self._buffer.append(event)

            # Flush if buffer is full
            if len(self._buffer) >= self.buffer_size:
                self._flush()

    def _flush(self) -> None:
        """Flush buffered events to log file."""
        if not self._buffer:
            return

        events_to_write = self._buffer.copy()
        self._buffer.clear()
        self._last_flush = time.time()

        for event in events_to_write:
            self._logger.info(event.to_json())

    def _background_flush(self) -> None:
        """Background thread for periodic flushing."""
        while not self._stop_event.is_set():
            time.sleep(1)
            with self._buffer_lock:
                if time.time() - self._last_flush >= self.flush_interval:
                    self._flush()

    def flush(self) -> None:
        """Manually flush all buffered events."""
        with self._buffer_lock:
            self._flush()

    def close(self) -> None:
        """Close the audit logger and flush remaining events."""
        self._stop_event.set()
        self.flush()
        self._flush_thread.join(timeout=5)

    # =========================================================================
    # Convenience Methods
    # =========================================================================

    def log_login_success(
        self,
        user_id: str,
        username: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        **details
    ) -> None:
        """Log successful login."""
        self.log(AuditEvent(
            event_type=AuditEventType.AUTH_LOGIN_SUCCESS,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            message=f"User '{username}' logged in successfully",
            details=details
        ))

    def log_login_failure(
        self,
        username: str,
        ip_address: Optional[str] = None,
        reason: Optional[str] = None,
        **details
    ) -> None:
        """Log failed login attempt."""
        self.log(AuditEvent(
            event_type=AuditEventType.AUTH_LOGIN_FAILURE,
            severity=AuditSeverity.WARNING,
            username=username,
            ip_address=ip_address,
            status="failure",
            message=f"Failed login attempt for '{username}'",
            error_message=reason,
            details=details
        ))

    def log_logout(
        self,
        user_id: str,
        username: str,
        **details
    ) -> None:
        """Log user logout."""
        self.log(AuditEvent(
            event_type=AuditEventType.AUTH_LOGOUT,
            user_id=user_id,
            username=username,
            message=f"User '{username}' logged out",
            details=details
        ))

    def log_file_upload(
        self,
        user_id: str,
        file_name: str,
        file_size: int,
        file_id: Optional[str] = None,
        **details
    ) -> None:
        """Log file upload."""
        self.log(AuditEvent(
            event_type=AuditEventType.FILE_UPLOADED,
            user_id=user_id,
            resource_type="file",
            resource_id=file_id,
            resource_name=file_name,
            message=f"File '{file_name}' uploaded ({file_size} bytes)",
            details={"file_size": file_size, **details}
        ))

    def log_file_download(
        self,
        user_id: str,
        file_name: str,
        file_id: Optional[str] = None,
        **details
    ) -> None:
        """Log file download."""
        self.log(AuditEvent(
            event_type=AuditEventType.FILE_DOWNLOADED,
            user_id=user_id,
            resource_type="file",
            resource_id=file_id,
            resource_name=file_name,
            message=f"File '{file_name}' downloaded",
            details=details
        ))

    def log_file_deleted(
        self,
        user_id: str,
        file_name: str,
        file_id: Optional[str] = None,
        **details
    ) -> None:
        """Log file deletion."""
        self.log(AuditEvent(
            event_type=AuditEventType.FILE_DELETED,
            user_id=user_id,
            resource_type="file",
            resource_id=file_id,
            resource_name=file_name,
            message=f"File '{file_name}' deleted",
            details=details
        ))

    def log_conversation_created(
        self,
        user_id: str,
        conversation_id: str,
        **details
    ) -> None:
        """Log conversation creation."""
        self.log(AuditEvent(
            event_type=AuditEventType.CONVERSATION_CREATED,
            user_id=user_id,
            resource_type="conversation",
            resource_id=conversation_id,
            message=f"Conversation '{conversation_id}' created",
            details=details
        ))

    def log_data_access(
        self,
        user_id: str,
        resource_type: str,
        resource_id: str,
        action: str = "read",
        **details
    ) -> None:
        """Log data access."""
        self.log(AuditEvent(
            event_type=AuditEventType.DATA_READ,
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            message=f"User accessed {resource_type} '{resource_id}'",
            details=details
        ))

    def log_security_event(
        self,
        event_type: AuditEventType,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        message: Optional[str] = None,
        **details
    ) -> None:
        """Log security-related event."""
        self.log(AuditEvent(
            event_type=event_type,
            severity=AuditSeverity.WARNING,
            user_id=user_id,
            ip_address=ip_address,
            message=message,
            details=details
        ))

    def log_error(
        self,
        error_message: str,
        error_code: Optional[str] = None,
        user_id: Optional[str] = None,
        **details
    ) -> None:
        """Log system error."""
        self.log(AuditEvent(
            event_type=AuditEventType.SYSTEM_ERROR,
            severity=AuditSeverity.ERROR,
            user_id=user_id,
            status="error",
            error_message=error_message,
            error_code=error_code,
            message=f"System error: {error_message}",
            details=details
        ))

    def log_config_change(
        self,
        user_id: str,
        setting_name: str,
        old_value: Any,
        new_value: Any,
        **details
    ) -> None:
        """Log configuration change."""
        self.log(AuditEvent(
            event_type=AuditEventType.SYSTEM_CONFIG_CHANGED,
            user_id=user_id,
            resource_type="config",
            resource_name=setting_name,
            old_value=old_value,
            new_value=new_value,
            message=f"Configuration '{setting_name}' changed",
            details=details
        ))

    # =========================================================================
    # Query and Export
    # =========================================================================

    def query_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_types: Optional[list[AuditEventType]] = None,
        user_id: Optional[str] = None,
        severity: Optional[AuditSeverity] = None,
        limit: int = 1000
    ) -> list[dict]:
        """
        Query audit events from log files.

        Args:
            start_time: Filter events after this time
            end_time: Filter events before this time
            event_types: Filter by event types
            user_id: Filter by user
            severity: Filter by severity
            limit: Maximum events to return

        Returns:
            List of matching events as dictionaries
        """
        events = []
        log_file = self.log_dir / f"{self.log_name}.json"

        if not log_file.exists():
            return events

        try:
            with open(log_file, 'r') as f:
                for line in f:
                    if len(events) >= limit:
                        break

                    try:
                        event = json.loads(line.strip())
                    except json.JSONDecodeError:
                        continue

                    # Apply filters
                    if start_time:
                        event_time = datetime.fromisoformat(
                            event.get('timestamp', '').replace('Z', '+00:00')
                        )
                        if event_time < start_time:
                            continue

                    if end_time:
                        event_time = datetime.fromisoformat(
                            event.get('timestamp', '').replace('Z', '+00:00')
                        )
                        if event_time > end_time:
                            continue

                    if event_types:
                        if event.get('event_type') not in [et.value for et in event_types]:
                            continue

                    if user_id and event.get('user_id') != user_id:
                        continue

                    if severity and event.get('severity') != severity.value:
                        continue

                    events.append(event)

        except Exception:
            pass

        return events

    def export_events(
        self,
        output_file: Union[str, Path],
        format: str = "json",
        **query_params
    ) -> int:
        """
        Export audit events to a file.

        Args:
            output_file: Path to output file
            format: Export format ('json' or 'csv')
            **query_params: Query parameters passed to query_events

        Returns:
            Number of events exported
        """
        events = self.query_events(**query_params)

        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if format == "csv":
            import csv
            with open(output_path, 'w', newline='') as f:
                if events:
                    writer = csv.DictWriter(f, fieldnames=events[0].keys())
                    writer.writeheader()
                    writer.writerows(events)
        else:
            with open(output_path, 'w') as f:
                json.dump(events, f, indent=2, default=str)

        return len(events)


# =============================================================================
# Audit Decorator
# =============================================================================

def audit_action(
    event_type: AuditEventType,
    resource_type: Optional[str] = None,
    get_user_id: Optional[Callable[..., str]] = None,
    get_resource_id: Optional[Callable[..., str]] = None
) -> Callable:
    """
    Decorator to automatically audit function calls.

    Usage:
        @audit_action(
            AuditEventType.DATA_UPDATED,
            resource_type="document",
            get_user_id=lambda user_id, **kw: user_id,
            get_resource_id=lambda doc_id, **kw: doc_id
        )
        def update_document(user_id, doc_id, content):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Extract identifiers
            user_id = get_user_id(*args, **kwargs) if get_user_id else None
            resource_id = get_resource_id(*args, **kwargs) if get_resource_id else None

            start_time = time.time()
            error = None

            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                error = e
                raise
            finally:
                duration_ms = (time.time() - start_time) * 1000

                event = AuditEvent(
                    event_type=event_type,
                    user_id=user_id,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    action=func.__name__,
                    status="error" if error else "success",
                    error_message=str(error) if error else None,
                    details={"duration_ms": round(duration_ms, 2)}
                )

                if error:
                    event.severity = AuditSeverity.ERROR

                audit_logger.log(event)

        return wrapper
    return decorator


# =============================================================================
# Global Instance
# =============================================================================

# Global audit logger instance
audit_logger = AuditLogger()


def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance."""
    return audit_logger

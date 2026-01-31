"""
Health check and monitoring utilities.

This module provides:
- Health check endpoints
- System metrics collection
- Dependency health monitoring
- Readiness and liveness probes
"""

import os
import platform
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


# =============================================================================
# Health Status Types
# =============================================================================

class HealthStatus(str, Enum):
    """Health check status values."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class ComponentHealth:
    """Health status of a single component."""
    name: str
    status: HealthStatus
    message: Optional[str] = None
    response_time_ms: Optional[float] = None
    details: Dict[str, Any] = field(default_factory=dict)
    last_check: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


@dataclass
class SystemHealth:
    """Overall system health status."""
    status: HealthStatus
    version: str = "unknown"
    uptime_seconds: float = 0
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    components: List[ComponentHealth] = field(default_factory=list)
    system_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = asdict(self)
        result['status'] = self.status.value
        result['components'] = [
            {**asdict(c), 'status': c.status.value}
            for c in self.components
        ]
        return result


# =============================================================================
# Health Check Functions
# =============================================================================

HealthCheckFunc = Callable[[], ComponentHealth]


class HealthChecker:
    """
    System health checker with configurable checks.

    Usage:
        checker = HealthChecker(app_version="1.0.0")

        # Add checks
        checker.add_check("database", check_database)
        checker.add_check("redis", check_redis)

        # Get health status
        health = checker.check_health()
        print(health.to_dict())
    """

    def __init__(
        self,
        app_version: str = "unknown",
        collect_system_info: bool = True
    ):
        """
        Initialize health checker.

        Args:
            app_version: Application version string
            collect_system_info: Whether to collect system info
        """
        self.app_version = app_version
        self.collect_system_info = collect_system_info
        self._checks: Dict[str, HealthCheckFunc] = {}
        self._start_time = time.time()
        self._lock = threading.Lock()

    def add_check(self, name: str, check_func: HealthCheckFunc) -> None:
        """
        Add a health check.

        Args:
            name: Check name
            check_func: Function that returns ComponentHealth
        """
        with self._lock:
            self._checks[name] = check_func

    def remove_check(self, name: str) -> None:
        """Remove a health check."""
        with self._lock:
            self._checks.pop(name, None)

    def check_health(self, include_details: bool = True) -> SystemHealth:
        """
        Run all health checks and return overall status.

        Args:
            include_details: Include detailed component info

        Returns:
            SystemHealth object
        """
        components = []
        overall_status = HealthStatus.HEALTHY

        # Run all checks
        with self._lock:
            checks = dict(self._checks)

        for name, check_func in checks.items():
            try:
                start = time.time()
                component = check_func()
                component.response_time_ms = (time.time() - start) * 1000

                # Update overall status
                if component.status == HealthStatus.UNHEALTHY:
                    overall_status = HealthStatus.UNHEALTHY
                elif component.status == HealthStatus.DEGRADED and overall_status == HealthStatus.HEALTHY:
                    overall_status = HealthStatus.DEGRADED

                if include_details:
                    components.append(component)

            except Exception as e:
                component = ComponentHealth(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    message=str(e)
                )
                overall_status = HealthStatus.UNHEALTHY
                if include_details:
                    components.append(component)

        # Collect system info
        system_info = {}
        if self.collect_system_info:
            system_info = self._get_system_info()

        return SystemHealth(
            status=overall_status,
            version=self.app_version,
            uptime_seconds=time.time() - self._start_time,
            components=components,
            system_info=system_info
        )

    def check_liveness(self) -> bool:
        """
        Simple liveness check (is the app running).

        Returns:
            True if alive
        """
        return True

    def check_readiness(self) -> bool:
        """
        Readiness check (is the app ready to serve traffic).

        Returns:
            True if ready
        """
        health = self.check_health(include_details=False)
        return health.status != HealthStatus.UNHEALTHY

    def _get_system_info(self) -> Dict[str, Any]:
        """Collect system information."""
        try:
            import psutil
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            cpu_percent = psutil.cpu_percent(interval=0.1)

            return {
                "python_version": sys.version,
                "platform": platform.platform(),
                "hostname": platform.node(),
                "cpu_count": os.cpu_count(),
                "cpu_percent": cpu_percent,
                "memory_total_gb": round(memory.total / (1024**3), 2),
                "memory_available_gb": round(memory.available / (1024**3), 2),
                "memory_percent": memory.percent,
                "disk_total_gb": round(disk.total / (1024**3), 2),
                "disk_free_gb": round(disk.free / (1024**3), 2),
                "disk_percent": round(disk.percent, 1)
            }
        except ImportError:
            return {
                "python_version": sys.version,
                "platform": platform.platform(),
                "hostname": platform.node(),
                "cpu_count": os.cpu_count()
            }


# =============================================================================
# Pre-built Health Checks
# =============================================================================

def create_database_check(
    engine,
    name: str = "database",
    timeout_seconds: float = 5.0
) -> HealthCheckFunc:
    """
    Create a database health check function.

    Args:
        engine: SQLAlchemy engine
        name: Check name
        timeout_seconds: Query timeout

    Returns:
        Health check function
    """
    def check() -> ComponentHealth:
        try:
            from sqlalchemy import text
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return ComponentHealth(
                name=name,
                status=HealthStatus.HEALTHY,
                message="Database connection successful"
            )
        except Exception as e:
            return ComponentHealth(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=f"Database error: {str(e)}"
            )

    return check


def create_redis_check(
    redis_client,
    name: str = "redis"
) -> HealthCheckFunc:
    """
    Create a Redis health check function.

    Args:
        redis_client: Redis client instance
        name: Check name

    Returns:
        Health check function
    """
    def check() -> ComponentHealth:
        try:
            redis_client.ping()
            return ComponentHealth(
                name=name,
                status=HealthStatus.HEALTHY,
                message="Redis connection successful"
            )
        except Exception as e:
            return ComponentHealth(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=f"Redis error: {str(e)}"
            )

    return check


def create_url_check(
    url: str,
    name: str = "external_service",
    timeout_seconds: float = 10.0,
    expected_status: int = 200
) -> HealthCheckFunc:
    """
    Create an HTTP URL health check function.

    Args:
        url: URL to check
        name: Check name
        timeout_seconds: Request timeout
        expected_status: Expected HTTP status code

    Returns:
        Health check function
    """
    def check() -> ComponentHealth:
        try:
            import requests
            response = requests.get(url, timeout=timeout_seconds)
            if response.status_code == expected_status:
                return ComponentHealth(
                    name=name,
                    status=HealthStatus.HEALTHY,
                    message=f"Service reachable at {url}",
                    details={"status_code": response.status_code}
                )
            else:
                return ComponentHealth(
                    name=name,
                    status=HealthStatus.DEGRADED,
                    message=f"Unexpected status: {response.status_code}",
                    details={"status_code": response.status_code}
                )
        except Exception as e:
            return ComponentHealth(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=f"Service unreachable: {str(e)}"
            )

    return check


def create_disk_space_check(
    path: str = "/",
    name: str = "disk_space",
    warning_threshold_percent: float = 80.0,
    critical_threshold_percent: float = 95.0
) -> HealthCheckFunc:
    """
    Create a disk space health check function.

    Args:
        path: Path to check disk space for
        name: Check name
        warning_threshold_percent: Percent usage for warning
        critical_threshold_percent: Percent usage for critical

    Returns:
        Health check function
    """
    def check() -> ComponentHealth:
        try:
            import shutil
            total, used, free = shutil.disk_usage(path)
            percent_used = (used / total) * 100

            details = {
                "total_gb": round(total / (1024**3), 2),
                "used_gb": round(used / (1024**3), 2),
                "free_gb": round(free / (1024**3), 2),
                "percent_used": round(percent_used, 1)
            }

            if percent_used >= critical_threshold_percent:
                return ComponentHealth(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    message=f"Disk space critical: {percent_used:.1f}% used",
                    details=details
                )
            elif percent_used >= warning_threshold_percent:
                return ComponentHealth(
                    name=name,
                    status=HealthStatus.DEGRADED,
                    message=f"Disk space warning: {percent_used:.1f}% used",
                    details=details
                )
            else:
                return ComponentHealth(
                    name=name,
                    status=HealthStatus.HEALTHY,
                    message=f"Disk space OK: {percent_used:.1f}% used",
                    details=details
                )
        except Exception as e:
            return ComponentHealth(
                name=name,
                status=HealthStatus.UNKNOWN,
                message=f"Could not check disk space: {str(e)}"
            )

    return check


def create_memory_check(
    name: str = "memory",
    warning_threshold_percent: float = 80.0,
    critical_threshold_percent: float = 95.0
) -> HealthCheckFunc:
    """
    Create a memory usage health check function.

    Args:
        name: Check name
        warning_threshold_percent: Percent usage for warning
        critical_threshold_percent: Percent usage for critical

    Returns:
        Health check function
    """
    def check() -> ComponentHealth:
        try:
            import psutil
            memory = psutil.virtual_memory()

            details = {
                "total_gb": round(memory.total / (1024**3), 2),
                "available_gb": round(memory.available / (1024**3), 2),
                "percent_used": memory.percent
            }

            if memory.percent >= critical_threshold_percent:
                return ComponentHealth(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    message=f"Memory critical: {memory.percent}% used",
                    details=details
                )
            elif memory.percent >= warning_threshold_percent:
                return ComponentHealth(
                    name=name,
                    status=HealthStatus.DEGRADED,
                    message=f"Memory warning: {memory.percent}% used",
                    details=details
                )
            else:
                return ComponentHealth(
                    name=name,
                    status=HealthStatus.HEALTHY,
                    message=f"Memory OK: {memory.percent}% used",
                    details=details
                )
        except ImportError:
            return ComponentHealth(
                name=name,
                status=HealthStatus.UNKNOWN,
                message="psutil not available"
            )
        except Exception as e:
            return ComponentHealth(
                name=name,
                status=HealthStatus.UNKNOWN,
                message=f"Could not check memory: {str(e)}"
            )

    return check


# =============================================================================
# Metrics Collection
# =============================================================================

@dataclass
class Metric:
    """A single metric value."""
    name: str
    value: float
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    metric_type: str = "gauge"  # gauge, counter, histogram


class MetricsCollector:
    """
    Simple metrics collector for monitoring.

    Usage:
        metrics = MetricsCollector()

        # Record metrics
        metrics.gauge("requests_active", 42)
        metrics.counter("requests_total", labels={"method": "GET"})
        metrics.histogram("request_duration_seconds", 0.123)

        # Get all metrics
        all_metrics = metrics.get_metrics()
    """

    def __init__(self):
        self._metrics: Dict[str, Metric] = {}
        self._counters: Dict[str, float] = {}
        self._histograms: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Record a gauge metric (current value)."""
        key = self._make_key(name, labels)
        with self._lock:
            self._metrics[key] = Metric(
                name=name,
                value=value,
                labels=labels or {},
                metric_type="gauge"
            )

    def counter(
        self,
        name: str,
        increment: float = 1.0,
        labels: Optional[Dict[str, str]] = None
    ) -> None:
        """Increment a counter metric."""
        key = self._make_key(name, labels)
        with self._lock:
            if key not in self._counters:
                self._counters[key] = 0
            self._counters[key] += increment
            self._metrics[key] = Metric(
                name=name,
                value=self._counters[key],
                labels=labels or {},
                metric_type="counter"
            )

    def histogram(
        self,
        name: str,
        value: float,
        labels: Optional[Dict[str, str]] = None
    ) -> None:
        """Record a histogram metric value."""
        key = self._make_key(name, labels)
        with self._lock:
            if key not in self._histograms:
                self._histograms[key] = []
            self._histograms[key].append(value)

            # Keep last 1000 values
            if len(self._histograms[key]) > 1000:
                self._histograms[key] = self._histograms[key][-1000:]

            values = self._histograms[key]
            self._metrics[key] = Metric(
                name=name,
                value=sum(values) / len(values),  # Store average
                labels=labels or {},
                metric_type="histogram"
            )

    def get_metrics(self) -> List[Dict[str, Any]]:
        """Get all recorded metrics."""
        with self._lock:
            return [asdict(m) for m in self._metrics.values()]

    def _make_key(self, name: str, labels: Optional[Dict[str, str]]) -> str:
        """Create unique key for metric + labels."""
        if not labels:
            return name
        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"


# =============================================================================
# Global instances
# =============================================================================

# Global health checker
_health_checker: Optional[HealthChecker] = None


def get_health_checker(app_version: str = "unknown") -> HealthChecker:
    """Get or create the global health checker."""
    global _health_checker
    if _health_checker is None:
        _health_checker = HealthChecker(app_version=app_version)
    return _health_checker


# Global metrics collector
_metrics_collector: Optional[MetricsCollector] = None


def get_metrics_collector() -> MetricsCollector:
    """Get or create the global metrics collector."""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector

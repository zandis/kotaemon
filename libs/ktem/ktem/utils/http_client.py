"""
Production-grade HTTP client utilities.

This module provides:
- HTTP client with timeouts, retries, and circuit breaker
- Connection pooling
- Rate limiting for outbound requests
- Request/response logging
"""

import logging
import random
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict, Optional, TypeVar, Union
from urllib.parse import urljoin

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

logger = logging.getLogger(__name__)

F = TypeVar('F', bound=Callable[..., Any])


# =============================================================================
# Circuit Breaker
# =============================================================================

class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"        # Normal operation
    OPEN = "open"            # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""
    failure_threshold: int = 5      # Failures before opening
    success_threshold: int = 2      # Successes to close from half-open
    timeout_seconds: float = 30.0   # Time before trying half-open
    excluded_exceptions: tuple = () # Exceptions that don't count as failures


class CircuitBreaker:
    """
    Circuit breaker pattern implementation.

    Prevents cascading failures by stopping requests to failing services.

    Usage:
        breaker = CircuitBreaker(CircuitBreakerConfig(failure_threshold=3))

        @breaker
        def call_external_api():
            return requests.get("https://api.example.com")

        # Or manual:
        if breaker.allow_request():
            try:
                result = call_api()
                breaker.record_success()
            except Exception as e:
                breaker.record_failure()
                raise
    """

    def __init__(self, config: Optional[CircuitBreakerConfig] = None, name: str = "default"):
        self.config = config or CircuitBreakerConfig()
        self.name = name
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        with self._lock:
            if self._state == CircuitState.OPEN:
                # Check if timeout has passed
                if self._last_failure_time:
                    elapsed = time.time() - self._last_failure_time
                    if elapsed >= self.config.timeout_seconds:
                        self._state = CircuitState.HALF_OPEN
                        self._success_count = 0
            return self._state

    def allow_request(self) -> bool:
        """Check if a request should be allowed."""
        state = self.state
        if state == CircuitState.CLOSED:
            return True
        elif state == CircuitState.HALF_OPEN:
            return True  # Allow test request
        else:
            return False

    def record_success(self) -> None:
        """Record a successful request."""
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.config.success_threshold:
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
                    self._success_count = 0
                    logger.info(f"Circuit breaker '{self.name}' closed")
            elif self._state == CircuitState.CLOSED:
                # Reset failure count on success
                self._failure_count = 0

    def record_failure(self, exception: Optional[Exception] = None) -> None:
        """Record a failed request."""
        # Check if exception should be excluded
        if exception and isinstance(exception, self.config.excluded_exceptions):
            return

        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()

            if self._state == CircuitState.HALF_OPEN:
                # Failed during test - reopen
                self._state = CircuitState.OPEN
                logger.warning(f"Circuit breaker '{self.name}' reopened after failure")
            elif self._state == CircuitState.CLOSED:
                if self._failure_count >= self.config.failure_threshold:
                    self._state = CircuitState.OPEN
                    logger.warning(f"Circuit breaker '{self.name}' opened after {self._failure_count} failures")

    def reset(self) -> None:
        """Reset the circuit breaker."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._success_count = 0
            self._last_failure_time = None

    def __call__(self, func: F) -> F:
        """Decorator for protecting functions with circuit breaker."""
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not self.allow_request():
                raise CircuitOpenError(f"Circuit breaker '{self.name}' is open")

            try:
                result = func(*args, **kwargs)
                self.record_success()
                return result
            except Exception as e:
                self.record_failure(e)
                raise

        return wrapper  # type: ignore


class CircuitOpenError(Exception):
    """Exception raised when circuit breaker is open."""
    pass


# =============================================================================
# Retry Logic
# =============================================================================

@dataclass
class RetryConfig:
    """Configuration for retry logic."""
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True
    retryable_exceptions: tuple = (Exception,)
    retryable_status_codes: tuple = (429, 500, 502, 503, 504)


def retry_with_backoff(config: Optional[RetryConfig] = None) -> Callable[[F], F]:
    """
    Decorator for retrying functions with exponential backoff.

    Usage:
        @retry_with_backoff(RetryConfig(max_retries=3))
        def call_api():
            return requests.get(url)
    """
    config = config or RetryConfig()

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None

            for attempt in range(config.max_retries + 1):
                try:
                    result = func(*args, **kwargs)

                    # Check for retryable status codes if result is a Response
                    if REQUESTS_AVAILABLE and isinstance(result, requests.Response):
                        if result.status_code in config.retryable_status_codes:
                            if attempt < config.max_retries:
                                delay = calculate_backoff(
                                    attempt, config.base_delay,
                                    config.max_delay, config.exponential_base,
                                    config.jitter
                                )
                                logger.warning(
                                    f"Retrying {func.__name__} after status {result.status_code}, "
                                    f"attempt {attempt + 1}/{config.max_retries}, delay {delay:.2f}s"
                                )
                                time.sleep(delay)
                                continue

                    return result

                except config.retryable_exceptions as e:
                    last_exception = e

                    if attempt < config.max_retries:
                        delay = calculate_backoff(
                            attempt, config.base_delay,
                            config.max_delay, config.exponential_base,
                            config.jitter
                        )
                        logger.warning(
                            f"Retrying {func.__name__} after error: {e}, "
                            f"attempt {attempt + 1}/{config.max_retries}, delay {delay:.2f}s"
                        )
                        time.sleep(delay)
                    else:
                        raise

            if last_exception:
                raise last_exception

        return wrapper  # type: ignore
    return decorator


def calculate_backoff(
    attempt: int,
    base_delay: float,
    max_delay: float,
    exponential_base: float,
    jitter: bool
) -> float:
    """Calculate backoff delay with optional jitter."""
    delay = min(base_delay * (exponential_base ** attempt), max_delay)
    if jitter:
        delay = delay * (0.5 + random.random())
    return delay


# =============================================================================
# HTTP Client
# =============================================================================

@dataclass
class HTTPClientConfig:
    """Configuration for HTTP client."""
    timeout: float = 30.0
    connect_timeout: float = 10.0
    read_timeout: float = 30.0
    max_retries: int = 3
    pool_connections: int = 10
    pool_maxsize: int = 20
    pool_block: bool = False
    verify_ssl: bool = True
    default_headers: Dict[str, str] = field(default_factory=dict)


class HTTPClient:
    """
    Production-grade HTTP client with connection pooling and resilience.

    Features:
    - Connection pooling
    - Automatic retries with backoff
    - Timeouts (connect + read)
    - Circuit breaker integration
    - Request/response logging

    Usage:
        client = HTTPClient(HTTPClientConfig(timeout=30))

        response = client.get("https://api.example.com/data")
        response = client.post("https://api.example.com/data", json={"key": "value"})
    """

    def __init__(
        self,
        config: Optional[HTTPClientConfig] = None,
        circuit_breaker: Optional[CircuitBreaker] = None
    ):
        """
        Initialize HTTP client.

        Args:
            config: Client configuration
            circuit_breaker: Optional circuit breaker for resilience
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library required for HTTPClient")

        self.config = config or HTTPClientConfig()
        self.circuit_breaker = circuit_breaker
        self._session: Optional[requests.Session] = None
        self._lock = threading.Lock()

    @property
    def session(self) -> 'requests.Session':
        """Get or create the session with connection pooling."""
        if self._session is None:
            with self._lock:
                if self._session is None:
                    self._session = self._create_session()
        return self._session

    def _create_session(self) -> 'requests.Session':
        """Create a configured requests session."""
        session = requests.Session()

        # Configure retries
        retry_strategy = Retry(
            total=self.config.max_retries,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE"],
            backoff_factor=1.0,
            raise_on_status=False
        )

        # Configure adapter with connection pooling
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=self.config.pool_connections,
            pool_maxsize=self.config.pool_maxsize,
            pool_block=self.config.pool_block
        )

        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Set default headers
        session.headers.update(self.config.default_headers)

        return session

    def _get_timeout(self) -> tuple:
        """Get timeout tuple (connect, read)."""
        return (self.config.connect_timeout, self.config.read_timeout)

    def request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> 'requests.Response':
        """
        Make an HTTP request.

        Args:
            method: HTTP method
            url: Request URL
            **kwargs: Additional arguments for requests

        Returns:
            Response object

        Raises:
            CircuitOpenError: If circuit breaker is open
            requests.RequestException: On request failure
        """
        # Check circuit breaker
        if self.circuit_breaker and not self.circuit_breaker.allow_request():
            raise CircuitOpenError("Circuit breaker is open")

        # Set defaults
        kwargs.setdefault('timeout', self._get_timeout())
        kwargs.setdefault('verify', self.config.verify_ssl)

        try:
            response = self.session.request(method, url, **kwargs)

            # Record success/failure for circuit breaker
            if self.circuit_breaker:
                if response.status_code >= 500:
                    self.circuit_breaker.record_failure()
                else:
                    self.circuit_breaker.record_success()

            return response

        except requests.RequestException as e:
            if self.circuit_breaker:
                self.circuit_breaker.record_failure(e)
            raise

    def get(self, url: str, **kwargs) -> 'requests.Response':
        """HTTP GET request."""
        return self.request('GET', url, **kwargs)

    def post(self, url: str, **kwargs) -> 'requests.Response':
        """HTTP POST request."""
        return self.request('POST', url, **kwargs)

    def put(self, url: str, **kwargs) -> 'requests.Response':
        """HTTP PUT request."""
        return self.request('PUT', url, **kwargs)

    def patch(self, url: str, **kwargs) -> 'requests.Response':
        """HTTP PATCH request."""
        return self.request('PATCH', url, **kwargs)

    def delete(self, url: str, **kwargs) -> 'requests.Response':
        """HTTP DELETE request."""
        return self.request('DELETE', url, **kwargs)

    def close(self) -> None:
        """Close the session and release resources."""
        if self._session:
            self._session.close()
            self._session = None

    def __enter__(self) -> 'HTTPClient':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


# =============================================================================
# API Client Base Class
# =============================================================================

class APIClient(HTTPClient):
    """
    Base class for API-specific clients.

    Provides common functionality for REST API interactions.

    Usage:
        class MyAPIClient(APIClient):
            def __init__(self, api_key: str):
                super().__init__(
                    base_url="https://api.example.com",
                    default_headers={"Authorization": f"Bearer {api_key}"}
                )

            def get_users(self):
                return self.get("/users").json()
    """

    def __init__(
        self,
        base_url: str,
        config: Optional[HTTPClientConfig] = None,
        default_headers: Optional[Dict[str, str]] = None,
        **kwargs
    ):
        """
        Initialize API client.

        Args:
            base_url: Base URL for all requests
            config: HTTP client configuration
            default_headers: Default headers for all requests
        """
        if config is None:
            config = HTTPClientConfig()
        if default_headers:
            config.default_headers.update(default_headers)

        super().__init__(config, **kwargs)
        self.base_url = base_url.rstrip('/')

    def request(self, method: str, path: str, **kwargs) -> 'requests.Response':
        """Make a request to the API."""
        url = urljoin(self.base_url + '/', path.lstrip('/'))
        return super().request(method, url, **kwargs)


# =============================================================================
# Request Rate Limiter (Outbound)
# =============================================================================

class OutboundRateLimiter:
    """
    Rate limiter for outbound HTTP requests.

    Prevents overwhelming external APIs with too many requests.

    Usage:
        limiter = OutboundRateLimiter(requests_per_second=10)

        for item in items:
            limiter.wait()  # Wait if needed
            response = client.get(f"/items/{item}")
    """

    def __init__(
        self,
        requests_per_second: float = 10.0,
        burst_size: int = 1
    ):
        """
        Initialize rate limiter.

        Args:
            requests_per_second: Maximum requests per second
            burst_size: Number of requests allowed in burst
        """
        self.interval = 1.0 / requests_per_second
        self.burst_size = burst_size
        self._tokens = burst_size
        self._last_update = time.time()
        self._lock = threading.Lock()

    def wait(self) -> float:
        """
        Wait if necessary to respect rate limit.

        Returns:
            Time waited in seconds
        """
        with self._lock:
            now = time.time()
            elapsed = now - self._last_update

            # Add tokens based on elapsed time
            self._tokens = min(
                self.burst_size,
                self._tokens + elapsed / self.interval
            )
            self._last_update = now

            if self._tokens >= 1:
                self._tokens -= 1
                return 0.0
            else:
                # Calculate wait time
                wait_time = (1 - self._tokens) * self.interval
                time.sleep(wait_time)
                self._tokens = 0
                self._last_update = time.time()
                return wait_time

    def __call__(self, func: F) -> F:
        """Decorator to apply rate limiting."""
        @wraps(func)
        def wrapper(*args, **kwargs):
            self.wait()
            return func(*args, **kwargs)
        return wrapper  # type: ignore


# =============================================================================
# Default instances
# =============================================================================

# Default HTTP client with sensible defaults
default_client = HTTPClient(HTTPClientConfig(
    timeout=30.0,
    connect_timeout=10.0,
    read_timeout=30.0,
    max_retries=3
)) if REQUESTS_AVAILABLE else None


def get_http_client() -> HTTPClient:
    """Get the default HTTP client."""
    if default_client is None:
        raise ImportError("requests library required")
    return default_client

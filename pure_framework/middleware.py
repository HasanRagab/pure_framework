"""
Pipeline-based middleware system with proper type safety and chain of responsibility pattern.
"""

from typing import List, Optional, Callable, Protocol, Any, Type
from abc import ABC, abstractmethod
from enum import Enum

from .framework_types import IRequest, IResponse, IMiddleware, IGuard, FrameworkError


class PipelineResult(Enum):
    """Result of pipeline execution."""

    CONTINUE = "continue"
    HALT = "halt"
    ERROR = "error"


class MiddlewareContext:
    """Context passed through middleware pipeline."""

    def __init__(self, request: IRequest, response: IResponse) -> None:
        self.request = request
        self.response = response
        self.data: dict[str, Any] = {}
        self.should_continue = True
        self.error: Optional[Exception] = None

    def halt(self, reason: Optional[str] = None) -> None:
        """Halt the pipeline execution."""
        self.should_continue = False
        if reason:
            self.data["halt_reason"] = reason

    def set_data(self, key: str, value: Any) -> None:
        """Set context data."""
        self.data[key] = value

    def get_data(self, key: str, default: Any = None) -> Any:
        """Get context data."""
        return self.data.get(key, default)


class BaseMiddleware(IMiddleware, ABC):
    """Base class for middleware implementations."""

    @abstractmethod
    def process(self, req: IRequest, res: IResponse) -> None:
        """Process the request/response."""
        pass

    def on_error(self, error: Exception, req: IRequest, res: IResponse) -> bool:
        """
        Handle errors that occur during processing.

        Args:
            error: The exception that occurred
            request: HTTP request
            response: HTTP response

        Returns:
            True if error was handled, False to propagate
        """
        return False


class AsyncMiddleware(BaseMiddleware):
    """Base class for async middleware (placeholder for future async support)."""

    def process(self, req: IRequest, res: IResponse) -> None:
        """Sync wrapper for async processing."""
        # For now, delegate to sync method
        self.process_sync(req, res)

    @abstractmethod
    def process_sync(self, request: IRequest, response: IResponse) -> None:
        """Synchronous processing method."""
        pass


class MiddlewarePipeline:
    """
    Pipeline for executing middleware in sequence.
    Implements chain of responsibility pattern with error handling.
    """

    def __init__(self, middlewares: Optional[List[IMiddleware]] = None) -> None:
        """
        Initialize pipeline with middlewares.

        Args:
            middlewares: List of middleware to execute
        """
        self._middlewares: List[IMiddleware] = middlewares or []
        self._error_handlers: List[Callable[[Exception, IRequest, IResponse], bool]] = []

    def add_middleware(self, middleware: IMiddleware) -> "MiddlewarePipeline":
        """
        Add middleware to the pipeline.

        Args:
            middleware: Middleware to add

        Returns:
            Self for method chaining
        """
        self._middlewares.append(middleware)
        return self

    def add_error_handler(
        self, handler: Callable[[Exception, IRequest, IResponse], bool]
    ) -> "MiddlewarePipeline":
        """
        Add error handler to the pipeline.

        Args:
            handler: Error handler function

        Returns:
            Self for method chaining
        """
        self._error_handlers.append(handler)
        return self

    def execute(self, request: IRequest, response: IResponse) -> PipelineResult:
        """
        Execute the middleware pipeline.

        Args:
            request: HTTP request
            response: HTTP response

        Returns:
            Pipeline execution result
        """
        context = MiddlewareContext(request, response)

        for middleware in self._middlewares:
            if not context.should_continue:
                break

            try:
                middleware.process(request, response)
            except Exception as e:
                context.error = e

                # Try to handle the error
                handled = False

                # First, try middleware's own error handler
                if isinstance(middleware, BaseMiddleware):
                    handled = middleware.on_error(e, request, response)

                # Then try pipeline error handlers
                if not handled:
                    for error_handler in self._error_handlers:
                        if error_handler(e, request, response):
                            handled = True
                            break

                if not handled:
                    return PipelineResult.ERROR

        if context.error:
            return PipelineResult.ERROR
        elif not context.should_continue:
            return PipelineResult.HALT
        else:
            return PipelineResult.CONTINUE

    def __len__(self) -> int:
        """Return number of middlewares."""
        return len(self._middlewares)

    def __repr__(self) -> str:
        return f"MiddlewarePipeline(middlewares={len(self._middlewares)})"


class BaseGuard(IGuard, ABC):
    """Base class for guard implementations."""

    @abstractmethod
    def can_activate(self, request: IRequest) -> bool:
        """Determine if the request can proceed."""
        pass

    def on_access_denied(self, request: IRequest, response: IResponse) -> None:
        """Called when access is denied."""
        response.status_code = 403
        response.json({"error": "Access denied", "message": "Insufficient permissions"})


class GuardPipeline:
    """Pipeline for executing guards in sequence."""

    def __init__(self, guards: Optional[List[IGuard]] = None) -> None:
        """
        Initialize pipeline with guards.

        Args:
            guards: List of guards to execute
        """
        self._guards: List[IGuard] = guards or []

    def add_guard(self, guard: IGuard) -> "GuardPipeline":
        """
        Add guard to the pipeline.

        Args:
            guard: Guard to add

        Returns:
            Self for method chaining
        """
        self._guards.append(guard)
        return self

    def can_activate(self, request: IRequest, response: IResponse) -> bool:
        """
        Check if all guards allow activation.

        Args:
            request: HTTP request
            response: HTTP response

        Returns:
            True if all guards pass, False otherwise
        """
        for guard in self._guards:
            if not guard.can_activate(request):
                # Handle access denied
                if isinstance(guard, BaseGuard):
                    guard.on_access_denied(request, response)
                else:
                    # Default access denied handling
                    response.status_code = 403
                    response.json({"error": "Access denied"})
                return False

        return True

    def __len__(self) -> int:
        """Return number of guards."""
        return len(self._guards)

    def __repr__(self) -> str:
        return f"GuardPipeline(guards={len(self._guards)})"


# Built-in middleware implementations


class LoggingMiddleware(BaseMiddleware):
    """Middleware for logging requests."""

    def __init__(self, logger: Optional[Callable[[str], None]] = None) -> None:
        """
        Initialize logging middleware.

        Args:
            logger: Optional custom logger function
        """
        self._logger = logger or print

    def process(self, req: IRequest, res: IResponse) -> None:
        """Log the request."""
        self._logger(f"{req.method.value} {req.path}")


class CorsMiddleware(BaseMiddleware):
    """Middleware for handling CORS."""

    def __init__(
        self,
        origins: Optional[List[str]] = None,
        methods: Optional[List[str]] = None,
        headers: Optional[List[str]] = None,
        allow_credentials: bool = False,
    ) -> None:
        """
        Initialize CORS middleware.

        Args:
            origins: Allowed origins
            methods: Allowed methods
            headers: Allowed headers
            allow_credentials: Whether to allow credentials
        """
        self.origins = origins or ["*"]
        self.methods = methods or ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
        self.headers = headers or ["Content-Type", "Authorization"]
        self.allow_credentials = allow_credentials

    def process(self, req: IRequest, res: IResponse) -> None:
        """Add CORS headers."""
        origin = req.get_header("origin")

        if self._is_origin_allowed(origin):
            res.set_header("Access-Control-Allow-Origin", origin or "*")

        res.set_header("Access-Control-Allow-Methods", ", ".join(self.methods))
        res.set_header("Access-Control-Allow-Headers", ", ".join(self.headers))

        if self.allow_credentials:
            res.set_header("Access-Control-Allow-Credentials", "true")

    def _is_origin_allowed(self, origin: Optional[str]) -> bool:
        """Check if origin is allowed."""
        if not origin:
            return True

        return "*" in self.origins or origin in self.origins


class SecurityHeadersMiddleware(BaseMiddleware):
    """Middleware for adding security headers."""

    def process(self, req: IRequest, res: IResponse) -> None:
        """Add security headers."""
        res.set_header("X-Content-Type-Options", "nosniff")
        res.set_header("X-Frame-Options", "DENY")
        res.set_header("X-XSS-Protection", "1; mode=block")
        res.set_header("Referrer-Policy", "strict-origin-when-cross-origin")


class CompressionMiddleware(BaseMiddleware):
    """Middleware for response compression (placeholder)."""

    def process(self, req: IRequest, res: IResponse) -> None:
        """Add compression headers."""
        accept_encoding = req.get_header("accept-encoding", "")

        if accept_encoding and "gzip" in accept_encoding:
            res.set_header("Content-Encoding", "gzip")
        elif accept_encoding and "deflate" in accept_encoding:
            res.set_header("Content-Encoding", "deflate")


# Built-in guard implementations


class AuthenticationGuard(BaseGuard):
    """Guard for checking authentication."""

    def __init__(self, token_header: str = "authorization") -> None:
        """
        Initialize authentication guard.

        Args:
            token_header: Header name for authentication token
        """
        self.token_header = token_header.lower()

    def can_activate(self, request: IRequest) -> bool:
        """Check if request has valid authentication."""
        auth_header = request.get_header(self.token_header)
        return auth_header is not None and auth_header.startswith("Bearer ")


class RoleGuard(BaseGuard):
    """Guard for checking user roles."""

    def __init__(self, required_roles: List[str]) -> None:
        """
        Initialize role guard.

        Args:
            required_roles: List of required roles
        """
        self.required_roles = required_roles

    def can_activate(self, request: IRequest) -> bool:
        """Check if user has required roles."""
        # This is a placeholder - in real implementation,
        # you would extract user roles from JWT token or session
        roles_header = request.get_header("x-user-roles", "")
        if not roles_header:
            return False
        user_roles = roles_header.split(",")
        return any(role.strip() in self.required_roles for role in user_roles)


class RateLimitGuard(BaseGuard):
    """Guard for rate limiting (simple implementation)."""

    def __init__(self, max_requests: int = 100, window_seconds: int = 3600) -> None:
        """
        Initialize rate limit guard.

        Args:
            max_requests: Maximum requests allowed
            window_seconds: Time window in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, List[float]] = {}

    def can_activate(self, request: IRequest) -> bool:
        """Check if request is within rate limits."""
        import time

        # Use IP as identifier (simplified)
        identifier = request.get_header("x-forwarded-for") or "unknown"
        current_time = time.time()

        if identifier not in self._requests:
            self._requests[identifier] = []

        # Clean old requests
        self._requests[identifier] = [
            req_time
            for req_time in self._requests[identifier]
            if current_time - req_time < self.window_seconds
        ]

        # Check limit
        if len(self._requests[identifier]) >= self.max_requests:
            return False

        # Add current request
        self._requests[identifier].append(current_time)
        return True

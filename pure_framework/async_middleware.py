"""
Async pipeline-based middleware system with proper    async def on_error(self, error: Exception, req: IRequest, res: IResponse) -> bool:
        Handle errors in async middleware.

        Args:
            error: The exception that occurred
            req: HTTP request
            res: HTTP response

        Returns:
            True if error was handled, False otherwise
        return Falseand chain of responsibility pattern.
"""

import asyncio
import inspect
from typing import List, Optional, Callable, Protocol, Any, Type, Union
from abc import ABC, abstractmethod
from enum import Enum

from .framework_types import (
    IRequest,
    IResponse,
    IMiddleware,
    IAsyncMiddleware,
    IGuard,
    IAsyncGuard,
    FrameworkError,
)


class AsyncPipelineResult(Enum):
    """Result of async pipeline execution."""

    CONTINUE = "continue"
    HALT = "halt"
    ERROR = "error"


class AsyncMiddlewareContext:
    """Context passed through async middleware pipeline."""

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


class BaseAsyncMiddleware(IAsyncMiddleware, ABC):
    """Base class for async middleware implementations."""

    @abstractmethod
    async def process(self, req: IRequest, res: IResponse) -> None:
        """Process the request/response through middleware."""
        pass

    async def on_error(self, error: Exception, req: IRequest, res: IResponse) -> bool:
        """
        Handle errors in async middleware.

        Args:
            error: The exception that occurred
            req: HTTP request
            res: HTTP response

        Returns:
            True if error was handled, False otherwise
        """
        return False


class AsyncMiddlewarePipeline:
    """
    Pipeline for executing middleware in sequence (async version).
    Implements chain of responsibility pattern with error handling.
    """

    def __init__(
        self, middlewares: Optional[List[Union[IMiddleware, IAsyncMiddleware]]] = None
    ) -> None:
        """
        Initialize pipeline with middlewares.

        Args:
            middlewares: List of middleware to execute (sync or async)
        """
        self._middlewares: List[Union[IMiddleware, IAsyncMiddleware]] = middlewares or []
        self._error_handlers: List[Callable[[Exception, IRequest, IResponse], bool]] = []

    def add_middleware(
        self, middleware: Union[IMiddleware, IAsyncMiddleware]
    ) -> "AsyncMiddlewarePipeline":
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
    ) -> "AsyncMiddlewarePipeline":
        """
        Add error handler to the pipeline.

        Args:
            handler: Error handler function

        Returns:
            Self for method chaining
        """
        self._error_handlers.append(handler)
        return self

    async def execute(self, request: IRequest, response: IResponse) -> AsyncPipelineResult:
        """
        Execute the async middleware pipeline.

        Args:
            request: HTTP request
            response: HTTP response

        Returns:
            Pipeline execution result
        """
        context = AsyncMiddlewareContext(request, response)

        for middleware in self._middlewares:
            if not context.should_continue:
                break

            try:
                # Check if middleware is async
                if hasattr(middleware, "process") and inspect.iscoroutinefunction(
                    middleware.process
                ):
                    await middleware.process(request, response)
                else:
                    # Sync middleware - run in thread pool to avoid blocking
                    middleware.process(request, response)
            except Exception as e:
                context.error = e

                # Try to handle the error
                handled = False

                # First, try middleware's own error handler
                if hasattr(middleware, "on_error"):
                    if inspect.iscoroutinefunction(middleware.on_error):
                        handled = await middleware.on_error(e, request, response)
                    else:
                        handled = middleware.on_error(e, request, response)

                # Then try pipeline error handlers
                if not handled:
                    for error_handler in self._error_handlers:
                        if inspect.iscoroutinefunction(error_handler):
                            if await error_handler(e, request, response):
                                handled = True
                                break
                        else:
                            if error_handler(e, request, response):
                                handled = True
                                break

                if not handled:
                    return AsyncPipelineResult.ERROR

        if context.error:
            return AsyncPipelineResult.ERROR
        elif not context.should_continue:
            return AsyncPipelineResult.HALT
        else:
            return AsyncPipelineResult.CONTINUE

    def __len__(self) -> int:
        """Return number of middlewares."""
        return len(self._middlewares)

    def __repr__(self) -> str:
        return f"AsyncMiddlewarePipeline(middlewares={len(self._middlewares)})"


class BaseAsyncGuard(IAsyncGuard, ABC):
    """Base class for async guard implementations."""

    @abstractmethod
    async def can_activate(self, request: IRequest) -> bool:
        """Determine if the request can proceed."""
        pass

    async def on_deny(self, request: IRequest, response: IResponse) -> None:
        """
        Called when guard denies access.

        Args:
            request: HTTP request
            response: HTTP response
        """
        response.status_code = 403
        response.json(
            {"error": "Forbidden", "message": "Access denied by guard", "status_code": 403}
        )


class AsyncGuardPipeline:
    """Pipeline for executing guards in sequence (async version)."""

    def __init__(self, guards: Optional[List[Union[IGuard, IAsyncGuard]]] = None) -> None:
        """
        Initialize pipeline with guards.

        Args:
            guards: List of guards to execute (sync or async)
        """
        self._guards: List[Union[IGuard, IAsyncGuard]] = guards or []

    def add_guard(self, guard: Union[IGuard, IAsyncGuard]) -> "AsyncGuardPipeline":
        """
        Add guard to the pipeline.

        Args:
            guard: Guard to add

        Returns:
            Self for method chaining
        """
        self._guards.append(guard)
        return self

    async def can_activate(self, request: IRequest, response: IResponse) -> bool:
        """
        Execute all guards and check if request can proceed.

        Args:
            request: HTTP request
            response: HTTP response

        Returns:
            True if all guards allow access
        """
        for guard in self._guards:
            try:
                # Check if guard is async
                if hasattr(guard, "can_activate") and inspect.iscoroutinefunction(
                    guard.can_activate
                ):
                    can_proceed = await guard.can_activate(request)
                else:
                    # Sync guard
                    can_proceed = guard.can_activate(request)

                if not can_proceed:
                    # Handle denial
                    if hasattr(guard, "on_deny"):
                        if inspect.iscoroutinefunction(guard.on_deny):
                            await guard.on_deny(request, response)
                        else:
                            guard.on_deny(request, response)
                    else:
                        # Default denial response
                        response.status_code = 403
                        response.json(
                            {"error": "Forbidden", "message": "Access denied", "status_code": 403}
                        )
                    return False
            except Exception as e:
                # Guard error - deny by default
                response.status_code = 500
                response.json(
                    {
                        "error": "Internal Server Error",
                        "message": f"Guard error: {str(e)}",
                        "status_code": 500,
                    }
                )
                return False

        return True

    def __len__(self) -> int:
        """Return number of guards."""
        return len(self._guards)

    def __repr__(self) -> str:
        return f"AsyncGuardPipeline(guards={len(self._guards)})"


# Built-in async middleware implementations


class AsyncLoggingMiddleware(BaseAsyncMiddleware):
    """Async middleware for logging requests."""

    def __init__(self, logger_name: str = "pure_framework_async") -> None:
        import logging

        self.logger = logging.getLogger(logger_name)

    async def process(self, req: IRequest, res: IResponse) -> None:
        """Log the request."""
        self.logger.info(f"{req.method} {req.path}")


class AsyncCorsMiddleware(BaseAsyncMiddleware):
    """Async middleware for handling CORS."""

    def __init__(
        self,
        allow_origins: Optional[List[str]] = None,
        allow_methods: Optional[List[str]] = None,
        allow_headers: Optional[List[str]] = None,
        allow_credentials: bool = False,
    ) -> None:
        self.allow_origins = allow_origins or ["*"]
        self.allow_methods = allow_methods or ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
        self.allow_headers = allow_headers or ["Content-Type", "Authorization"]
        self.allow_credentials = allow_credentials

    async def process(self, req: IRequest, res: IResponse) -> None:
        """Add CORS headers."""
        origin = req.get_header("origin")

        if "*" in self.allow_origins or (origin and origin in self.allow_origins):
            res.set_header("Access-Control-Allow-Origin", origin or "*")

        res.set_header("Access-Control-Allow-Methods", ", ".join(self.allow_methods))
        res.set_header("Access-Control-Allow-Headers", ", ".join(self.allow_headers))

        if self.allow_credentials:
            res.set_header("Access-Control-Allow-Credentials", "true")

        # Handle preflight requests
        if req.method.value == "OPTIONS":
            res.status_code = 204


class AsyncSecurityHeadersMiddleware(BaseAsyncMiddleware):
    """Async middleware for adding security headers."""

    async def process(self, req: IRequest, res: IResponse) -> None:
        """Add security headers."""
        res.set_header("X-Content-Type-Options", "nosniff")
        res.set_header("X-Frame-Options", "DENY")
        res.set_header("X-XSS-Protection", "1; mode=block")
        res.set_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")


# Built-in async guards


class AsyncAuthGuard(BaseAsyncGuard):
    """Async guard for authentication."""

    def __init__(self, auth_header_name: str = "authorization") -> None:
        self.auth_header_name = auth_header_name

    async def can_activate(self, request: IRequest) -> bool:
        """Check if request has valid authentication."""
        auth_header = request.get_header(self.auth_header_name)
        return auth_header is not None and len(auth_header.strip()) > 0

    async def on_deny(self, request: IRequest, response: IResponse) -> None:
        """Handle authentication denial."""
        response.status_code = 401
        response.json(
            {"error": "Unauthorized", "message": "Authentication required", "status_code": 401}
        )


class AsyncRoleGuard(BaseAsyncGuard):
    """Async guard for role-based authorization."""

    def __init__(self, required_roles: List[str]) -> None:
        self.required_roles = required_roles

    async def can_activate(self, request: IRequest) -> bool:
        """Check if request has required roles."""
        # This is a simple example - in practice you'd decode JWT or check session
        roles_header = request.get_header("x-user-roles")
        if not roles_header:
            return False

        user_roles = roles_header.split(",")
        return any(role.strip() in user_roles for role in self.required_roles)

    async def on_deny(self, request: IRequest, response: IResponse) -> None:
        """Handle role authorization denial."""
        response.status_code = 403
        response.json(
            {
                "error": "Forbidden",
                "message": f"Required roles: {', '.join(self.required_roles)}",
                "status_code": 403,
            }
        )

"""
Pure Framework - A lightweight Python web framework with modern design patterns.

Version 2.1.0 with enhanced features:
- Full type safety with protocols and generics
- Advanced dependency injection with automatic parameter resolution
- Pipeline-based middleware system with error handling
- Guard-based authorization with proper interfaces
- Async/await support for modern Python applications
- Request/response validation with detailed error messages
- Enhanced error handling with structured responses
- Comprehensive test client for easy testing
- CLI tool for project scaffolding and management
- Improved routing with regex compilation and parameter extraction
- Clean separation of concerns using SOLID principles
- Comprehensive OpenAPI documentation generation

Example usage:
    ```python
    from pure_framework import PureFramework, get, controller
    from pure_framework.framework_types import IRequest, IResponse

    app = PureFramework()

    @get('/hello')
    def hello(req: IRequest, res: IResponse) -> None:
        res.json({'message': 'Hello, World!'})

    app.run()
    ```

Async example:
    ```python
    from pure_framework import AsyncPureFramework, async_get
    from pure_framework.framework_types import IRequest, IResponse

    app = AsyncPureFramework()

    @async_get('/hello')
    async def hello(req: IRequest, res: IResponse) -> None:
        res.json({'message': 'Hello from async!'})

    app.run_async()
    ```
"""

# Core application
from .application import PureFramework

# Async application
try:
    from .async_application import AsyncPureFramework, AsyncApp
except ImportError:
    # Async features not available
    AsyncPureFramework = None
    AsyncApp = None

# Type definitions and protocols
from .framework_types import (
    # Core interfaces
    IRequest,
    IResponse,
    IMiddleware,
    IGuard,
    IRouter,
    IDependencyContainer,
    IApplication,
    IController,
    # Async interfaces
    IAsyncMiddleware,
    IAsyncGuard,
    # HTTP types
    HTTPMethod,
    Headers,
    QueryParams,
    PathParams,
    JSON,
    # Configuration and metadata
    ApplicationConfig,
    RouteInfo,
    ControllerMetadata,
    # Exceptions
    FrameworkError,
    RouteNotFoundError,
    DependencyResolutionError,
    ValidationError,
    ConfigurationError,
)

# HTTP abstractions
from .http import Request, Response

# Routing system
from .routing import Router, RouteGroup, RouteCompiler

# Dependency injection
from .dependency_injection import DependencyContainer, ServiceLocator, LifecycleType, inject

# Middleware and guards
from .middleware import (
    # Base classes
    BaseMiddleware,
    BaseGuard,
    # Pipeline classes
    MiddlewarePipeline,
    GuardPipeline,
)

# Decorators
from .decorators import (
    # Route decorators
    route,
    get,
    post,
    put,
    delete,
    patch,
    # Controller decorator
    controller,
    # Registry
    RouteRegistry,
)

# Async middleware and guards (if available)
try:
    from .async_middleware import (
        BaseAsyncMiddleware,
        BaseAsyncGuard,
        AsyncMiddlewarePipeline,
        AsyncGuardPipeline,
        AsyncLoggingMiddleware,
        AsyncCorsMiddleware,
        AsyncSecurityHeadersMiddleware,
        AsyncAuthGuard,
        AsyncRoleGuard,
    )
except ImportError:
    # Async features not available
    BaseAsyncMiddleware = None
    BaseAsyncGuard = None
    AsyncMiddlewarePipeline = None
    AsyncGuardPipeline = None
    AsyncLoggingMiddleware = None
    AsyncCorsMiddleware = None
    AsyncSecurityHeadersMiddleware = None
    AsyncAuthGuard = None
    AsyncRoleGuard = None

# Async decorators (if available)
try:
    from .async_decorators import (
        async_route,
        async_get,
        async_post,
        async_put,
        async_delete,
        async_patch,
        async_controller,
    )
except ImportError:
    # Async features not available
    async_route = None
    async_get = None
    async_post = None
    async_put = None
    async_delete = None
    async_patch = None
    async_controller = None

# Validation system
try:
    from .validation import (
        Schema,
        Validator,
        TypeValidator,
        StringValidator,
        NumberValidator,
        EmailValidator,
        ListValidator,
        ValidationResult,
        ValidationErrorDetail,
        ValidationErrorType,
        validate_json,
        validate_query,
        string,
        integer,
        number,
        email,
        list_of,
    )
except ImportError:
    # Validation features not available
    Schema = None
    Validator = None
    ValidationResult = None

# Enhanced error handling
try:
    from .errors import (
        HTTPException,
        BadRequestError,
        UnauthorizedError,
        ForbiddenError,
        NotFoundError,
        MethodNotAllowedError,
        ConflictError,
        ValidationError as ValidationHTTPError,
        RateLimitError,
        InternalServerError,
        ServiceUnavailableError,
        ErrorHandler,
        HTTPExceptionHandler,
        ValidationErrorHandler,
        GenericErrorHandler,
        ErrorHandlerRegistry,
        ErrorCategory,
        handle_errors,
        bad_request,
        unauthorized,
        forbidden,
        not_found,
        conflict,
        validation_error,
        rate_limit,
        internal_server_error,
        service_unavailable,
    )
except ImportError:
    # Error handling features not available
    HTTPException = None
    ErrorHandler = None
    handle_errors = None

# Test client
try:
    from .test_client import TestClient, TestResponse
except ImportError:
    # Test client not available
    TestClient = None
    TestResponse = None

# Documentation
from .swagger import OpenAPIGenerator

# Backward compatibility aliases
App = PureFramework

# Version
__version__ = "0.0.4"
__author__ = "Hasan Ragab"
__email__ = "hr145310@gmail.com"

# Public API
__all__ = [
    # Core
    "PureFramework",
    "App",
    # Async core (if available)
    "AsyncPureFramework",
    "AsyncApp",
    # Types and protocols
    "IRequest",
    "IResponse",
    "IMiddleware",
    "IAsyncMiddleware",
    "IGuard",
    "IAsyncGuard",
    "IRouter",
    "IDependencyContainer",
    "IApplication",
    "IController",
    "HTTPMethod",
    "Headers",
    "QueryParams",
    "PathParams",
    "JSON",
    "ApplicationConfig",
    "RouteInfo",
    "ControllerMetadata",
    "FrameworkError",
    "RouteNotFoundError",
    "DependencyResolutionError",
    "ValidationError",
    "ConfigurationError",
    # HTTP
    "Request",
    "Response",
    # Routing
    "Router",
    "RouteGroup",
    "RouteCompiler",
    # Dependency injection
    "DependencyContainer",
    "ServiceLocator",
    "LifecycleType",
    "inject",
    # Middleware and guards
    "BaseMiddleware",
    "BaseGuard",
    "MiddlewarePipeline",
    "GuardPipeline",
    # Decorators
    "route",
    "get",
    "post",
    "put",
    "delete",
    "patch",
    "controller",
    "RouteRegistry",
    # Documentation
    "OpenAPIGenerator",
]

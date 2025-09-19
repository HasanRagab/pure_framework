"""
Core type definitions and protocols for Pure Framework.
Provides type safety and clear interfaces for all framework components.
"""

from typing import (
    Any,
    Dict,
    List,
    Optional,
    Union,
    Callable,
    Protocol,
    TypeVar,
    Generic,
    runtime_checkable,
    Type,
    ClassVar,
    Awaitable,
    Tuple,
    Iterator,
)
from abc import ABC, abstractmethod
from enum import Enum
import json
from http.server import BaseHTTPRequestHandler


# Type aliases for better readability
JSON = Union[str, int, float, bool, None, Dict[str, Any], List[Any]]
Headers = Dict[str, str]
QueryParams = Dict[str, Union[str, List[str]]]
PathParams = Dict[str, str]
RouteHandler = Callable[..., Any]
AsyncRouteHandler = Callable[..., Awaitable[Any]]
MiddlewareFunction = Callable[["IRequest", "IResponse"], None]
AsyncMiddlewareFunction = Callable[["IRequest", "IResponse"], Awaitable[None]]
GuardFunction = Callable[["IRequest"], bool]
AsyncGuardFunction = Callable[["IRequest"], Awaitable[bool]]


# HTTP Method enumeration
class HTTPMethod(str, Enum):
    """HTTP methods supported by the framework."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


# Generic type variables
T = TypeVar("T")
RequestType = TypeVar("RequestType", bound="IRequest")
ResponseType = TypeVar("ResponseType", bound="IResponse")
ControllerType = TypeVar("ControllerType")


@runtime_checkable
class IRequest(Protocol):
    """Protocol defining the interface for HTTP request objects."""

    @property
    def path(self) -> str:
        """The request path."""
        ...

    @property
    def method(self) -> HTTPMethod:
        """The HTTP method."""
        ...

    @property
    def headers(self) -> Headers:
        """Request headers."""
        ...

    @property
    def query(self) -> QueryParams:
        """Query parameters."""
        ...

    @property
    def params(self) -> PathParams:
        """Path parameters from route matching."""
        ...

    @property
    def body(self) -> Optional[str]:
        """Raw request body."""
        ...

    @property
    def json(self) -> Optional[JSON]:
        """Parsed JSON body."""
        ...

    def get_header(self, name: str, default: Optional[str] = None) -> Optional[str]:
        """Get a specific header value."""
        ...

    def get_query(
        self, name: str, default: Optional[str] = None
    ) -> Optional[Union[str, List[str]]]:
        """Get a specific query parameter."""
        ...


@runtime_checkable
class IResponse(Protocol):
    """Protocol defining the interface for HTTP response objects."""

    @property
    def status_code(self) -> int:
        """HTTP status code."""
        ...

    @status_code.setter
    def status_code(self, value: int) -> None:
        """Set HTTP status code."""
        ...

    @property
    def headers(self) -> Headers:
        """Response headers."""
        ...

    def set_header(self, name: str, value: str) -> "IResponse":
        """Set a response header."""
        ...

    def json(self, data: JSON, status_code: Optional[int] = None) -> None:
        """Send JSON response."""
        ...

    def html(self, content: str, status_code: Optional[int] = None) -> None:
        """Send HTML response."""
        ...

    def text(self, content: str, status_code: Optional[int] = None) -> None:
        """Send text response."""
        ...

    def send(self, data: Union[str, bytes], status_code: Optional[int] = None) -> None:
        """Send raw response."""
        ...


@runtime_checkable
class IMiddleware(Protocol):
    """Protocol for middleware components."""

    def process(self, req: IRequest, res: IResponse) -> None:
        """Process the request/response through middleware."""
        ...

    def on_error(self, error: Exception, req: IRequest, res: IResponse) -> bool:
        """Handle errors in middleware. Return True if error was handled."""
        return False


@runtime_checkable
class IAsyncMiddleware(Protocol):
    """Protocol for async middleware components."""

    async def process(self, req: IRequest, res: IResponse) -> None:
        """Process the request/response through async middleware."""
        ...

    async def on_error(self, error: Exception, req: IRequest, res: IResponse) -> bool:
        """Handle errors in async middleware. Return True if error was handled."""
        return False


@runtime_checkable
class IGuard(Protocol):
    """Protocol for guard components."""

    def can_activate(self, request: IRequest) -> bool:
        """Determine if the request can proceed."""
        ...

    def on_deny(self, request: IRequest, response: IResponse) -> None:
        """Handle access denial."""
        response.status_code = 403
        response.json({"error": "Forbidden", "message": "Access denied", "status_code": 403})


@runtime_checkable
class IAsyncGuard(Protocol):
    """Protocol for async guard components."""

    async def can_activate(self, request: IRequest) -> bool:
        """Determine if the request can proceed (async)."""
        ...

    async def on_deny(self, request: IRequest, response: IResponse) -> None:
        """Handle access denial (async)."""
        response.status_code = 403
        response.json({"error": "Forbidden", "message": "Access denied", "status_code": 403})


class RouteInfo:
    """Immutable data class representing a route configuration."""

    def __init__(
        self,
        path: str,
        methods: List[HTTPMethod],
        handler: Union[RouteHandler, AsyncRouteHandler],
        controller_class: Optional[Type[Any]] = None,
        middlewares: Optional[List[Union[IMiddleware, IAsyncMiddleware]]] = None,
        guards: Optional[List[Union[IGuard, IAsyncGuard]]] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> None:
        self._path = path
        self._methods = tuple(methods)  # Immutable
        self._handler = handler
        self._controller_class = controller_class
        self._middlewares = tuple(middlewares or [])  # Immutable
        self._guards = tuple(guards or [])  # Immutable
        self._name = name or handler.__name__
        self._description = description or handler.__doc__

    @property
    def path(self) -> str:
        return self._path

    @property
    def methods(self) -> Tuple[HTTPMethod, ...]:
        return self._methods

    @property
    def handler(self) -> Union[RouteHandler, AsyncRouteHandler]:
        return self._handler

    @property
    def controller_class(self) -> Optional[Type[Any]]:
        return self._controller_class

    @property
    def middlewares(self) -> Tuple[Union[IMiddleware, IAsyncMiddleware], ...]:
        return self._middlewares

    @property
    def guards(self) -> Tuple[Union[IGuard, IAsyncGuard], ...]:
        return self._guards

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> Optional[str]:
        return self._description

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RouteInfo):
            return False
        return (
            self.path == other.path
            and self.methods == other.methods
            and self.handler == other.handler
        )

    def __hash__(self) -> int:
        return hash((self.path, self.methods, self.handler))

    def __repr__(self) -> str:
        return f"RouteInfo(path='{self.path}', methods={list(self.methods)}, handler={self.handler.__name__})"


@runtime_checkable
class IRouter(Protocol):
    """Protocol for routing components."""

    def add_route(self, route_info: RouteInfo) -> None:
        """Add a route to the router."""
        ...

    def match(self, path: str, method: HTTPMethod) -> Optional[Tuple[RouteInfo, PathParams]]:
        """Match a path and method to a route."""
        ...

    def get_routes(self) -> List[RouteInfo]:
        """Get all registered routes."""
        ...


@runtime_checkable
class IDependencyContainer(Protocol):
    """Protocol for dependency injection containers."""

    def register(
        self, interface: Type[T], implementation: Union[Type[T], T], singleton: bool = True
    ) -> None:
        """Register a dependency."""
        ...

    def register_type(
        self, interface: Type[T], implementation: Union[Type[T], T], lifecycle: Any = None
    ) -> "IDependencyContainer":
        """Register a type dependency."""
        ...

    def resolve(self, interface: Type[T]) -> T:
        """Resolve a dependency."""
        ...

    def is_registered(self, interface: Type[T]) -> bool:
        """Check if a dependency is registered."""
        ...


class ControllerMetadata:
    """Metadata for controller classes."""

    def __init__(
        self,
        prefix: str = "",
        children: Optional[List[Type[Any]]] = None,
        middlewares: Optional[List[IMiddleware]] = None,
        guards: Optional[List[IGuard]] = None,
    ) -> None:
        self.prefix = prefix
        self.children = children or []
        self.middlewares = middlewares or []
        self.guards = guards or []


@runtime_checkable
class IController(Protocol):
    """Protocol for controller classes."""

    __controller_metadata__: ClassVar[ControllerMetadata]


class ApplicationConfig:
    """Configuration for the application."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8000,
        debug: bool = False,
        enable_docs: bool = True,
        docs_path: str = "/docs",
        api_title: str = "Pure Framework API",
        api_version: str = "1.0.0",
        cors_enabled: bool = False,
        cors_origins: Optional[List[str]] = None,
        log_level: str = "INFO",
        max_request_size: int = 1024 * 1024 * 10,  # 10MB
        request_timeout: int = 30,
        enable_security_headers: bool = True,
        enable_request_logging: bool = True,
    ) -> None:
        self.host = host
        self.port = port
        self.debug = debug
        self.enable_docs = enable_docs
        self.docs_path = docs_path
        self.api_title = api_title
        self.api_version = api_version
        self.cors_enabled = cors_enabled
        self.cors_origins = cors_origins or ["*"]
        self.log_level = log_level
        self.max_request_size = max_request_size
        self.request_timeout = request_timeout
        self.enable_security_headers = enable_security_headers
        self.enable_request_logging = enable_request_logging


@runtime_checkable
class IApplication(Protocol):
    """Protocol for the main application."""

    def add_middleware(self, middleware: Union[IMiddleware, IAsyncMiddleware]) -> "IApplication":
        """Add global middleware."""
        ...

    def add_guard(self, guard: Union[IGuard, IAsyncGuard]) -> "IApplication":
        """Add global guard."""
        ...

    def register_controller(self, controller_class: Type[IController]) -> "IApplication":
        """Register a controller."""
        ...

    def run(self, host: Optional[str] = None, port: Optional[int] = None) -> None:
        """Start the application."""
        ...


class FrameworkError(Exception):
    """Base exception for framework errors."""

    pass


class RouteNotFoundError(FrameworkError):
    """Raised when a route is not found."""

    pass


class DependencyResolutionError(FrameworkError):
    """Raised when dependency resolution fails."""

    pass


class ValidationError(FrameworkError):
    """Raised when validation fails."""

    pass


class ConfigurationError(FrameworkError):
    """Raised when configuration is invalid."""

    pass

"""
Core type definitions and protocols for Pure Framework.
Provides type safety and clear interfaces for all framework components.
"""

from typing import (
    Any, Dict, List, Optional, Union, Callable, Protocol, TypeVar, Generic,
    runtime_checkable, Type, ClassVar, Awaitable, Tuple, Iterator
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
MiddlewareFunction = Callable[["IRequest", "IResponse"], None]
GuardFunction = Callable[["IRequest"], bool]

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
T = TypeVar('T')
RequestType = TypeVar('RequestType', bound='IRequest')
ResponseType = TypeVar('ResponseType', bound='IResponse')
ControllerType = TypeVar('ControllerType')


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
    
    def get_query(self, name: str, default: Optional[str] = None) -> Optional[Union[str, List[str]]]:
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
    
    def set_header(self, name: str, value: str) -> 'IResponse':
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
    
    def process(self, request: IRequest, response: IResponse) -> None:
        """Process the request/response through middleware."""
        ...


@runtime_checkable
class IGuard(Protocol):
    """Protocol for guard components."""
    
    def can_activate(self, request: IRequest) -> bool:
        """Determine if the request can proceed."""
        ...


class RouteInfo:
    """Immutable data class representing a route configuration."""
    
    def __init__(
        self,
        path: str,
        methods: List[HTTPMethod],
        handler: RouteHandler,
        controller_class: Optional[Type[Any]] = None,
        middlewares: Optional[List[IMiddleware]] = None,
        guards: Optional[List[IGuard]] = None,
        name: Optional[str] = None,
        description: Optional[str] = None
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
    def handler(self) -> RouteHandler:
        return self._handler
    
    @property
    def controller_class(self) -> Optional[Type[Any]]:
        return self._controller_class
    
    @property
    def middlewares(self) -> Tuple[IMiddleware, ...]:
        return self._middlewares
    
    @property
    def guards(self) -> Tuple[IGuard, ...]:
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
            self.path == other.path and
            self.methods == other.methods and
            self.handler == other.handler
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
    
    def register(self, interface: Type[T], implementation: Union[Type[T], T], singleton: bool = True) -> None:
        """Register a dependency."""
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
        guards: Optional[List[IGuard]] = None
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
        cors_origins: Optional[List[str]] = None
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


@runtime_checkable
class IApplication(Protocol):
    """Protocol for the main application."""
    
    def add_middleware(self, middleware: IMiddleware) -> 'IApplication':
        """Add global middleware."""
        ...
    
    def add_guard(self, guard: IGuard) -> 'IApplication':
        """Add global guard."""
        ...
    
    def register_controller(self, controller_class: Type[IController]) -> 'IApplication':
        """Register a controller."""
        ...
    
    def run(self, config: Optional[ApplicationConfig] = None) -> None:
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
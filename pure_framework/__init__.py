"""
Pure Framework - A lightweight Python web framework with modern design patterns.

Version 2.0.0 with improved architecture:
- Full type safety with protocols and generics
- Advanced dependency injection with automatic parameter resolution  
- Pipeline-based middleware system with error handling
- Guard-based authorization with proper interfaces
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
"""

# Core application
from .application import PureFramework

# Type definitions and protocols
from .framework_types import (
    # Core interfaces
    IRequest, IResponse, IMiddleware, IGuard, IRouter, IDependencyContainer,
    IApplication, IController,
    
    # HTTP types
    HTTPMethod, Headers, QueryParams, PathParams, JSON,
    
    # Configuration and metadata
    ApplicationConfig, RouteInfo, ControllerMetadata,
    
    # Exceptions
    FrameworkError, RouteNotFoundError, DependencyResolutionError,
    ValidationError, ConfigurationError
)

# HTTP abstractions
from .http import Request, Response

# Routing system
from .routing import Router, RouteGroup, RouteCompiler

# Dependency injection
from .dependency_injection import (
    DependencyContainer, ServiceLocator, LifecycleType,
    inject
)

# Middleware and guards
from .middleware import (
    # Base classes
    BaseMiddleware, BaseGuard,
    
    # Pipeline classes
    MiddlewarePipeline, GuardPipeline
)

# Decorators
from .decorators import (
    # Route decorators
    route, get, post, put, delete, patch,
    
    # Controller decorator
    controller,
    
    # Registry
    RouteRegistry
)

# Documentation
from .swagger import OpenAPIGenerator

from .http import Request, Response
from .routing import Router

# Backward compatibility aliases
App = PureFramework

# Version
__version__ = "0.0.3"
__author__ = "Hasan Ragab"
__email__ = "hr145310@gmail.com"

# Public API
__all__ = [
    # Core
    'PureFramework', 'App',
    
    # Types and protocols  
    'IRequest', 'IResponse', 'IMiddleware', 'IGuard', 'IRouter',
    'IDependencyContainer', 'IApplication', 'IController',
    'HTTPMethod', 'Headers', 'QueryParams', 'PathParams', 'JSON',
    'ApplicationConfig', 'RouteInfo', 'ControllerMetadata',
    'FrameworkError', 'RouteNotFoundError', 'DependencyResolutionError',
    'ValidationError', 'ConfigurationError',
    
    # HTTP
    'Request', 'Response',
    
    # Routing
    'Router', 'RouteGroup', 'RouteCompiler',
    
    # Dependency injection
    'DependencyContainer', 'ServiceLocator', 'LifecycleType', 'inject',

    # Middleware and guards
    'BaseMiddleware', 'BaseGuard',
    'MiddlewarePipeline', 'GuardPipeline',
    
    # Decorators
    'route', 'get', 'post', 'put', 'delete', 'patch', 'controller',
    'RouteRegistry',
    
    # Documentation
    'OpenAPIGenerator',
    
]

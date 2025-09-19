"""
Async decorators for the Pure Framework.
"""

from typing import Callable, List, Optional, Union, Type, Any
from functools import wraps
import inspect

from .framework_types import (
    HTTPMethod,
    IMiddleware,
    IAsyncMiddleware,
    IGuard,
    IAsyncGuard,
    RouteHandler,
    AsyncRouteHandler,
)
from .decorators import RouteRegistry, RouteInfo


# Type for functions that can be sync or async
AsyncRouteHandlerType = Union[RouteHandler, AsyncRouteHandler]
F = Callable[..., Any]


def async_route(
    path: str,
    methods: Optional[List[Union[str, HTTPMethod]]] = None,
    *,
    middlewares: Optional[
        List[Union[IMiddleware, IAsyncMiddleware, Type[IMiddleware], Type[IAsyncMiddleware]]]
    ] = None,
    guards: Optional[List[Union[IGuard, IAsyncGuard, Type[IGuard], Type[IAsyncGuard]]]] = None,
    name: Optional[str] = None,
    description: Optional[str] = None,
) -> Callable[[F], F]:
    """
    Decorator for defining async routes.

    Args:
        path: Route path pattern
        methods: HTTP methods (defaults to GET for async routes)
        middlewares: Middleware instances or classes (sync or async)
        guards: Guard instances or classes (sync or async)
        name: Route name for URL generation
        description: Route description for documentation

    Returns:
        Decorated function
    """
    from .decorators import _resolve_middleware_instances, _resolve_guard_instances

    # Default to GET if not specified
    if methods is None:
        converted_methods = [HTTPMethod.GET]
    else:
        converted_methods = [HTTPMethod(m) if isinstance(m, str) else m for m in methods]

    # Resolve middleware instances (supporting both sync and async)
    resolved_middlewares = []
    if middlewares:
        for middleware in middlewares:
            if inspect.isclass(middleware):
                resolved_middlewares.append(middleware())
            else:
                resolved_middlewares.append(middleware)

    # Resolve guard instances (supporting both sync and async)
    resolved_guards = []
    if guards:
        for guard in guards:
            if inspect.isclass(guard):
                resolved_guards.append(guard())
            else:
                resolved_guards.append(guard)

    def decorator(func: F) -> F:
        # Ensure the function is async
        if not inspect.iscoroutinefunction(func):
            raise ValueError(
                f"Function {func.__name__} must be async when using async_route decorator"
            )

        # Check if this is a controller method
        frame = inspect.currentframe()
        is_controller_method = False
        if frame and frame.f_back:
            caller_locals = frame.f_back.f_locals
            if "self" in caller_locals or any(
                hasattr(obj, "__controller_metadata__")
                for obj in caller_locals.values()
                if hasattr(obj, "__dict__")
            ):
                is_controller_method = True

        # Create route info
        route_info = RouteInfo(
            path=path,
            methods=converted_methods,
            handler=func,
            middlewares=resolved_middlewares,
            guards=resolved_guards,
            name=name or func.__name__,
            description=description or func.__doc__,
        )

        if not is_controller_method:
            # Standalone function - register immediately
            RouteRegistry.add_route(route_info)
        else:
            # Controller method - store for later registration
            if not hasattr(func, "_route_info"):
                setattr(func, "_route_info", [])
            route_list = getattr(func, "_route_info", [])
            route_list.append(route_info)
            setattr(func, "_route_info", route_list)

        return func

    return decorator


def async_get(
    path: str,
    *,
    middlewares: Optional[
        List[Union[IMiddleware, IAsyncMiddleware, Type[IMiddleware], Type[IAsyncMiddleware]]]
    ] = None,
    guards: Optional[List[Union[IGuard, IAsyncGuard, Type[IGuard], Type[IAsyncGuard]]]] = None,
    name: Optional[str] = None,
    description: Optional[str] = None,
) -> Callable[[F], F]:
    """Decorator for async GET routes."""
    return async_route(
        path,
        [HTTPMethod.GET],
        middlewares=middlewares,
        guards=guards,
        name=name,
        description=description,
    )


def async_post(
    path: str,
    *,
    middlewares: Optional[
        List[Union[IMiddleware, IAsyncMiddleware, Type[IMiddleware], Type[IAsyncMiddleware]]]
    ] = None,
    guards: Optional[List[Union[IGuard, IAsyncGuard, Type[IGuard], Type[IAsyncGuard]]]] = None,
    name: Optional[str] = None,
    description: Optional[str] = None,
) -> Callable[[F], F]:
    """Decorator for async POST routes."""
    return async_route(
        path,
        [HTTPMethod.POST],
        middlewares=middlewares,
        guards=guards,
        name=name,
        description=description,
    )


def async_put(
    path: str,
    *,
    middlewares: Optional[
        List[Union[IMiddleware, IAsyncMiddleware, Type[IMiddleware], Type[IAsyncMiddleware]]]
    ] = None,
    guards: Optional[List[Union[IGuard, IAsyncGuard, Type[IGuard], Type[IAsyncGuard]]]] = None,
    name: Optional[str] = None,
    description: Optional[str] = None,
) -> Callable[[F], F]:
    """Decorator for async PUT routes."""
    return async_route(
        path,
        [HTTPMethod.PUT],
        middlewares=middlewares,
        guards=guards,
        name=name,
        description=description,
    )


def async_delete(
    path: str,
    *,
    middlewares: Optional[
        List[Union[IMiddleware, IAsyncMiddleware, Type[IMiddleware], Type[IAsyncMiddleware]]]
    ] = None,
    guards: Optional[List[Union[IGuard, IAsyncGuard, Type[IGuard], Type[IAsyncGuard]]]] = None,
    name: Optional[str] = None,
    description: Optional[str] = None,
) -> Callable[[F], F]:
    """Decorator for async DELETE routes."""
    return async_route(
        path,
        [HTTPMethod.DELETE],
        middlewares=middlewares,
        guards=guards,
        name=name,
        description=description,
    )


def async_patch(
    path: str,
    *,
    middlewares: Optional[
        List[Union[IMiddleware, IAsyncMiddleware, Type[IMiddleware], Type[IAsyncMiddleware]]]
    ] = None,
    guards: Optional[List[Union[IGuard, IAsyncGuard, Type[IGuard], Type[IAsyncGuard]]]] = None,
    name: Optional[str] = None,
    description: Optional[str] = None,
) -> Callable[[F], F]:
    """Decorator for async PATCH routes."""
    return async_route(
        path,
        [HTTPMethod.PATCH],
        middlewares=middlewares,
        guards=guards,
        name=name,
        description=description,
    )


def async_controller(
    prefix: str = "",
    *,
    middlewares: Optional[
        List[Union[IMiddleware, IAsyncMiddleware, Type[IMiddleware], Type[IAsyncMiddleware]]]
    ] = None,
    guards: Optional[List[Union[IGuard, IAsyncGuard, Type[IGuard], Type[IAsyncGuard]]]] = None,
    children: Optional[List[Type[Any]]] = None,
) -> Callable[[Type[Any]], Type[Any]]:
    """
    Decorator for defining async controllers.

    Args:
        prefix: Path prefix for all routes in controller
        middlewares: Default middlewares for all routes (sync or async)
        guards: Default guards for all routes (sync or async)
        children: Child controller classes

    Returns:
        Decorated controller class
    """
    from .decorators import _validate_controller_class, _process_controller_routes
    from .framework_types import ControllerMetadata

    # Resolve middleware instances
    resolved_middlewares = []
    if middlewares:
        for middleware in middlewares:
            if inspect.isclass(middleware):
                resolved_middlewares.append(middleware())
            else:
                resolved_middlewares.append(middleware)

    # Resolve guard instances
    resolved_guards = []
    if guards:
        for guard in guards:
            if inspect.isclass(guard):
                resolved_guards.append(guard())
            else:
                resolved_guards.append(guard)

    def decorator(cls: Type[Any]) -> Type[Any]:
        # Validate controller class
        _validate_controller_class(cls)

        # Create controller metadata
        metadata = ControllerMetadata(
            prefix=prefix.rstrip("/"),  # Remove trailing slash
            children=children or [],
            middlewares=resolved_middlewares,
            guards=resolved_guards,
        )

        # Store metadata on the class
        setattr(cls, "__controller_metadata__", metadata)

        # Register controller
        RouteRegistry.add_controller(cls, metadata)

        # Process route methods
        _process_controller_routes(cls, metadata)

        return cls

    return decorator

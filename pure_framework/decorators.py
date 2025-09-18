"""
Type-safe decorator system with improved route registration and validation.
"""

import inspect
from typing import Any, Callable, List, Optional, Type, TypeVar, Union, get_type_hints, Dict, cast
from functools import wraps

from .framework_types import (
    HTTPMethod,
    RouteInfo,
    IMiddleware,
    IGuard,
    ControllerMetadata,
    IController,
    ValidationError,
)
from .middleware import BaseMiddleware, BaseGuard


# Type variables
F = TypeVar("F", bound=Callable[..., Any])
ControllerType = TypeVar("ControllerType")

# Global route registry
_route_registry: List[RouteInfo] = []
_controller_registry: Dict[Type[Any], ControllerMetadata] = {}


class RouteRegistry:
    """Global registry for routes and controllers."""

    @classmethod
    def add_route(cls, route_info: RouteInfo) -> None:
        """Add a route to the global registry."""
        _route_registry.append(route_info)

    @classmethod
    def get_routes(cls) -> List[RouteInfo]:
        """Get all registered routes."""
        return _route_registry.copy()

    @classmethod
    def clear_routes(cls) -> None:
        """Clear all registered routes."""
        _route_registry.clear()

    @classmethod
    def add_controller(cls, controller_class: Type[Any], metadata: ControllerMetadata) -> None:
        """Add a controller to the registry."""
        _controller_registry[controller_class] = metadata

    @classmethod
    def get_controllers(cls) -> Dict[Type[Any], ControllerMetadata]:
        """Get all registered controllers."""
        return _controller_registry.copy()

    @classmethod
    def clear_controllers(cls) -> None:
        """Clear all registered controllers."""
        _controller_registry.clear()


def route(
    path: str,
    methods: Optional[List[Union[str, HTTPMethod]]] = None,
    *,
    middlewares: Optional[List[Union[IMiddleware, Type[IMiddleware]]]] = None,
    guards: Optional[List[Union[IGuard, Type[IGuard]]]] = None,
    name: Optional[str] = None,
    description: Optional[str] = None,
) -> Callable[[F], F]:
    """
    Decorator for defining routes with type safety and validation.

    Args:
        path: Route path pattern (e.g., '/users/:id')
        methods: HTTP methods (defaults to ['GET'])
        middlewares: Middleware instances or classes
        guards: Guard instances or classes
        name: Optional route name
        description: Optional route description

    Returns:
        Decorated function

    Raises:
        ValidationError: If route configuration is invalid
    """
    # Normalize methods
    if methods is None:
        normalized_methods = [HTTPMethod.GET]
    else:
        normalized_methods = [HTTPMethod(m) if isinstance(m, str) else m for m in methods]

    # Resolve middleware instances
    resolved_middlewares = _resolve_middleware_instances(middlewares or [])

    # Resolve guard instances
    resolved_guards = _resolve_guard_instances(guards or [])

    def decorator(func: F) -> F:
        # Validate function signature
        _validate_route_handler(func)

        # Determine if this is a controller method or standalone function
        sig = inspect.signature(func)
        params = list(sig.parameters.keys())
        is_controller_method = len(params) > 0 and params[0] == "self"

        # Create route info
        route_info = RouteInfo(
            path=path,
            methods=normalized_methods,
            handler=func,
            controller_class=None,  # Will be set later for controller methods
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


def get(
    path: str,
    *,
    middlewares: Optional[List[Union[IMiddleware, Type[IMiddleware]]]] = None,
    guards: Optional[List[Union[IGuard, Type[IGuard]]]] = None,
    name: Optional[str] = None,
    description: Optional[str] = None,
) -> Callable[[F], F]:
    """Decorator for GET routes."""
    return route(
        path,
        [HTTPMethod.GET],
        middlewares=middlewares,
        guards=guards,
        name=name,
        description=description,
    )


def post(
    path: str,
    *,
    middlewares: Optional[List[Union[IMiddleware, Type[IMiddleware]]]] = None,
    guards: Optional[List[Union[IGuard, Type[IGuard]]]] = None,
    name: Optional[str] = None,
    description: Optional[str] = None,
) -> Callable[[F], F]:
    """Decorator for POST routes."""
    return route(
        path,
        [HTTPMethod.POST],
        middlewares=middlewares,
        guards=guards,
        name=name,
        description=description,
    )


def put(
    path: str,
    *,
    middlewares: Optional[List[Union[IMiddleware, Type[IMiddleware]]]] = None,
    guards: Optional[List[Union[IGuard, Type[IGuard]]]] = None,
    name: Optional[str] = None,
    description: Optional[str] = None,
) -> Callable[[F], F]:
    """Decorator for PUT routes."""
    return route(
        path,
        [HTTPMethod.PUT],
        middlewares=middlewares,
        guards=guards,
        name=name,
        description=description,
    )


def delete(
    path: str,
    *,
    middlewares: Optional[List[Union[IMiddleware, Type[IMiddleware]]]] = None,
    guards: Optional[List[Union[IGuard, Type[IGuard]]]] = None,
    name: Optional[str] = None,
    description: Optional[str] = None,
) -> Callable[[F], F]:
    """Decorator for DELETE routes."""
    return route(
        path,
        [HTTPMethod.DELETE],
        middlewares=middlewares,
        guards=guards,
        name=name,
        description=description,
    )


def patch(
    path: str,
    *,
    middlewares: Optional[List[Union[IMiddleware, Type[IMiddleware]]]] = None,
    guards: Optional[List[Union[IGuard, Type[IGuard]]]] = None,
    name: Optional[str] = None,
    description: Optional[str] = None,
) -> Callable[[F], F]:
    """Decorator for PATCH routes."""
    return route(
        path,
        [HTTPMethod.PATCH],
        middlewares=middlewares,
        guards=guards,
        name=name,
        description=description,
    )


def controller(
    prefix: str = "",
    *,
    middlewares: Optional[List[Union[IMiddleware, Type[IMiddleware]]]] = None,
    guards: Optional[List[Union[IGuard, Type[IGuard]]]] = None,
    children: Optional[List[Type[Any]]] = None,
) -> Callable[[Type[ControllerType]], Type[ControllerType]]:
    """
    Decorator for defining controllers with type safety.

    Args:
        prefix: Path prefix for all routes in controller
        middlewares: Default middlewares for all routes
        guards: Default guards for all routes
        children: Child controller classes

    Returns:
        Decorated controller class
    """
    # Resolve middleware instances
    resolved_middlewares = _resolve_middleware_instances(middlewares or [])

    # Resolve guard instances
    resolved_guards = _resolve_guard_instances(guards or [])

    def decorator(cls: Type[ControllerType]) -> Type[ControllerType]:
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


def middleware(*middleware_classes: Type[IMiddleware]) -> Callable[[F], F]:
    """
    Decorator for applying middleware to individual routes.

    Args:
        middleware_classes: Middleware classes to apply

    Returns:
        Decorated function
    """

    def decorator(func: F) -> F:
        if not hasattr(func, "_middleware_classes"):
            setattr(func, "_middleware_classes", [])
        middleware_list = getattr(func, "_middleware_classes", [])
        middleware_list.extend(middleware_classes)
        setattr(func, "_middleware_classes", middleware_list)
        return func

    return decorator


def guard(*guard_classes: Type[IGuard]) -> Callable[[F], F]:
    """
    Decorator for applying guards to individual routes.

    Args:
        guard_classes: Guard classes to apply

    Returns:
        Decorated function
    """

    def decorator(func: F) -> F:
        if not hasattr(func, "_guard_classes"):
            setattr(func, "_guard_classes", [])
        guard_list = getattr(func, "_guard_classes", [])
        guard_list.extend(guard_classes)
        setattr(func, "_guard_classes", guard_list)
        return func

    return decorator


def validate_json(schema: Dict[str, Any]) -> Callable[[F], F]:
    """
    Decorator for JSON validation (placeholder for future implementation).

    Args:
        schema: JSON schema for validation

    Returns:
        Decorated function
    """

    def decorator(func: F) -> F:
        # Store schema for later use
        setattr(func, "_json_schema", schema)
        return func

    return decorator


def _resolve_middleware_instances(
    middlewares: List[Union[IMiddleware, Type[IMiddleware]]],
) -> List[IMiddleware]:
    """Resolve middleware classes to instances."""
    instances: List[IMiddleware] = []

    for mw in middlewares:
        if inspect.isclass(mw):
            # It's a class, instantiate it
            instances.append(mw())  # type: ignore
        else:
            # It's already an instance
            instances.append(mw)

    return instances


def _resolve_guard_instances(guards: List[Union[IGuard, Type[IGuard]]]) -> List[IGuard]:
    """Resolve guard classes to instances."""
    instances: List[IGuard] = []

    for guard in guards:
        if inspect.isclass(guard):
            # It's a class, instantiate it
            instances.append(guard())  # type: ignore
        else:
            # It's already an instance
            instances.append(guard)

    return instances


def _validate_route_handler(func: Callable[..., Any]) -> None:
    """
    Validate that a function can be used as a route handler.

    Args:
        func: Function to validate

    Raises:
        ValidationError: If function is not valid
    """
    if not callable(func):
        raise ValidationError(f"Route handler must be callable, got {type(func)}")

    sig = inspect.signature(func)
    params = list(sig.parameters.keys())

    # Check for required parameters
    if len(params) < 2:
        raise ValidationError(
            f"Route handler must accept at least 2 parameters (req, res), got {len(params)}"
        )

    # Get type hints
    type_hints = get_type_hints(func)

    # Check parameter names and types (for standalone functions)
    if params[0] != "self":
        # Standalone function
        expected_params = ["req", "res"]
        for i, expected in enumerate(expected_params):
            if i >= len(params):
                raise ValidationError(f"Route handler missing parameter '{expected}'")

            if params[i] != expected:
                # Allow flexibility in parameter names, but warn
                pass


def _validate_controller_class(cls: Type[Any]) -> None:
    """
    Validate that a class can be used as a controller.

    Args:
        cls: Class to validate

    Raises:
        ValidationError: If class is not valid
    """
    if not inspect.isclass(cls):
        raise ValidationError(f"Controller must be a class, got {type(cls)}")

    # Check for route methods
    has_routes = False
    for attr_name in dir(cls):
        attr = getattr(cls, attr_name, None)
        if hasattr(attr, "_route_info"):
            has_routes = True
            break

    if not has_routes:
        # Warning: controller has no routes
        pass


def _process_controller_routes(cls: Type[Any], metadata: ControllerMetadata) -> None:
    """
    Process routes defined in a controller class.

    Args:
        cls: Controller class
        metadata: Controller metadata
    """
    for attr_name in dir(cls):
        attr = getattr(cls, attr_name, None)

        if attr is not None and hasattr(attr, "_route_info"):
            # Process each route defined on this method
            for route_info in attr._route_info:
                # Create full path with controller prefix
                full_path = metadata.prefix + (
                    "/" + route_info.path.lstrip("/") if route_info.path else ""
                )

                # Combine controller and route middlewares/guards
                combined_middlewares = list(metadata.middlewares) + list(route_info.middlewares)
                combined_guards = list(metadata.guards) + list(route_info.guards)

                # Create new route info with controller data
                controller_route_info = RouteInfo(
                    path=full_path,
                    methods=route_info.methods,
                    handler=route_info.handler,
                    controller_class=cls,
                    middlewares=combined_middlewares,
                    guards=combined_guards,
                    name=route_info.name,
                    description=route_info.description,
                )

                # Register the route
                RouteRegistry.add_route(controller_route_info)


def api_response(
    status_code: int = 200, description: str = "", content_type: str = "application/json"
) -> Callable[[F], F]:
    """
    Decorator for documenting API responses (for OpenAPI generation).

    Args:
        status_code: HTTP status code
        description: Response description
        content_type: Response content type

    Returns:
        Decorated function
    """

    def decorator(func: F) -> F:
        if not hasattr(func, "_api_responses"):
            setattr(func, "_api_responses", [])

        api_responses = getattr(func, "_api_responses", [])
        api_responses.append(
            {
                "status_code": status_code,
                "description": description,
                "content_type": content_type,
            }
        )
        setattr(func, "_api_responses", api_responses)

        return func

    return decorator


def deprecated(reason: str = "") -> Callable[[F], F]:
    """
    Decorator for marking routes as deprecated.

    Args:
        reason: Reason for deprecation

    Returns:
        Decorated function
    """

    def decorator(func: F) -> F:
        setattr(func, "_deprecated", True)
        setattr(func, "_deprecation_reason", reason)
        return func

    return decorator

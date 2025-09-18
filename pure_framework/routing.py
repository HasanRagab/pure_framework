"""
Type-safe routing system with improved pattern matching and route management.
"""

import re
from typing import Dict, List, Optional, Tuple, Set, Pattern, Iterator
from dataclasses import dataclass

from .framework_types import IRouter, RouteInfo, HTTPMethod, PathParams, ValidationError


@dataclass(frozen=True)
class CompiledRoute:
    """Immutable compiled route with regex pattern and metadata."""
    route_info: RouteInfo
    pattern: Pattern[str]
    param_names: Tuple[str, ...]
    
    def match(self, path: str, method: HTTPMethod) -> Optional[PathParams]:
        """
        Match a path against this route.
        
        Args:
            path: Request path
            method: HTTP method
            
        Returns:
            Path parameters if matched, None otherwise
        """
        if method not in self.route_info.methods:
            return None
            
        match = self.pattern.match(path)
        if not match:
            return None
            
        # Extract path parameters
        params: PathParams = {}
        for i, name in enumerate(self.param_names, 1):
            value = match.group(i)
            if value is not None:
                params[name] = value
                
        return params


class RouteCompiler:
    """Compiles route patterns into regex patterns with parameter extraction."""
    
    # Parameter pattern: :param or :param(regex)
    PARAM_PATTERN = re.compile(r':([a-zA-Z_][a-zA-Z0-9_]*)(?:\(([^)]+)\))?')
    
    @classmethod
    def compile_route(cls, route_info: RouteInfo) -> CompiledRoute:
        """
        Compile a route into a regex pattern.
        
        Args:
            route_info: Route information
            
        Returns:
            Compiled route
            
        Raises:
            ValidationError: If route pattern is invalid
        """
        try:
            pattern, param_names = cls._compile_pattern(route_info.path)
            return CompiledRoute(
                route_info=route_info,
                pattern=pattern,
                param_names=tuple(param_names)
            )
        except re.error as e:
            raise ValidationError(f"Invalid route pattern '{route_info.path}': {e}")
    
    @classmethod
    def _compile_pattern(cls, path: str) -> Tuple[Pattern[str], List[str]]:
        """
        Compile a path pattern into regex.
        
        Args:
            path: Path pattern (e.g., "/users/:id/posts/:slug")
            
        Returns:
            Tuple of compiled regex and parameter names
        """
        if not path.startswith('/'):
            path = '/' + path
            
        param_names: List[str] = []
        regex_parts: List[str] = ['^']
        
        last_end = 0
        
        for match in cls.PARAM_PATTERN.finditer(path):
            # Add literal part before parameter
            literal_part = path[last_end:match.start()]
            regex_parts.append(re.escape(literal_part))
            
            param_name = match.group(1)
            param_regex = match.group(2) or '[^/]+'  # Default to non-slash characters
            
            param_names.append(param_name)
            regex_parts.append(f'({param_regex})')
            
            last_end = match.end()
        
        # Add remaining literal part
        if last_end < len(path):
            regex_parts.append(re.escape(path[last_end:]))
        
        regex_parts.append('$')
        
        pattern = re.compile(''.join(regex_parts))
        return pattern, param_names


class Router(IRouter):
    """
    High-performance router with type safety and efficient matching.
    
    Features:
    - Compiled regex patterns for fast matching
    - Method-based route grouping for efficiency
    - Conflict detection and validation
    - Immutable route storage
    """
    
    def __init__(self) -> None:
        """Initialize empty router."""
        self._routes: List[CompiledRoute] = []
        self._routes_by_method: Dict[HTTPMethod, List[CompiledRoute]] = {}
        self._route_patterns: Set[str] = set()
        
    def add_route(self, route_info: RouteInfo) -> None:
        """
        Add a route to the router.
        
        Args:
            route_info: Route information
            
        Raises:
            ValidationError: If route conflicts with existing routes
        """
        self._validate_route(route_info)
        
        compiled_route = RouteCompiler.compile_route(route_info)
        self._routes.append(compiled_route)
        
        # Group by HTTP method for efficient lookup
        for method in route_info.methods:
            if method not in self._routes_by_method:
                self._routes_by_method[method] = []
            self._routes_by_method[method].append(compiled_route)
        
        # Track patterns for conflict detection
        for method in route_info.methods:
            pattern_key = f"{method.value}:{route_info.path}"
            if pattern_key in self._route_patterns:
                raise ValidationError(
                    f"Route conflict: {method.value} {route_info.path} already exists"
                )
            self._route_patterns.add(pattern_key)
    
    def match(self, path: str, method: HTTPMethod) -> Optional[Tuple[RouteInfo, PathParams]]:
        """
        Match a path and method to a route.
        
        Args:
            path: Request path
            method: HTTP method
            
        Returns:
            Tuple of route info and path parameters, or None if no match
        """
        # Normalize path
        if not path.startswith('/'):
            path = '/' + path
            
        # Look up routes for this method
        method_routes = self._routes_by_method.get(method, [])
        
        for compiled_route in method_routes:
            params = compiled_route.match(path, method)
            if params is not None:
                return compiled_route.route_info, params
        
        return None
    
    def get_routes(self) -> List[RouteInfo]:
        """
        Get all registered routes.
        
        Returns:
            List of route information (immutable)
        """
        return [compiled_route.route_info for compiled_route in self._routes]
    
    def get_routes_for_method(self, method: HTTPMethod) -> List[RouteInfo]:
        """
        Get routes for a specific HTTP method.
        
        Args:
            method: HTTP method
            
        Returns:
            List of route information for the method
        """
        method_routes = self._routes_by_method.get(method, [])
        return [compiled_route.route_info for compiled_route in method_routes]
    
    def remove_route(self, path: str, method: HTTPMethod) -> bool:
        """
        Remove a route from the router.
        
        Args:
            path: Route path
            method: HTTP method
            
        Returns:
            True if route was removed, False if not found
        """
        pattern_key = f"{method.value}:{path}"
        if pattern_key not in self._route_patterns:
            return False
        
        # Remove from main routes list
        self._routes = [
            route for route in self._routes 
            if not (route.route_info.path == path and method in route.route_info.methods)
        ]
        
        # Remove from method-specific lists
        if method in self._routes_by_method:
            self._routes_by_method[method] = [
                route for route in self._routes_by_method[method]
                if route.route_info.path != path
            ]
        
        # Remove from pattern tracking
        self._route_patterns.discard(pattern_key)
        
        return True
    
    def clear(self) -> None:
        """Clear all routes."""
        self._routes.clear()
        self._routes_by_method.clear()
        self._route_patterns.clear()
    
    def _validate_route(self, route_info: RouteInfo) -> None:
        """
        Validate a route before adding it.
        
        Args:
            route_info: Route to validate
            
        Raises:
            ValidationError: If route is invalid
        """
        if not route_info.path:
            raise ValidationError("Route path cannot be empty")
        
        if not route_info.methods:
            raise ValidationError("Route must have at least one HTTP method")
        
        if not route_info.handler:
            raise ValidationError("Route must have a handler")
        
        # Validate path format
        if not route_info.path.startswith('/'):
            # This is just a warning - we'll normalize it
            pass
    
    def __len__(self) -> int:
        """Return number of routes."""
        return len(self._routes)
    
    def __iter__(self) -> Iterator[RouteInfo]:
        """Iterate over route information."""
        return iter(self.get_routes())
    
    def __repr__(self) -> str:
        return f"Router(routes={len(self._routes)})"


class RouteGroup:
    """
    Helper class for grouping routes with common properties.
    Implements fluent interface for route building.
    """
    
    def __init__(
        self, 
        prefix: str = "",
        middlewares: Optional[List] = None,
        guards: Optional[List] = None
    ) -> None:
        """
        Initialize route group.
        
        Args:
            prefix: Path prefix for all routes in group
            middlewares: Default middlewares for routes
            guards: Default guards for routes
        """
        self.prefix = prefix.rstrip('/')  # Remove trailing slash
        self.middlewares = middlewares or []
        self.guards = guards or []
        self._routes: List[RouteInfo] = []
    
    def route(
        self,
        path: str,
        methods: List[HTTPMethod],
        handler,
        name: Optional[str] = None,
        description: Optional[str] = None,
        middlewares: Optional[List] = None,
        guards: Optional[List] = None
    ) -> 'RouteGroup':
        """
        Add a route to the group.
        
        Args:
            path: Route path (will be prefixed)
            methods: HTTP methods
            handler: Route handler
            name: Optional route name
            description: Optional route description
            middlewares: Additional middlewares for this route
            guards: Additional guards for this route
            
        Returns:
            Self for method chaining
        """
        full_path = self.prefix + ('/' + path.lstrip('/') if path else '')
        
        # Combine group and route-specific middlewares/guards
        combined_middlewares = self.middlewares + (middlewares or [])
        combined_guards = self.guards + (guards or [])
        
        route_info = RouteInfo(
            path=full_path,
            methods=methods,
            handler=handler,
            middlewares=combined_middlewares,
            guards=combined_guards,
            name=name,
            description=description
        )
        
        self._routes.append(route_info)
        return self
    
    def get(self, path: str, handler, **kwargs) -> 'RouteGroup':
        """Add GET route."""
        return self.route(path, [HTTPMethod.GET], handler, **kwargs)
    
    def post(self, path: str, handler, **kwargs) -> 'RouteGroup':
        """Add POST route."""
        return self.route(path, [HTTPMethod.POST], handler, **kwargs)
    
    def put(self, path: str, handler, **kwargs) -> 'RouteGroup':
        """Add PUT route."""
        return self.route(path, [HTTPMethod.PUT], handler, **kwargs)
    
    def delete(self, path: str, handler, **kwargs) -> 'RouteGroup':
        """Add DELETE route."""
        return self.route(path, [HTTPMethod.DELETE], handler, **kwargs)
    
    def get_routes(self) -> List[RouteInfo]:
        """Get all routes in this group."""
        return self._routes.copy()
    
    def register_to(self, router: IRouter) -> None:
        """Register all routes in this group to a router."""
        for route_info in self._routes:
            router.add_route(route_info)
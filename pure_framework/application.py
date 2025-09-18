"""
Main application class with proper composition, lifecycle management, and type safety.
"""

import json
import logging
from typing import Optional, List, Type, Any, Callable, Dict
from http.server import BaseHTTPRequestHandler, HTTPServer
from contextlib import contextmanager

from .framework_types import (
    IRequest,
    IResponse,
    IMiddleware,
    IGuard,
    IRouter,
    IDependencyContainer,
    RouteInfo,
    ApplicationConfig,
    HTTPMethod,
    IController,
    IApplication,
    FrameworkError,
    ConfigurationError,
    RouteNotFoundError,
    ValidationError,
)
from .http import Request, Response
from .routing import Router
from .dependency_injection import DependencyContainer, ServiceLocator
from .middleware import MiddlewarePipeline, GuardPipeline, PipelineResult
from .decorators import RouteRegistry
from .swagger import OpenAPIGenerator


class PureFrameworkHTTPServer(HTTPServer):
    """HTTP Server with reference to the application."""

    app: "PureFramework"


class PureFramework(IApplication):
    """
    Main application class implementing modern design patterns.

    Features:
    - Dependency injection with type safety
    - Middleware pipeline with error handling
    - Guard-based authorization
    - Automatic route registration
    - OpenAPI documentation generation
    - Proper lifecycle management
    - Configuration-driven setup
    """

    def __init__(
        self,
        config: Optional[ApplicationConfig] = None,
        container: Optional[DependencyContainer] = None,
        router: Optional[IRouter] = None,
    ) -> None:
        """
        Initialize the application.

        Args:
            config: Application configuration
            container: Dependency injection container
            router: Routing engine
        """
        self._config = config or ApplicationConfig()
        self._container = container or DependencyContainer()
        self._router = router or Router()

        self._global_middlewares: List[IMiddleware] = []
        self._global_guards: List[IGuard] = []
        self._error_handlers: Dict[
            Type[Exception], Callable[[Exception, IRequest, IResponse], bool]
        ] = {}

        self._logger = self._setup_logging()
        self._server: Optional[PureFrameworkHTTPServer] = None
        self._started = False

        # Setup service locator
        ServiceLocator.set_container(self._container)

        # Register built-in services
        self._register_builtin_services()

    def add_middleware(self, middleware: IMiddleware) -> "PureFramework":
        """
        Add global middleware.

        Args:
            middleware: Middleware instance

        Returns:
            Self for method chaining
        """
        self._global_middlewares.append(middleware)
        return self

    def add_guard(self, guard: IGuard) -> "PureFramework":
        """
        Add global guard.

        Args:
            guard: Guard instance

        Returns:
            Self for method chaining
        """
        self._global_guards.append(guard)
        return self

    def register_controller(self, controller_class: Type[IController]) -> "PureFramework":
        """
        Register a controller class.

        Args:
            controller_class: Controller class to register

        Returns:
            Self for method chaining
        """
        # Controller routes are automatically registered via decorators
        # This method is for explicit registration if needed
        self._container.register_type(controller_class, controller_class)
        return self

    def add_error_handler(
        self,
        exception_type: Type[Exception],
        handler: Callable[[Exception, IRequest, IResponse], bool],
    ) -> "PureFramework":
        """
        Add global error handler.

        Args:
            exception_type: Exception type to handle
            handler: Error handler function

        Returns:
            Self for method chaining
        """
        self._error_handlers[exception_type] = handler
        return self

    def configure_container(
        self, configurator: Callable[[IDependencyContainer], None]
    ) -> "PureFramework":
        """
        Configure the dependency injection container.

        Args:
            configurator: Function to configure the container

        Returns:
            Self for method chaining
        """
        configurator(self._container)
        return self

    def run(self, config: Optional[ApplicationConfig] = None) -> None:
        """
        Start the application.

        Args:
            config: Optional configuration override
        """
        if config:
            self._config = config

        try:
            self._startup()
            self._start_server()
        except KeyboardInterrupt:
            self._logger.info("Application interrupted by user")
        except Exception as e:
            self._logger.error(f"Application startup failed: {e}")
            raise
        finally:
            self._shutdown()

    def _startup(self) -> None:
        """Application startup sequence."""
        if self._started:
            raise ConfigurationError("Application is already started")

        self._logger.info("Starting Pure Framework application...")

        # Register routes from decorators
        self._register_routes()

        # Validate configuration
        self._validate_configuration()

        # Log startup information
        route_count = len(self._router.get_routes())
        self._logger.info(f"Registered {route_count} routes")

        self._started = True

    def _shutdown(self) -> None:
        """Application shutdown sequence."""
        if not self._started:
            return

        self._logger.info("Shutting down Pure Framework application...")

        if self._server:
            self._server.server_close()

        self._started = False

    def _start_server(self) -> None:
        """Start the HTTP server."""

        class RequestHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.handle_request("GET")

            def do_POST(self):
                self.handle_request("POST")

            def do_PUT(self):
                self.handle_request("PUT")

            def do_DELETE(self):
                self.handle_request("DELETE")

            def do_PATCH(self):
                self.handle_request("PATCH")

            def do_HEAD(self):
                self.handle_request("HEAD")

            def do_OPTIONS(self):
                self.handle_request("OPTIONS")

            def handle_request(self, method: str) -> None:
                app: PureFramework = self.server.app  # type: ignore
                app._handle_request(self, HTTPMethod(method))

            def log_message(self, format: str, *args: Any) -> None:
                # Use application logger instead of default logging
                self.server.app._logger.info(format % args)  # type: ignore

        self._server = PureFrameworkHTTPServer(
            (self._config.host, self._config.port), RequestHandler
        )
        self._server.app = self

        url = f"http://{self._config.host}:{self._config.port}"
        docs_url = f"{url}{self._config.docs_path}" if self._config.enable_docs else "disabled"

        self._logger.info(f"Server running at {url}")
        self._logger.info(f"API documentation at {docs_url}")

        try:
            self._server.serve_forever()
        except OSError as e:
            raise ConfigurationError(f"Failed to start server: {e}")

    def _handle_request(self, handler: BaseHTTPRequestHandler, method: HTTPMethod) -> None:
        """
        Handle HTTP request with full middleware and error handling pipeline.

        Args:
            handler: HTTP request handler
            method: HTTP method
        """
        # Clear scoped dependencies for this request
        self._container.clear_scoped()

        path = handler.path.split("?")[0]
        request = Request(handler)
        response = Response(handler)

        try:
            # Handle special routes
            if self._handle_special_routes(path, request, response):
                return

            # Global middleware pipeline
            global_pipeline = MiddlewarePipeline(self._global_middlewares)
            global_result = global_pipeline.execute(request, response)

            if global_result != PipelineResult.CONTINUE:
                return

            # Global guards
            global_guard_pipeline = GuardPipeline(self._global_guards)
            if not global_guard_pipeline.can_activate(request, response):
                return

            # Route matching
            route_match = self._router.match(path, method)
            if not route_match:
                self._handle_404(request, response)
                return

            route_info, path_params = route_match
            request.set_params(path_params)

            # Route-specific guards
            route_guard_pipeline = GuardPipeline(list(route_info.guards))
            if not route_guard_pipeline.can_activate(request, response):
                return

            # Route-specific middleware
            route_pipeline = MiddlewarePipeline(list(route_info.middlewares))
            route_result = route_pipeline.execute(request, response)

            if route_result != PipelineResult.CONTINUE:
                return

            # Execute route handler
            self._execute_route_handler(route_info, request, response)

        except Exception as e:
            self._handle_error(e, request, response)

    def _handle_special_routes(self, path: str, request: IRequest, response: IResponse) -> bool:
        """
        Handle special framework routes (like documentation).

        Args:
            path: Request path
            request: HTTP request
            response: HTTP response

        Returns:
            True if special route was handled
        """
        if self._config.enable_docs and path == self._config.docs_path:
            self._serve_documentation(response)
            return True

        return False

    def _serve_documentation(self, response: IResponse) -> None:
        """Serve OpenAPI documentation."""
        try:
            generator = OpenAPIGenerator(
                title=self._config.api_title, version=self._config.api_version
            )

            openapi_spec = generator.generate(self._router.get_routes())
            html_content = generator.generate_swagger_ui(openapi_spec)

            response.html(html_content)
        except Exception as e:
            self._logger.error(f"Failed to generate documentation: {e}")
            response.text("Documentation generation failed", 500)

    def _execute_route_handler(self, route_info, request: IRequest, response: IResponse) -> None:
        """
        Execute a route handler with dependency injection.

        Args:
            route_info: Route information
            request: HTTP request
            response: HTTP response
        """
        handler = route_info.handler

        if route_info.controller_class:
            # Controller method
            controller_instance = self._container.resolve(route_info.controller_class)

            # Inject dependencies into handler method
            kwargs = self._inject_handler_parameters(handler, request, response)
            handler(controller_instance, **kwargs)
        else:
            # Standalone function
            kwargs = self._inject_handler_parameters(handler, request, response)
            handler(**kwargs)

    def _inject_handler_parameters(
        self, handler: Callable, request: IRequest, response: IResponse
    ) -> Dict[str, Any]:
        """
        Inject parameters into route handler using dependency injection.

        Args:
            handler: Route handler function
            request: HTTP request
            response: HTTP response

        Returns:
            Keyword arguments for handler
        """
        import inspect
        from typing import get_type_hints

        signature = inspect.signature(handler)
        type_hints = get_type_hints(handler)
        kwargs = {}

        for param_name, param in signature.parameters.items():
            if param_name in ("self", "req", "res", "request", "response"):
                # Handle special parameters
                if param_name in ("req", "request"):
                    kwargs[param_name] = request
                elif param_name in ("res", "response"):
                    kwargs[param_name] = response
                continue

            # Get parameter type
            param_type = type_hints.get(param_name, param.annotation)

            if param_type == inspect.Parameter.empty:
                # No type annotation - try to get from query/path params
                if param_name in request.params:
                    kwargs[param_name] = request.params[param_name]
                elif param_name in request.query:
                    kwargs[param_name] = request.query[param_name]
                elif param.default != inspect.Parameter.empty:
                    kwargs[param_name] = param.default
                continue

            # Try dependency injection first
            try:
                if self._container.is_registered(param_type):
                    kwargs[param_name] = self._container.resolve(param_type)
                    continue
            except Exception:
                pass

            # Try path/query parameters with type conversion
            if param_name in request.params:
                try:
                    kwargs[param_name] = self._convert_parameter(
                        request.params[param_name], param_type
                    )
                except (ValueError, TypeError) as e:
                    raise ValidationError(
                        f"Invalid value for parameter '{param_name}': {request.params[param_name]}. Expected {param_type.__name__}."
                    ) from e
            elif param_name in request.query:
                value = request.query[param_name]
                if isinstance(value, list):
                    value = value[0]  # Take first value
                try:
                    kwargs[param_name] = self._convert_parameter(value, param_type)
                except (ValueError, TypeError) as e:
                    raise ValidationError(
                        f"Invalid value for query parameter '{param_name}': {value}. Expected {param_type.__name__}."
                    ) from e
            elif param.default != inspect.Parameter.empty:
                kwargs[param_name] = param.default

        return kwargs

    def _convert_parameter(self, value: str, target_type: Type[Any]) -> Any:
        """
        Convert string parameter to target type.

        Args:
            value: String value
            target_type: Target type

        Returns:
            Converted value
        """
        if target_type == str:
            return value
        elif target_type == int:
            return int(value)
        elif target_type == float:
            return float(value)
        elif target_type == bool:
            return value.lower() in ("true", "1", "yes", "on")
        else:
            return value

    def _handle_404(self, request: IRequest, response: IResponse) -> None:
        """Handle 404 Not Found."""
        self._logger.warning(f"Route not found: {request.method.value} {request.path}")
        response.json(
            {
                "error": "Not Found",
                "message": f"Route {request.method.value} {request.path} not found",
                "status_code": 404,
            },
            404,
        )

    def _handle_error(self, error: Exception, request: IRequest, response: IResponse) -> None:
        """
        Handle application errors.

        Args:
            error: Exception that occurred
            request: HTTP request
            response: HTTP response
        """
        # Try specific error handlers first
        for error_type, handler in self._error_handlers.items():
            if isinstance(error, error_type):
                if handler(error, request, response):
                    return

        # Log the error
        self._logger.error(f"Unhandled error: {error}", exc_info=True)

        # Send generic error response
        if self._config.debug:
            response.json(
                {
                    "error": "Internal Server Error",
                    "message": str(error),
                    "type": type(error).__name__,
                    "status_code": 500,
                },
                500,
            )
        else:
            response.json(
                {
                    "error": "Internal Server Error",
                    "message": "An unexpected error occurred",
                    "status_code": 500,
                },
                500,
            )

    def _handle_validation_error(
        self, error: Exception, request: IRequest, response: IResponse
    ) -> bool:
        """
        Handle parameter validation errors.

        Args:
            error: Validation error (will be ValidationError)
            request: HTTP request
            response: HTTP response

        Returns:
            True to indicate error was handled
        """
        self._logger.warning(f"Validation error: {error}")
        response.json({"error": "Bad Request", "message": str(error), "status_code": 400}, 400)
        return True

    def _register_routes(self) -> None:
        """Register routes from the decorator registry."""
        for route_info in RouteRegistry.get_routes():
            self._router.add_route(route_info)

        self._logger.debug(f"Registered {len(RouteRegistry.get_routes())} routes from decorators")

    def _validate_configuration(self) -> None:
        """Validate application configuration."""
        if not (1 <= self._config.port <= 65535):
            raise ConfigurationError(f"Invalid port number: {self._config.port}")

        if not self._config.host:
            raise ConfigurationError("Host cannot be empty")

    def _register_builtin_services(self) -> None:
        """Register built-in framework services."""
        self._container.register_instance(IApplication, self)
        self._container.register_instance(IRouter, self._router)
        self._container.register_instance(DependencyContainer, self._container)
        self._container.register_instance(ApplicationConfig, self._config)

        # Register built-in error handlers
        self.add_error_handler(ValidationError, self._handle_validation_error)

    def _setup_logging(self) -> logging.Logger:
        """Setup application logging."""
        logger = logging.getLogger("pure_framework")

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        logger.setLevel(logging.DEBUG if self._config.debug else logging.INFO)
        return logger

    @property
    def config(self) -> ApplicationConfig:
        """Get application configuration."""
        return self._config

    @property
    def container(self) -> IDependencyContainer:
        """Get dependency container."""
        return self._container

    @property
    def router(self) -> IRouter:
        """Get router."""
        return self._router

    @property
    def is_running(self) -> bool:
        """Check if application is running."""
        return self._started

    def __repr__(self) -> str:
        return f"PureFramework(routes={len(self._router.get_routes())}, running={self._started})"


# Factory function for creating applications
def create_app(config: Optional[ApplicationConfig] = None) -> PureFramework:
    """
    Factory function for creating Pure Framework applications.

    Args:
        config: Optional application configuration

    Returns:
        Configured application instance
    """
    return PureFramework(config)

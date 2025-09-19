"""
Async version of the Pure Framework application with asyncio support.
"""

import asyncio
import json
import logging
from typing import Optional, List, Type, Any, Callable, Dict, Union
from http.server import BaseHTTPRequestHandler, HTTPServer
from contextlib import asynccontextmanager
import threading
import inspect

from .framework_types import (
    IRequest,
    IResponse,
    IMiddleware,
    IAsyncMiddleware,
    IGuard,
    IAsyncGuard,
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
    AsyncRouteHandler,
)
from .http import Request, Response
from .routing import Router
from .dependency_injection import DependencyContainer, ServiceLocator
from .async_middleware import AsyncMiddlewarePipeline, AsyncGuardPipeline, AsyncPipelineResult
from .decorators import RouteRegistry
from .swagger import OpenAPIGenerator


class AsyncPureFrameworkHTTPServer(HTTPServer):
    """Async HTTP Server with reference to the application."""

    app: "AsyncPureFramework"


class AsyncPureFramework(IApplication):
    """
    Async version of the Pure Framework application.

    Features:
    - Full async/await support
    - Async middleware pipeline
    - Async guards and dependency injection
    - Concurrent request handling
    - Backward compatibility with sync handlers
    """

    def __init__(
        self,
        config: Optional[ApplicationConfig] = None,
        container: Optional[DependencyContainer] = None,
        router: Optional[IRouter] = None,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        """
        Initialize the async application.

        Args:
            config: Application configuration
            container: Dependency injection container
            router: Routing engine
            loop: Event loop (optional, will create if not provided)
        """
        self._config = config or ApplicationConfig()
        self._container = container or DependencyContainer()
        self._router = router or Router()
        self._loop = loop or asyncio.new_event_loop()

        self._global_middlewares: List[Union[IMiddleware, IAsyncMiddleware]] = []
        self._global_guards: List[Union[IGuard, IAsyncGuard]] = []
        self._error_handlers: Dict[
            Type[Exception], Callable[[Exception, IRequest, IResponse], bool]
        ] = {}

        self._logger = self._setup_logging()
        self._server: Optional[AsyncPureFrameworkHTTPServer] = None
        self._started = False

        # Setup service locator
        ServiceLocator.set_container(self._container)

        # Register built-in services
        self._register_builtin_services()

    def add_middleware(
        self, middleware: Union[IMiddleware, IAsyncMiddleware]
    ) -> "AsyncPureFramework":
        """
        Add global middleware (sync or async).

        Args:
            middleware: Middleware instance

        Returns:
            Self for method chaining
        """
        self._global_middlewares.append(middleware)
        return self

    def add_guard(self, guard: Union[IGuard, IAsyncGuard]) -> "AsyncPureFramework":
        """
        Add global guard (sync or async).

        Args:
            guard: Guard instance

        Returns:
            Self for method chaining
        """
        self._global_guards.append(guard)
        return self

    def register_controller(self, controller_class: Type[IController]) -> "AsyncPureFramework":
        """
        Register a controller class.

        Args:
            controller_class: Controller class to register

        Returns:
            Self for method chaining
        """
        self._container.register_type(controller_class, controller_class)
        return self

    def add_error_handler(
        self,
        exception_type: Type[Exception],
        handler: Callable[[Exception, IRequest, IResponse], bool],
    ) -> "AsyncPureFramework":
        """
        Add error handler for specific exception type.

        Args:
            exception_type: Exception type to handle
            handler: Error handler function

        Returns:
            Self for method chaining
        """
        self._error_handlers[exception_type] = handler
        return self

    def configure_container(
        self, configurator: Callable[[DependencyContainer], None]
    ) -> "AsyncPureFramework":
        """
        Configure the dependency injection container.

        Args:
            configurator: Function that configures the container

        Returns:
            Self for method chaining
        """
        configurator(self._container)
        return self

    async def startup(self) -> None:
        """Application startup tasks."""
        self._logger.info("Starting AsyncPureFramework application...")

        # Register routes from decorators
        for route_info in RouteRegistry.get_routes():
            self._router.add_route(route_info)

        # Register controller routes
        for controller_class, metadata in RouteRegistry.get_controllers().items():
            self._container.register_type(controller_class, controller_class)

        self._started = True
        self._logger.info(f"Application started with {len(self._router.get_routes())} routes")

    async def shutdown(self) -> None:
        """Application shutdown tasks."""
        self._logger.info("Shutting down AsyncPureFramework application...")
        self._started = False

    async def handle_request(self, handler: BaseHTTPRequestHandler, method: HTTPMethod) -> None:
        """
        Handle HTTP request with full async middleware and error handling pipeline.

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
            if await self._handle_special_routes(path, request, response):
                return

            # Global middleware pipeline
            global_pipeline = AsyncMiddlewarePipeline(self._global_middlewares)
            global_result = await global_pipeline.execute(request, response)

            if global_result != AsyncPipelineResult.CONTINUE:
                return

            # Global guards
            global_guard_pipeline = AsyncGuardPipeline(self._global_guards)
            if not await global_guard_pipeline.can_activate(request, response):
                return

            # Route matching
            route_match = self._router.match(path, method)
            if not route_match:
                self._handle_404(request, response)
                return

            route_info, path_params = route_match
            request.set_params(path_params)

            # Route-specific guards
            route_guard_pipeline = AsyncGuardPipeline(list(route_info.guards))
            if not await route_guard_pipeline.can_activate(request, response):
                return

            # Route-specific middleware
            route_pipeline = AsyncMiddlewarePipeline(list(route_info.middlewares))
            route_result = await route_pipeline.execute(request, response)

            if route_result != AsyncPipelineResult.CONTINUE:
                return

            # Execute route handler
            await self._execute_route_handler(route_info, request, response)

        except Exception as e:
            self._handle_error(e, request, response)

    async def _handle_special_routes(
        self, path: str, request: IRequest, response: IResponse
    ) -> bool:
        """Handle special framework routes like documentation."""
        if path == "/docs" and self._config.enable_docs:
            from .swagger import OpenAPIGenerator

            openapi_gen = OpenAPIGenerator(
                title=self._config.api_title, version=self._config.api_version
            )
            openapi_spec = openapi_gen.generate(self._router.get_routes())
            swagger_html = openapi_gen.generate_swagger_ui(openapi_spec)
            response.html(swagger_html)
            return True

        if path == "/openapi.json" and self._config.enable_docs:
            from .swagger import OpenAPIGenerator

            openapi_gen = OpenAPIGenerator(
                title=self._config.api_title, version=self._config.api_version
            )
            openapi_spec = openapi_gen.generate(self._router.get_routes())
            response.json(openapi_spec)
            return True

        return False

    async def _execute_route_handler(
        self, route_info: RouteInfo, request: IRequest, response: IResponse
    ) -> None:
        """
        Execute a route handler with dependency injection (sync or async).

        Args:
            route_info: Route information
            request: HTTP request
            response: HTTP response
        """
        handler = route_info.handler

        if route_info.controller_class:
            # Controller method
            controller_instance = self._container.resolve(route_info.controller_class)
            kwargs = self._inject_handler_parameters(handler, request, response)

            if inspect.iscoroutinefunction(handler):
                await handler(controller_instance, **kwargs)
            else:
                handler(controller_instance, **kwargs)
        else:
            # Standalone function
            kwargs = self._inject_handler_parameters(handler, request, response)

            if inspect.iscoroutinefunction(handler):
                await handler(**kwargs)
            else:
                handler(**kwargs)

    def _inject_handler_parameters(
        self, handler: Callable, request: IRequest, response: IResponse
    ) -> Dict[str, Any]:
        """Inject dependencies into handler parameters."""
        kwargs = {}
        sig = inspect.signature(handler)

        for param_name, param in sig.parameters.items():
            if param_name in ["self"]:  # Skip self for controller methods
                continue

            # Check for request/response parameters
            if param.annotation == IRequest or param_name in ["req", "request"]:
                kwargs[param_name] = request
            elif param.annotation == IResponse or param_name in ["res", "response"]:
                kwargs[param_name] = response
            elif param_name in request.params:
                # Path parameters with type conversion
                value = request.params[param_name]
                if param.annotation in [int, float, bool]:
                    try:
                        kwargs[param_name] = param.annotation(value)
                    except (ValueError, TypeError):
                        kwargs[param_name] = value
                else:
                    kwargs[param_name] = value
            elif param.annotation and param.annotation != param.empty:
                # Dependency injection
                try:
                    kwargs[param_name] = self._container.resolve(param.annotation)
                except Exception:
                    if param.default != param.empty:
                        kwargs[param_name] = param.default

        return kwargs

    def _handle_404(self, request: IRequest, response: IResponse) -> None:
        """Handle 404 Not Found."""
        response.status_code = 404
        response.json(
            {
                "error": "Not Found",
                "message": f"Route not found: {request.method} {request.path}",
                "status_code": 404,
            }
        )

    def _handle_error(self, error: Exception, request: IRequest, response: IResponse) -> None:
        """Handle uncaught errors."""
        error_type = type(error)

        # Try registered error handlers
        for exc_type, handler in self._error_handlers.items():
            if issubclass(error_type, exc_type):
                if handler(error, request, response):
                    return

        # Default error handling
        self._logger.error(f"Unhandled error: {error}", exc_info=True)

        if not response.status_code or response.status_code < 400:
            response.status_code = 500

        if self._config.debug:
            response.json(
                {
                    "error": "Internal Server Error",
                    "message": str(error),
                    "type": error_type.__name__,
                    "status_code": response.status_code,
                }
            )
        else:
            response.json(
                {
                    "error": "Internal Server Error",
                    "message": "An unexpected error occurred",
                    "status_code": response.status_code,
                }
            )

    def _setup_logging(self) -> logging.Logger:
        """Setup application logging."""
        logger = logging.getLogger("pure_framework_async")

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(self._config.log_level)

        return logger

    def _register_builtin_services(self) -> None:
        """Register built-in services."""
        self._container.register_instance(IApplication, self)
        self._container.register_instance(IRouter, self._router)
        self._container.register_instance(IDependencyContainer, self._container)
        self._container.register_instance(ApplicationConfig, self._config)

    def run(self, host: Optional[str] = None, port: Optional[int] = None) -> None:
        """
        Start the application (sync interface for compatibility).

        Args:
            host: Host to bind to
            port: Port to bind to
        """
        actual_host = host or self._config.host
        actual_port = port or self._config.port
        self.run_async(actual_host, actual_port)

    def run_async(self, host: str = "localhost", port: int = 8000) -> None:
        """
        Run the application in async mode.

        Args:
            host: Host to bind to
            port: Port to bind to
        """

        async def _run():
            await self.startup()

            # For now, we'll use a thread to run the HTTP server
            # In a real implementation, you'd use an async HTTP server like aiohttp
            server_thread = threading.Thread(
                target=self._run_sync_server, args=(host, port), daemon=True
            )
            server_thread.start()

            # Keep the async loop running
            try:
                while self._started:
                    await asyncio.sleep(0.1)
            except KeyboardInterrupt:
                await self.shutdown()

        if asyncio.get_event_loop().is_running():
            # If we're already in an async context, create a new task
            task = asyncio.create_task(_run())
            # Don't return the task, let it run in background
            print(f"🚀 Async server started on {host}:{port}")
        else:
            # Run in the main event loop
            asyncio.run(_run())

    def _run_sync_server(self, host: str, port: int) -> None:
        """Run the synchronous HTTP server in a thread."""
        # This is a simplified version - in practice you'd use an async HTTP server
        from .application import PureFramework

        # Create a sync wrapper
        sync_app = PureFramework(self._config, self._container, self._router)

        # Filter to only sync middleware and guards
        sync_middlewares = []
        for m in self._global_middlewares:
            if hasattr(m, "process") and not inspect.iscoroutinefunction(m.process):
                sync_middlewares.append(m)  # type: ignore
        sync_app._global_middlewares = sync_middlewares  # type: ignore

        sync_guards = []
        for g in self._global_guards:
            if hasattr(g, "can_activate") and not inspect.iscoroutinefunction(g.can_activate):
                sync_guards.append(g)  # type: ignore
        sync_app._global_guards = sync_guards  # type: ignore

        # Update config for sync app\n        sync_config = ApplicationConfig(\n            host=host,\n            port=port,\n            debug=self._config.debug,\n            enable_docs=self._config.enable_docs,\n            api_title=self._config.api_title,\n            api_version=self._config.api_version\n        )\n        sync_app.run(sync_config)


# Convenience alias
AsyncApp = AsyncPureFramework

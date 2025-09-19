"""
Advanced Features Example - Pure Framework

This example demonstrates:
- Advanced error handling with custom exceptions
- Configuration management and environment variables
- Request/Response validation
- Performance monitoring and metrics
- Health checks and system status
- Custom decorators
- OpenAPI documentation basics
"""

import os
import time
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from functools import wraps
import traceback

from pure_framework import PureFramework, get, post, put, delete
from pure_framework.framework_types import IRequest, IResponse, ApplicationConfig


# Configuration Management
@dataclass
class AppConfig:
    """Application configuration with environment variable support."""

    debug: bool
    host: str
    port: int
    api_version: str
    enable_metrics: bool
    enable_swagger: bool

    @classmethod
    def from_env(cls) -> "AppConfig":
        """Load configuration from environment variables."""
        return cls(
            debug=os.getenv("DEBUG", "False").lower() == "true",
            host=os.getenv("HOST", "localhost"),
            port=int(os.getenv("PORT", "8000")),
            api_version=os.getenv("API_VERSION", "v1"),
            enable_metrics=os.getenv("ENABLE_METRICS", "True").lower() == "true",
            enable_swagger=os.getenv("ENABLE_SWAGGER", "True").lower() == "true",
        )


# Custom Exceptions
class APIException(Exception):
    """Base API exception with status code and details."""

    def __init__(self, message: str, status_code: int = 500, details: Optional[Dict] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for JSON response."""
        return {
            "error": {
                "type": self.__class__.__name__,
                "message": self.message,
                "status_code": self.status_code,
                "details": self.details,
                "timestamp": self.timestamp,
            }
        }


class ValidationError(APIException):
    """Validation error with field-specific details."""

    def __init__(self, message: str, field_errors: Optional[Dict] = None):
        super().__init__(message, 400, {"field_errors": field_errors or {}})


class NotFoundError(APIException):
    """Resource not found error."""

    def __init__(self, resource: str, identifier: str):
        message = f"{resource} with identifier '{identifier}' not found"
        super().__init__(message, 404, {"resource": resource, "identifier": identifier})


# Data Models
@dataclass
class User:
    """User model with validation."""

    id: str
    username: str
    email: str
    full_name: str
    is_active: bool
    created_at: str

    def validate(self) -> None:
        """Validate user data."""
        errors = {}

        if not self.username or len(self.username) < 3:
            errors["username"] = "Username must be at least 3 characters"

        if not self.email or "@" not in self.email:
            errors["email"] = "Invalid email format"

        if not self.full_name:
            errors["full_name"] = "Full name is required"

        if errors:
            raise ValidationError("User validation failed", errors)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


# Performance Monitoring
class PerformanceMonitor:
    """Simple performance monitoring system."""

    def __init__(self):
        self.metrics: Dict[str, List[float]] = {}
        self.requests_count = 0
        self.start_time = time.time()

    def record_request_duration(self, endpoint: str, duration: float) -> None:
        """Record request duration for an endpoint."""
        if endpoint not in self.metrics:
            self.metrics[endpoint] = []
        self.metrics[endpoint].append(duration)
        self.requests_count += 1

    def get_stats(self) -> Dict[str, Any]:
        """Get performance statistics."""
        uptime = time.time() - self.start_time
        stats = {
            "uptime_seconds": uptime,
            "total_requests": self.requests_count,
            "requests_per_second": self.requests_count / uptime if uptime > 0 else 0,
            "endpoints": {},
        }

        for endpoint, durations in self.metrics.items():
            if durations:
                stats["endpoints"][endpoint] = {
                    "request_count": len(durations),
                    "avg_duration_ms": sum(durations) * 1000 / len(durations),
                    "min_duration_ms": min(durations) * 1000,
                    "max_duration_ms": max(durations) * 1000,
                }

        return stats


# Global instances
config = AppConfig.from_env()
performance_monitor = PerformanceMonitor()

# In-memory user storage
users_db: Dict[str, User] = {}


# Custom Decorators
def timed(func):
    """Decorator to measure execution time."""

    @wraps(func)
    def wrapper(req: IRequest, res: IResponse, *args, **kwargs):
        start_time = time.time()
        try:
            result = func(req, res, *args, **kwargs)
            return result
        finally:
            duration = time.time() - start_time
            endpoint = f"{req.method} {req.path}"
            performance_monitor.record_request_duration(endpoint, duration)

    return wrapper


def error_handler(func):
    """Decorator for centralized error handling."""

    @wraps(func)
    def wrapper(req: IRequest, res: IResponse, *args, **kwargs):
        try:
            return func(req, res, *args, **kwargs)
        except APIException as e:
            res.json(e.to_dict(), status_code=e.status_code)
        except Exception as e:
            error_details = {
                "type": type(e).__name__,
                "message": str(e),
                "traceback": traceback.format_exc() if config.debug else None,
            }

            error_response = {
                "error": {
                    "type": "InternalServerError",
                    "message": "An unexpected error occurred",
                    "status_code": 500,
                    "timestamp": datetime.now().isoformat(),
                }
            }

            if config.debug:
                error_response["error"]["details"] = error_details

            res.json(error_response, status_code=500)

    return wrapper


# Route Handlers
@get("/")
@timed
@error_handler
def api_info(req: IRequest, res: IResponse) -> None:
    """API information and documentation."""
    res.json(
        {
            "api": "Advanced Features Example - Pure Framework",
            "version": config.api_version,
            "description": "Demonstrates advanced framework features and best practices",
            "features": [
                "Advanced error handling with custom exceptions",
                "Configuration management with environment variables",
                "Request/Response validation",
                "Performance monitoring and metrics",
                "Health checks and system status",
                "Custom decorators and middleware",
                "Structured error responses",
            ],
            "endpoints": {
                "system": {
                    "GET /": "API information",
                    "GET /health": "Health check",
                    "GET /metrics": "Performance metrics",
                    "GET /config": "Configuration (debug mode only)",
                },
                "users": {
                    "GET /users": "List all users",
                    "POST /users": "Create a new user",
                    "GET /users/:id": "Get user by ID",
                    "PUT /users/:id": "Update user",
                    "DELETE /users/:id": "Delete user",
                },
                "testing": {
                    "GET /error-test": "Test error handling",
                    "GET /slow-endpoint": "Test performance monitoring",
                },
            },
            "configuration": {
                "debug": config.debug,
                "api_version": config.api_version,
                "metrics_enabled": config.enable_metrics,
                "swagger_enabled": config.enable_swagger,
            },
        }
    )


@get("/health")
@timed
@error_handler
def health_check(req: IRequest, res: IResponse) -> None:
    """Health check endpoint."""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "uptime_seconds": time.time() - performance_monitor.start_time,
        "version": config.api_version,
        "environment": "development" if config.debug else "production",
        "checks": {
            "database": {"status": "ok", "response_time_ms": 2.3},  # Mock
            "cache": {"status": "ok", "response_time_ms": 1.1},  # Mock
            "external_api": {"status": "ok", "response_time_ms": 45.2},  # Mock
        },
    }

    res.json(health_status)


@get("/metrics")
@timed
@error_handler
def get_metrics(req: IRequest, res: IResponse) -> None:
    """Get performance metrics."""
    if not config.enable_metrics:
        raise APIException("Metrics are disabled", 403)

    metrics = {
        "system": performance_monitor.get_stats(),
        "memory": {
            "users_count": len(users_db),
            "metrics_points": sum(
                len(durations) for durations in performance_monitor.metrics.values()
            ),
        },
    }

    res.json(metrics)


@get("/config")
@timed
@error_handler
def get_config(req: IRequest, res: IResponse) -> None:
    """Get current configuration (debug mode only)."""
    if not config.debug:
        raise APIException("Configuration access is only available in debug mode", 403)

    res.json(
        {
            "configuration": asdict(config),
            "environment_variables": {
                key: value
                for key, value in os.environ.items()
                if key.startswith(("DEBUG", "HOST", "PORT", "API_", "ENABLE_"))
            },
        }
    )


# User Management Endpoints
@get("/users")
@timed
@error_handler
def list_users(req: IRequest, res: IResponse) -> None:
    """List all users."""
    users_list = list(users_db.values())

    res.json({"users": [user.to_dict() for user in users_list], "total": len(users_list)})


@post("/users")
@timed
@error_handler
def create_user(req: IRequest, res: IResponse) -> None:
    """Create a new user."""
    import uuid

    data = req.json
    if not isinstance(data, dict):
        raise ValidationError("Invalid request body")

    # Validate required fields
    required_fields = ["username", "email", "full_name"]
    missing_fields = [field for field in required_fields if field not in data]

    if missing_fields:
        raise ValidationError("Missing required fields", {"missing_fields": missing_fields})

    # Check if username already exists
    for user in users_db.values():
        if user.username == data["username"]:
            raise ValidationError(
                "Username already exists", {"username": "This username is already taken"}
            )
        if user.email == data["email"]:
            raise ValidationError(
                "Email already exists", {"email": "This email is already registered"}
            )

    # Create new user
    user = User(
        id=str(uuid.uuid4()),
        username=data["username"],
        email=data["email"],
        full_name=data["full_name"],
        is_active=True,
        created_at=datetime.now().isoformat(),
    )

    user.validate()
    users_db[user.id] = user

    res.json({"message": "User created successfully", "user": user.to_dict()}, status_code=201)


@get("/users/:id")
@timed
@error_handler
def get_user(req: IRequest, res: IResponse) -> None:
    """Get a specific user."""
    user_id = req.params.get("id")
    if not user_id:
        raise ValidationError("User ID is required")

    user = users_db.get(user_id)
    if not user:
        raise NotFoundError("User", user_id)

    res.json(user.to_dict())


@put("/users/:id")
@timed
@error_handler
def update_user(req: IRequest, res: IResponse) -> None:
    """Update a user."""
    user_id = req.params.get("id")
    if not user_id:
        raise ValidationError("User ID is required")

    user = users_db.get(user_id)
    if not user:
        raise NotFoundError("User", user_id)

    data = req.json
    if not isinstance(data, dict):
        raise ValidationError("Invalid request body")

    # Update allowed fields
    allowed_fields = ["username", "email", "full_name", "is_active"]
    for field in allowed_fields:
        if field in data:
            setattr(user, field, data[field])

    user.validate()

    res.json({"message": "User updated successfully", "user": user.to_dict()})


@delete("/users/:id")
@timed
@error_handler
def delete_user(req: IRequest, res: IResponse) -> None:
    """Delete a user."""
    user_id = req.params.get("id")
    if not user_id:
        raise ValidationError("User ID is required")

    if user_id not in users_db:
        raise NotFoundError("User", user_id)

    deleted_user = users_db.pop(user_id)

    res.json(
        {
            "message": "User deleted successfully",
            "deleted_user": {"id": deleted_user.id, "username": deleted_user.username},
        }
    )


# Testing Endpoints
@get("/error-test")
@timed
@error_handler
def error_test(req: IRequest, res: IResponse) -> None:
    """Test error handling."""
    error_type_param = req.get_query("type")
    if isinstance(error_type_param, list):
        error_type = error_type_param[0]
    else:
        error_type = error_type_param or "api"

    if error_type == "validation":
        raise ValidationError("Test validation error", {"field": "test error message"})
    elif error_type == "not_found":
        raise NotFoundError("TestResource", "test-id")
    elif error_type == "generic":
        raise Exception("Test generic exception")
    else:
        raise APIException("Test API exception", 418, {"teapot": True})


@get("/slow-endpoint")
@timed
@error_handler
def slow_endpoint(req: IRequest, res: IResponse) -> None:
    """Test performance monitoring with artificial delay."""
    delay_param = req.get_query("delay")
    if isinstance(delay_param, list):
        delay_param = delay_param[0]

    try:
        delay = float(delay_param or "1.0")
        delay = min(delay, 5.0)  # Max 5 seconds
    except (ValueError, TypeError):
        delay = 1.0

    time.sleep(delay)

    res.json(
        {
            "message": f"Delayed response after {delay} seconds",
            "timestamp": datetime.now().isoformat(),
        }
    )


def setup_sample_data() -> None:
    """Set up sample users for testing."""
    import uuid

    sample_users = [
        User(
            id=str(uuid.uuid4()),
            username="alice",
            email="alice@example.com",
            full_name="Alice Johnson",
            is_active=True,
            created_at=datetime.now().isoformat(),
        ),
        User(
            id=str(uuid.uuid4()),
            username="bob",
            email="bob@example.com",
            full_name="Bob Smith",
            is_active=True,
            created_at=(datetime.now() - timedelta(days=1)).isoformat(),
        ),
    ]

    for user in sample_users:
        users_db[user.id] = user


if __name__ == "__main__":
    print("Starting Pure Framework Advanced Features Example...")
    print(f"\nConfiguration loaded from environment:")
    print(f"  ├── Debug Mode: {config.debug}")
    print(f"  ├── API Version: {config.api_version}")
    print(f"  ├── Metrics Enabled: {config.enable_metrics}")
    print(f"  └── Swagger Enabled: {config.enable_swagger}")
    print(f"\nAdvanced Features:")
    print(f"  ✓ Custom exception handling with detailed error responses")
    print(f"  ✓ Request/Response validation with type safety")
    print(f"  ✓ Performance monitoring and metrics collection")
    print(f"  ✓ Health checks and system status monitoring")
    print(f"  ✓ Custom decorators for cross-cutting concerns")
    print(f"  ✓ Configuration management with environment variables")
    print(f"\nSystem Endpoints:")
    print(f"  GET    /                 - API information")
    print(f"  GET    /health           - Health check")
    print(f"  GET    /metrics          - Performance metrics")
    print(f"  GET    /config           - Configuration (debug mode)")
    print(f"\nUser Management:")
    print(f"  GET    /users            - List all users")
    print(f"  POST   /users            - Create user")
    print(f"  GET    /users/:id        - Get user")
    print(f"  PUT    /users/:id        - Update user")
    print(f"  DELETE /users/:id        - Delete user")
    print(f"\nTesting Endpoints:")
    print(f"  GET    /error-test       - Test error handling")
    print(f"  GET    /slow-endpoint    - Test performance monitoring")
    print(f"\nExample requests:")
    print(f"  curl http://localhost:{config.port}/health")
    print(f"  curl http://localhost:{config.port}/users")
    print(f"  curl -X POST http://localhost:{config.port}/users \\")
    print(f"       -H 'Content-Type: application/json' \\")
    print('       -d \'{"username":"test","email":"test@example.com","full_name":"Test User"}\'')
    print(f"\nSample data preloaded for testing!")
    print(f"Server running on http://{config.host}:{config.port}")

    # Set up sample data
    setup_sample_data()

    app = PureFramework()
    app_config = ApplicationConfig(host=config.host, port=config.port, debug=config.debug)
    app.run(app_config)

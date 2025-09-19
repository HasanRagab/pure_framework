"""
Middleware Example - Pure Framework

This example demonstrates:
- Custom middleware creation
- Logging middleware for request/response tracking
- Authentication middleware using API keys
- Request validation middleware
- Error handling middleware
- Middleware registration and chaining
"""

import time
import json
from typing import Dict, Set, Optional
from datetime import datetime

from pure_framework import PureFramework, get, post
from pure_framework.framework_types import IRequest, IResponse, ApplicationConfig
from pure_framework.middleware import BaseMiddleware


# Sample data for demonstration
API_KEYS: Set[str] = {"demo-key-123", "admin-key-456", "user-key-789"}

# In-memory request log for demonstration
request_log: list = []


class LoggingMiddleware(BaseMiddleware):
    """Middleware that logs all requests and responses."""

    def process(self, req: IRequest, res: IResponse) -> None:
        """Log request details and track response time."""
        start_time = time.time()
        timestamp = datetime.now().isoformat()

        # Log request
        log_entry = {
            "timestamp": timestamp,
            "method": req.method.value,
            "path": req.path,
            "user_agent": req.get_header("User-Agent"),
            "ip": req.get_header("X-Forwarded-For") or "127.0.0.1",
            "query_params": dict(req.query),
        }

        # Store start time in response for calculating duration
        res.set_header("X-Request-Start", str(start_time))

        print(f"[{timestamp}] {req.method.value} {req.path} - Processing...")
        request_log.append(log_entry)

    def on_error(self, error: Exception, req: IRequest, res: IResponse) -> bool:
        """Log errors that occur during processing."""
        print(f"ERROR in {req.method.value} {req.path}: {str(error)}")
        return False  # Don't handle the error, just log it


class AuthenticationMiddleware(BaseMiddleware):
    """Middleware that validates API keys."""

    def __init__(self, required_paths: Optional[Set[str]] = None):
        """
        Initialize with optional path restrictions.

        Args:
            required_paths: Set of paths that require authentication.
                          If None, all paths require authentication.
        """
        self.required_paths = required_paths

    def process(self, req: IRequest, res: IResponse) -> None:
        """Validate API key for protected routes."""
        # Check if this path requires authentication
        if self.required_paths and req.path not in self.required_paths:
            return  # Skip authentication for this path

        # Get API key from header or query parameter
        api_key = req.get_header("X-API-Key") or req.get_query("api_key")

        if isinstance(api_key, list):
            api_key = api_key[0] if api_key else None

        if not api_key:
            res.json(
                {
                    "error": "Authentication required",
                    "message": "Please provide an API key via X-API-Key header or api_key query parameter",
                },
                status_code=401,
            )
            return

        if api_key not in API_KEYS:
            res.json(
                {"error": "Invalid API key", "message": "The provided API key is not valid"},
                status_code=401,
            )
            return

        # Store the API key in a header for later use
        res.set_header("X-Authenticated-Key", api_key)
        print(f"Authentication successful for key: {api_key[:8]}...")


class RequestValidationMiddleware(BaseMiddleware):
    """Middleware that validates request content."""

    def process(self, req: IRequest, res: IResponse) -> None:
        """Validate request content."""
        # Validate Content-Type for POST/PUT requests
        if req.method.value in ["POST", "PUT"]:
            content_type = req.get_header("Content-Type", "")

            if not content_type or not content_type.startswith("application/json"):
                res.json(
                    {
                        "error": "Invalid Content-Type",
                        "message": "POST and PUT requests must have Content-Type: application/json",
                    },
                    status_code=400,
                )
                return

            # Try to parse JSON body to validate it
            try:
                body = req.json
                if body is None and content_type and content_type.startswith("application/json"):
                    res.json(
                        {
                            "error": "Invalid JSON",
                            "message": "Request body must contain valid JSON",
                        },
                        status_code=400,
                    )
                    return
            except Exception as e:
                res.json(
                    {
                        "error": "JSON parsing failed",
                        "message": f"Invalid JSON in request body: {str(e)}",
                    },
                    status_code=400,
                )
                return

        # Validate request size (example: max 1MB)
        content_length = req.get_header("Content-Length")
        if content_length:
            try:
                size = int(content_length)
                max_size = 1024 * 1024  # 1MB
                if size > max_size:
                    res.json(
                        {
                            "error": "Request too large",
                            "message": f"Request body cannot exceed {max_size} bytes",
                        },
                        status_code=413,
                    )
                    return
            except ValueError:
                pass  # Invalid Content-Length header, ignore


class CORSMiddleware(BaseMiddleware):
    """Middleware that handles CORS headers."""

    def __init__(self, allowed_origins: Optional[list] = None):
        """
        Initialize CORS middleware.

        Args:
            allowed_origins: List of allowed origins. If None, allows all origins.
        """
        self.allowed_origins = allowed_origins or ["*"]

    def process(self, req: IRequest, res: IResponse) -> None:
        """Add CORS headers to response."""
        origin = req.get_header("Origin")

        # Check if origin is allowed
        if "*" in self.allowed_origins or (origin and origin in self.allowed_origins):
            res.set_header("Access-Control-Allow-Origin", origin or "*")

        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        res.set_header("Access-Control-Allow-Headers", "Content-Type, X-API-Key, Authorization")
        res.set_header("Access-Control-Max-Age", "3600")

        # Handle preflight requests
        if req.method.value == "OPTIONS":
            res.text("", status_code=204)
            return


class ResponseTimeMiddleware(BaseMiddleware):
    """Middleware that adds response time headers."""

    def process(self, req: IRequest, res: IResponse) -> None:
        """Add response time calculation."""
        start_time_header = res.headers.get("x-request-start")
        if start_time_header:
            try:
                start_time = float(start_time_header)
                duration = (time.time() - start_time) * 1000  # Convert to milliseconds
                res.set_header("X-Response-Time", f"{duration:.2f}ms")
            except ValueError:
                pass


# Create application
app = PureFramework()

# Register global middleware
cors_middleware = CORSMiddleware(allowed_origins=["http://localhost:3000", "http://127.0.0.1:3000"])
logging_middleware = LoggingMiddleware()
response_time_middleware = ResponseTimeMiddleware()

# Register middleware globally
app.add_middleware(cors_middleware)
app.add_middleware(logging_middleware)
app.add_middleware(response_time_middleware)


# Public endpoints (no authentication required)
@get("/")
def home(req: IRequest, res: IResponse) -> None:
    """Public home endpoint."""
    res.json(
        {
            "message": "Welcome to the Middleware Example API",
            "authentication": "Use X-API-Key header or api_key query parameter",
            "available_keys": ["demo-key-123", "admin-key-456", "user-key-789"],
            "endpoints": {
                "GET /": "This endpoint (public)",
                "GET /health": "Health check (public)",
                "GET /protected": "Protected endpoint (requires auth)",
                "POST /data": "Submit data (requires auth + validation)",
                "GET /logs": "View request logs (requires auth)",
            },
        }
    )


@get("/health")
def health_check(req: IRequest, res: IResponse) -> None:
    """Public health check endpoint."""
    res.json(
        {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "uptime": "unknown",  # In a real app, you'd track this
        }
    )


# Protected endpoints with specific middleware
@get("/protected", middlewares=[AuthenticationMiddleware()])
def protected_endpoint(req: IRequest, res: IResponse) -> None:
    """Protected endpoint that requires authentication."""
    authenticated_key = res.headers.get("x-authenticated-key", "unknown")

    res.json(
        {
            "message": "Access granted to protected resource",
            "authenticated_key": (
                authenticated_key[:8] + "..." if len(authenticated_key) > 8 else authenticated_key
            ),
            "data": {"secret": "This is sensitive information", "user_level": "authenticated"},
        }
    )


@post("/data", middlewares=[AuthenticationMiddleware(), RequestValidationMiddleware()])
def submit_data(req: IRequest, res: IResponse) -> None:
    """Submit data with authentication and validation."""
    try:
        data = req.json
        if not isinstance(data, dict):
            res.json(
                {"error": "Invalid data format", "message": "Request body must be a JSON object"},
                status_code=400,
            )
            return

        # Process the data (example validation)
        required_fields = ["name", "value"]
        missing_fields = [field for field in required_fields if field not in data]

        if missing_fields:
            res.json(
                {
                    "error": "Missing required fields",
                    "missing_fields": missing_fields,
                    "required_fields": required_fields,
                },
                status_code=400,
            )
            return

        # Simulate data processing
        processed_data = {
            "id": len(request_log) + 1,  # Simple ID generation
            "processed_at": datetime.now().isoformat(),
            "received_data": data,
            "status": "processed",
        }

        res.json(
            {"message": "Data processed successfully", "result": processed_data}, status_code=201
        )

    except Exception as e:
        res.json({"error": "Processing failed", "message": str(e)}, status_code=500)


@get("/logs", middlewares=[AuthenticationMiddleware()])
def get_logs(req: IRequest, res: IResponse) -> None:
    """Get request logs (admin endpoint)."""
    # Simple pagination
    limit = req.get_query("limit", "10")
    if isinstance(limit, list):
        limit = limit[0]

    try:
        limit_int = int(limit) if limit is not None else 10
        limit_int = min(max(1, limit_int), 100)  # Clamp between 1 and 100
    except (ValueError, TypeError):
        limit_int = 10

    recent_logs = request_log[-limit_int:] if request_log else []

    res.json({"total_requests": len(request_log), "showing": len(recent_logs), "logs": recent_logs})


# Example of route-specific middleware
@get(
    "/admin",
    middlewares=[
        AuthenticationMiddleware(required_paths={"/admin"}),
        RequestValidationMiddleware(),
    ],
)
def admin_endpoint(req: IRequest, res: IResponse) -> None:
    """Admin-only endpoint with additional validation."""
    authenticated_key = res.headers.get("x-authenticated-key")

    # Check if this is an admin key (simple example)
    is_admin = authenticated_key == "admin-key-456"

    if not is_admin:
        res.json(
            {"error": "Insufficient privileges", "message": "This endpoint requires admin access"},
            status_code=403,
        )
        return

    res.json(
        {
            "message": "Welcome, admin!",
            "admin_data": {
                "total_api_keys": len(API_KEYS),
                "total_requests": len(request_log),
                "recent_requests": len([log for log in request_log if log]),
            },
        }
    )


if __name__ == "__main__":
    print("Starting Pure Framework Middleware Example...")
    print("\nMiddleware Chain:")
    print("  1. CORS Middleware (global)")
    print("  2. Logging Middleware (global)")
    print("  3. Response Time Middleware (global)")
    print("  4. Authentication Middleware (route-specific)")
    print("  5. Request Validation Middleware (route-specific)")
    print("\nEndpoints:")
    print("  GET  /           - Public home page")
    print("  GET  /health     - Public health check")
    print("  GET  /protected  - Protected endpoint (requires API key)")
    print("  POST /data       - Submit data (requires API key + validation)")
    print("  GET  /logs       - View logs (requires API key)")
    print("  GET  /admin      - Admin endpoint (requires admin API key)")
    print("\nAPI Keys for testing:")
    print("  demo-key-123    - Regular user")
    print("  admin-key-456   - Admin user")
    print("  user-key-789    - Regular user")
    print("\nExample requests:")
    print("  curl -H 'X-API-Key: demo-key-123' http://localhost:8000/protected")
    print("  curl -H 'X-API-Key: admin-key-456' http://localhost:8000/admin")
    print("  curl -H 'X-API-Key: demo-key-123' -H 'Content-Type: application/json' \\")
    print('       -d \'{"name":"test","value":"data"}\' http://localhost:8000/data')
    print("\nServer running on http://localhost:8000")

    config = ApplicationConfig(host="localhost", port=8000, debug=True)
    app.run(config)

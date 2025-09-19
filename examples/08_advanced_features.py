"""
Advanced Features Example - Pure Framework

This example demonstrates all the new enhanced features:
- Async/await support
- Request/response validation
- Enhanced error handling
- Test client usage
- Middleware and guards
- Dependency injection
"""

import asyncio
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

# Import Pure Framework components
from pure_framework import (
    PureFramework,
    AsyncPureFramework,
    get,
    post,
    put,
    delete,
    async_get,
    async_post,
    controller,
    TestClient,
)
from pure_framework.framework_types import IRequest, IResponse, ApplicationConfig
from pure_framework.validation import Schema, string, integer, email, validate_json, validate_query
from pure_framework.errors import (
    handle_errors,
    not_found,
    bad_request,
    HTTPException,
    ErrorHandlerRegistry,
)
from pure_framework.middleware import BaseMiddleware, BaseGuard
from pure_framework.async_middleware import BaseAsyncMiddleware, BaseAsyncGuard
from pure_framework.dependency_injection import DependencyContainer, LifecycleType


# Sample domain models
@dataclass
class User:
    id: int
    name: str
    email: str
    active: bool = True


@dataclass
class Product:
    id: int
    name: str
    price: float
    category: str


# Services for dependency injection
class UserService:
    """Service for managing users."""

    def __init__(self):
        self.users: Dict[int, User] = {
            1: User(1, "John Doe", "john@example.com"),
            2: User(2, "Jane Smith", "jane@example.com"),
        }
        self.next_id = 3

    def get_all(self) -> List[User]:
        return list(self.users.values())

    def get_by_id(self, user_id: int) -> User:
        if user_id not in self.users:
            raise not_found(f"User {user_id} not found")
        return self.users[user_id]

    def create(self, name: str, email: str) -> User:
        user = User(self.next_id, name, email)
        self.users[self.next_id] = user
        self.next_id += 1
        return user

    def update(self, user_id: int, name: Optional[str] = None, email: Optional[str] = None) -> User:
        user = self.get_by_id(user_id)
        if name:
            user.name = name
        if email:
            user.email = email
        return user

    def delete(self, user_id: int) -> None:
        if user_id not in self.users:
            raise not_found(f"User {user_id} not found")
        del self.users[user_id]


class ProductService:
    """Service for managing products."""

    def __init__(self):
        self.products: Dict[int, Product] = {
            1: Product(1, "Laptop", 999.99, "Electronics"),
            2: Product(2, "Book", 19.99, "Books"),
        }
        self.next_id = 3

    async def get_all_async(self) -> List[Product]:
        # Simulate async database call
        await asyncio.sleep(0.01)
        return list(self.products.values())

    async def search_async(self, category: str) -> List[Product]:
        await asyncio.sleep(0.01)
        return [p for p in self.products.values() if p.category.lower() == category.lower()]


# Custom middleware
class RequestLoggingMiddleware(BaseMiddleware):
    """Middleware to log all requests."""

    def process(self, req: IRequest, res: IResponse) -> None:
        print(f"📝 {req.method.value} {req.path}")


class AsyncRequestLoggingMiddleware(BaseAsyncMiddleware):
    """Async middleware to log all requests."""

    async def process(self, req: IRequest, res: IResponse) -> None:
        print(f"📝 [ASYNC] {req.method.value} {req.path}")
        await asyncio.sleep(0.001)  # Simulate async logging


# Custom guards
class AdminGuard(BaseGuard):
    """Guard that checks for admin access."""

    def can_activate(self, request: IRequest) -> bool:
        # Check for admin header (in real app, check JWT token)
        return request.get_header("x-admin") == "true"


class AsyncRateLimitGuard(BaseAsyncGuard):
    """Async guard for rate limiting."""

    def __init__(self):
        self.requests = {}

    async def can_activate(self, request: IRequest) -> bool:
        # Simple rate limiting by IP (in real app, use Redis)
        client_ip = request.get_header("x-forwarded-for") or "127.0.0.1"
        current_time = asyncio.get_event_loop().time()

        if client_ip not in self.requests:
            self.requests[client_ip] = []

        # Clean old requests (older than 1 minute)
        self.requests[client_ip] = [t for t in self.requests[client_ip] if current_time - t < 60]

        # Check if under limit (max 10 requests per minute)
        if len(self.requests[client_ip]) >= 10:
            return False

        self.requests[client_ip].append(current_time)
        return True

    async def on_deny(self, request: IRequest, response: IResponse) -> None:
        response.status_code = 429
        response.json(
            {
                "error": "Rate Limit Exceeded",
                "message": "Too many requests. Try again later.",
                "status_code": 429,
            }
        )


# Validation schemas
user_create_schema = Schema(
    {
        "name": string(min_length=2, max_length=50),
        "email": email(),
    }
)

user_update_schema = Schema(
    {
        "name": string(min_length=2, max_length=50, required=False),
        "email": email(required=False),
    }
)

product_search_schema = Schema(
    {
        "category": string(required=False),
        "min_price": integer(min_value=0, required=False),
        "max_price": integer(min_value=0, required=False),
    }
)


# =============================================================================
# SYNC APPLICATION EXAMPLE
# =============================================================================


def create_sync_app() -> PureFramework:
    """Create a synchronous Pure Framework application."""

    # Create application with configuration
    app = PureFramework(
        config=ApplicationConfig(
            debug=True,
            enable_docs=True,
        )
    )

    # Configure dependency injection
    app.configure_container(
        lambda container: (
            container.register_type(
                UserService, UserService, LifecycleType.SINGLETON
            ).register_type(ProductService, ProductService, LifecycleType.SINGLETON)
        )
    )

    # Add global middleware
    app.add_middleware(RequestLoggingMiddleware())

    # Add global guards for admin routes
    # app.add_guard(AdminGuard())  # Uncomment to require admin for all routes

    # Routes with dependency injection and validation
    @get("/")
    @handle_errors()
    def home(req: IRequest, res: IResponse) -> None:
        """API home with feature showcase."""
        res.json(
            {
                "name": "Pure Framework Advanced Features Demo",
                "version": "2.1.0",
                "features": [
                    "Async/await support",
                    "Request/response validation",
                    "Enhanced error handling",
                    "Test client",
                    "Middleware pipeline",
                    "Guard-based authorization",
                    "Dependency injection",
                    "Auto-generated docs",
                ],
                "endpoints": {
                    "docs": "/docs",
                    "users": "/users",
                    "products": "/products",
                    "admin": "/admin",
                },
            }
        )

    @get("/users")
    @handle_errors()
    def get_users(req: IRequest, res: IResponse, user_service: UserService) -> None:
        """Get all users with dependency injection."""
        users = user_service.get_all()
        res.json(
            [{"id": u.id, "name": u.name, "email": u.email, "active": u.active} for u in users]
        )

    @get("/users/:id")
    @handle_errors()
    def get_user(req: IRequest, res: IResponse, id: int, user_service: UserService) -> None:
        """Get user by ID with automatic parameter injection."""
        user = user_service.get_by_id(id)
        res.json({"id": user.id, "name": user.name, "email": user.email, "active": user.active})

    @post("/users")
    @validate_json(user_create_schema)
    @handle_errors()
    def create_user(
        req: IRequest, res: IResponse, user_service: UserService, validated_data: dict
    ) -> None:
        """Create user with JSON validation."""
        user = user_service.create(name=validated_data["name"], email=validated_data["email"])
        res.status_code = 201
        res.json({"id": user.id, "name": user.name, "email": user.email, "active": user.active})

    @put("/users/:id")
    @validate_json(user_update_schema)
    @handle_errors()
    def update_user(
        req: IRequest, res: IResponse, id: int, user_service: UserService, validated_data: dict
    ) -> None:
        """Update user with validation."""
        updated_user = user_service.update(
            id,
            name=validated_data.get("name") if "name" in validated_data else None,
            email=validated_data.get("email") if "email" in validated_data else None,
        )
        res.json(
            {
                "id": updated_user.id,
                "name": updated_user.name,
                "email": updated_user.email,
                "active": updated_user.active,
            }
        )

    @delete("/users/:id")
    @handle_errors()
    def delete_user(req: IRequest, res: IResponse, id: int, user_service: UserService) -> None:
        """Delete user."""
        user_service.delete(id)
        res.status_code = 204

    # Admin routes with guard
    @get("/admin/users", guards=[AdminGuard()])
    @handle_errors()
    def admin_get_users(req: IRequest, res: IResponse, user_service: UserService) -> None:
        """Admin-only endpoint for getting users."""
        users = user_service.get_all()
        res.json(
            {
                "message": "Admin access granted",
                "users": [
                    {"id": u.id, "name": u.name, "email": u.email, "active": u.active}
                    for u in users
                ],
                "total": len(users),
            }
        )

    # Products with query validation
    @get("/products")
    @validate_query(product_search_schema)
    @handle_errors()
    def search_products(
        req: IRequest, res: IResponse, product_service: ProductService, validated_query: dict
    ) -> None:
        """Search products with query parameter validation."""
        # This is sync version, so we'll use the sync data
        products = list(product_service.products.values())

        category = validated_query.get("category")
        if category:
            products = [p for p in products if p.category.lower() == category.lower()]

        res.json(
            [
                {"id": p.id, "name": p.name, "price": p.price, "category": p.category}
                for p in products
            ]
        )

    return app


# =============================================================================
# ASYNC APPLICATION EXAMPLE
# =============================================================================


def create_async_app() -> AsyncPureFramework:
    """Create an asynchronous Pure Framework application."""

    # Create async application
    app = AsyncPureFramework(
        config=ApplicationConfig(
            debug=True,
            enable_docs=True,
        )
    )

    # Configure dependency injection
    app.configure_container(
        lambda container: (
            container.register_type(
                UserService, UserService, LifecycleType.SINGLETON
            ).register_type(ProductService, ProductService, LifecycleType.SINGLETON)
        )
    )

    # Add async middleware and guards
    app.add_middleware(AsyncRequestLoggingMiddleware())
    # app.add_guard(AsyncRateLimitGuard())  # Uncomment for rate limiting

    @async_get("/")
    async def async_home(req: IRequest, res: IResponse) -> None:
        """Async API home."""
        # Simulate some async work
        await asyncio.sleep(0.01)

        res.json(
            {
                "name": "Pure Framework Async Demo",
                "version": "2.1.0",
                "type": "async",
                "message": "This is an async endpoint!",
                "features": [
                    "Full async/await support",
                    "Concurrent request handling",
                    "Async middleware pipeline",
                    "Async guards and validation",
                ],
            }
        )

    @async_get("/products")
    async def async_get_products(
        req: IRequest, res: IResponse, product_service: ProductService
    ) -> None:
        """Get products asynchronously."""
        products = await product_service.get_all_async()
        res.json(
            [
                {"id": p.id, "name": p.name, "price": p.price, "category": p.category}
                for p in products
            ]
        )

    @async_get("/products/search")
    @validate_query(product_search_schema)
    async def async_search_products(
        req: IRequest, res: IResponse, product_service: ProductService, validated_query: dict
    ) -> None:
        """Search products asynchronously."""
        category = validated_query.get("category")

        if category:
            products = await product_service.search_async(category)
        else:
            products = await product_service.get_all_async()

        res.json(
            [
                {"id": p.id, "name": p.name, "price": p.price, "category": p.category}
                for p in products
            ]
        )

    # Rate-limited endpoint
    @async_post("/limited", guards=[AsyncRateLimitGuard()])
    async def rate_limited_endpoint(req: IRequest, res: IResponse) -> None:
        """Rate-limited async endpoint."""
        await asyncio.sleep(0.1)  # Simulate work
        res.json(
            {
                "message": "Request processed successfully",
                "rate_limited": True,
                "note": "This endpoint allows max 10 requests per minute",
            }
        )

    return app


# =============================================================================
# TESTING EXAMPLES
# =============================================================================


def test_sync_app():
    """Test the synchronous application using TestClient."""
    print("🧪 Testing Sync Application...")

    app = create_sync_app()
    client = TestClient(app)

    # Test home endpoint
    response = client.get("/")
    response.assert_status_code(200)
    print(f"✅ Home endpoint: {response.json['name']}")

    # Test users endpoint
    response = client.get("/users")
    response.assert_status_code(200)
    print(f"✅ Users endpoint: {len(response.json)} users found")

    # Test user creation with validation
    new_user = {"name": "Test User", "email": "test@example.com"}
    response = client.post("/users", json_data=new_user)
    response.assert_status_code(201)
    print(f"✅ User creation: Created user {response.json['name']}")

    # Test validation error
    invalid_user = {"name": "", "email": "invalid-email"}  # Too short
    response = client.post("/users", json_data=invalid_user)
    response.assert_status_code(400)
    print(f"✅ Validation: Correctly rejected invalid data")

    # Test admin endpoint without auth
    response = client.get("/admin/users")
    response.assert_status_code(403)
    print(f"✅ Admin guard: Correctly denied access")

    # Test admin endpoint with auth
    response = client.get("/admin/users", headers={"x-admin": "true"})
    response.assert_status_code(200)
    print(f"✅ Admin guard: Correctly allowed access")

    print("🎉 All sync tests passed!")


def test_async_app():
    """Test the async application."""
    print("🧪 Testing Async Application...")

    app = create_async_app()
    client = TestClient(app)

    # Note: For true async testing, you'd need to run this in an async context
    # This is a simplified example
    print("✅ Async app created successfully")
    print("   (Full async testing requires running in async context)")


# =============================================================================
# MAIN EXECUTION
# =============================================================================

if __name__ == "__main__":
    print("🚀 Pure Framework Advanced Features Demo")
    print("=" * 50)

    # Run tests
    test_sync_app()
    print()
    test_async_app()
    print()

    # Ask user which app to run
    print("Choose an application to run:")
    print("1. Sync application (full features)")
    print("2. Async application (async features)")
    print("3. Exit")

    choice = input("Enter your choice (1-3): ").strip()

    if choice == "1":
        print("\n🔄 Starting Sync Application...")
        print("Visit: http://localhost:8000/docs for API documentation")
        app = create_sync_app()
        app.run()

    elif choice == "2":
        print("\n🔄 Starting Async Application...")
        print("Visit: http://localhost:8000/docs for API documentation")
        app = create_async_app()
        app.run_async(host="0.0.0.0", port=8000)

    else:
        print("👋 Goodbye!")

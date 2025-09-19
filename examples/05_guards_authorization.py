"""
Guards and Authorization Example - Pure Framework

This example demonstrates:
- Custom guard implementations
- Role-based access control (RBAC)
- Simple token validation guards (no external dependencies)
- Rate limiting guards
- Permission-based authorization
- Guard composition and chaining
"""

# Simple token implementation (replaces JWT for simplicity)
import base64
import json
import time
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

from pure_framework import PureFramework, get, post
from pure_framework.framework_types import IRequest, IResponse, ApplicationConfig
from pure_framework.middleware import BaseGuard


# User roles and permissions
class Role(Enum):
    ADMIN = "admin"
    MODERATOR = "moderator"
    USER = "user"
    GUEST = "guest"


class Permission(Enum):
    READ_USERS = "read:users"
    WRITE_USERS = "write:users"
    DELETE_USERS = "delete:users"
    READ_ADMIN = "read:admin"
    WRITE_ADMIN = "write:admin"
    MODERATE_CONTENT = "moderate:content"


# Role-to-permissions mapping
ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.ADMIN: {
        Permission.READ_USERS,
        Permission.WRITE_USERS,
        Permission.DELETE_USERS,
        Permission.READ_ADMIN,
        Permission.WRITE_ADMIN,
        Permission.MODERATE_CONTENT,
    },
    Role.MODERATOR: {Permission.READ_USERS, Permission.WRITE_USERS, Permission.MODERATE_CONTENT},
    Role.USER: {Permission.READ_USERS},
    Role.GUEST: set(),
}


@dataclass
class User:
    id: str
    username: str
    email: str
    roles: List[Role]
    is_active: bool = True

    def has_permission(self, permission: Permission) -> bool:
        """Check if user has a specific permission."""
        for role in self.roles:
            if permission in ROLE_PERMISSIONS.get(role, set()):
                return True
        return False

    def has_role(self, role: Role) -> bool:
        """Check if user has a specific role."""
        return role in self.roles


# Mock user database
USERS_DB: Dict[str, User] = {
    "admin": User("1", "admin", "admin@example.com", [Role.ADMIN]),
    "moderator": User("2", "moderator", "mod@example.com", [Role.MODERATOR]),
    "user": User("3", "user", "user@example.com", [Role.USER]),
    "guest": User("4", "guest", "guest@example.com", [Role.GUEST]),
}

# Simple token key (in production, use proper JWT)
TOKEN_KEY = "simple-token-key-change-this-in-production"

# Rate limiting storage
rate_limit_storage: Dict[str, List[float]] = {}


# Simple token functions (replaces JWT)
def create_simple_token(username: str, expires_in_hours: int = 24) -> str:
    """Create a simple token for a user."""
    expiration = datetime.utcnow() + timedelta(hours=expires_in_hours)
    payload = {
        "username": username,
        "exp": expiration.timestamp(),
        "iat": datetime.utcnow().timestamp(),
    }
    # Simple base64 encoding (not secure, just for demo)
    token_data = json.dumps(payload)
    return base64.b64encode(token_data.encode()).decode()


def decode_simple_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode a simple token."""
    try:
        token_data = base64.b64decode(token.encode()).decode()
        payload = json.loads(token_data)

        # Check token expiration
        if payload.get("exp", 0) < time.time():
            return None

        return payload
    except (json.JSONDecodeError, ValueError):
        return None


def get_user_from_token(token: str) -> Optional[User]:
    """Extract user from token."""
    payload = decode_simple_token(token)
    if not payload:
        return None

    username = payload.get("username")
    return USERS_DB.get(username) if username else None


# Simple token implementation (replaces JWT for simplicity)
import base64
import json
import time
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

from pure_framework import PureFramework, get, post
from pure_framework.framework_types import IRequest, IResponse, ApplicationConfig
from pure_framework.middleware import BaseGuard


# User roles and permissions
class Role(Enum):
    ADMIN = "admin"
    MODERATOR = "moderator"
    USER = "user"
    GUEST = "guest"


class Permission(Enum):
    READ_USERS = "read:users"
    WRITE_USERS = "write:users"
    DELETE_USERS = "delete:users"
    READ_ADMIN = "read:admin"
    WRITE_ADMIN = "write:admin"
    MODERATE_CONTENT = "moderate:content"


# Role-to-permissions mapping
ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.ADMIN: {
        Permission.READ_USERS,
        Permission.WRITE_USERS,
        Permission.DELETE_USERS,
        Permission.READ_ADMIN,
        Permission.WRITE_ADMIN,
        Permission.MODERATE_CONTENT,
    },
    Role.MODERATOR: {Permission.READ_USERS, Permission.WRITE_USERS, Permission.MODERATE_CONTENT},
    Role.USER: {Permission.READ_USERS},
    Role.GUEST: set(),
}


@dataclass
class User:
    id: str
    username: str
    email: str
    roles: List[Role]
    is_active: bool = True

    def has_permission(self, permission: Permission) -> bool:
        """Check if user has a specific permission."""
        for role in self.roles:
            if permission in ROLE_PERMISSIONS.get(role, set()):
                return True
        return False

    def has_role(self, role: Role) -> bool:
        """Check if user has a specific role."""
        return role in self.roles


# Mock user database
USERS_DB: Dict[str, User] = {
    "admin": User("1", "admin", "admin@example.com", [Role.ADMIN]),
    "moderator": User("2", "moderator", "mod@example.com", [Role.MODERATOR]),
    "user": User("3", "user", "user@example.com", [Role.USER]),
    "guest": User("4", "guest", "guest@example.com", [Role.GUEST]),
}

# Simple token key (in production, use proper JWT)
TOKEN_KEY = "simple-token-key-change-this-in-production"

# Rate limiting storage
rate_limit_storage: Dict[str, List[float]] = {}


# Custom Guards
class JWTAuthGuard(BaseGuard):
    """Guard that validates simple tokens."""

    def can_activate(self, request: IRequest) -> bool:
        """Validate token in Authorization header."""
        auth_header = request.get_header("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return False

        token = auth_header[7:]  # Remove "Bearer " prefix
        payload = decode_simple_token(token)

        if not payload:
            return False

        # Check if user exists and is valid
        username = payload.get("username")
        return username is not None and username in USERS_DB

    def on_access_denied(self, request: IRequest, response: IResponse) -> None:
        """Handle authentication failure."""
        response.json(
            {
                "error": "Authentication required",
                "message": "Please provide a valid token in Authorization header",
                "code": "AUTH_REQUIRED",
            },
            status_code=401,
        )


class RoleGuard(BaseGuard):
    """Guard that checks user roles."""

    def __init__(self, required_roles: List[Role]):
        self.required_roles = required_roles

    def can_activate(self, request: IRequest) -> bool:
        """Check if user has any of the required roles."""
        user = self._get_user_from_request(request)
        if not user:
            return False

        return any(user.has_role(role) for role in self.required_roles)

    def _get_user_from_request(self, request: IRequest) -> Optional[User]:
        """Extract user from JWT token."""
        auth_header = request.get_header("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None

        token = auth_header[7:]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            username = payload.get("username")
            return USERS_DB.get(username) if username else None
        except jwt.InvalidTokenError:
            return None

    def on_access_denied(self, request: IRequest, response: IResponse) -> None:
        """Handle authorization failure."""
        response.json(
            {
                "error": "Insufficient permissions",
                "message": f"This endpoint requires one of these roles: {[role.value for role in self.required_roles]}",
                "code": "INSUFFICIENT_PERMISSIONS",
            },
            status_code=403,
        )


class PermissionGuard(BaseGuard):
    """Guard that checks specific permissions."""

    def __init__(self, required_permissions: List[Permission]):
        self.required_permissions = required_permissions

    def can_activate(self, request: IRequest) -> bool:
        """Check if user has all required permissions."""
        user = self._get_user_from_request(request)
        if not user:
            return False

        return all(user.has_permission(perm) for perm in self.required_permissions)

    def _get_user_from_request(self, request: IRequest) -> Optional[User]:
        """Extract user from JWT token."""
        auth_header = request.get_header("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None

        token = auth_header[7:]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            username = payload.get("username")
            return USERS_DB.get(username) if username else None
        except jwt.InvalidTokenError:
            return None

    def on_access_denied(self, request: IRequest, response: IResponse) -> None:
        """Handle authorization failure."""
        response.json(
            {
                "error": "Permission denied",
                "message": f"This endpoint requires permissions: {[perm.value for perm in self.required_permissions]}",
                "code": "PERMISSION_DENIED",
            },
            status_code=403,
        )


class RateLimitGuard(BaseGuard):
    """Guard that implements rate limiting."""

    def __init__(self, max_requests: int = 100, window_seconds: int = 3600):
        self.max_requests = max_requests
        self.window_seconds = window_seconds

    def can_activate(self, request: IRequest) -> bool:
        """Check if request is within rate limits."""
        # Use IP address as identifier
        identifier = request.get_header("X-Forwarded-For") or "127.0.0.1"
        current_time = time.time()

        if identifier not in rate_limit_storage:
            rate_limit_storage[identifier] = []

        # Clean old requests outside the time window
        rate_limit_storage[identifier] = [
            req_time
            for req_time in rate_limit_storage[identifier]
            if current_time - req_time < self.window_seconds
        ]

        # Check if limit exceeded
        if len(rate_limit_storage[identifier]) >= self.max_requests:
            return False

        # Add current request
        rate_limit_storage[identifier].append(current_time)
        return True

    def on_access_denied(self, request: IRequest, response: IResponse) -> None:
        """Handle rate limit exceeded."""
        response.json(
            {
                "error": "Rate limit exceeded",
                "message": f"Maximum {self.max_requests} requests per {self.window_seconds} seconds",
                "code": "RATE_LIMIT_EXCEEDED",
                "retry_after": self.window_seconds,
            },
            status_code=429,
        )


class ActiveUserGuard(BaseGuard):
    """Guard that checks if user account is active."""

    def can_activate(self, request: IRequest) -> bool:
        """Check if user account is active."""
        user = self._get_user_from_request(request)
        return user is not None and user.is_active

    def _get_user_from_request(self, request: IRequest) -> Optional[User]:
        """Extract user from JWT token."""
        auth_header = request.get_header("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None

        token = auth_header[7:]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            username = payload.get("username")
            return USERS_DB.get(username) if username else None
        except jwt.InvalidTokenError:
            return None

    def on_access_denied(self, request: IRequest, response: IResponse) -> None:
        """Handle inactive user."""
        response.json(
            {
                "error": "Account inactive",
                "message": "Your account has been deactivated. Please contact support.",
                "code": "ACCOUNT_INACTIVE",
            },
            status_code=403,
        )


# Simple token functions (replaces JWT)
def create_simple_token(username: str, expires_in_hours: int = 24) -> str:
    """Create a simple token for a user."""
    expiration = datetime.utcnow() + timedelta(hours=expires_in_hours)
    payload = {
        "username": username,
        "exp": expiration.timestamp(),
        "iat": datetime.utcnow().timestamp(),
    }
    # Simple base64 encoding (not secure, just for demo)
    token_data = json.dumps(payload)
    return base64.b64encode(token_data.encode()).decode()


def decode_simple_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode a simple token."""
    try:
        token_data = base64.b64decode(token.encode()).decode()
        payload = json.loads(token_data)

        # Check token expiration
        if payload.get("exp", 0) < time.time():
            return None

        return payload
    except (json.JSONDecodeError, ValueError):
        return None


def get_user_from_token(token: str) -> Optional[User]:
    """Extract user from token."""
    payload = decode_simple_token(token)
    if not payload:
        return None

    username = payload.get("username")
    return USERS_DB.get(username) if username else None


# Create application
app = PureFramework()


# Public endpoints
@get("/")
def home(req: IRequest, res: IResponse) -> None:
    """Public home endpoint."""
    res.json(
        {
            "api": "Guards and Authorization Example",
            "description": "Demonstrates RBAC, JWT auth, and guard-based security",
            "auth_info": {
                "login_endpoint": "POST /auth/login",
                "token_header": "Authorization: Bearer <token>",
                "available_users": list(USERS_DB.keys()),
                "roles": [role.value for role in Role],
                "permissions": [perm.value for perm in Permission],
            },
            "endpoints": {
                "public": ["GET /", "POST /auth/login", "GET /auth/users"],
                "authenticated": ["GET /protected", "GET /profile"],
                "admin_only": ["GET /admin/users", "POST /admin/users/:id/deactivate"],
                "moderator_plus": ["GET /moderation/dashboard"],
            },
        }
    )


@post("/auth/login")
def login(req: IRequest, res: IResponse) -> None:
    """Login endpoint to get JWT token."""
    try:
        data = req.json
        if not isinstance(data, dict):
            res.json({"error": "Invalid request body"}, status_code=400)
            return

        username = data.get("username")
        password = data.get("password")  # In real app, verify password hash

        if not username:
            res.json({"error": "Username is required"}, status_code=400)
            return

        user = USERS_DB.get(username)
        if not user:
            res.json({"error": "Invalid credentials"}, status_code=401)
            return

        # Create token
        token = create_simple_token(username)

        res.json(
            {
                "message": "Login successful",
                "token": token,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "roles": [role.value for role in user.roles],
                    "is_active": user.is_active,
                },
                "expires_in": "24 hours",
            }
        )

    except Exception as e:
        res.json({"error": str(e)}, status_code=500)


@get("/auth/users")
def list_users(req: IRequest, res: IResponse) -> None:
    """Public endpoint to see available users for testing."""
    users_info = []
    for username, user in USERS_DB.items():
        # Get all permissions for this user
        all_permissions = set()
        for role in user.roles:
            all_permissions.update(ROLE_PERMISSIONS.get(role, set()))

        users_info.append(
            {
                "username": username,
                "roles": [role.value for role in user.roles],
                "permissions": [perm.value for perm in all_permissions],
                "is_active": user.is_active,
            }
        )

    res.json({"message": "Available users for testing (use any password)", "users": users_info})


# Protected endpoints with guards
@get("/protected", guards=[JWTAuthGuard(), ActiveUserGuard()])
def protected_endpoint(req: IRequest, res: IResponse) -> None:
    """Protected endpoint requiring authentication."""
    try:
        auth_header = req.get_header("Authorization") or ""
        token = auth_header[7:] if auth_header.startswith("Bearer ") else ""
        user = get_user_from_token(token)

        if user:
            res.json(
                {
                    "message": "Welcome to the protected area!",
                    "user": {
                        "username": user.username,
                        "roles": [role.value for role in user.roles],
                    },
                    "access_time": datetime.now().isoformat(),
                }
            )
        else:
            res.json({"error": "Invalid token"}, status_code=401)
    except Exception as e:
        res.json({"error": str(e)}, status_code=500)


@get(
    "/profile",
    guards=[JWTAuthGuard(), ActiveUserGuard(), RateLimitGuard(max_requests=10, window_seconds=60)],
)
def get_profile(req: IRequest, res: IResponse) -> None:
    """Get user profile with rate limiting."""
    try:
        auth_header = req.get_header("Authorization", "")
        token = auth_header[7:] if auth_header.startswith("Bearer ") else ""
        user = get_user_from_token(token)

        if user:
            # Get user permissions
            permissions = set()
            for role in user.roles:
                permissions.update(ROLE_PERMISSIONS.get(role, set()))

            res.json(
                {
                    "profile": {
                        "id": user.id,
                        "username": user.username,
                        "email": user.email,
                        "roles": [role.value for role in user.roles],
                        "permissions": [perm.value for perm in permissions],
                        "is_active": user.is_active,
                    },
                    "rate_limit_info": "Max 10 requests per minute",
                }
            )
        else:
            res.json({"error": "Invalid token"}, status_code=401)
    except Exception as e:
        res.json({"error": str(e)}, status_code=500)


@get("/admin/users", guards=[JWTAuthGuard(), ActiveUserGuard(), RoleGuard([Role.ADMIN])])
def admin_get_users(req: IRequest, res: IResponse) -> None:
    """Admin-only endpoint to manage users."""
    try:
        users_data = []
        for user in USERS_DB.values():
            users_data.append(
                {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "roles": [role.value for role in user.roles],
                    "is_active": user.is_active,
                }
            )

        res.json(
            {"message": "Admin access granted", "users": users_data, "total_users": len(users_data)}
        )
    except Exception as e:
        res.json({"error": str(e)}, status_code=500)


@post(
    "/admin/users/:id/deactivate",
    guards=[JWTAuthGuard(), ActiveUserGuard(), PermissionGuard([Permission.DELETE_USERS])],
)
def deactivate_user(req: IRequest, res: IResponse) -> None:
    """Deactivate user (requires DELETE_USERS permission)."""
    try:
        user_id = req.params.get("id")
        if not user_id:
            res.json({"error": "User ID is required"}, status_code=400)
            return

        # Find user by ID
        target_user = None
        for user in USERS_DB.values():
            if user.id == user_id:
                target_user = user
                break

        if not target_user:
            res.json({"error": "User not found"}, status_code=404)
            return

        target_user.is_active = False

        res.json(
            {
                "message": f"User {target_user.username} has been deactivated",
                "user": {
                    "id": target_user.id,
                    "username": target_user.username,
                    "is_active": target_user.is_active,
                },
            }
        )
    except Exception as e:
        res.json({"error": str(e)}, status_code=500)


@get(
    "/moderation/dashboard",
    guards=[
        JWTAuthGuard(),
        ActiveUserGuard(),
        RoleGuard([Role.ADMIN, Role.MODERATOR]),  # Either admin or moderator
    ],
)
def moderation_dashboard(req: IRequest, res: IResponse) -> None:
    """Moderation dashboard (requires admin or moderator role)."""
    try:
        auth_header = req.get_header("Authorization", "")
        token = auth_header[7:] if auth_header.startswith("Bearer ") else ""
        user = get_user_from_token(token)

        if user:
            res.json(
                {
                    "message": "Welcome to the moderation dashboard",
                    "moderator": {
                        "username": user.username,
                        "roles": [role.value for role in user.roles],
                    },
                    "stats": {
                        "total_users": len(USERS_DB),
                        "active_users": sum(1 for u in USERS_DB.values() if u.is_active),
                        "inactive_users": sum(1 for u in USERS_DB.values() if not u.is_active),
                    },
                }
            )
        else:
            res.json({"error": "Invalid token"}, status_code=401)
    except Exception as e:
        res.json({"error": str(e)}, status_code=500)


# Debug endpoints
@get("/debug/rate-limits")
def debug_rate_limits(req: IRequest, res: IResponse) -> None:
    """Debug endpoint to view current rate limits."""
    current_time = time.time()
    rate_info = {}

    for identifier, requests in rate_limit_storage.items():
        active_requests = [
            req_time for req_time in requests if current_time - req_time < 3600  # Show last hour
        ]
        rate_info[identifier] = {
            "total_requests": len(active_requests),
            "requests_in_last_hour": len(active_requests),
            "oldest_request": min(active_requests) if active_requests else None,
            "newest_request": max(active_requests) if active_requests else None,
        }

    res.json({"message": "Current rate limit status", "rate_limits": rate_info})


if __name__ == "__main__":
    print("Starting Pure Framework Guards and Authorization Example...")
    print("\nSecurity Features:")
    print("  ✓ JWT-based authentication")
    print("  ✓ Role-based access control (RBAC)")
    print("  ✓ Permission-based authorization")
    print("  ✓ Rate limiting")
    print("  ✓ Account activation checks")
    print("  ✓ Guard composition and chaining")
    print("\nAvailable Users (use any password):")
    for username, user in USERS_DB.items():
        roles_str = ", ".join([role.value for role in user.roles])
        print(f"  {username:<10} - Roles: {roles_str}")
    print("\nEndpoints:")
    print("  Public:")
    print("    GET  /                    - API documentation")
    print("    POST /auth/login          - Get JWT token")
    print("    GET  /auth/users          - List available users")
    print("  Protected (JWT required):")
    print("    GET  /protected           - Basic protected endpoint")
    print("    GET  /profile             - User profile (rate limited)")
    print("  Admin only:")
    print("    GET  /admin/users         - User management")
    print("    POST /admin/users/:id/deactivate - Deactivate user")
    print("  Moderator/Admin:")
    print("    GET  /moderation/dashboard - Moderation tools")
    print("  Debug:")
    print("    GET  /debug/rate-limits   - View rate limit status")
    print("\nExample workflow:")
    print('  1. POST /auth/login with {"username": "admin"}')
    print("  2. Use returned token: Authorization: Bearer <token>")
    print("  3. Access protected endpoints")
    print("\nTesting different roles:")
    print("  Login as 'admin' -> Full access")
    print("  Login as 'moderator' -> Moderation access")
    print("  Login as 'user' -> Basic access only")
    print("  Login as 'guest' -> Minimal access")
    print("\nServer running on http://localhost:8000")

    config = ApplicationConfig(host="localhost", port=8000, debug=True)
    app.run(config)

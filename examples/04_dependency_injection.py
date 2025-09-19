"""
Dependency Injection Example - Pure Framework

This example demonstrates:
- Service registration with different lifecycles (Singleton, Transient, Scoped)
- Interface-based dependency injection
- Automatic constructor injection
- Factory functions and named dependencies
- Repository pattern with DI
- Service layer architecture
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime
import uuid

from pure_framework import PureFramework, get, post, put, delete
from pure_framework.framework_types import IRequest, IResponse, ApplicationConfig
from pure_framework.dependency_injection import DependencyContainer, LifecycleType, inject


# Domain Models
@dataclass
class User:
    id: str
    username: str
    email: str
    created_at: str
    is_active: bool = True

    @classmethod
    def create(cls, username: str, email: str) -> "User":
        return cls(
            id=str(uuid.uuid4()),
            username=username,
            email=email,
            created_at=datetime.now().isoformat(),
            is_active=True,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "created_at": self.created_at,
            "is_active": self.is_active,
        }


# Interfaces (Abstract Base Classes)
class IUserRepository(ABC):
    """Interface for user data access."""

    @abstractmethod
    def get_all(self) -> List[User]:
        """Get all users."""
        pass

    @abstractmethod
    def get_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        pass

    @abstractmethod
    def get_by_username(self, username: str) -> Optional[User]:
        """Get user by username."""
        pass

    @abstractmethod
    def create(self, user: User) -> User:
        """Create a new user."""
        pass

    @abstractmethod
    def update(self, user: User) -> User:
        """Update an existing user."""
        pass

    @abstractmethod
    def delete(self, user_id: str) -> bool:
        """Delete a user."""
        pass


class IEmailService(ABC):
    """Interface for email service."""

    @abstractmethod
    def send_welcome_email(self, user: User) -> bool:
        """Send welcome email to user."""
        pass

    @abstractmethod
    def send_notification(self, user: User, message: str) -> bool:
        """Send notification email to user."""
        pass


class ILogger(ABC):
    """Interface for logging service."""

    @abstractmethod
    def info(self, message: str) -> None:
        """Log info message."""
        pass

    @abstractmethod
    def error(self, message: str) -> None:
        """Log error message."""
        pass

    @abstractmethod
    def debug(self, message: str) -> None:
        """Log debug message."""
        pass


class IUserService(ABC):
    """Interface for user business logic."""

    @abstractmethod
    def get_all_users(self) -> List[User]:
        """Get all users."""
        pass

    @abstractmethod
    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        pass

    @abstractmethod
    def create_user(self, username: str, email: str) -> User:
        """Create a new user."""
        pass

    @abstractmethod
    def update_user(
        self, user_id: str, username: Optional[str] = None, email: Optional[str] = None
    ) -> Optional[User]:
        """Update user."""
        pass

    @abstractmethod
    def deactivate_user(self, user_id: str) -> bool:
        """Deactivate user."""
        pass


# Implementations
class InMemoryUserRepository(IUserRepository):
    """In-memory implementation of user repository."""

    def __init__(self):
        self._users: Dict[str, User] = {}
        self._logger: Optional[ILogger] = None

    def set_logger(self, logger: ILogger) -> None:
        """Set logger (for demonstration of setter injection)."""
        self._logger = logger

    def get_all(self) -> List[User]:
        if self._logger:
            self._logger.debug(f"Getting all users, found {len(self._users)}")
        return list(self._users.values())

    def get_by_id(self, user_id: str) -> Optional[User]:
        user = self._users.get(user_id)
        if self._logger:
            self._logger.debug(f"Getting user by ID {user_id}: {'found' if user else 'not found'}")
        return user

    def get_by_username(self, username: str) -> Optional[User]:
        for user in self._users.values():
            if user.username == username:
                if self._logger:
                    self._logger.debug(f"Found user by username: {username}")
                return user
        if self._logger:
            self._logger.debug(f"User not found by username: {username}")
        return None

    def create(self, user: User) -> User:
        self._users[user.id] = user
        if self._logger:
            self._logger.info(f"Created user: {user.username} ({user.id})")
        return user

    def update(self, user: User) -> User:
        self._users[user.id] = user
        if self._logger:
            self._logger.info(f"Updated user: {user.username} ({user.id})")
        return user

    def delete(self, user_id: str) -> bool:
        if user_id in self._users:
            user = self._users.pop(user_id)
            if self._logger:
                self._logger.info(f"Deleted user: {user.username} ({user_id})")
            return True
        return False


class MockEmailService(IEmailService):
    """Mock email service for demonstration."""

    def __init__(self, logger: ILogger):
        self._logger = logger
        self._sent_emails: List[Dict[str, Any]] = []

    def send_welcome_email(self, user: User) -> bool:
        email_data = {
            "to": user.email,
            "subject": f"Welcome {user.username}!",
            "body": f"Welcome to our platform, {user.username}!",
            "sent_at": datetime.now().isoformat(),
        }
        self._sent_emails.append(email_data)
        self._logger.info(f"Sent welcome email to {user.email}")
        return True

    def send_notification(self, user: User, message: str) -> bool:
        email_data = {
            "to": user.email,
            "subject": "Notification",
            "body": message,
            "sent_at": datetime.now().isoformat(),
        }
        self._sent_emails.append(email_data)
        self._logger.info(f"Sent notification to {user.email}: {message}")
        return True

    def get_sent_emails(self) -> List[Dict[str, Any]]:
        """Get all sent emails (for debugging)."""
        return self._sent_emails.copy()


class ConsoleLogger(ILogger):
    """Console logger implementation."""

    def __init__(self, prefix: str = "[APP]"):
        self.prefix = prefix

    def info(self, message: str) -> None:
        print(f"{self.prefix} INFO: {message}")

    def error(self, message: str) -> None:
        print(f"{self.prefix} ERROR: {message}")

    def debug(self, message: str) -> None:
        print(f"{self.prefix} DEBUG: {message}")


class UserService(IUserService):
    """User service with business logic."""

    def __init__(
        self, user_repository: IUserRepository, email_service: IEmailService, logger: ILogger
    ):
        self._repository = user_repository
        self._email_service = email_service
        self._logger = logger

    def get_all_users(self) -> List[User]:
        self._logger.debug("UserService: Getting all users")
        return self._repository.get_all()

    def get_user(self, user_id: str) -> Optional[User]:
        self._logger.debug(f"UserService: Getting user {user_id}")
        return self._repository.get_by_id(user_id)

    def create_user(self, username: str, email: str) -> User:
        self._logger.info(f"UserService: Creating user {username}")

        # Check if username already exists
        existing_user = self._repository.get_by_username(username)
        if existing_user:
            raise ValueError(f"Username '{username}' already exists")

        # Create and save user
        user = User.create(username, email)
        created_user = self._repository.create(user)

        # Send welcome email
        try:
            self._email_service.send_welcome_email(created_user)
        except Exception as e:
            self._logger.error(f"Failed to send welcome email: {e}")

        return created_user

    def update_user(
        self, user_id: str, username: Optional[str] = None, email: Optional[str] = None
    ) -> Optional[User]:
        self._logger.info(f"UserService: Updating user {user_id}")

        user = self._repository.get_by_id(user_id)
        if not user:
            return None

        # Update fields
        if username is not None:
            user.username = username
        if email is not None:
            user.email = email

        return self._repository.update(user)

    def deactivate_user(self, user_id: str) -> bool:
        self._logger.info(f"UserService: Deactivating user {user_id}")

        user = self._repository.get_by_id(user_id)
        if not user:
            return False

        user.is_active = False
        self._repository.update(user)

        # Send notification
        try:
            self._email_service.send_notification(
                user, "Your account has been deactivated. Contact support if you have questions."
            )
        except Exception as e:
            self._logger.error(f"Failed to send deactivation email: {e}")

        return True


# Application setup with dependency injection
def configure_dependencies(container: DependencyContainer) -> None:
    """Configure all application dependencies."""

    # Register logger as singleton (shared across all services)
    container.register_type(ILogger, ConsoleLogger, LifecycleType.SINGLETON)

    # Register repository as singleton (shared data store)
    def create_repository() -> IUserRepository:
        repo = InMemoryUserRepository()
        # Inject logger into repository
        logger = container.resolve(ILogger)
        repo.set_logger(logger)
        return repo

    container.register_factory(IUserRepository, create_repository, LifecycleType.SINGLETON)

    # Register email service as singleton with automatic injection
    container.register_type(IEmailService, MockEmailService, LifecycleType.SINGLETON)

    # Register user service as transient (new instance per request)
    container.register_type(IUserService, UserService, LifecycleType.TRANSIENT)

    # Named dependency example
    container.register_instance(ILogger, ConsoleLogger("[API]"), name="api_logger")


# Create application and configure DI
app = PureFramework()
container = DependencyContainer()
configure_dependencies(container)

# Set global container for the inject decorator
from pure_framework.dependency_injection import ServiceLocator

ServiceLocator.set_container(container)


# Route handlers with dependency injection
@get("/users")
def get_users(req: IRequest, res: IResponse) -> None:
    """Get all users."""
    try:
        user_service = container.resolve(IUserService)
        users = user_service.get_all_users()

        res.json({"users": [user.to_dict() for user in users], "total": len(users)})
    except Exception as e:
        res.json({"error": str(e)}, status_code=500)


@get("/users/:id")
def get_user(req: IRequest, res: IResponse) -> None:
    """Get user by ID."""
    try:
        user_id = req.params.get("id")
        if not user_id:
            res.json({"error": "User ID is required"}, status_code=400)
            return

        user_service = container.resolve(IUserService)
        user = user_service.get_user(user_id)

        if not user:
            res.json({"error": "User not found"}, status_code=404)
            return

        res.json(user.to_dict())
    except Exception as e:
        res.json({"error": str(e)}, status_code=500)


@post("/users")
def create_user(req: IRequest, res: IResponse) -> None:
    """Create a new user."""
    try:
        data = req.json
        if not isinstance(data, dict):
            res.json({"error": "Invalid request body"}, status_code=400)
            return

        username = data.get("username")
        email = data.get("email")

        if not username or not email:
            res.json(
                {
                    "error": "Username and email are required",
                    "required_fields": ["username", "email"],
                },
                status_code=400,
            )
            return

        user_service = container.resolve(IUserService)
        user = user_service.create_user(username, email)

        res.json({"message": "User created successfully", "user": user.to_dict()}, status_code=201)

    except ValueError as e:
        res.json({"error": str(e)}, status_code=400)
    except Exception as e:
        res.json({"error": str(e)}, status_code=500)


@put("/users/:id")
def update_user(req: IRequest, res: IResponse) -> None:
    """Update user."""
    try:
        user_id = req.params.get("id")
        if not user_id:
            res.json({"error": "User ID is required"}, status_code=400)
            return

        data = req.json
        if not isinstance(data, dict):
            res.json({"error": "Invalid request body"}, status_code=400)
            return

        user_service = container.resolve(IUserService)
        user = user_service.update_user(
            user_id, username=data.get("username"), email=data.get("email")
        )

        if not user:
            res.json({"error": "User not found"}, status_code=404)
            return

        res.json({"message": "User updated successfully", "user": user.to_dict()})

    except Exception as e:
        res.json({"error": str(e)}, status_code=500)


@delete("/users/:id")
def deactivate_user(req: IRequest, res: IResponse) -> None:
    """Deactivate user."""
    try:
        user_id = req.params.get("id")
        if not user_id:
            res.json({"error": "User ID is required"}, status_code=400)
            return

        user_service = container.resolve(IUserService)
        success = user_service.deactivate_user(user_id)

        if not success:
            res.json({"error": "User not found"}, status_code=404)
            return

        res.json({"message": "User deactivated successfully"})

    except Exception as e:
        res.json({"error": str(e)}, status_code=500)


# Example using the inject decorator
@get("/debug/emails")
@inject(IEmailService)
def get_sent_emails(email_service: IEmailService, req: IRequest, res: IResponse) -> None:
    """Get all sent emails (debug endpoint using inject decorator)."""
    try:
        if isinstance(email_service, MockEmailService):
            emails = email_service.get_sent_emails()
            res.json({"total_emails": len(emails), "emails": emails})
        else:
            res.json({"message": "Email service doesn't support email history"})
    except Exception as e:
        res.json({"error": str(e)}, status_code=500)


# Admin endpoint with named dependency
@get("/debug/container")
def get_container_info(req: IRequest, res: IResponse) -> None:
    """Get dependency container information."""
    try:
        # Use named logger
        api_logger = container.resolve(ILogger, name="api_logger")
        api_logger.info("Admin requested container information")

        registrations = container.get_registrations()

        container_info = {
            "total_registrations": len(registrations),
            "registrations": [
                {
                    "interface": reg.interface.__name__,
                    "implementation": (
                        reg.implementation.__name__
                        if hasattr(reg.implementation, "__name__")
                        else str(type(reg.implementation))
                    ),
                    "lifecycle": reg.lifecycle.value,
                    "name": reg.name,
                    "has_instance": reg.instance is not None,
                }
                for reg in registrations
            ],
        }

        res.json(container_info)
    except Exception as e:
        res.json({"error": str(e)}, status_code=500)


@get("/")
def home(req: IRequest, res: IResponse) -> None:
    """API documentation."""
    res.json(
        {
            "api": "Dependency Injection Example",
            "description": "Demonstrates advanced DI patterns with Pure Framework",
            "features": [
                "Interface-based dependency injection",
                "Multiple lifecycle types (Singleton, Transient, Scoped)",
                "Automatic constructor injection",
                "Factory functions",
                "Named dependencies",
                "Service layer architecture",
            ],
            "endpoints": {
                "GET /": "This documentation",
                "GET /users": "Get all users",
                "GET /users/:id": "Get user by ID",
                "POST /users": "Create new user",
                "PUT /users/:id": "Update user",
                "DELETE /users/:id": "Deactivate user",
                "GET /debug/emails": "Get sent emails (debug)",
                "GET /debug/container": "Get DI container info (debug)",
            },
            "example_request": {
                "url": "POST /users",
                "body": {"username": "john_doe", "email": "john@example.com"},
            },
        }
    )


if __name__ == "__main__":
    print("Starting Pure Framework Dependency Injection Example...")
    print("\nDI Container Configuration:")
    print("  ILogger -> ConsoleLogger (Singleton)")
    print("  IUserRepository -> InMemoryUserRepository (Singleton)")
    print("  IEmailService -> MockEmailService (Singleton)")
    print("  IUserService -> UserService (Transient)")
    print("  Named 'api_logger' -> ConsoleLogger('[API]') (Singleton)")
    print("\nService Architecture:")
    print("  Controllers -> UserService -> UserRepository")
    print("                           -> EmailService")
    print("                           -> Logger")
    print("\nEndpoints:")
    print("  GET  /               - API documentation")
    print("  GET  /users          - List all users")
    print("  GET  /users/:id      - Get specific user")
    print("  POST /users          - Create user (sends welcome email)")
    print("  PUT  /users/:id      - Update user")
    print("  DELETE /users/:id    - Deactivate user (sends notification)")
    print("  GET  /debug/emails   - View sent emails")
    print("  GET  /debug/container - View DI container info")
    print("\nTry creating a user:")
    print("  curl -X POST -H 'Content-Type: application/json' \\")
    print('       -d \'{"username":"alice","email":"alice@example.com"}\' \\')
    print("       http://localhost:8000/users")
    print("\nServer running on http://localhost:8000")

    config = ApplicationConfig(host="localhost", port=8000, debug=True)
    app.run(config)

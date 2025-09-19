"""
Type-safe dependency injection container with automatic parameter resolution.
"""

import inspect
from typing import (
    Dict,
    Any,
    Type,
    TypeVar,
    Union,
    Callable,
    Optional,
    get_type_hints,
    get_origin,
    get_args,
    Set,
    List,
)
from abc import ABC, abstractmethod
from enum import Enum

from .framework_types import IDependencyContainer, T, DependencyResolutionError


T = TypeVar("T")


class LifecycleType(Enum):
    """Dependency lifecycle types."""

    SINGLETON = "singleton"
    TRANSIENT = "transient"
    SCOPED = "scoped"


class DependencyInfo:
    """Information about a registered dependency."""

    def __init__(
        self,
        interface: Type[Any],
        implementation: Union[Type[Any], Any, Callable[[], Any]],
        lifecycle: LifecycleType = LifecycleType.SINGLETON,
        name: Optional[str] = None,
    ) -> None:
        self.interface = interface
        self.implementation = implementation
        self.lifecycle = lifecycle
        self.name = name
        self.instance: Optional[Any] = None
        self.factory: Optional[Callable[[], Any]] = None

        # Prepare the factory based on implementation type
        if callable(implementation) and not inspect.isclass(implementation):
            self.factory = implementation
        elif inspect.isclass(implementation):
            self.factory = lambda: implementation()  # type: ignore
        else:
            # It's an instance
            self.instance = implementation
            self.lifecycle = LifecycleType.SINGLETON


class DependencyContainer(IDependencyContainer):
    """
    Advanced dependency injection container with type safety and automatic resolution.

    Features:
    - Type-safe registration and resolution
    - Singleton, transient, and scoped lifecycles
    - Automatic constructor injection
    - Circular dependency detection
    - Named dependencies
    - Factory functions
    """

    def __init__(self) -> None:
        """Initialize empty container."""
        self._dependencies: Dict[Type[Any], DependencyInfo] = {}
        self._named_dependencies: Dict[str, DependencyInfo] = {}
        self._resolution_stack: Set[Type[Any]] = set()
        self._scoped_instances: Dict[Type[Any], Any] = {}

    def register(
        self, interface: Type[T], implementation: Union[Type[T], T], singleton: bool = True
    ) -> None:
        """
        Register a dependency (legacy interface for compatibility).

        Args:
            interface: Interface type
            implementation: Implementation type or instance
            singleton: Whether to use singleton lifecycle
        """
        lifecycle = LifecycleType.SINGLETON if singleton else LifecycleType.TRANSIENT
        self.register_type(interface, implementation, lifecycle)

    def register_type(
        self,
        interface: Type[T],
        implementation: Union[Type[T], T],
        lifecycle: LifecycleType = LifecycleType.SINGLETON,
        name: Optional[str] = None,
    ) -> "DependencyContainer":
        """
        Register a type dependency.

        Args:
            interface: Interface type
            implementation: Implementation type or instance
            lifecycle: Dependency lifecycle
            name: Optional name for named dependencies

        Returns:
            Self for method chaining
        """
        dependency_info = DependencyInfo(interface, implementation, lifecycle, name)
        self._dependencies[interface] = dependency_info

        if name:
            self._named_dependencies[name] = dependency_info

        return self

    def register_factory(
        self,
        interface: Type[T],
        factory: Callable[[], T],
        lifecycle: LifecycleType = LifecycleType.SINGLETON,
        name: Optional[str] = None,
    ) -> "DependencyContainer":
        """
        Register a factory function.

        Args:
            interface: Interface type
            factory: Factory function
            lifecycle: Dependency lifecycle
            name: Optional name for named dependencies

        Returns:
            Self for method chaining
        """
        dependency_info = DependencyInfo(interface, factory, lifecycle, name)
        self._dependencies[interface] = dependency_info

        if name:
            self._named_dependencies[name] = dependency_info

        return self

    def register_instance(
        self, interface: Type[T], instance: T, name: Optional[str] = None
    ) -> "DependencyContainer":
        """
        Register a specific instance (always singleton).

        Args:
            interface: Interface type
            instance: Instance to register
            name: Optional name for named dependencies

        Returns:
            Self for method chaining
        """
        dependency_info = DependencyInfo(interface, instance, LifecycleType.SINGLETON, name)
        self._dependencies[interface] = dependency_info

        if name:
            self._named_dependencies[name] = dependency_info

        return self

    def resolve(self, interface: Type[T], name: Optional[str] = None) -> T:
        """
        Resolve a dependency.

        Args:
            interface: Interface type to resolve
            name: Optional name for named dependencies

        Returns:
            Resolved instance

        Raises:
            DependencyResolutionError: If dependency cannot be resolved
        """
        try:
            return self._resolve_internal(interface, name)
        except Exception as e:
            raise DependencyResolutionError(f"Failed to resolve {interface.__name__}: {e}")

    def _detect_circular_dependency(self, interface: Type[T]) -> Optional[str]:
        """Detect circular dependencies and return error message if found."""
        if interface in self._resolution_stack:
            cycle = " -> ".join([t.__name__ for t in self._resolution_stack])
            return f"Circular dependency detected: {cycle} -> {interface.__name__}"
        return None

    def _resolve_internal(self, interface: Type[T], name: Optional[str] = None) -> T:
        """Internal resolution logic with circular dependency detection."""

        # Check for circular dependencies
        circular_error = self._detect_circular_dependency(interface)
        if circular_error:
            raise DependencyResolutionError(circular_error)

        # Look up dependency info
        dependency_info = None
        if name:
            dependency_info = self._named_dependencies.get(name)
        else:
            dependency_info = self._dependencies.get(interface)

        if not dependency_info:
            # Try to auto-register if it's a concrete class
            if inspect.isclass(interface) and not inspect.isabstract(interface):
                self.register_type(interface, interface, LifecycleType.TRANSIENT)
                dependency_info = self._dependencies[interface]
            else:
                raise DependencyResolutionError(f"No registration found for {interface.__name__}")

        # Handle different lifecycle types
        if dependency_info.lifecycle == LifecycleType.SINGLETON:
            if dependency_info.instance is not None:
                return dependency_info.instance

            # Create singleton instance
            self._resolution_stack.add(interface)
            try:
                instance = self._create_instance(dependency_info)
                dependency_info.instance = instance
                return instance
            finally:
                self._resolution_stack.discard(interface)

        elif dependency_info.lifecycle == LifecycleType.SCOPED:
            if interface in self._scoped_instances:
                return self._scoped_instances[interface]

            # Create scoped instance
            self._resolution_stack.add(interface)
            try:
                instance = self._create_instance(dependency_info)
                self._scoped_instances[interface] = instance
                return instance
            finally:
                self._resolution_stack.discard(interface)

        else:  # TRANSIENT
            # Always create new instance
            self._resolution_stack.add(interface)
            try:
                return self._create_instance(dependency_info)
            finally:
                self._resolution_stack.discard(interface)

    def _create_instance(self, dependency_info: DependencyInfo) -> Any:
        """Create an instance using dependency info."""
        if dependency_info.factory:
            return dependency_info.factory()
        elif dependency_info.instance is not None:
            return dependency_info.instance
        elif inspect.isclass(dependency_info.implementation):
            return self._create_with_injection(dependency_info.implementation)
        else:
            return dependency_info.implementation

    def _create_with_injection(self, cls: Type[T]) -> T:
        """Create instance with automatic constructor injection."""
        constructor = cls.__init__
        signature = inspect.signature(constructor)

        # Get type hints for parameters
        type_hints = get_type_hints(constructor)

        kwargs = {}
        for param_name, param in signature.parameters.items():
            if param_name == "self":
                continue

            # Get parameter type
            param_type = type_hints.get(param_name, param.annotation)

            if param_type == inspect.Parameter.empty:
                if param.default != inspect.Parameter.empty:
                    continue  # Use default value
                else:
                    raise DependencyResolutionError(
                        f"Cannot inject parameter '{param_name}' in {cls.__name__}: no type annotation"
                    )

            # Check for optional parameters
            if self._is_optional_type(param_type):
                try:
                    # Try to resolve, but don't fail if not found
                    actual_type = self._get_optional_inner_type(param_type)
                    if self.is_registered(actual_type):
                        kwargs[param_name] = self.resolve(actual_type)
                except DependencyResolutionError:
                    pass  # Use default value (None)
            else:
                # Required parameter
                kwargs[param_name] = self.resolve(param_type)

        return cls(**kwargs)

    def _is_optional_type(self, param_type: Type[Any]) -> bool:
        """Check if type is Optional[T] (Union[T, None])."""
        origin = get_origin(param_type)
        if origin is Union:
            args = get_args(param_type)
            return len(args) == 2 and type(None) in args
        return False

    def _get_optional_inner_type(self, param_type: Type[Any]) -> Type[Any]:
        """Get the inner type from Optional[T]."""
        args = get_args(param_type)
        for arg in args:
            if arg is not type(None):
                return arg
        raise ValueError("Invalid Optional type")

    def is_registered(self, interface: Type[T], name: Optional[str] = None) -> bool:
        """
        Check if a dependency is registered.

        Args:
            interface: Interface type
            name: Optional name for named dependencies

        Returns:
            True if registered
        """
        if name:
            return name in self._named_dependencies
        return interface in self._dependencies

    def clear_scoped(self) -> None:
        """Clear all scoped instances (for request scope management)."""
        self._scoped_instances.clear()

    def get_registrations(self) -> List[DependencyInfo]:
        """Get all registered dependencies."""
        return list(self._dependencies.values())

    def __repr__(self) -> str:
        return f"DependencyContainer(registrations={len(self._dependencies)})"


class ServiceLocator:
    """
    Global service locator pattern implementation.
    Provides static access to dependency container.
    """

    _container: Optional[DependencyContainer] = None

    @classmethod
    def set_container(cls, container: DependencyContainer) -> None:
        """Set the global container."""
        cls._container = container

    @classmethod
    def get_container(cls) -> DependencyContainer:
        """Get the global container."""
        if cls._container is None:
            cls._container = DependencyContainer()
        return cls._container

    @classmethod
    def resolve(cls, interface: Type[T], name: Optional[str] = None) -> T:
        """Resolve a dependency from the global container."""
        return cls.get_container().resolve(interface, name)

    @classmethod
    def register(
        cls, interface: Type[T], implementation: Union[Type[T], T], singleton: bool = True
    ) -> None:
        """Register a dependency in the global container."""
        cls.get_container().register(interface, implementation, singleton)


# Decorator for dependency injection
def inject(interface: Type[T], name: Optional[str] = None):
    """
    Decorator for injecting dependencies into functions.

    Args:
        interface: Interface type to inject
        name: Optional name for named dependencies
    """

    def decorator(func: Callable) -> Callable:
        original_func = func

        def wrapper(*args, **kwargs):
            # Inject the dependency as the first argument
            dependency = ServiceLocator.resolve(interface, name)
            return original_func(dependency, *args, **kwargs)

        return wrapper

    return decorator

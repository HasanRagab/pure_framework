# Pure Framework

A lightweight, modern Python web framework built with type safety, dependency injection, and clean architecture principles. Pure Framework provides everything you need to build robust web APIs with minimal overhead and maximum developer experience.

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.0.4-orange.svg)](pyproject.toml)

## ✨ Features

### Core Framework
- **🔒 Full Type Safety**: Built with Python protocols and generics for comprehensive type checking
- **💉 Advanced Dependency Injection**: Automatic parameter resolution with singleton, transient, and scoped lifecycles
- **🔄 Pipeline-based Middleware**: Chain of responsibility pattern with error handling
- **🛡️ Guard-based Authorization**: Flexible authorization system with clean interfaces
- **🚀 High-Performance Routing**: Regex-compiled routes with parameter extraction
- **📚 Auto-Generated Documentation**: Built-in OpenAPI/Swagger documentation
- **🎯 Decorator-based Routing**: Clean, intuitive route definitions
- **🏗️ SOLID Principles**: Clean separation of concerns and maintainable architecture
- **🐍 Pure Python**: No external dependencies, works with standard library only

### New in v0.0.4
- **⚡ Async/Await Support**: Full async support with AsyncPureFramework for modern Python applications
- **✅ Request/Response Validation**: Pydantic-style validation with detailed error messages
- **�️ Enhanced Error Handling**: Structured error responses with proper HTTP status codes
- **🧪 Test Client**: Comprehensive testing utilities for easy unit and integration testing
- **⚙️ CLI Tool**: Command-line interface for project scaffolding and development
- **🔗 Advanced Middleware**: Support for both sync and async middleware pipelines
- **🛡️ Enhanced Guards**: Async guards with rate limiting and authorization patterns

## �🚀 Quick Start

### Installation

```bash
pip install pure-framework
```

### Basic Example

```python
from pure_framework import PureFramework, get, post
from pure_framework.framework_types import IRequest, IResponse

app = PureFramework()

@get('/hello')
def hello_world(req: IRequest, res: IResponse) -> None:
    res.json({'message': 'Hello, World!'})

@get('/users/:id')
def get_user(req: IRequest, res: IResponse, id: int) -> None:
    # Automatic parameter injection and type conversion
    res.json({'user_id': id, 'name': f'User {id}'})

@post('/users')
def create_user(req: IRequest, res: IResponse) -> None:
    user_data = req.json
    res.json({'created': user_data}, status_code=201)

if __name__ == "__main__":
    app.run()
```

### Async Example

```python
from pure_framework import AsyncPureFramework, async_get, async_post
from pure_framework.framework_types import IRequest, IResponse
import asyncio

app = AsyncPureFramework()

@async_get('/hello')
async def hello_world(req: IRequest, res: IResponse) -> None:
    # Simulate async work
    await asyncio.sleep(0.01)
    res.json({'message': 'Hello from async!', 'type': 'async'})

@async_post('/process')
async def process_data(req: IRequest, res: IResponse) -> None:
    # Async data processing
    data = req.json
    await asyncio.sleep(0.1)  # Simulate async processing
    res.json({'processed': data, 'status': 'completed'})

if __name__ == "__main__":
    app.run_async()
```

### CLI Usage

Create a new project:
```bash
pure new my-api                    # Basic API project
pure new my-async-api --template async-api  # Async API project
```

Run your project:
```bash
pure run                           # Run the current project
pure run --reload                  # Run with auto-reload
```

Run tests:
```bash
pure test                          # Run all tests
pure test --verbose                # Verbose output
```

if __name__ == '__main__':
    app.run()  # Starts server at http://127.0.0.1:8000
```

Visit `http://127.0.0.1:8000/docs` to see the auto-generated API documentation!

## 🏛️ Architecture Overview

Pure Framework is built around several core concepts:

### 1. **Application (`PureFramework`)**
The main application class that orchestrates all components:

```python
from pure_framework import PureFramework
from pure_framework.framework_types import ApplicationConfig

# Basic setup
app = PureFramework()

# Advanced configuration
config = ApplicationConfig(
    host="0.0.0.0",
    port=8080,
    enable_docs=True,
    docs_path="/api-docs"
)
app = PureFramework(config=config)
```

### 2. **Routing System**
High-performance routing with parameter extraction:

```python
from pure_framework import get, post, put, delete, route
from pure_framework.framework_types import HTTPMethod

# Simple routes
@get('/health')
def health_check(req, res):
    res.json({'status': 'healthy'})

# Multiple methods
@route('/api/data', methods=[HTTPMethod.GET, HTTPMethod.POST])
def handle_data(req, res):
    if req.method == HTTPMethod.GET:
        res.json({'data': 'value'})
    else:
        res.json({'created': req.json})

# Parameter routes with type conversion
@get('/posts/:id/comments/:comment_id')
def get_comment(req, res, id: int, comment_id: int):
    res.json({'post_id': id, 'comment_id': comment_id})
```

### 3. **Controller Classes**
Organize related routes into controller classes:

```python
from pure_framework import controller, get, post
from pure_framework.framework_types import IRequest, IResponse

@controller('/api/users')
class UserController:
    
    @get('/')
    def list_users(self, req: IRequest, res: IResponse):
        res.json({'users': []})
    
    @get('/:id')
    def get_user(self, req: IRequest, res: IResponse, id: int):
        res.json({'user_id': id})
    
    @post('/')
    def create_user(self, req: IRequest, res: IResponse):
        user_data = req.json
        res.json({'created': user_data})
```

### 4. **Dependency Injection**
Type-safe dependency injection with automatic resolution:

```python
from pure_framework import PureFramework, get, inject
from pure_framework.dependency_injection import DependencyContainer, LifecycleType

# Define services
class DatabaseService:
    def get_user(self, user_id: int):
        return {'id': user_id, 'name': f'User {user_id}'}

class UserService:
    def __init__(self, db: DatabaseService):
        self.db = db
    
    def find_user(self, user_id: int):
        return self.db.get_user(user_id)

# Configure container
app = PureFramework()
app.configure_container(lambda container: (
    container.register_type(DatabaseService, DatabaseService, LifecycleType.SINGLETON)
    .register_type(UserService, UserService, LifecycleType.SINGLETON)
))

# Use in routes with automatic injection
@get('/users/:id')
def get_user(req, res, id: int, user_service: UserService = inject()):
    user = user_service.find_user(id)
    res.json(user)
```

### 5. **Middleware System**
Pipeline-based middleware with error handling:

```python
from pure_framework import PureFramework
from pure_framework.middleware import BaseMiddleware
from pure_framework.framework_types import IRequest, IResponse

class LoggingMiddleware(BaseMiddleware):
    def process(self, request: IRequest, response: IResponse) -> None:
        print(f"{request.method} {request.path}")

class AuthMiddleware(BaseMiddleware):
    def process(self, request: IRequest, response: IResponse) -> None:
        auth_header = request.get_header('authorization')
        if not auth_header:
            response.status_code = 401
            response.json({'error': 'Unauthorized'})
            return

# Global middleware
app = PureFramework()
app.add_middleware(LoggingMiddleware())

# Route-specific middleware
@get('/protected', middlewares=[AuthMiddleware()])
def protected_route(req, res):
    res.json({'message': 'Access granted'})
```

### 6. **Guards for Authorization**
Clean authorization with guard classes:

```python
from pure_framework.middleware import BaseGuard
from pure_framework.framework_types import IRequest

class AdminGuard(BaseGuard):
    def can_activate(self, request: IRequest) -> bool:
        user_role = request.get_header('user-role')
        return user_role == 'admin'

@get('/admin/users', guards=[AdminGuard()])
def admin_users(req, res):
    res.json({'admin_data': 'sensitive'})
```

## 📖 API Reference

### Request Object (`IRequest`)

```python
from pure_framework.framework_types import IRequest

def my_handler(req: IRequest, res):
    # Path and method
    path = req.path          # "/api/users/123"
    method = req.method      # HTTPMethod.GET
    
    # Headers (case-insensitive)
    auth = req.get_header('authorization')
    content_type = req.headers.get('content-type')
    
    # Query parameters
    page = req.get_query('page', '1')        # Single value
    tags = req.query.get('tags', [])         # List of values
    
    # Path parameters (from route pattern)
    user_id = req.params.get('id')           # From /users/:id
    
    # Request body
    raw_body = req.body                      # Raw string
    json_data = req.json                     # Parsed JSON
```

### Response Object (`IResponse`)

```python
from pure_framework.framework_types import IResponse

def my_handler(req, res: IResponse):
    # Set status code
    res.status_code = 201
    
    # Set headers
    res.set_header('X-Custom', 'value')
    
    # Send responses
    res.json({'key': 'value'})                    # JSON response
    res.html('<h1>Hello</h1>')                    # HTML response
    res.text('Plain text')                        # Text response
    res.send(b'Binary data')                      # Raw bytes
    
    # With custom status
    res.json({'error': 'Not found'}, status_code=404)
```

### Route Decorators

```python
from pure_framework import route, get, post, put, delete, patch
from pure_framework.framework_types import HTTPMethod

# Basic decorators
@get('/path')           # GET only
@post('/path')          # POST only
@put('/path')           # PUT only
@delete('/path')        # DELETE only
@patch('/path')         # PATCH only

# Multiple methods
@route('/path', methods=[HTTPMethod.GET, HTTPMethod.POST])

# With middleware and guards
@get('/path', 
     middlewares=[LoggingMiddleware()],
     guards=[AuthGuard()],
     name='custom_name',
     description='Route description')
```

### Dependency Injection

```python
from pure_framework.dependency_injection import (
    DependencyContainer, LifecycleType, inject
)

# Container setup
container = DependencyContainer()

# Register types
container.register_type(IService, ServiceImpl, LifecycleType.SINGLETON)
container.register_type(IRepo, RepoImpl, LifecycleType.TRANSIENT)

# Register instances
container.register_instance(IConfig, config_instance)

# Register factories
container.register_factory(IService, lambda: create_service())

# Use in route handlers
@get('/users')
def get_users(req, res, service: IService = inject()):
    users = service.get_all_users()
    res.json(users)
```

## 🔧 Configuration

### Application Configuration

```python
from pure_framework import PureFramework
from pure_framework.framework_types import ApplicationConfig

config = ApplicationConfig(
    host="0.0.0.0",              # Bind host
    port=8080,                   # Bind port  
    enable_docs=True,            # Enable Swagger docs
    docs_path="/docs",           # Docs endpoint path
    log_level="INFO"             # Logging level
)

app = PureFramework(config=config)
```

### Error Handling

```python
from pure_framework import PureFramework

app = PureFramework()

# Global error handler
def handle_validation_error(error: ValueError, req, res):
    res.json({'error': str(error)}, status_code=400)
    return True  # Mark as handled

app.add_error_handler(ValueError, handle_validation_error)
```

## 📊 Examples

### Complete REST API

```python
from pure_framework import PureFramework, controller, get, post, put, delete
from pure_framework.framework_types import IRequest, IResponse
from pure_framework.dependency_injection import inject, LifecycleType

# Data models
class User:
    def __init__(self, id: int, name: str, email: str):
        self.id = id
        self.name = name
        self.email = email
    
    def to_dict(self):
        return {'id': self.id, 'name': self.name, 'email': self.email}

# Services
class UserService:
    def __init__(self):
        self.users = {}
        self.next_id = 1
    
    def create_user(self, name: str, email: str) -> User:
        user = User(self.next_id, name, email)
        self.users[self.next_id] = user
        self.next_id += 1
        return user
    
    def get_user(self, user_id: int) -> User:
        return self.users.get(user_id)
    
    def get_all_users(self) -> list[User]:
        return list(self.users.values())
    
    def update_user(self, user_id: int, name: str = None, email: str = None) -> User:
        user = self.users.get(user_id)
        if user:
            if name: user.name = name
            if email: user.email = email
        return user
    
    def delete_user(self, user_id: int) -> bool:
        return self.users.pop(user_id, None) is not None

# Controllers
@controller('/api/users')
class UserController:
    
    @get('/')
    def list_users(self, req: IRequest, res: IResponse, 
                  user_service: UserService = inject()):
        users = user_service.get_all_users()
        res.json([user.to_dict() for user in users])
    
    @get('/:id')
    def get_user(self, req: IRequest, res: IResponse, id: int,
                user_service: UserService = inject()):
        user = user_service.get_user(id)
        if user:
            res.json(user.to_dict())
        else:
            res.json({'error': 'User not found'}, status_code=404)
    
    @post('/')
    def create_user(self, req: IRequest, res: IResponse,
                   user_service: UserService = inject()):
        data = req.json
        user = user_service.create_user(data['name'], data['email'])
        res.json(user.to_dict(), status_code=201)
    
    @put('/:id')
    def update_user(self, req: IRequest, res: IResponse, id: int,
                   user_service: UserService = inject()):
        data = req.json
        user = user_service.update_user(id, data.get('name'), data.get('email'))
        if user:
            res.json(user.to_dict())
        else:
            res.json({'error': 'User not found'}, status_code=404)
    
    @delete('/:id')
    def delete_user(self, req: IRequest, res: IResponse, id: int,
                   user_service: UserService = inject()):
        if user_service.delete_user(id):
            res.json({'message': 'User deleted'})
        else:
            res.json({'error': 'User not found'}, status_code=404)

# Application setup
app = PureFramework()

# Configure dependencies
app.configure_container(lambda container:
    container.register_type(UserService, UserService, LifecycleType.SINGLETON)
)

if __name__ == '__main__':
    app.run()
```

## 🧪 Testing

Pure Framework is designed to be easily testable:

```python
import unittest
from pure_framework import PureFramework, get
from pure_framework.framework_types import IRequest, IResponse

class TestAPI(unittest.TestCase):
    def setUp(self):
        self.app = PureFramework()
        
        @get('/test')
        def test_endpoint(req: IRequest, res: IResponse):
            res.json({'test': True})
    
    def test_endpoint_response(self):
        # Test your endpoints using the application instance
        # Note: Full testing utilities coming in future versions
        pass
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/hasanragab/pure_framework.git
cd pure_framework

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode
pip install -e .

# Run tests
python -m pytest tests/

# Build package
python -m build
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔮 Roadmap

- [ ] Async/await support
- [ ] WebSocket support  
- [ ] Database ORM integration
- [ ] Template engine integration
- [ ] Built-in testing utilities
- [ ] CLI tools for project scaffolding
- [ ] Performance optimizations
- [ ] Plugin system

## 📞 Support

- 📧 Email: hr145310@gmail.com
- 🐛 Issues: [GitHub Issues](https://github.com/hasanragab/pure_framework/issues)
---

Made with ❤️ by [Hasan Ragab](mailto:hr145310@gmail.com)
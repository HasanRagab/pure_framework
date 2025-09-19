"""
Controller-based Example - Pure Framework

This example demonstrates:
- Class-based controllers for organizing related routes
- Controller decorators and metadata
- Dependency injection in controllers
- Route grouping and prefixes
- Method-based route handlers
- Clean separation of concerns
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import uuid

from pure_framework import PureFramework, get, post, put, delete, controller
from pure_framework.framework_types import IRequest, IResponse, ApplicationConfig
from pure_framework.dependency_injection import DependencyContainer, LifecycleType


# Data Models
@dataclass
class Product:
    id: str
    name: str
    description: Optional[str]
    price: float
    category_id: str
    stock: int
    created_at: str

    @classmethod
    def create(
        cls, name: str, description: Optional[str], price: float, category_id: str, stock: int = 0
    ) -> "Product":
        return cls(
            id=str(uuid.uuid4()),
            name=name,
            description=description,
            price=price,
            category_id=category_id,
            stock=stock,
            created_at=datetime.now().isoformat(),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "price": self.price,
            "category_id": self.category_id,
            "stock": self.stock,
            "created_at": self.created_at,
        }


@dataclass
class Category:
    id: str
    name: str
    description: Optional[str]
    created_at: str

    @classmethod
    def create(cls, name: str, description: Optional[str] = None) -> "Category":
        return cls(
            id=str(uuid.uuid4()),
            name=name,
            description=description,
            created_at=datetime.now().isoformat(),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at,
        }


# Services (for dependency injection)
class ProductService:
    """Service for product business logic."""

    def __init__(self):
        self._products: Dict[str, Product] = {}

    def get_all(self) -> List[Product]:
        """Get all products."""
        return list(self._products.values())

    def get_by_id(self, product_id: str) -> Optional[Product]:
        """Get product by ID."""
        return self._products.get(product_id)

    def get_by_category(self, category_id: str) -> List[Product]:
        """Get products by category."""
        return [p for p in self._products.values() if p.category_id == category_id]

    def create(
        self, name: str, description: Optional[str], price: float, category_id: str, stock: int = 0
    ) -> Product:
        """Create a new product."""
        product = Product.create(name, description, price, category_id, stock)
        self._products[product.id] = product
        return product

    def update(self, product_id: str, **kwargs) -> Optional[Product]:
        """Update a product."""
        product = self._products.get(product_id)
        if not product:
            return None

        # Update fields
        for key, value in kwargs.items():
            if hasattr(product, key) and value is not None:
                setattr(product, key, value)

        return product

    def delete(self, product_id: str) -> bool:
        """Delete a product."""
        if product_id in self._products:
            del self._products[product_id]
            return True
        return False

    def search(self, query: str) -> List[Product]:
        """Search products by name or description."""
        query_lower = query.lower()
        results = []
        for product in self._products.values():
            if query_lower in product.name.lower() or (
                product.description and query_lower in product.description.lower()
            ):
                results.append(product)
        return results


class CategoryService:
    """Service for category business logic."""

    def __init__(self):
        self._categories: Dict[str, Category] = {}
        # Create some default categories
        self._create_defaults()

    def _create_defaults(self):
        """Create default categories."""
        electronics = Category.create("Electronics", "Electronic devices and gadgets")
        books = Category.create("Books", "Books and literature")
        clothing = Category.create("Clothing", "Apparel and accessories")

        self._categories[electronics.id] = electronics
        self._categories[books.id] = books
        self._categories[clothing.id] = clothing

    def get_all(self) -> List[Category]:
        """Get all categories."""
        return list(self._categories.values())

    def get_by_id(self, category_id: str) -> Optional[Category]:
        """Get category by ID."""
        return self._categories.get(category_id)

    def create(self, name: str, description: Optional[str] = None) -> Category:
        """Create a new category."""
        category = Category.create(name, description)
        self._categories[category.id] = category
        return category

    def update(
        self, category_id: str, name: Optional[str] = None, description: Optional[str] = None
    ) -> Optional[Category]:
        """Update a category."""
        category = self._categories.get(category_id)
        if not category:
            return None

        if name is not None:
            category.name = name
        if description is not None:
            category.description = description

        return category

    def delete(self, category_id: str) -> bool:
        """Delete a category."""
        if category_id in self._categories:
            del self._categories[category_id]
            return True
        return False


# Controllers using class-based approach
@controller("/api/products")
class ProductController:
    """Controller for product-related operations."""

    def __init__(self, product_service: ProductService, category_service: CategoryService):
        self.product_service = product_service
        self.category_service = category_service

    @get("/")
    def get_products(self, req: IRequest, res: IResponse) -> None:
        """Get all products with optional filtering."""
        try:
            # Get query parameters
            category_id = req.get_query("category_id")
            search_query = req.get_query("search")

            if isinstance(category_id, list):
                category_id = category_id[0]
            if isinstance(search_query, list):
                search_query = search_query[0]

            # Apply filters
            if search_query:
                products = self.product_service.search(search_query)
            elif category_id:
                products = self.product_service.get_by_category(category_id)
            else:
                products = self.product_service.get_all()

            res.json(
                {
                    "products": [p.to_dict() for p in products],
                    "total": len(products),
                    "filters": {"category_id": category_id, "search": search_query},
                }
            )
        except Exception as e:
            res.json({"error": str(e)}, status_code=500)

    @get("/:id")
    def get_product(self, req: IRequest, res: IResponse) -> None:
        """Get a specific product."""
        try:
            product_id = req.params.get("id")
            if not product_id:
                res.json({"error": "Product ID is required"}, status_code=400)
                return

            product = self.product_service.get_by_id(product_id)
            if not product:
                res.json({"error": "Product not found"}, status_code=404)
                return

            res.json(product.to_dict())
        except Exception as e:
            res.json({"error": str(e)}, status_code=500)

    @post("/")
    def create_product(self, req: IRequest, res: IResponse) -> None:
        """Create a new product."""
        try:
            data = req.json
            if not isinstance(data, dict):
                res.json({"error": "Invalid request body"}, status_code=400)
                return

            # Validate required fields
            required_fields = ["name", "price", "category_id"]
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

            # Validate category exists
            category = self.category_service.get_by_id(data["category_id"])
            if not category:
                res.json({"error": "Invalid category_id"}, status_code=400)
                return

            # Validate price
            try:
                price = float(data["price"])
                if price < 0:
                    res.json({"error": "Price must be non-negative"}, status_code=400)
                    return
            except (ValueError, TypeError):
                res.json({"error": "Invalid price format"}, status_code=400)
                return

            # Create product
            product = self.product_service.create(
                name=data["name"],
                description=data.get("description"),
                price=price,
                category_id=data["category_id"],
                stock=data.get("stock", 0),
            )

            res.json(
                {"message": "Product created successfully", "product": product.to_dict()},
                status_code=201,
            )

        except Exception as e:
            res.json({"error": str(e)}, status_code=500)

    @put("/:id")
    def update_product(self, req: IRequest, res: IResponse) -> None:
        """Update a product."""
        try:
            product_id = req.params.get("id")
            if not product_id:
                res.json({"error": "Product ID is required"}, status_code=400)
                return

            data = req.json
            if not isinstance(data, dict):
                res.json({"error": "Invalid request body"}, status_code=400)
                return

            # Validate category if provided
            if "category_id" in data:
                category = self.category_service.get_by_id(data["category_id"])
                if not category:
                    res.json({"error": "Invalid category_id"}, status_code=400)
                    return

            # Validate price if provided
            if "price" in data:
                try:
                    price = float(data["price"])
                    if price < 0:
                        res.json({"error": "Price must be non-negative"}, status_code=400)
                        return
                    data["price"] = price
                except (ValueError, TypeError):
                    res.json({"error": "Invalid price format"}, status_code=400)
                    return

            # Update product
            product = self.product_service.update(product_id, **data)
            if not product:
                res.json({"error": "Product not found"}, status_code=404)
                return

            res.json({"message": "Product updated successfully", "product": product.to_dict()})

        except Exception as e:
            res.json({"error": str(e)}, status_code=500)

    @delete("/:id")
    def delete_product(self, req: IRequest, res: IResponse) -> None:
        """Delete a product."""
        try:
            product_id = req.params.get("id")
            if not product_id:
                res.json({"error": "Product ID is required"}, status_code=400)
                return

            success = self.product_service.delete(product_id)
            if not success:
                res.json({"error": "Product not found"}, status_code=404)
                return

            res.json({"message": "Product deleted successfully"})

        except Exception as e:
            res.json({"error": str(e)}, status_code=500)


@controller("/api/categories")
class CategoryController:
    """Controller for category-related operations."""

    def __init__(self, category_service: CategoryService):
        self.category_service = category_service

    @get("/")
    def get_categories(self, req: IRequest, res: IResponse) -> None:
        """Get all categories."""
        try:
            categories = self.category_service.get_all()
            res.json({"categories": [c.to_dict() for c in categories], "total": len(categories)})
        except Exception as e:
            res.json({"error": str(e)}, status_code=500)

    @get("/:id")
    def get_category(self, req: IRequest, res: IResponse) -> None:
        """Get a specific category."""
        try:
            category_id = req.params.get("id")
            if not category_id:
                res.json({"error": "Category ID is required"}, status_code=400)
                return

            category = self.category_service.get_by_id(category_id)
            if not category:
                res.json({"error": "Category not found"}, status_code=404)
                return

            res.json(category.to_dict())
        except Exception as e:
            res.json({"error": str(e)}, status_code=500)

    @post("/")
    def create_category(self, req: IRequest, res: IResponse) -> None:
        """Create a new category."""
        try:
            data = req.json
            if not isinstance(data, dict):
                res.json({"error": "Invalid request body"}, status_code=400)
                return

            name = data.get("name")
            if not name:
                res.json({"error": "Category name is required"}, status_code=400)
                return

            category = self.category_service.create(name=name, description=data.get("description"))

            res.json(
                {"message": "Category created successfully", "category": category.to_dict()},
                status_code=201,
            )

        except Exception as e:
            res.json({"error": str(e)}, status_code=500)

    @put("/:id")
    def update_category(self, req: IRequest, res: IResponse) -> None:
        """Update a category."""
        try:
            category_id = req.params.get("id")
            if not category_id:
                res.json({"error": "Category ID is required"}, status_code=400)
                return

            data = req.json
            if not isinstance(data, dict):
                res.json({"error": "Invalid request body"}, status_code=400)
                return

            category = self.category_service.update(
                category_id, name=data.get("name"), description=data.get("description")
            )

            if not category:
                res.json({"error": "Category not found"}, status_code=404)
                return

            res.json({"message": "Category updated successfully", "category": category.to_dict()})

        except Exception as e:
            res.json({"error": str(e)}, status_code=500)

    @delete("/:id")
    def delete_category(self, req: IRequest, res: IResponse) -> None:
        """Delete a category."""
        try:
            category_id = req.params.get("id")
            if not category_id:
                res.json({"error": "Category ID is required"}, status_code=400)
                return

            success = self.category_service.delete(category_id)
            if not success:
                res.json({"error": "Category not found"}, status_code=404)
                return

            res.json({"message": "Category deleted successfully"})

        except Exception as e:
            res.json({"error": str(e)}, status_code=500)


@controller("/api/categories/:id/products")
class CategoryProductsController:
    """Controller for category-specific product operations."""

    def __init__(self, product_service: ProductService, category_service: CategoryService):
        self.product_service = product_service
        self.category_service = category_service

    @get("/")
    def get_category_products(self, req: IRequest, res: IResponse) -> None:
        """Get all products in a specific category."""
        try:
            category_id = req.params.get("id")
            if not category_id:
                res.json({"error": "Category ID is required"}, status_code=400)
                return

            # Verify category exists
            category = self.category_service.get_by_id(category_id)
            if not category:
                res.json({"error": "Category not found"}, status_code=404)
                return

            products = self.product_service.get_by_category(category_id)

            res.json(
                {
                    "category": category.to_dict(),
                    "products": [p.to_dict() for p in products],
                    "total_products": len(products),
                }
            )

        except Exception as e:
            res.json({"error": str(e)}, status_code=500)


# Simple function-based controller for comparison
@get("/")
def home(req: IRequest, res: IResponse) -> None:
    """API home page."""
    res.json(
        {
            "api": "Controller-based Example - Pure Framework",
            "description": "Demonstrates class-based controllers and clean code organization",
            "features": [
                "Class-based controllers with dependency injection",
                "Route grouping with controller decorators",
                "Clean separation of concerns",
                "Service layer architecture",
                "Method-based route handlers",
            ],
            "endpoints": {
                "categories": {
                    "GET /api/categories": "List all categories",
                    "GET /api/categories/:id": "Get specific category",
                    "POST /api/categories": "Create category",
                    "PUT /api/categories/:id": "Update category",
                    "DELETE /api/categories/:id": "Delete category",
                },
                "products": {
                    "GET /api/products": "List products (supports ?category_id=... and ?search=...)",
                    "GET /api/products/:id": "Get specific product",
                    "POST /api/products": "Create product",
                    "PUT /api/products/:id": "Update product",
                    "DELETE /api/products/:id": "Delete product",
                },
                "category_products": {
                    "GET /api/categories/:id/products": "Get all products in a category"
                },
            },
            "examples": {
                "create_category": {
                    "method": "POST",
                    "url": "/api/categories",
                    "body": {
                        "name": "Home & Garden",
                        "description": "Home improvement and gardening supplies",
                    },
                },
                "create_product": {
                    "method": "POST",
                    "url": "/api/products",
                    "body": {
                        "name": "Wireless Headphones",
                        "description": "High-quality wireless headphones with noise cancellation",
                        "price": 149.99,
                        "category_id": "<category_id>",
                        "stock": 50,
                    },
                },
            },
        }
    )


# Application setup with dependency injection
def setup_application() -> PureFramework:
    """Set up the application with dependency injection."""
    app = PureFramework()
    container = DependencyContainer()

    # Register services
    container.register_type(ProductService, ProductService, LifecycleType.SINGLETON)
    container.register_type(CategoryService, CategoryService, LifecycleType.SINGLETON)

    # Register controllers with dependency injection
    # Note: The framework should automatically inject dependencies into controllers
    # For now, we'll create instances manually
    product_service = container.resolve(ProductService)
    category_service = container.resolve(CategoryService)

    # Create controller instances
    product_controller = ProductController(product_service, category_service)
    category_controller = CategoryController(category_service)
    category_products_controller = CategoryProductsController(product_service, category_service)

    # Add some sample data
    setup_sample_data(product_service, category_service)

    return app


def setup_sample_data(product_service: ProductService, category_service: CategoryService) -> None:
    """Set up some sample data for demonstration."""
    # Get default categories
    categories = category_service.get_all()
    if len(categories) >= 3:
        electronics_id = categories[0].id
        books_id = categories[1].id
        clothing_id = categories[2].id

        # Create sample products
        product_service.create(
            "Smartphone",
            "Latest model smartphone with advanced features",
            699.99,
            electronics_id,
            25,
        )

        product_service.create(
            "Laptop", "High-performance laptop for work and gaming", 1299.99, electronics_id, 10
        )

        product_service.create(
            "Python Programming Guide",
            "Comprehensive guide to Python programming",
            49.99,
            books_id,
            100,
        )

        product_service.create("T-Shirt", "Comfortable cotton t-shirt", 19.99, clothing_id, 50)


if __name__ == "__main__":
    print("Starting Pure Framework Controller-based Example...")
    print("\nArchitecture:")
    print("  Controllers -> Services -> Data Models")
    print("  ├── ProductController (CRUD operations)")
    print("  ├── CategoryController (Category management)")
    print("  └── CategoryProductsController (Category-specific products)")
    print("\nDependency Injection:")
    print("  ✓ Services registered as singletons")
    print("  ✓ Controllers receive services via constructor injection")
    print("  ✓ Clean separation of concerns")
    print("\nAPI Endpoints:")
    print("  Categories:")
    print("    GET    /api/categories           - List all categories")
    print("    POST   /api/categories           - Create category")
    print("    GET    /api/categories/:id       - Get category")
    print("    PUT    /api/categories/:id       - Update category")
    print("    DELETE /api/categories/:id       - Delete category")
    print("  Products:")
    print("    GET    /api/products             - List products (with filters)")
    print("    POST   /api/products             - Create product")
    print("    GET    /api/products/:id         - Get product")
    print("    PUT    /api/products/:id         - Update product")
    print("    DELETE /api/products/:id         - Delete product")
    print("  Category Products:")
    print("    GET    /api/categories/:id/products - Products by category")
    print("\nFiltering Examples:")
    print("  GET /api/products?search=phone     - Search products")
    print("  GET /api/products?category_id=...  - Filter by category")
    print("\nSample data preloaded for testing!")
    print("\nServer running on http://localhost:8000")

    app = setup_application()
    config = ApplicationConfig(host="localhost", port=8000, debug=True)
    app.run(config)

"""
RESTful API Example - Pure Framework

This example demonstrates:
- Complete CRUD operations (Create, Read, Update, Delete)
- Proper HTTP status codes
- Data validation
- Error handling
- JSON request/response handling
- In-memory data storage (for demonstration)
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import uuid

from pure_framework import PureFramework, get, post, put, delete
from pure_framework.framework_types import IRequest, IResponse, ApplicationConfig


# Data Models
@dataclass
class Task:
    id: str
    title: str
    description: Optional[str]
    completed: bool
    created_at: str
    updated_at: str

    @classmethod
    def create(cls, title: str, description: Optional[str] = None) -> "Task":
        """Create a new task."""
        now = datetime.now().isoformat()
        return cls(
            id=str(uuid.uuid4()),
            title=title,
            description=description,
            completed=False,
            created_at=now,
            updated_at=now,
        )

    def update(
        self,
        title: Optional[str] = None,
        description: Optional[str] = None,
        completed: Optional[bool] = None,
    ) -> None:
        """Update task fields."""
        if title is not None:
            self.title = title
        if description is not None:
            self.description = description
        if completed is not None:
            self.completed = completed
        self.updated_at = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


# In-memory storage (in a real app, this would be a database)
tasks_storage: Dict[str, Task] = {}


# Helper functions
def validate_task_data(data: Any) -> Dict[str, str]:
    """Validate task creation/update data."""
    errors = {}

    if not isinstance(data, dict):
        errors["general"] = "Request body must be a JSON object"
        return errors

    title = data.get("title")
    if not title or not isinstance(title, str) or not title.strip():
        errors["title"] = "Title is required and must be a non-empty string"

    description = data.get("description")
    if description is not None and not isinstance(description, str):
        errors["description"] = "Description must be a string"

    completed = data.get("completed")
    if completed is not None and not isinstance(completed, bool):
        errors["completed"] = "Completed must be a boolean"

    return errors


def create_error_response(
    res: IResponse, status_code: int, message: str, errors: Optional[Dict[str, str]] = None
) -> None:
    """Create a standardized error response."""
    error_data = {"error": True, "message": message, "status_code": status_code}

    if errors:
        error_data["validation_errors"] = errors

    res.json(error_data, status_code=status_code)


# API Routes
app = PureFramework()


@get("/api/tasks")
def get_tasks(req: IRequest, res: IResponse) -> None:
    """Get all tasks with optional filtering."""
    # Get query parameters for filtering
    completed_filter = req.get_query("completed")
    search_query = req.get_query("search")

    # Convert completed filter to boolean if provided
    completed_bool = None
    if completed_filter:
        if isinstance(completed_filter, list):
            completed_filter = completed_filter[0]
        if completed_filter.lower() in ["true", "1"]:
            completed_bool = True
        elif completed_filter.lower() in ["false", "0"]:
            completed_bool = False

    # Filter tasks
    filtered_tasks = []
    for task in tasks_storage.values():
        # Filter by completed status
        if completed_bool is not None and task.completed != completed_bool:
            continue

        # Filter by search query (title or description)
        if search_query:
            if isinstance(search_query, list):
                search_query = search_query[0]
            search_lower = search_query.lower()
            title_match = search_lower in task.title.lower()
            desc_match = task.description and search_lower in task.description.lower()
            if not (title_match or desc_match):
                continue

        filtered_tasks.append(task.to_dict())

    # Sort by created_at (newest first)
    filtered_tasks.sort(key=lambda x: x["created_at"], reverse=True)

    res.json(
        {
            "tasks": filtered_tasks,
            "total": len(filtered_tasks),
            "filters": {"completed": completed_bool, "search": search_query},
        }
    )


@get("/api/tasks/:id")
def get_task(req: IRequest, res: IResponse) -> None:
    """Get a specific task by ID."""
    task_id = req.params.get("id")

    if not task_id:
        create_error_response(res, 400, "Task ID is required")
        return

    task = tasks_storage.get(task_id)
    if not task:
        create_error_response(res, 404, f"Task with ID '{task_id}' not found")
        return

    res.json(task.to_dict())


@post("/api/tasks")
def create_task(req: IRequest, res: IResponse) -> None:
    """Create a new task."""
    try:
        data = req.json
        if not data:
            create_error_response(res, 400, "Request body is required")
            return

        # Validate data
        validation_errors = validate_task_data(data)
        if validation_errors:
            create_error_response(res, 400, "Validation failed", validation_errors)
            return

        # Create task - data is validated to be a dict by validate_task_data
        if not isinstance(data, dict):
            create_error_response(res, 400, "Invalid data format")
            return

        task = Task.create(
            title=data["title"].strip(), description=data.get("description", "").strip() or None
        )

        # Store task
        tasks_storage[task.id] = task

        # Return created task
        res.json({"message": "Task created successfully", "task": task.to_dict()}, status_code=201)

    except Exception as e:
        create_error_response(res, 500, f"Failed to create task: {str(e)}")


@put("/api/tasks/:id")
def update_task(req: IRequest, res: IResponse) -> None:
    """Update an existing task."""
    task_id = req.params.get("id")

    if not task_id:
        create_error_response(res, 400, "Task ID is required")
        return

    task = tasks_storage.get(task_id)
    if not task:
        create_error_response(res, 404, f"Task with ID '{task_id}' not found")
        return

    try:
        data = req.json
        if not data:
            create_error_response(res, 400, "Request body is required")
            return

        # Validate data
        validation_errors = validate_task_data(data)
        if validation_errors:
            create_error_response(res, 400, "Validation failed", validation_errors)
            return

        # Update task
        if not isinstance(data, dict):
            create_error_response(res, 400, "Invalid data format")
            return

        task.update(
            title=data.get("title", "").strip() or None,
            description=data.get("description", "").strip() or None,
            completed=data.get("completed"),
        )

        # Return updated task
        res.json({"message": "Task updated successfully", "task": task.to_dict()})

    except Exception as e:
        create_error_response(res, 500, f"Failed to update task: {str(e)}")


@delete("/api/tasks/:id")
def delete_task(req: IRequest, res: IResponse) -> None:
    """Delete a task."""
    task_id = req.params.get("id")

    if not task_id:
        create_error_response(res, 400, "Task ID is required")
        return

    task = tasks_storage.get(task_id)
    if not task:
        create_error_response(res, 404, f"Task with ID '{task_id}' not found")
        return

    # Delete task
    del tasks_storage[task_id]

    res.json({"message": "Task deleted successfully", "deleted_task_id": task_id})


@post("/api/tasks/:id/toggle")
def toggle_task(req: IRequest, res: IResponse) -> None:
    """Toggle task completion status."""
    task_id = req.params.get("id")

    if not task_id:
        create_error_response(res, 400, "Task ID is required")
        return

    task = tasks_storage.get(task_id)
    if not task:
        create_error_response(res, 404, f"Task with ID '{task_id}' not found")
        return

    # Toggle completion status
    task.update(completed=not task.completed)

    res.json({"message": "Task status toggled successfully", "task": task.to_dict()})


# Statistics endpoint
@get("/api/stats")
def get_stats(req: IRequest, res: IResponse) -> None:
    """Get task statistics."""
    total_tasks = len(tasks_storage)
    completed_tasks = sum(1 for task in tasks_storage.values() if task.completed)
    pending_tasks = total_tasks - completed_tasks

    res.json(
        {
            "total_tasks": total_tasks,
            "completed_tasks": completed_tasks,
            "pending_tasks": pending_tasks,
            "completion_rate": round(
                (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0, 2
            ),
        }
    )


# Bulk operations
@delete("/api/tasks")
def delete_all_tasks(req: IRequest, res: IResponse) -> None:
    """Delete all tasks (with confirmation)."""
    # Check for confirmation in query params
    confirm = req.get_query("confirm")
    if not confirm or (isinstance(confirm, list) and confirm[0].lower() != "true"):
        create_error_response(
            res, 400, "This operation requires confirmation. Add ?confirm=true to proceed."
        )
        return

    deleted_count = len(tasks_storage)
    tasks_storage.clear()

    res.json({"message": "All tasks deleted successfully", "deleted_count": deleted_count})


# Root endpoint with API documentation
@get("/")
def api_documentation(req: IRequest, res: IResponse) -> None:
    """API documentation."""
    docs = {
        "api": "Task Management API",
        "version": "1.0.0",
        "description": "A simple REST API for managing tasks",
        "endpoints": {
            "GET /api/tasks": "Get all tasks (supports ?completed=true/false and ?search=query)",
            "GET /api/tasks/:id": "Get a specific task",
            "POST /api/tasks": "Create a new task",
            "PUT /api/tasks/:id": "Update a task",
            "DELETE /api/tasks/:id": "Delete a task",
            "POST /api/tasks/:id/toggle": "Toggle task completion status",
            "GET /api/stats": "Get task statistics",
            "DELETE /api/tasks": "Delete all tasks (requires ?confirm=true)",
        },
        "task_model": {
            "id": "string (UUID)",
            "title": "string (required)",
            "description": "string (optional)",
            "completed": "boolean",
            "created_at": "string (ISO datetime)",
            "updated_at": "string (ISO datetime)",
        },
    }

    res.json(docs)


if __name__ == "__main__":
    print("Starting Pure Framework RESTful API Example...")
    print("\nTask Management API Endpoints:")
    print("  GET    /                    - API documentation")
    print("  GET    /api/tasks           - Get all tasks")
    print("  GET    /api/tasks/:id       - Get specific task")
    print("  POST   /api/tasks           - Create new task")
    print("  PUT    /api/tasks/:id       - Update task")
    print("  DELETE /api/tasks/:id       - Delete task")
    print("  POST   /api/tasks/:id/toggle - Toggle task completion")
    print("  GET    /api/stats           - Get statistics")
    print("  DELETE /api/tasks           - Delete all tasks")
    print("\nExample requests:")
    print(
        "  Create task: POST /api/tasks {'title': 'Learn Pure Framework', 'description': 'Build awesome APIs'}"
    )
    print("  Filter:      GET /api/tasks?completed=false&search=framework")
    print("\nServer running on http://localhost:8000")

    config = ApplicationConfig(host="localhost", port=8000, debug=True)
    app.run(config)

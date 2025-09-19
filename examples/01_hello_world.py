"""
Hello World Example - Pure Framework
Demonstrates basic routing, parameters, and JSON responses.
"""

from pure_framework import PureFramework, get, post, route
from pure_framework.framework_types import IRequest, IResponse, ApplicationConfig


@get("/hello/:name")
def hello_name(req: IRequest, res: IResponse) -> None:
    name = req.params.get("name", "World")
    res.json({"message": f"Hello, {name}!"})


@get("/users")
def greet(req: IRequest, res: IResponse) -> None:
    name = req.get_query("name") or "Friend"
    age = req.get_query("age")

    if isinstance(name, list):
        name = name[0]
    if isinstance(age, list):
        age = age[0]

    response = {"message": f"Hello, {name}!"}

    if age:
        try:
            age_int = int(age)
            response["age_group"] = (
                "child" if age_int < 18 else "senior" if age_int >= 65 else "adult"
            )
        except ValueError:
            response["error"] = "Invalid age"

    res.json(response)


from pure_framework import PureFramework, get, post
from pure_framework.framework_types import IRequest, IResponse, ApplicationConfig


# Create the application instance
app = PureFramework()


@get("/")
def home(req: IRequest, res: IResponse) -> None:
    """Home page with a simple greeting."""
    res.json({"message": "Welcome to Pure Framework!", "version": "2.0.0", "docs": "/docs"})


@get("/hello")
def hello(req: IRequest, res: IResponse) -> None:
    """Simple hello endpoint."""
    name = req.get_query("name", "World")
    if isinstance(name, list):
        name = name[0]
    res.json({"message": f"Hello, {name}!"})


@get("/hello/:name")
def hello_with_path(req: IRequest, res: IResponse) -> None:
    """Hello endpoint with path parameter."""
    name = req.params.get("name", "Anonymous")
    greeting = req.get_query("greeting", "Hello")
    if isinstance(greeting, list):
        greeting = greeting[0]

    res.json({"message": f"{greeting}, {name}!", "path_param": name, "query_greeting": greeting})


@get("/plain")
def plain_text(req: IRequest, res: IResponse) -> None:
    """Example of plain text response."""
    res.set_header("Content-Type", "text/plain")
    res.text("This is a plain text response from Pure Framework!")


@post("/echo")
def echo(req: IRequest, res: IResponse) -> None:
    """Echo back the request body."""
    try:
        # Get the request body as JSON
        body = req.json

        response_data = {
            "echoed_data": body,
            "method": req.method.value,
            "headers": dict(req.headers),
            "query_params": dict(req.query),
        }

        res.json(response_data)
    except Exception as e:
        res.json({"error": "Invalid JSON in request body", "message": str(e)}, status_code=400)


@get("/info")
def request_info(req: IRequest, res: IResponse) -> None:
    """Display request information."""
    info = {
        "method": req.method.value,
        "path": req.path,
        "headers": dict(req.headers),
        "query_params": dict(req.query),
        "user_agent": req.get_header("User-Agent", "Unknown"),
    }

    res.json(info)


if __name__ == "__main__":
    print("Starting Pure Framework Hello World Example...")
    print("Available endpoints:")
    print("  GET  /           - Home page")
    print("  GET  /hello      - Hello with query param (?name=...)")
    print("  GET  /hello/:name - Hello with path param")
    print("  GET  /plain      - Plain text response")
    print("  POST /echo       - Echo request body")
    print("  GET  /info       - Request information")
    print("\nServer running on http://localhost:8000")

    # Create configuration for the server
    config = ApplicationConfig(host="localhost", port=8000, debug=True)
    app.run(config)

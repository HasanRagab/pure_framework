"""
Test client for Pure Framework applications.

Provides comprehensive testing utilities for both sync and async applications.
"""

import json
import io
import threading
import time
from typing import Any, Dict, Optional, Union, List, TYPE_CHECKING
from urllib.parse import urlencode, urlparse, parse_qs
from http.server import HTTPServer, BaseHTTPRequestHandler
from contextlib import contextmanager
import inspect
import asyncio

if TYPE_CHECKING:
    from .application import PureFramework
    from .async_application import AsyncPureFramework

from .framework_types import IRequest, IResponse, JSON, Headers
from .http import Request, Response


class TestResponse:
    """
    Test response object with assertion methods.

    Provides convenient methods for testing HTTP responses.
    """

    def __init__(
        self,
        status_code: int,
        headers: Headers,
        content: bytes,
        json_data: Optional[Any] = None,
    ) -> None:
        self._status_code = status_code
        self._headers = headers
        self._content = content
        self._json_data = json_data

    @property
    def status_code(self) -> int:
        """HTTP status code."""
        return self._status_code

    @property
    def headers(self) -> Headers:
        """Response headers."""
        return self._headers

    @property
    def content(self) -> bytes:
        """Raw response content."""
        return self._content

    @property
    def text(self) -> str:
        """Response content as text."""
        return self._content.decode("utf-8")

    @property
    def json(self) -> Any:
        """Response content as JSON."""
        if self._json_data is None:
            try:
                self._json_data = json.loads(self.text)
            except json.JSONDecodeError:
                raise ValueError("Response is not valid JSON")
        return self._json_data

    def assert_status_code(self, expected: int) -> None:
        """Assert that response has expected status code."""
        assert (
            self.status_code == expected
        ), f"Expected status code {expected}, got {self.status_code}"

    def assert_json_equals(self, expected: Any) -> None:
        """Assert that response JSON equals expected value."""
        assert self.json == expected, f"Expected {expected}, got {self.json}"

    def assert_json_contains(self, **kwargs: Any) -> None:
        """Assert that response JSON contains expected key-value pairs."""
        json_data = self.json
        if not isinstance(json_data, dict):
            raise AssertionError("Response JSON is not a dictionary")

        for key, expected_value in kwargs.items():
            assert key in json_data, f"Key '{key}' not found in response JSON"
            assert (
                json_data[key] == expected_value
            ), f"Expected {key}={expected_value}, got {key}={json_data[key]}"

    def assert_header_exists(self, header_name: str) -> None:
        """Assert that response contains a specific header."""
        header_name_lower = header_name.lower()
        headers_lower = {k.lower(): v for k, v in self.headers.items()}
        assert header_name_lower in headers_lower, f"Header '{header_name}' not found in response"

    def assert_header_equals(self, header_name: str, expected_value: str) -> None:
        """Assert that response header has expected value."""
        header_name_lower = header_name.lower()
        headers_lower = {k.lower(): v for k, v in self.headers.items()}

        assert header_name_lower in headers_lower, f"Header '{header_name}' not found in response"

        actual_value = headers_lower[header_name_lower]
        assert (
            actual_value == expected_value
        ), f"Expected header {header_name}={expected_value}, got {actual_value}"

    def assert_contains_text(self, text: str) -> None:
        """Assert that response text contains the specified text."""
        assert text in self.text, f"Text '{text}' not found in response"

    def assert_not_contains_text(self, text: str) -> None:
        """Assert that response text does not contain the specified text."""
        assert text not in self.text, f"Text '{text}' found in response"

    def __repr__(self) -> str:
        return f"TestResponse(status={self.status_code}, headers={len(self.headers)})"


class MockHTTPHandler(BaseHTTPRequestHandler):
    """Mock HTTP handler for capturing responses."""

    def __init__(self, test_client: "TestClient") -> None:
        self.test_client = test_client
        self.response_status = 200
        self.response_headers: Headers = {}
        self.response_content = b""
        super().__init__(None, None, None)  # type: ignore

    def setup(self) -> None:
        """Override setup to avoid socket operations."""
        pass

    def finish(self) -> None:
        """Override finish to avoid socket operations."""
        pass

    def send_response(self, code: int, message: Optional[str] = None) -> None:
        """Capture response status."""
        self.response_status = code

    def send_header(self, keyword: str, value: str) -> None:
        """Capture response headers."""
        self.response_headers[keyword] = value

    def end_headers(self) -> None:
        """End headers (no-op for testing)."""
        pass

    def wfile_write(self, data: bytes) -> None:
        """Capture response content."""
        self.response_content += data

    @property
    def wfile(self) -> Any:
        """Mock wfile for writing response."""

        class MockWFile:
            def __init__(self, handler: MockHTTPHandler):
                self.handler = handler

            def write(self, data: bytes) -> None:
                self.handler.wfile_write(data)

            def flush(self) -> None:
                pass

        return MockWFile(self)

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress log messages during testing."""
        pass


class TestClient:
    """
    Comprehensive test client for Pure Framework applications.

    Supports both sync and async applications with convenient testing methods.
    """

    def __init__(self, app: Union["PureFramework", "AsyncPureFramework"]) -> None:
        """
        Initialize test client with application.

        Args:
            app: Pure Framework application instance (sync or async)
        """
        self.app = app
        self._is_async = hasattr(app, "run_async")

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: Optional[Headers] = None,
        query_params: Optional[Dict[str, Union[str, List[str]]]] = None,
        json_data: Optional[Any] = None,
        form_data: Optional[Dict[str, str]] = None,
        content: Optional[Union[str, bytes]] = None,
        content_type: Optional[str] = None,
    ) -> TestResponse:
        """
        Make a test request to the application.

        Args:
            method: HTTP method
            path: Request path
            headers: Request headers
            query_params: Query parameters
            json_data: JSON data for request body
            form_data: Form data for request body
            content: Raw content for request body
            content_type: Content-Type header

        Returns:
            TestResponse object
        """
        # Prepare headers
        request_headers = headers or {}

        # Handle different content types
        body_content = b""
        if json_data is not None:
            body_content = json.dumps(json_data).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        elif form_data is not None:
            body_content = urlencode(form_data).encode("utf-8")
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif content is not None:
            if isinstance(content, str):
                body_content = content.encode("utf-8")
            else:
                body_content = content
            if content_type:
                request_headers["Content-Type"] = content_type

        # Add query parameters to path
        if query_params:
            separator = "&" if "?" in path else "?"
            query_string = urlencode(query_params, doseq=True)
            path = f"{path}{separator}{query_string}"

        # Create mock handler
        handler = MockHTTPHandler(self)
        handler.command = method.upper()
        handler.path = path
        handler.headers = request_headers
        handler.rfile = io.BytesIO(body_content)

        # Handle request based on app type
        if self._is_async:
            return self._handle_async_request(handler)
        else:
            return self._handle_sync_request(handler)

    def _handle_sync_request(self, handler: MockHTTPHandler) -> TestResponse:
        """Handle request for sync application."""
        from .framework_types import HTTPMethod

        try:
            method = HTTPMethod(handler.command)
            self.app.handle_request(handler, method)
        except Exception as e:
            # Handle errors by setting appropriate response
            handler.response_status = 500
            handler.response_content = json.dumps(
                {"error": "Internal Server Error", "message": str(e)}
            ).encode("utf-8")

        return TestResponse(
            status_code=handler.response_status,
            headers=handler.response_headers,
            content=handler.response_content,
        )

    def _handle_async_request(self, handler: MockHTTPHandler) -> TestResponse:
        """Handle request for async application."""
        from .framework_types import HTTPMethod

        async def async_handler():
            try:
                method = HTTPMethod(handler.command)
                await self.app.handle_request(handler, method)
            except Exception as e:
                # Handle errors by setting appropriate response
                handler.response_status = 500
                handler.response_content = json.dumps(
                    {"error": "Internal Server Error", "message": str(e)}
                ).encode("utf-8")

        # Run async handler
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If we're already in an async context, create a new task
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(asyncio.run, async_handler())
                    future.result()
            else:
                loop.run_until_complete(async_handler())
        except RuntimeError:
            # Create new event loop if none exists
            asyncio.run(async_handler())

        return TestResponse(
            status_code=handler.response_status,
            headers=handler.response_headers,
            content=handler.response_content,
        )

    def get(
        self,
        path: str,
        *,
        headers: Optional[Headers] = None,
        query_params: Optional[Dict[str, Union[str, List[str]]]] = None,
    ) -> TestResponse:
        """Make a GET request."""
        return self.request("GET", path, headers=headers, query_params=query_params)

    def post(
        self,
        path: str,
        *,
        headers: Optional[Headers] = None,
        query_params: Optional[Dict[str, Union[str, List[str]]]] = None,
        json_data: Optional[Any] = None,
        form_data: Optional[Dict[str, str]] = None,
        content: Optional[Union[str, bytes]] = None,
        content_type: Optional[str] = None,
    ) -> TestResponse:
        """Make a POST request."""
        return self.request(
            "POST",
            path,
            headers=headers,
            query_params=query_params,
            json_data=json_data,
            form_data=form_data,
            content=content,
            content_type=content_type,
        )

    def put(
        self,
        path: str,
        *,
        headers: Optional[Headers] = None,
        query_params: Optional[Dict[str, Union[str, List[str]]]] = None,
        json_data: Optional[Any] = None,
        form_data: Optional[Dict[str, str]] = None,
        content: Optional[Union[str, bytes]] = None,
        content_type: Optional[str] = None,
    ) -> TestResponse:
        """Make a PUT request."""
        return self.request(
            "PUT",
            path,
            headers=headers,
            query_params=query_params,
            json_data=json_data,
            form_data=form_data,
            content=content,
            content_type=content_type,
        )

    def delete(
        self,
        path: str,
        *,
        headers: Optional[Headers] = None,
        query_params: Optional[Dict[str, Union[str, List[str]]]] = None,
    ) -> TestResponse:
        """Make a DELETE request."""
        return self.request("DELETE", path, headers=headers, query_params=query_params)

    def patch(
        self,
        path: str,
        *,
        headers: Optional[Headers] = None,
        query_params: Optional[Dict[str, Union[str, List[str]]]] = None,
        json_data: Optional[Any] = None,
        form_data: Optional[Dict[str, str]] = None,
        content: Optional[Union[str, bytes]] = None,
        content_type: Optional[str] = None,
    ) -> TestResponse:
        """Make a PATCH request."""
        return self.request(
            "PATCH",
            path,
            headers=headers,
            query_params=query_params,
            json_data=json_data,
            form_data=form_data,
            content=content,
            content_type=content_type,
        )

    @contextmanager
    def session(self, **session_data: Any):
        """
        Context manager for session-based testing.

        Args:
            **session_data: Session data to maintain across requests
        """
        # Store original state
        original_container_state = None
        if hasattr(self.app, "_container"):
            original_container_state = self.app._container._scoped_instances.copy()

        try:
            # Set session data in container if available
            if hasattr(self.app, "_container"):
                for key, value in session_data.items():
                    self.app._container._scoped_instances[key] = value

            yield self
        finally:
            # Restore original state
            if hasattr(self.app, "_container") and original_container_state is not None:
                self.app._container._scoped_instances = original_container_state

    def __repr__(self) -> str:
        app_type = "async" if self._is_async else "sync"
        return f"TestClient(app_type={app_type})"


# Convenience functions for testing
def create_test_client(app: Union["PureFramework", "AsyncPureFramework"]) -> TestClient:
    """
    Create a test client for the given application.

    Args:
        app: Pure Framework application instance

    Returns:
        TestClient instance
    """
    return TestClient(app)


def assert_response_ok(response: TestResponse) -> None:
    """Assert that response is successful (2xx status code)."""
    assert (
        200 <= response.status_code < 300
    ), f"Expected successful response, got {response.status_code}"


def assert_response_error(response: TestResponse, expected_status: Optional[int] = None) -> None:
    """Assert that response is an error (4xx or 5xx status code)."""
    if expected_status:
        response.assert_status_code(expected_status)
    else:
        assert response.status_code >= 400, f"Expected error response, got {response.status_code}"

"""
HTTP request and response implementations with full type safety and proper encapsulation.
"""

import json
from typing import Optional, Dict, List, Union, Any, cast
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler

from .framework_types import (
    IRequest,
    IResponse,
    Headers,
    QueryParams,
    PathParams,
    JSON,
    HTTPMethod,
    ValidationError,
)


class Request(IRequest):
    """
    HTTP Request implementation with type safety and proper encapsulation.
    Provides immutable access to request data with validation.
    """

    def __init__(
        self, handler: BaseHTTPRequestHandler, path_params: Optional[PathParams] = None
    ) -> None:
        """
        Initialize request from HTTP handler.

        Args:
            handler: The HTTP request handler
            path_params: Path parameters from route matching
        """
        self._handler = handler
        self._path = handler.path.split("?")[0]  # Remove query string
        self._method = HTTPMethod(handler.command)
        self._headers = self._parse_headers(handler.headers)
        self._query = self._parse_query_params(handler.path)
        self._params = path_params or {}
        self._body: Optional[str] = None
        self._json: Optional[JSON] = None
        self._parsed_body = False

    def _parse_headers(self, raw_headers: Any) -> Headers:
        """Parse headers into a case-insensitive dictionary."""
        headers: Headers = {}
        for key, value in raw_headers.items():
            headers[key.lower()] = value
        return headers

    def _parse_query_params(self, full_path: str) -> QueryParams:
        """Parse query parameters from the path."""
        parsed = urlparse(full_path)
        query_dict = parse_qs(parsed.query)

        # Convert to expected format
        result: QueryParams = {}
        for key, values in query_dict.items():
            if len(values) == 1:
                result[key] = values[0]
            else:
                result[key] = values
        return result

    def _ensure_body_parsed(self) -> None:
        """Lazily parse the request body."""
        if self._parsed_body:
            return

        content_length = self._headers.get("content-length")
        if content_length:
            try:
                length = int(content_length)
                self._body = self._handler.rfile.read(length).decode("utf-8")

                # Try to parse as JSON
                if self._headers.get("content-type", "").startswith("application/json"):
                    try:
                        self._json = json.loads(self._body)
                    except json.JSONDecodeError:
                        # Invalid JSON, leave as None
                        pass
            except (ValueError, UnicodeDecodeError) as e:
                raise ValidationError(f"Failed to parse request body: {e}")

        self._parsed_body = True

    @property
    def path(self) -> str:
        """The request path without query parameters."""
        return self._path

    @property
    def method(self) -> HTTPMethod:
        """The HTTP method."""
        return self._method

    @property
    def headers(self) -> Headers:
        """Request headers (case-insensitive access)."""
        return self._headers.copy()  # Return copy to maintain immutability

    @property
    def query(self) -> QueryParams:
        """Query parameters."""
        return self._query.copy()  # Return copy to maintain immutability

    @property
    def params(self) -> PathParams:
        """Path parameters from route matching."""
        return self._params.copy()  # Return copy to maintain immutability

    @property
    def body(self) -> Optional[str]:
        """Raw request body."""
        self._ensure_body_parsed()
        return self._body

    @property
    def json(self) -> Optional[JSON]:
        """Parsed JSON body."""
        self._ensure_body_parsed()
        return self._json

    def get_header(self, name: str, default: Optional[str] = None) -> Optional[str]:
        """
        Get a specific header value (case-insensitive).

        Args:
            name: Header name
            default: Default value if header not found

        Returns:
            Header value or default
        """
        return self._headers.get(name.lower(), default)

    def get_query(
        self, name: str, default: Optional[str] = None
    ) -> Optional[Union[str, List[str]]]:
        """
        Get a specific query parameter.

        Args:
            name: Parameter name
            default: Default value if parameter not found

        Returns:
            Parameter value(s) or default
        """
        return self._query.get(name, default)

    def set_params(self, params: PathParams) -> None:
        """
        Set path parameters (used by router).

        Args:
            params: Path parameters
        """
        self._params = params.copy()

    def __repr__(self) -> str:
        return f"Request(method={self.method.value}, path='{self.path}')"


class Response(IResponse):
    """
    HTTP Response implementation with type safety and proper encapsulation.
    Provides fluent interface for building responses.
    """

    def __init__(self, handler: BaseHTTPRequestHandler) -> None:
        """
        Initialize response with HTTP handler.

        Args:
            handler: The HTTP request handler
        """
        self._handler = handler
        self._status_code = 200
        self._headers: Headers = {"content-type": "text/plain", "x-powered-by": "Pure Framework"}
        self._sent = False

    @property
    def status_code(self) -> int:
        """HTTP status code."""
        return self._status_code

    @status_code.setter
    def status_code(self, value: int) -> None:
        """
        Set HTTP status code.

        Args:
            value: Status code (100-599)

        Raises:
            ValidationError: If status code is invalid
        """
        if not isinstance(value, int) or not (100 <= value <= 599):
            raise ValidationError(f"Invalid status code: {value}")

        if self._sent:
            raise ValidationError("Cannot modify status code after response has been sent")

        self._status_code = value

    @property
    def headers(self) -> Headers:
        """Response headers."""
        return self._headers.copy()  # Return copy to maintain encapsulation

    def set_header(self, name: str, value: str) -> "Response":
        """
        Set a response header.

        Args:
            name: Header name
            value: Header value

        Returns:
            Self for method chaining

        Raises:
            ValidationError: If response has already been sent
        """
        if self._sent:
            raise ValidationError("Cannot modify headers after response has been sent")

        self._headers[name.lower()] = value
        return self

    def json(self, data: JSON, status_code: Optional[int] = None) -> None:
        """
        Send JSON response.

        Args:
            data: Data to serialize as JSON
            status_code: Optional status code override

        Raises:
            ValidationError: If data cannot be serialized or response already sent
        """
        if status_code is not None:
            self.status_code = status_code

        self.set_header("content-type", "application/json")

        try:
            json_str = json.dumps(data, indent=2 if self._is_debug_mode() else None)
            self._send_response(json_str.encode("utf-8"))
        except (TypeError, ValueError) as e:
            raise ValidationError(f"Failed to serialize JSON: {e}")

    def html(self, content: str, status_code: Optional[int] = None) -> None:
        """
        Send HTML response.

        Args:
            content: HTML content
            status_code: Optional status code override
        """
        if status_code is not None:
            self.status_code = status_code

        self.set_header("content-type", "text/html; charset=utf-8")
        self._send_response(content.encode("utf-8"))

    def text(self, content: str, status_code: Optional[int] = None) -> None:
        """
        Send plain text response.

        Args:
            content: Text content
            status_code: Optional status code override
        """
        if status_code is not None:
            self.status_code = status_code

        self.set_header("content-type", "text/plain; charset=utf-8")
        self._send_response(content.encode("utf-8"))

    def send(self, data: Union[str, bytes], status_code: Optional[int] = None) -> None:
        """
        Send raw response.

        Args:
            data: Response data
            status_code: Optional status code override
        """
        if status_code is not None:
            self.status_code = status_code

        if isinstance(data, str):
            data = data.encode("utf-8")

        self._send_response(data)

    def redirect(self, location: str, status_code: int = 302) -> None:
        """
        Send redirect response.

        Args:
            location: Redirect location
            status_code: Redirect status code (301, 302, 303, 307, 308)
        """
        if status_code not in (301, 302, 303, 307, 308):
            raise ValidationError(f"Invalid redirect status code: {status_code}")

        self.status_code = status_code
        self.set_header("location", location)
        self._send_response(b"")

    def _send_response(self, data: bytes) -> None:
        """
        Send the actual HTTP response.

        Args:
            data: Response body

        Raises:
            ValidationError: If response has already been sent
        """
        if self._sent:
            raise ValidationError("Response has already been sent")

        try:
            # Send status line
            self._handler.send_response(self._status_code)

            # Send headers
            for name, value in self._headers.items():
                self._handler.send_header(name, value)

            # End headers
            self._handler.end_headers()

            # Send body
            self._handler.wfile.write(data)

            self._sent = True

        except Exception as e:
            raise ValidationError(f"Failed to send response: {e}")

    def _is_debug_mode(self) -> bool:
        """Check if debug mode is enabled (placeholder for now)."""
        # TODO: Get from application config
        return False

    def __repr__(self) -> str:
        return f"Response(status_code={self.status_code}, sent={self._sent})"

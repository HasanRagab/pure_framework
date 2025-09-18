"""
Simple OpenAPI documentation generator for Pure Framework.
"""

import json
from typing import Dict, Any, List
from .framework_types import RouteInfo, HTTPMethod


class OpenAPIGenerator:
    """Simple OpenAPI 3.0 specification generator."""

    def __init__(self, title: str = "Pure Framework API", version: str = "1.0.0") -> None:
        """
        Initialize the generator.

        Args:
            title: API title
            version: API version
        """
        self.title = title
        self.version = version

    def generate(self, routes: List[RouteInfo]) -> Dict[str, Any]:
        """
        Generate OpenAPI specification.

        Args:
            routes: List of route information

        Returns:
            OpenAPI specification dictionary
        """
        paths: Dict[str, Any] = {}

        for route in routes:
            path = route.path
            if path not in paths:
                paths[path] = {}

            for method in route.methods:
                method_lower = method.value.lower()
                paths[path][method_lower] = {
                    "summary": route.name,
                    "description": route.description or f"{method.value} {path}",
                    "responses": {
                        "200": {"description": "Success"},
                        "404": {"description": "Not Found"},
                        "500": {"description": "Internal Server Error"},
                    },
                }

        return {
            "openapi": "3.0.0",
            "info": {"title": self.title, "version": self.version},
            "paths": paths,
        }

    def generate_swagger_ui(self, openapi_spec: Dict[str, Any]) -> str:
        """
        Generate Swagger UI HTML.

        Args:
            openapi_spec: OpenAPI specification

        Returns:
            HTML content for Swagger UI
        """
        spec_json = json.dumps(openapi_spec, indent=2)

        return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Swagger UI - {self.title}</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@4.18.2/swagger-ui.css" />
    <style>
        html {{
            box-sizing: border-box;
            overflow: -moz-scrollbars-vertical;
            overflow-y: scroll;
        }}
        *, *:before, *:after {{
            box-sizing: inherit;
        }}
        body {{
            margin:0;
            background: #fafafa;
        }}
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@4.18.2/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@4.18.2/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {{
            const ui = SwaggerUIBundle({{
                url: '',
                spec: {spec_json},
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout"
            }});
        }};
    </script>
</body>
</html>
        """.strip()

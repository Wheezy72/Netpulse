"""The published API reference.

Swagger groups routes by tag, so a tag without a description shows up as an
unexplained heading in the middle of the reference. This keeps the metadata in
step with the routers: adding a router without documenting its tag fails here
rather than months later in the browser.
"""
from __future__ import annotations

import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://netpulse:netpulse@localhost:5432/netpulse")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("ENVIRONMENT", "development")

from app.api.routes import api_router  # noqa: E402
from app.main import app  # noqa: E402


def _router_tags() -> set[str]:
    tags: set[str] = set()
    for route in api_router.routes:
        for tag in getattr(route, "tags", None) or ():
            if tag:
                tags.add(str(tag))
    return tags


class TestOpenApiMetadata:
    def test_every_router_tag_has_a_description(self) -> None:
        described = {tag["name"]: tag.get("description", "") for tag in app.openapi_tags or []}

        assert _router_tags() - set(described) == set()
        assert [name for name, text in described.items() if not text.strip()] == []

    def test_the_document_has_a_description_and_a_version(self) -> None:
        assert app.description and len(app.description.strip()) > 80
        assert app.version and app.version.strip()

    def test_docs_are_served_in_development(self) -> None:
        paths = {getattr(route, "path", "") for route in app.routes}

        assert "/api/docs" in paths
        assert app.openapi_url == "/api/openapi.json"

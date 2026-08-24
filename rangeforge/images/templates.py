"""Reusable base-template metadata and readiness management."""

from __future__ import annotations

import hashlib
import json
from typing import Protocol

import yaml

from rangeforge import __version__
from rangeforge.images.cache import ImageCache
from rangeforge.images.manager import ImageManager, ImageManagerError
from rangeforge.images.models import BaseTemplate, TemplateState
from rangeforge.runtime.models import VMBackend

TEMPLATE_SCHEMA_VERSION = 1


def template_fingerprint(
    image_id: str,
    source_checksum: str,
    backend: VMBackend,
    schema_version: int = TEMPLATE_SCHEMA_VERSION,
) -> str:
    payload = {
        "backend": backend.value,
        "image_id": image_id,
        "schema_version": schema_version,
        "source_checksum": source_checksum.lower(),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def template_id(image_id: str) -> str:
    return f"rf-base-{image_id}"


class TemplateBackend(Protocol):
    def available(self) -> bool: ...

    def template_exists(self, reference: str) -> bool: ...


class TemplateManager:
    def __init__(self, image_manager: ImageManager) -> None:
        self.image_manager = image_manager
        self.cache: ImageCache = image_manager.cache

    def prepare(
        self,
        image_id: str,
        backend: VMBackend,
        backend_driver: TemplateBackend,
        *,
        reference: str | None = None,
        force: bool = False,
    ) -> BaseTemplate:
        manifest = self.image_manager.registry.require(image_id)
        verification = self.image_manager.verify(image_id)
        if not verification.valid or verification.expected_sha256 is None:
            raise ImageManagerError(
                f"Source image '{image_id}' is not READY. Pull or import and verify it first."
            )
        if backend not in manifest.backends:
            raise ImageManagerError(
                f"Image '{image_id}' does not support backend '{backend.value}'."
            )
        if not backend_driver.available():
            raise ImageManagerError(f"{backend.value.upper()} backend is unavailable.")

        stable_reference = reference or self._default_reference(image_id, backend)
        existing = self.cache.load_template(image_id, backend)
        expected_fingerprint = template_fingerprint(
            image_id, verification.expected_sha256, backend
        )
        if existing and existing.status is TemplateState.READY and not force:
            if existing.fingerprint == expected_fingerprint:
                if backend_driver.template_exists(existing.reference):
                    return existing
                raise ImageManagerError(
                    f"Template metadata exists but backend resource '{existing.reference}' "
                    "is missing. Recreate it, then use --force."
                )
            raise ImageManagerError(
                "Existing template is stale. Recreate the backend template, then use --force."
            )
        if not backend_driver.template_exists(stable_reference):
            raise ImageManagerError(
                f"Prepared {backend.value.upper()} template '{stable_reference}' was not found. "
                "Create the clean base template explicitly, then run this command again."
            )

        template = BaseTemplate(
            id=template_id(image_id),
            image_id=image_id,
            backend=backend,
            architecture=manifest.architecture,
            reference=stable_reference,
            status=TemplateState.READY,
            source_checksum=verification.expected_sha256,
            schema_version=TEMPLATE_SCHEMA_VERSION,
            created_by_version=__version__,
            fingerprint=expected_fingerprint,
        )
        path = self.cache.template_metadata_path(image_id, backend)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".yaml.partial")
        temporary.write_text(
            yaml.safe_dump(template.model_dump(mode="json"), sort_keys=False),
            encoding="utf-8",
        )
        temporary.replace(path)
        return template

    def require_ready(self, image_id: str, backend: VMBackend) -> BaseTemplate:
        manifest = self.image_manager.registry.require(image_id)
        template = self.cache.load_template(image_id, backend)
        if template is None or template.status is not TemplateState.READY:
            raise ImageManagerError(
                f"{backend.value.upper()} base template is missing for '{image_id}'."
            )
        expected = template_fingerprint(
            template.image_id,
            template.source_checksum,
            template.backend,
            template.schema_version,
        )
        if expected != template.fingerprint:
            raise ImageManagerError(f"Base template '{template.id}' metadata is stale.")
        if (
            manifest.checksum.value is None
            or template.source_checksum.lower() != manifest.checksum.value.lower()
        ):
            raise ImageManagerError(f"Base template '{template.id}' source checksum is stale.")
        return template

    def state(self, image_id: str, backend: VMBackend) -> TemplateState:
        try:
            self.require_ready(image_id, backend)
        except ImageManagerError as exc:
            return TemplateState.STALE if "stale" in str(exc).lower() else TemplateState.MISSING
        return TemplateState.READY

    def _default_reference(self, image_id: str, backend: VMBackend) -> str:
        manifest = self.image_manager.registry.require(image_id)
        if backend is VMBackend.VAGRANT:
            if manifest.vagrant_box is None:
                raise ImageManagerError("Trusted Vagrant box metadata is missing.")
            return manifest.vagrant_box.name
        return template_id(image_id)

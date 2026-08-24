"""Configurable, local-only image cache paths and readiness checks."""

from pathlib import Path

import yaml
from pydantic import ValidationError

from rangeforge.images.models import BaseTemplate, ImageManifest, TemplateState
from rangeforge.runtime.models import VMBackend


class ImageCache:
    def __init__(self, root: Path) -> None:
        self.root = root.expanduser()

    @property
    def downloads(self) -> Path:
        return self.root / "downloads"

    @property
    def templates(self) -> Path:
        return self.root / "templates"

    @property
    def metadata(self) -> Path:
        return self.root / "metadata"

    def ensure(self) -> None:
        self.downloads.mkdir(parents=True, exist_ok=True)
        self.metadata.mkdir(parents=True, exist_ok=True)
        for backend in VMBackend:
            (self.templates / backend.value).mkdir(parents=True, exist_ok=True)

    def status(self) -> str:
        if not self.root.exists():
            return "not initialized"
        if not self.root.is_dir():
            return "invalid"
        return "ready"

    def artifact_path(self, manifest: ImageManifest) -> Path:
        return self.downloads / manifest.source.filename

    def metadata_path(self, image_id: str) -> Path:
        return self.metadata / f"{image_id}.yaml"

    def template_path(self, image_id: str, backend: VMBackend) -> Path:
        return self.templates / backend.value / image_id

    def template_metadata_path(self, image_id: str, backend: VMBackend) -> Path:
        return self.template_path(image_id, backend) / "template.yaml"

    def load_template(self, image_id: str, backend: VMBackend) -> BaseTemplate | None:
        path = self.template_metadata_path(image_id, backend)
        if not path.is_file():
            return None
        try:
            return BaseTemplate.model_validate(
                yaml.safe_load(path.read_text(encoding="utf-8"))
            )
        except (OSError, yaml.YAMLError, ValidationError):
            return None

    def template_state(
        self,
        image_id: str,
        backend: VMBackend,
        current_checksum: str | None = None,
    ) -> TemplateState:
        template = self.load_template(image_id, backend)
        if template is None:
            return TemplateState.MISSING
        if template.status is not TemplateState.READY:
            return template.status
        if current_checksum and template.source_checksum.lower() != current_checksum.lower():
            return TemplateState.STALE
        from rangeforge.images.templates import template_fingerprint

        expected = template_fingerprint(
            template.image_id,
            template.source_checksum,
            template.backend,
            template.schema_version,
        )
        return TemplateState.READY if expected == template.fingerprint else TemplateState.STALE

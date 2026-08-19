"""Configurable, local-only image cache paths and readiness checks."""

from pathlib import Path

from rangeforge.images.models import ImageManifest, TemplateState
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

    def template_state(self, image_id: str, backend: VMBackend) -> TemplateState:
        path = self.template_path(image_id, backend)
        return TemplateState.READY if path.exists() else TemplateState.MISSING


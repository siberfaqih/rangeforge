"""Predictable cache layout for shared CVE runtime artifacts."""

from pathlib import Path

from rangeforge.artifacts.models import ArtifactManifest


class ArtifactCache:
    def __init__(self, root: Path) -> None:
        self.root = root.expanduser()

    @property
    def downloads(self) -> Path:
        return self.root / "downloads"

    @property
    def metadata(self) -> Path:
        return self.root / "metadata"

    @property
    def extracted(self) -> Path:
        return self.root / "extracted"

    def ensure(self) -> None:
        self.downloads.mkdir(parents=True, exist_ok=True)
        self.metadata.mkdir(parents=True, exist_ok=True)
        self.extracted.mkdir(parents=True, exist_ok=True)

    def artifact_path(self, manifest: ArtifactManifest) -> Path:
        return self.downloads / manifest.filename

    def metadata_path(self, artifact_id: str) -> Path:
        return self.metadata / f"{artifact_id}.yaml"

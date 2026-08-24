"""Typed manifests and lifecycle results for CVE runtime artifacts."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import Field, model_validator

from rangeforge.host.models import Architecture
from rangeforge.images.models import ArtifactState, VerificationStatus
from rangeforge.models import StrictModel


class ArtifactType(StrEnum):
    ARCHIVE = "archive"
    BINARY = "binary"
    PACKAGE = "package"
    CONTAINER_IMAGE = "container_image"
    CONFIGURATION_BUNDLE = "configuration_bundle"


class ArtifactSourceType(StrEnum):
    UPSTREAM = "upstream"
    OFFICIAL = "official"


class ArtifactSource(StrictModel):
    type: ArtifactSourceType
    vendor: str
    url: str

    @model_validator(mode="after")
    def requires_https(self) -> ArtifactSource:
        if not self.url.startswith("https://"):
            raise ValueError("Artifact sources must use HTTPS")
        return self


class ArtifactChecksum(StrictModel):
    algorithm: str = Field(default="sha256", pattern=r"^sha256$")
    value: str = Field(pattern=r"^[a-fA-F0-9]{64}$")


class ArtifactManifest(StrictModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]*$")
    type: ArtifactType
    filename: str
    version: str
    platforms: tuple[str, ...] = Field(min_length=1)
    architectures: tuple[Architecture, ...] = Field(min_length=1)
    source: ArtifactSource
    checksum: ArtifactChecksum
    license: str
    redistributable: bool = False

    @model_validator(mode="after")
    def safe_filename_and_architectures(self) -> ArtifactManifest:
        path = Path(self.filename)
        if path.is_absolute() or path.name != self.filename:
            raise ValueError("Artifact filename must be a plain filename")
        if Architecture.UNSUPPORTED in self.architectures:
            raise ValueError("Artifact architecture cannot be unsupported")
        return self


class ArtifactVerification(StrictModel):
    artifact_id: str
    status: VerificationStatus
    expected_sha256: str
    actual_sha256: str | None = None
    path: Path
    message: str

    @property
    def valid(self) -> bool:
        return self.status is VerificationStatus.VALID


class ArtifactInspection(StrictModel):
    manifest: ArtifactManifest
    path: Path
    state: ArtifactState


class ArtifactPullResult(StrictModel):
    inspection: ArtifactInspection
    downloaded: bool
    reused: bool

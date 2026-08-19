"""Typed image manifests and lifecycle state."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import Field, model_validator

from rangeforge.host.models import Architecture
from rangeforge.models import StrictModel
from rangeforge.runtime.models import RuntimeType, VMBackend


class ImageSourceType(StrEnum):
    OFFICIAL = "official"


class ChecksumAlgorithm(StrEnum):
    SHA256 = "sha256"


class ArtifactState(StrEnum):
    MISSING = "missing"
    DOWNLOADING = "downloading"
    DOWNLOADED = "downloaded"
    VERIFYING = "verifying"
    READY = "ready"
    INVALID = "invalid"


class TemplateState(StrEnum):
    MISSING = "missing"
    READY = "ready"
    INVALID = "invalid"


class VerificationStatus(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    MISSING = "missing"
    UNVERIFIABLE = "unverifiable"


class ImageOS(StrictModel):
    family: str
    distribution: str
    version: str


class ImageSource(StrictModel):
    type: ImageSourceType
    vendor: str
    url: str | None = None
    filename: str

    @model_validator(mode="after")
    def filename_stays_inside_cache(self) -> ImageSource:
        path = Path(self.filename)
        if path.is_absolute() or path.name != self.filename:
            raise ValueError("Image source filename must be a plain filename")
        return self


class Checksum(StrictModel):
    algorithm: ChecksumAlgorithm = ChecksumAlgorithm.SHA256
    value: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")


class ImageManifest(StrictModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]*$")
    os: ImageOS
    architecture: Architecture
    runtimes: tuple[RuntimeType, ...] = Field(min_length=1)
    backends: tuple[VMBackend, ...] = ()
    source: ImageSource
    checksum: Checksum

    @model_validator(mode="after")
    def vm_images_declare_a_backend(self) -> ImageManifest:
        if RuntimeType.VM in self.runtimes and not self.backends:
            raise ValueError("VM images must declare at least one supported backend")
        return self


class VerificationResult(StrictModel):
    image_id: str
    status: VerificationStatus
    expected_sha256: str | None = None
    actual_sha256: str | None = None
    artifact_path: Path | None = None
    message: str

    @property
    def valid(self) -> bool:
        return self.status is VerificationStatus.VALID


class ImageInspection(StrictModel):
    manifest: ImageManifest
    artifact_path: Path
    artifact_state: ArtifactState
    template_states: dict[VMBackend, TemplateState]


class BaseTemplate(StrictModel):
    id: str
    image_id: str
    backend: VMBackend
    architecture: Architecture
    reference: Path | str
    status: TemplateState

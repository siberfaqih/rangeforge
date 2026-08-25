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


class ArtifactFormat(StrEnum):
    QCOW2 = "qcow2"
    VAGRANT_BOX = "vagrant_box"
    UTM_PACKAGE = "utm_package"
    ISO = "iso"


class ImageAcquisitionMethod(StrEnum):
    """How a trusted source image is expected to arrive locally.

    ``AUTOMATIC`` sources carry a trusted HTTPS URL the RangeForge
    downloader may fetch. ``MANUAL`` sources must be imported by the
    operator from media they obtained and reviewed themselves.
    ``BACKEND_MANAGED`` sources are acquired through their declared VM
    backend instead of the RangeForge downloader.
    """

    AUTOMATIC = "automatic"
    MANUAL = "manual"
    BACKEND_MANAGED = "backend_managed"


def derive_acquisition_method(
    *,
    url: str | None,
    has_backend_reference: bool,
) -> ImageAcquisitionMethod:
    """Deterministically derive the default acquisition method.

    A configured URL means ``AUTOMATIC``; a backend reference (for example
    a Vagrant box) without a URL means ``BACKEND_MANAGED``; anything else
    is ``MANUAL``. Explicitly configured acquisition values always win over
    this default.
    """
    if url is not None:
        return ImageAcquisitionMethod.AUTOMATIC
    if has_backend_reference:
        return ImageAcquisitionMethod.BACKEND_MANAGED
    return ImageAcquisitionMethod.MANUAL


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
    PREPARING = "preparing"
    READY = "ready"
    STALE = "stale"
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
    artifact_format: ArtifactFormat
    version: str
    url: str | None = None
    filename: str
    acquisition: ImageAcquisitionMethod | None = None

    @model_validator(mode="after")
    def filename_stays_inside_cache(self) -> ImageSource:
        path = Path(self.filename)
        if path.is_absolute() or path.name != self.filename:
            raise ValueError("Image source filename must be a plain filename")
        return self

    @model_validator(mode="after")
    def acquisition_matches_source_fields(self) -> ImageSource:
        if self.acquisition is ImageAcquisitionMethod.MANUAL and self.url is not None:
            raise ValueError(
                "Manual image sources must not configure a download URL; "
                "import reviewed media with 'rangeforge images import' instead."
            )
        if (
            self.acquisition is ImageAcquisitionMethod.BACKEND_MANAGED
            and self.url is not None
        ):
            raise ValueError(
                "Backend-managed image sources must not configure a download "
                "URL; they are acquired through their declared VM backend."
            )
        if self.acquisition is ImageAcquisitionMethod.AUTOMATIC and (
            self.url is None or not self.url.startswith("https://")
        ):
            raise ValueError(
                "Automatic image sources require a trusted https download URL."
            )
        return self


class Checksum(StrictModel):
    algorithm: ChecksumAlgorithm = ChecksumAlgorithm.SHA256
    value: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")


class VagrantBox(StrictModel):
    name: str = Field(pattern=r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)?$")
    version: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._-]+$")
    provider: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._-]+$")


class ImageManifest(StrictModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]*$")
    os: ImageOS
    architecture: Architecture
    runtimes: tuple[RuntimeType, ...] = Field(min_length=1)
    backends: tuple[VMBackend, ...] = ()
    source: ImageSource
    checksum: Checksum
    vagrant_box: VagrantBox | None = None

    @model_validator(mode="before")
    @classmethod
    def default_source_acquisition(cls, data: object) -> object:
        """Fill an unset source acquisition deterministically.

        The default depends on manifest-level context (the optional backend
        reference), so it is derived here rather than inside ``ImageSource``.
        Explicitly configured acquisition values are preserved untouched.
        """
        if not isinstance(data, dict):
            return data
        source = data.get("source")
        has_backend_reference = data.get("vagrant_box") is not None
        if isinstance(source, dict):
            if source.get("acquisition") is None:
                source["acquisition"] = derive_acquisition_method(
                    url=source.get("url"),
                    has_backend_reference=has_backend_reference,
                )
        elif isinstance(source, ImageSource) and source.acquisition is None:
            data["source"] = source.model_copy(
                update={
                    "acquisition": derive_acquisition_method(
                        url=source.url,
                        has_backend_reference=has_backend_reference,
                    )
                }
            )
        return data

    @model_validator(mode="after")
    def vm_images_declare_a_backend(self) -> ImageManifest:
        if RuntimeType.VM in self.runtimes and not self.backends:
            raise ValueError("VM images must declare at least one supported backend")
        if (
            VMBackend.VAGRANT in self.backends
            and self.vagrant_box is None
            and self.source.acquisition is not ImageAcquisitionMethod.MANUAL
        ):
            raise ValueError(
                "Non-manual Vagrant images must declare a trusted box reference"
            )
        return self

    @property
    def acquisition_method(self) -> ImageAcquisitionMethod:
        """Return the acquisition method guaranteed by manifest validation."""
        if self.source.acquisition is None:
            raise ValueError("Image manifest acquisition method was not resolved")
        return self.source.acquisition


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
    reference: str
    status: TemplateState
    source_checksum: str
    schema_version: int = 1
    created_by_version: str
    fingerprint: str


class PullResult(StrictModel):
    inspection: ImageInspection
    downloaded: bool
    reused: bool

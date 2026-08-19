"""Side-effect-free image selection by guest and runtime requirements."""

from rangeforge.host.models import Architecture
from rangeforge.images.models import ImageManifest
from rangeforge.images.registry import ImageRegistry
from rangeforge.runtime.models import RuntimeType, VMBackend


class ImageResolutionError(ValueError):
    """Raised when zero or multiple image definitions match a requirement."""


class ImageResolver:
    def __init__(self, registry: ImageRegistry) -> None:
        self.registry = registry

    def resolve(
        self,
        *,
        family: str,
        distribution: str,
        version: str,
        architecture: Architecture,
        runtime: RuntimeType,
        backend: VMBackend | None,
    ) -> ImageManifest:
        matches = tuple(
            manifest
            for manifest in self.registry.all()
            if manifest.os.family == family
            and manifest.os.distribution == distribution
            and manifest.os.version == version
            and manifest.architecture is architecture
            and runtime in manifest.runtimes
            and (runtime is not RuntimeType.VM or backend in manifest.backends)
        )
        if not matches:
            backend_text = backend.value if backend else "none"
            raise ImageResolutionError(
                "No image matches "
                f"{distribution} {version} {architecture.value}, runtime={runtime.value}, "
                f"backend={backend_text}."
            )
        if len(matches) > 1:
            ids = ", ".join(item.id for item in matches)
            raise ImageResolutionError(f"Image requirement is ambiguous: {ids}")
        return matches[0]


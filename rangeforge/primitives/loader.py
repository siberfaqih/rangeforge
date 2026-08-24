"""Load primitive definitions from YAML files."""

from pathlib import Path

import yaml
from pydantic import ValidationError

from rangeforge.models import Primitive
from rangeforge.primitives.registry import PrimitiveRegistry


class PrimitiveLoadError(ValueError):
    """Raised when primitive data cannot be parsed."""


class PrimitiveLoader:
    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory or Path(__file__).parent / "definitions"
        self.include_cves = directory is None

    def load(self) -> PrimitiveRegistry:
        primitives: list[Primitive] = []
        try:
            paths = sorted(self.directory.glob("*.yaml"))
            if not paths:
                raise PrimitiveLoadError(f"No primitive definitions found in {self.directory}")
            for path in paths:
                document = yaml.safe_load(path.read_text(encoding="utf-8"))
                records = document if isinstance(document, list) else [document]
                primitives.extend(Primitive.model_validate(record) for record in records)
            if self.include_cves:
                from rangeforge.cve.loader import CVELoader

                primitives.extend(CVELoader().load().logical_primitives())
            return PrimitiveRegistry(primitives)
        except PrimitiveLoadError:
            raise
        except (OSError, yaml.YAMLError, ValidationError, TypeError) as exc:
            raise PrimitiveLoadError(f"Primitive definitions are invalid: {exc}") from exc

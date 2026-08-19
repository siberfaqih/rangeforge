"""Read-only runtime configuration with testable application paths."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import ValidationError

from rangeforge.host.models import RuntimeExecutables
from rangeforge.models import StrictModel


class RuntimeConfig(StrictModel):
    default: Literal["auto", "docker", "vm"] = "auto"


class ImagesConfig(StrictModel):
    cache_dir: Path = Path.home() / ".rangeforge" / "images"


class ExecutableConfig(StrictModel):
    executable: Path | None = None


class RangeForgeConfig(StrictModel):
    runtime: RuntimeConfig = RuntimeConfig()
    images: ImagesConfig = ImagesConfig()
    utm: ExecutableConfig = ExecutableConfig()
    vagrant: ExecutableConfig = ExecutableConfig()
    docker: ExecutableConfig = ExecutableConfig()

    @property
    def executable_overrides(self) -> RuntimeExecutables:
        return RuntimeExecutables(
            docker=self.docker.executable,
            vagrant=self.vagrant.executable,
            utmctl=self.utm.executable,
        )


class ConfigError(ValueError):
    """Raised when a user-supplied configuration is invalid."""


class ConfigLoader:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or Path.home() / ".config" / "rangeforge" / "config.yaml"

    def load(self) -> RangeForgeConfig:
        if not self.path.exists():
            return RangeForgeConfig()
        try:
            data = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
            return RangeForgeConfig.model_validate(data)
        except (OSError, yaml.YAMLError, ValidationError) as exc:
            raise ConfigError(f"Runtime configuration is invalid: {exc}") from exc

"""Load training profiles from data files."""

from pathlib import Path

import yaml
from pydantic import ValidationError

from rangeforge.models import TrainingProfile


class ProfileLoadError(ValueError):
    """Raised when a profile cannot be found or parsed."""


class ProfileLoader:
    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory or Path(__file__).parent

    def load(self, profile_id: str) -> TrainingProfile:
        path = self.directory / f"{profile_id}.yaml"
        if not path.is_file():
            raise ProfileLoadError(f"Profile '{profile_id}' does not exist.")
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            return TrainingProfile.model_validate(data)
        except (OSError, yaml.YAMLError, ValidationError) as exc:
            raise ProfileLoadError(f"Profile '{profile_id}' is invalid: {exc}") from exc


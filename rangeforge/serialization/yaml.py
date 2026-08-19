"""Deterministic YAML scenario serialization."""

from pathlib import Path
from typing import Any

import yaml

from rangeforge.models import Scenario


class ScenarioYamlSerializer:
    def dumps(self, scenario: Scenario) -> str:
        data: dict[str, Any] = scenario.model_dump(mode="json")
        return yaml.safe_dump(
            data,
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
        )

    def dump(self, scenario: Scenario, output_root: Path) -> Path:
        scenario_dir = output_root / f"scenario-{scenario.scenario.id}"
        scenario_dir.mkdir(parents=True, exist_ok=True)
        path = scenario_dir / "scenario.yaml"
        path.write_text(self.dumps(scenario), encoding="utf-8")
        return path

    def loads(self, content: str) -> Scenario:
        return Scenario.model_validate(yaml.safe_load(content))

    def load(self, path: Path) -> Scenario:
        return self.loads(path.read_text(encoding="utf-8"))


from __future__ import annotations

from pathlib import Path

import yaml

from rangeforge.models import Scenario
from rangeforge.serialization.yaml import ScenarioYamlSerializer


def test_scenario_serialization(scenario: Scenario, tmp_path: Path) -> None:
    serializer = ScenarioYamlSerializer()
    first = serializer.dump(scenario, tmp_path)
    first_content = first.read_text(encoding="utf-8")
    second = serializer.dump(scenario, tmp_path)
    assert second.read_text(encoding="utf-8") == first_content
    assert serializer.load(first) == scenario

    data = yaml.safe_load(first_content)
    assert data["scenario"]["seed"] == 1337
    assert data["attack_graph"]["objective"] == "root"
    assert data["validation"]["solvable"] is True


"""Narrow extension boundaries for later RangeForge phases.

Phase 1 intentionally provides no implementations for these protocols.
"""

from typing import Protocol

from rangeforge.models import Scenario, ValidationResult


class ProvisioningProvider(Protocol):
    def provision(self, scenario: Scenario) -> None: ...


class RuntimeValidator(Protocol):
    def validate(self, scenario: Scenario) -> ValidationResult: ...


class AIProvider(Protocol):
    def explain(self, scenario: Scenario) -> str: ...


class KnowledgeProvider(Protocol):
    def lookup(self, primitive_id: str) -> str: ...


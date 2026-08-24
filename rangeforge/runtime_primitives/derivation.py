"""Deterministic, domain-separated scenario credential and flag derivation."""

from __future__ import annotations

import hashlib

from rangeforge.models import Scenario
from rangeforge.runtime_primitives.models import ScenarioRuntimeConfiguration


class ScenarioSecretDeriver:
    """Derive lab-only identities and secrets without using global randomness."""

    schema_version = "phase3-v1"
    _salt = "rangeforge-authorized-local-training"
    _user_roots = ("analyst", "builder", "deploy", "operator", "support")
    management_account = "rangeforge"
    service_account = "rfsvc"
    audit_account = "rfaudit"

    def derive(self, scenario: Scenario) -> ScenarioRuntimeConfiguration:
        username_digest = self._digest(scenario, "scenario-user")
        root = self._user_roots[int(username_digest[:8], 16) % len(self._user_roots)]
        username = f"{root}_{username_digest[8:12]}"
        excluded = {"root", self.management_account, self.service_account, self.audit_account}
        if username in excluded:
            username = f"student_{username_digest[12:16]}"
        credential_digest = self._digest(scenario, "scenario-credential")
        credential = f"Rf!{credential_digest[:10]}-{credential_digest[10:22]}"
        port_digest = self._digest(scenario, "service-port")
        return ScenarioRuntimeConfiguration(
            scenario_id=scenario.scenario.id,
            service_account=self.service_account,
            scenario_user=username,
            audit_user=self.audit_account,
            management_account=self.management_account,
            scenario_credential=credential,
            local_flag=self._flag(scenario, "local"),
            proof_flag=self._flag(scenario, "proof"),
            service_port=8000 + int(port_digest[:8], 16) % 1000,
        )

    def _flag(self, scenario: Scenario, flag_type: str) -> str:
        return f"RANGEFORGE{{{self._digest(scenario, f'flag:{flag_type}')[:24]}}}"

    def _digest(self, scenario: Scenario, purpose: str) -> str:
        material = ":".join(
            (
                self._salt,
                self.schema_version,
                scenario.scenario.generator_version,
                scenario.scenario.profile,
                str(scenario.scenario.seed),
                scenario.scenario.id,
                purpose,
            )
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

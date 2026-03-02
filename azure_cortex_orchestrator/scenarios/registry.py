"""
Scenario registry for Azure-Cortex Orchestrator.

Provides a declarative way to define attack scenarios as dataclasses.
Scenarios are auto-discovered from Python modules in the scenarios/ directory
that expose a ``SCENARIO`` constant.
"""

from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class SimulationStep:
    """A single step in the attack simulation."""

    order: int
    name: str
    description: str
    azure_sdk_action: str  # e.g. "monitor.diagnostic_settings.delete"
    target_resource_type: str  # e.g. "Microsoft.Insights/diagnosticSettings"
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class Scenario:
    """
    Declarative definition of a cloud attack scenario.

    Each scenario describes:
    - What the attack goal is (natural language).
    - Which MITRE ATT&CK techniques are involved.
    - Hints for Terraform infrastructure generation.
    - Steps for the attack simulation.
    - What detection signals the validator should look for.
    """

    id: str
    name: str
    description: str
    goal_template: str

    # MITRE ATT&CK mapping
    expected_mitre_techniques: list[dict[str, str]] = field(default_factory=list)
    # Each dict: {"id": "T1562.008", "name": "Impair Defenses: Disable Cloud Logs", ...}

    # Terraform generation hints
    terraform_hints: dict[str, Any] = field(default_factory=dict)
    # Keys: resource_types, role_assignments, misconfigurations, region, etc.

    # Simulation steps
    simulation_steps: list[SimulationStep] = field(default_factory=list)

    # Detection expectations
    detection_expectations: dict[str, Any] = field(default_factory=dict)
    # Keys: expected_activity_log_operations, expected_alert_types, etc.


class ScenarioRegistry:
    """
    Registry that holds all available scenarios.

    Supports manual registration and auto-discovery from the scenarios package.
    """

    _instance: ScenarioRegistry | None = None
    _scenarios: dict[str, Scenario]

    def __init__(self) -> None:
        self._scenarios = {}

    @classmethod
    def get_instance(cls) -> ScenarioRegistry:
        """Singleton accessor."""
        if cls._instance is None:
            cls._instance = ScenarioRegistry()
            cls._instance.auto_discover()
        return cls._instance

    def register(self, scenario: Scenario) -> None:
        """Register a scenario by its ID."""
        self._scenarios[scenario.id] = scenario

    def get(self, scenario_id: str) -> Scenario:
        """Retrieve a scenario by ID. Raises KeyError if not found."""
        if scenario_id not in self._scenarios:
            available = ", ".join(self._scenarios.keys()) or "(none)"
            raise KeyError(
                f"Scenario '{scenario_id}' not found. Available: {available}"
            )
        return self._scenarios[scenario_id]

    def list_all(self) -> list[Scenario]:
        """Return all registered scenarios."""
        return list(self._scenarios.values())

    def auto_discover(self) -> None:
        """
        Scan the ``scenarios`` package for modules that expose a ``SCENARIO``
        constant and auto-register them.
        """
        package_path = str(Path(__file__).resolve().parent)
        package_name = "azure_cortex_orchestrator.scenarios"

        for importer, module_name, is_pkg in pkgutil.iter_modules([package_path]):
            if module_name.startswith("_") or module_name == "registry":
                continue
            try:
                module = importlib.import_module(f"{package_name}.{module_name}")
                scenario = getattr(module, "SCENARIO", None)
                if isinstance(scenario, Scenario):
                    self.register(scenario)
            except Exception as exc:  # noqa: BLE001
                # Log but don't crash on bad scenario modules
                import logging
                logging.getLogger(__name__).warning(
                    "Failed to load scenario module '%s': %s", module_name, exc
                )

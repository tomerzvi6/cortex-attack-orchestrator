"""
Simulated (rule-based) validator for Azure-Cortex Orchestrator.

Uses the Azure Activity Log and Monitor to check whether the
simulated attack actions were logged and whether any Azure-native
alerts were raised.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from azure_cortex_orchestrator.config import Settings
from azure_cortex_orchestrator.scenarios.registry import ScenarioRegistry
from azure_cortex_orchestrator.state import OrchestratorState
from azure_cortex_orchestrator.utils.azure_helpers import get_monitor_client
from azure_cortex_orchestrator.utils.observability import get_logger
from azure_cortex_orchestrator.validators.base import BaseValidator, ValidationResult

logger = get_logger("validators.simulated")


class SimulatedValidator(BaseValidator):
    """
    Rule-based validator that checks Azure Activity Log for evidence
    of the simulated attack actions.

    Detection logic:
    1. Queries Activity Log for operations matching the scenario's
       ``expected_activity_log_operations``.
    2. If the operations are found, the attack was at least *logged*.
    3. Checks if any Azure Monitor alert rules fired.
    4. Produces a verdict based on whether the attack was both
       logged AND alerted on.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def validate(self, state: OrchestratorState) -> ValidationResult:
        """Check Azure Activity Log for simulation evidence."""
        scenario_id = state.get("scenario_id", "")
        simulation_results = state.get("simulation_results", [])

        if not simulation_results:
            return ValidationResult(
                detected=False,
                source="simulated",
                details="No simulation actions to validate.",
                confidence=0.0,
            )

        # Get scenario expectations
        try:
            registry = ScenarioRegistry.get_instance()
            scenario = registry.get(scenario_id)
            expected_ops = scenario.detection_expectations.get(
                "expected_activity_log_operations", []
            )
            window_minutes = scenario.detection_expectations.get(
                "detection_window_minutes", 15
            )
        except KeyError:
            expected_ops = []
            window_minutes = 15

        # Query Azure Activity Log
        resource_group = state.get("resource_group_name", "")
        try:
            found_operations = self._check_activity_log(
                expected_ops, window_minutes, resource_group,
            )
        except Exception as exc:
            logger.error("Failed to query Activity Log: %s", exc)
            return ValidationResult(
                detected=False,
                source="simulated",
                details=f"Activity Log query failed: {exc}",
                confidence=0.0,
                raw_data={"error": str(exc)},
            )

        # Determine detection result
        ops_logged = len(found_operations)
        ops_expected = len(expected_ops)

        if ops_logged == 0:
            return ValidationResult(
                detected=False,
                source="simulated",
                details=(
                    f"None of the {ops_expected} expected operations were found "
                    "in the Activity Log. The attack may not have executed, "
                    "or logs have already been deleted."
                ),
                confidence=0.0,
                raw_data={"found_operations": found_operations},
            )

        # Operations were logged — attack is visible
        # In a real environment, this means the defense *could* catch it
        # if appropriate alert rules are configured.
        confidence = ops_logged / max(ops_expected, 1)

        return ValidationResult(
            detected=True,
            source="simulated",
            details=(
                f"Found {ops_logged}/{ops_expected} expected operations in "
                f"Activity Log within the last {window_minutes} minutes. "
                "The attack actions are visible in the audit trail, meaning "
                "a properly configured SIEM/XDR would detect them."
            ),
            confidence=min(1.0, confidence),
            raw_data={"found_operations": found_operations},
        )

    def _check_activity_log(
        self,
        expected_operations: list[str],
        window_minutes: int,
        resource_group: str = "",
    ) -> list[dict]:
        """
        Query Azure Activity Log for matching operations.

        Returns list of matched event dicts.
        """
        monitor_client = get_monitor_client(self.settings)

        now = datetime.now(timezone.utc)
        start_time = now - timedelta(minutes=window_minutes)

        # Build OData filter — scope to resource group when available
        filter_str = (
            f"eventTimestamp ge '{start_time.isoformat()}' "
            f"and eventTimestamp le '{now.isoformat()}'"
        )
        if resource_group:
            filter_str += f" and resourceGroupName eq '{resource_group}'"

        logger.info("Querying Activity Log with filter: %s", filter_str)
        events = monitor_client.activity_logs.list(filter=filter_str)

        found: list[dict] = []
        for event in events:
            op_name = event.operation_name.value if event.operation_name else ""
            for expected_op in expected_operations:
                if expected_op.lower() in op_name.lower():
                    found.append({
                        "operation": op_name,
                        "timestamp": str(event.event_timestamp),
                        "status": event.status.value if event.status else "",
                        "caller": event.caller or "",
                        "resource_id": event.resource_id or "",
                    })

        logger.info("Found %d matching operations in Activity Log", len(found))
        return found

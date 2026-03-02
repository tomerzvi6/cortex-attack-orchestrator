"""
Cortex XDR validator for Azure-Cortex Orchestrator.

Queries the Palo Alto Cortex XDR API for alerts and incidents
that correspond to the simulated attack.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import requests

from azure_cortex_orchestrator.config import Settings
from azure_cortex_orchestrator.scenarios.registry import ScenarioRegistry
from azure_cortex_orchestrator.state import OrchestratorState
from azure_cortex_orchestrator.utils.observability import get_logger
from azure_cortex_orchestrator.validators.base import BaseValidator, ValidationResult

logger = get_logger("validators.cortex_xdr")


class CortexXDRValidator(BaseValidator):
    """
    Validates simulation detection via the Cortex XDR Incidents API.

    Queries ``/public_api/v1/incidents/get_incidents`` for alerts
    raised within the simulation timeframe that match expected
    detection patterns from the scenario definition.
    """

    def __init__(self, settings: Settings) -> None:
        self.api_key = settings.cortex_xdr_api_key
        self.fqdn = settings.cortex_xdr_fqdn
        self.base_url = f"https://{self.fqdn}"

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "x-xdr-auth-id": "1",
            "Authorization": self.api_key,
            "Content-Type": "application/json",
        }

    def validate(self, state: OrchestratorState) -> ValidationResult:
        """Query Cortex XDR for incidents matching the simulation."""
        scenario_id = state.get("scenario_id", "")
        simulation_results = state.get("simulation_results", [])

        if not simulation_results:
            return ValidationResult(
                detected=False,
                source="cortex_xdr",
                details="No simulation actions to validate against.",
                confidence=0.0,
            )

        # Determine time window from simulation timestamps
        timestamps = [
            action.get("timestamp", "")
            for action in simulation_results
            if action.get("timestamp")
        ]
        if not timestamps:
            return ValidationResult(
                detected=False,
                source="cortex_xdr",
                details="No timestamps in simulation results.",
                confidence=0.0,
            )

        # Get scenario detection expectations
        try:
            registry = ScenarioRegistry.get_instance()
            scenario = registry.get(scenario_id)
            expected_alerts = scenario.detection_expectations.get(
                "cortex_xdr_expected_alerts", []
            )
            detection_window = scenario.detection_expectations.get(
                "detection_window_minutes", 15
            )
        except KeyError:
            expected_alerts = []
            detection_window = 15

        # Wait a bit for alerts to propagate
        logger.info(
            "Waiting 30 seconds for Cortex XDR alerts to propagate..."
        )
        time.sleep(30)

        # Query incidents
        try:
            incidents = self._query_incidents(detection_window)
        except Exception as exc:
            logger.error("Failed to query Cortex XDR: %s", exc)
            return ValidationResult(
                detected=False,
                source="cortex_xdr",
                details=f"API query failed: {exc}",
                confidence=0.0,
                raw_data={"error": str(exc)},
            )

        # Match incidents against expected alert patterns
        matched = []
        for incident in incidents:
            description = incident.get("description", "").lower()
            for expected in expected_alerts:
                if expected.lower() in description:
                    matched.append(incident)

        detected = len(matched) > 0
        confidence = min(1.0, len(matched) / max(len(expected_alerts), 1))

        return ValidationResult(
            detected=detected,
            source="cortex_xdr",
            details=(
                f"Found {len(matched)} matching incidents out of "
                f"{len(expected_alerts)} expected alert patterns. "
                f"Total incidents in window: {len(incidents)}."
            ),
            confidence=confidence,
            raw_data={"matched_incidents": matched, "total_incidents": len(incidents)},
        )

    def _query_incidents(self, window_minutes: int) -> list[dict]:
        """Query Cortex XDR incidents API for recent incidents."""
        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        from_ms = now_ms - (window_minutes * 60 * 1000)

        payload = {
            "request_data": {
                "filters": [
                    {
                        "field": "creation_time",
                        "operator": "gte",
                        "value": from_ms,
                    }
                ],
                "sort": {
                    "field": "creation_time",
                    "keyword": "desc",
                },
            }
        }

        url = f"{self.base_url}/public_api/v1/incidents/get_incidents"
        response = requests.post(url, json=payload, headers=self._headers, timeout=30)
        response.raise_for_status()

        data = response.json()
        return data.get("reply", {}).get("incidents", [])

"""
Cortex XDR validator for Azure-Cortex Orchestrator.

Queries the Palo Alto Cortex XDR API for alerts and incidents
that correspond to the simulated attack.  Uses a polling loop
with exponential backoff instead of a fixed sleep.
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

# ── Polling configuration ─────────────────────────────────────────
DEFAULT_POLL_TIMEOUT_SECONDS = 300   # 5 minutes max wait
DEFAULT_POLL_INITIAL_INTERVAL = 10   # start at 10s
DEFAULT_POLL_MAX_INTERVAL = 60       # cap at 60s
DEFAULT_POLL_BACKOFF_FACTOR = 1.5    # 10 → 15 → 22.5 → 33.7 → 50 → 60


class CortexXDRValidator(BaseValidator):
    """
    Validates simulation detection via the Cortex XDR Incidents API.

    Queries ``/public_api/v1/incidents/get_incidents`` using a polling
    loop with exponential backoff, waiting for alerts to appear within
    a configurable timeout window.
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

        if not expected_alerts:
            return ValidationResult(
                detected=False,
                source="cortex_xdr",
                details="No expected alerts defined for this scenario.",
                confidence=0.0,
            )

        # ── Poll for incidents with exponential backoff ───────────
        logger.info(
            "Polling Cortex XDR for up to %ds (looking for %d expected alerts)",
            DEFAULT_POLL_TIMEOUT_SECONDS,
            len(expected_alerts),
        )

        matched, all_incidents = self._poll_for_incidents(
            expected_alerts=expected_alerts,
            detection_window=detection_window,
            timeout_seconds=DEFAULT_POLL_TIMEOUT_SECONDS,
            initial_interval=DEFAULT_POLL_INITIAL_INTERVAL,
        )

        detected = len(matched) > 0
        confidence = min(1.0, len(matched) / max(len(expected_alerts), 1))

        return ValidationResult(
            detected=detected,
            source="cortex_xdr",
            details=(
                f"Found {len(matched)} matching incidents out of "
                f"{len(expected_alerts)} expected alert patterns. "
                f"Total incidents in window: {len(all_incidents)}."
            ),
            confidence=confidence,
            raw_data={
                "matched_incidents": matched,
                "total_incidents": len(all_incidents),
            },
        )

    def _poll_for_incidents(
        self,
        expected_alerts: list[str],
        detection_window: int,
        timeout_seconds: int = DEFAULT_POLL_TIMEOUT_SECONDS,
        initial_interval: int = DEFAULT_POLL_INITIAL_INTERVAL,
    ) -> tuple[list[dict], list[dict]]:
        """
        Poll Cortex XDR incidents API with exponential backoff.

        Returns:
            Tuple of (matched_incidents, all_incidents_in_window).
        """
        start_time = time.monotonic()
        interval = initial_interval
        attempt = 0

        while True:
            attempt += 1
            elapsed = time.monotonic() - start_time

            # Check timeout
            if elapsed >= timeout_seconds:
                logger.info(
                    "Polling timeout reached after %ds (%d attempts)",
                    int(elapsed), attempt,
                )
                break

            # Query incidents
            try:
                incidents = self._query_incidents(detection_window)
            except Exception as exc:
                logger.error("Failed to query Cortex XDR (attempt %d): %s", attempt, exc)
                # On API error, continue polling — it might be transient
                time.sleep(min(interval, timeout_seconds - elapsed))
                interval = min(interval * DEFAULT_POLL_BACKOFF_FACTOR, DEFAULT_POLL_MAX_INTERVAL)
                continue

            # Match incidents against expected alert patterns
            matched = self._match_incidents(incidents, expected_alerts)

            logger.info(
                "Poll attempt %d: %d incidents found, %d matched (elapsed=%ds)",
                attempt, len(incidents), len(matched), int(elapsed),
            )

            # If we found all expected alerts, return immediately
            if len(matched) >= len(expected_alerts):
                logger.info("All expected alerts detected — stopping poll early")
                return matched, incidents

            # If we found at least one match, that's a partial success
            # Continue polling to see if more arrive
            if matched and elapsed >= timeout_seconds / 2:
                logger.info(
                    "Partial match (%d/%d) and past half timeout — returning",
                    len(matched), len(expected_alerts),
                )
                return matched, incidents

            # Wait before next poll
            sleep_time = min(interval, max(0, timeout_seconds - elapsed))
            if sleep_time <= 0:
                break
            logger.debug("Sleeping %ds before next poll", int(sleep_time))
            time.sleep(sleep_time)
            interval = min(interval * DEFAULT_POLL_BACKOFF_FACTOR, DEFAULT_POLL_MAX_INTERVAL)

        # Final attempt after timeout
        try:
            incidents = self._query_incidents(detection_window)
            matched = self._match_incidents(incidents, expected_alerts)
            return matched, incidents
        except Exception as exc:
            logger.error("Final poll attempt failed: %s", exc)
            return [], []

    @staticmethod
    def _match_incidents(
        incidents: list[dict],
        expected_alerts: list[str],
    ) -> list[dict]:
        """Match incidents against expected alert text patterns."""
        matched = []
        for incident in incidents:
            description = incident.get("description", "").lower()
            for expected in expected_alerts:
                if expected.lower() in description:
                    matched.append(incident)
                    break  # Don't double-count the same incident
        return matched

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
        response = requests.post(
            url, json=payload, headers=self._headers, timeout=30,
        )
        response.raise_for_status()

        data = response.json()
        return data.get("reply", {}).get("incidents", [])

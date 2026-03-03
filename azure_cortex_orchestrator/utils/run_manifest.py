"""
Run manifest persistence for Azure-Cortex Orchestrator.

Tracks the state of each orchestration run on-disk so that if the
process crashes between deploy and teardown, the manifest can be used
to identify orphaned infrastructure and recover.

The manifest is a JSON file stored in the reports directory, updated
at each significant lifecycle event.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from azure_cortex_orchestrator.utils.observability import get_logger

logger = get_logger("run_manifest")


class RunManifest:
    """
    Persistent run manifest that tracks deployment lifecycle on disk.

    The manifest is written after each state transition so that
    on crash recovery, we know:
    - Which run ID was active
    - What Terraform code was deployed
    - Whether teardown completed
    - The working directory for recovery
    """

    def __init__(self, manifest_dir: Path, run_id: str) -> None:
        self.manifest_dir = manifest_dir
        self.run_id = run_id
        self.manifest_path = manifest_dir / f"run-{run_id}.manifest.json"
        self._data: dict[str, Any] = {
            "run_id": run_id,
            "status": "initialized",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "scenario_id": "",
            "cloud_provider": "",
            "terraform_working_dir": "",
            "deploy_status": "pending",
            "teardown_completed": False,
            "erasure_validated": False,
            "events": [],
        }
        self.manifest_dir.mkdir(parents=True, exist_ok=True)
        self._write()

    def update(self, **kwargs: Any) -> None:
        """Update manifest fields and persist to disk."""
        self._data["updated_at"] = datetime.now(timezone.utc).isoformat()
        self._data.update(kwargs)
        self._write()

    def record_event(self, event: str, details: str = "") -> None:
        """Append a timestamped event to the manifest."""
        self._data.setdefault("events", []).append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "details": details,
        })
        self._data["updated_at"] = datetime.now(timezone.utc).isoformat()
        self._write()

    def mark_deployed(
        self,
        terraform_working_dir: str,
        terraform_code: str,
        cloud_provider: str = "azure",
    ) -> None:
        """Record that infrastructure was successfully deployed."""
        self.update(
            status="deployed",
            deploy_status="success",
            terraform_working_dir=terraform_working_dir,
            terraform_code_hash=str(hash(terraform_code)),
            cloud_provider=cloud_provider,
        )
        self.record_event("deploy_success", f"Working dir: {terraform_working_dir}")

    def mark_teardown_complete(self) -> None:
        """Record that teardown completed successfully."""
        self.update(
            status="torn_down",
            teardown_completed=True,
        )
        self.record_event("teardown_complete")

    def mark_erasure_validated(self, fully_erased: bool) -> None:
        """Record the result of erasure validation."""
        self.update(
            erasure_validated=True,
            fully_erased=fully_erased,
            status="completed" if fully_erased else "orphaned_resources",
        )
        self.record_event(
            "erasure_validated",
            f"fully_erased={fully_erased}",
        )

    def mark_failed(self, error: str) -> None:
        """Record that the run failed."""
        self.update(status="failed")
        self.record_event("run_failed", error)

    @property
    def data(self) -> dict[str, Any]:
        return dict(self._data)

    def _write(self) -> None:
        """Persist manifest to disk as JSON."""
        try:
            self.manifest_path.write_text(
                json.dumps(self._data, indent=2, default=str),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning("Failed to write run manifest: %s", exc)

    # ── Static recovery utilities ─────────────────────────────────

    @staticmethod
    def find_incomplete_runs(manifest_dir: Path) -> list[dict[str, Any]]:
        """
        Scan for manifests of runs that have infrastructure deployed
        but teardown did not complete.

        Returns a list of manifest dicts for orphaned runs.
        """
        orphaned: list[dict[str, Any]] = []

        if not manifest_dir.exists():
            return orphaned

        for manifest_file in manifest_dir.glob("run-*.manifest.json"):
            try:
                data = json.loads(manifest_file.read_text(encoding="utf-8"))
                if (
                    data.get("deploy_status") == "success"
                    and not data.get("teardown_completed", False)
                ):
                    orphaned.append(data)
                    logger.warning(
                        "Found potentially orphaned run: %s (deployed at %s, "
                        "terraform_dir=%s)",
                        data.get("run_id"),
                        data.get("updated_at"),
                        data.get("terraform_working_dir"),
                    )
            except (json.JSONDecodeError, OSError) as exc:
                logger.debug("Skipping manifest %s: %s", manifest_file, exc)

        return orphaned

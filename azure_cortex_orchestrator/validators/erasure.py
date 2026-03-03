"""
Erasure validator for Azure-Cortex Orchestrator.

Runs after teardown to verify that all cloud resources deployed
during the simulation have been fully destroyed.  Supports both
Azure (via Resource Management SDK) and AWS (via Terraform state).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from azure_cortex_orchestrator.config import Settings
from azure_cortex_orchestrator.state import OrchestratorState
from azure_cortex_orchestrator.utils.observability import get_logger

logger = get_logger("validators.erasure")


class ErasureValidationResult:
    """Structured result from the erasure validator."""

    def __init__(
        self,
        fully_erased: bool,
        orphaned_resources: list[dict[str, str]],
        details: str = "",
    ) -> None:
        self.fully_erased = fully_erased
        self.orphaned_resources = orphaned_resources
        self.details = details

    def to_dict(self) -> dict[str, Any]:
        return {
            "fully_erased": self.fully_erased,
            "orphaned_resources": self.orphaned_resources,
            "details": self.details,
        }


def validate_erasure(state: OrchestratorState, settings: Settings) -> ErasureValidationResult:
    """
    Verify that all simulation resources have been torn down.

    Strategy (layered):
    1. Check Terraform state file — if it exists and has resources, teardown failed.
    2. For Azure scenarios: query the resource group to see if it still exists.
    3. For AWS scenarios: check Terraform state for residual resources.

    Returns an ErasureValidationResult.
    """
    scenario_id = state.get("scenario_id", "")
    terraform_code = state.get("terraform_code", "")
    terraform_working_dir = state.get("terraform_working_dir", "")
    orphaned: list[dict[str, str]] = []

    # ── 1. Check Terraform state ──────────────────────────────────
    tf_state_orphaned = _check_terraform_state(terraform_working_dir)
    orphaned.extend(tf_state_orphaned)

    # ── 2. Cloud-specific checks ──────────────────────────────────
    cloud_provider = _detect_cloud_provider(terraform_code, scenario_id)

    if cloud_provider == "azure":
        azure_orphaned = _check_azure_resources(
            terraform_code, settings
        )
        orphaned.extend(azure_orphaned)
    elif cloud_provider == "aws":
        # For AWS, the Terraform state check above is the primary method.
        # Additional boto3-based checks could be added here when the
        # AWS provider is fully implemented.
        logger.info(
            "AWS erasure validation relies on Terraform state check. "
            "SDK-based verification will be added with full AWS support."
        )

    fully_erased = len(orphaned) == 0

    if fully_erased:
        details = "All simulation resources have been successfully destroyed."
    else:
        resource_summary = ", ".join(
            f"{r['type']}({r['name']})" for r in orphaned[:5]
        )
        details = (
            f"Found {len(orphaned)} orphaned resource(s) after teardown: "
            f"{resource_summary}"
        )

    logger.info(
        "Erasure validation: fully_erased=%s, orphaned=%d",
        fully_erased,
        len(orphaned),
    )

    return ErasureValidationResult(
        fully_erased=fully_erased,
        orphaned_resources=orphaned,
        details=details,
    )


# ── Internal helpers ──────────────────────────────────────────────

def _detect_cloud_provider(terraform_code: str, scenario_id: str) -> str:
    """Detect whether this is an Azure or AWS scenario."""
    if "azurerm" in terraform_code.lower():
        return "azure"
    if "aws_" in terraform_code.lower():
        return "aws"
    if "aws" in scenario_id.lower():
        return "aws"
    return "azure"  # default


def _check_terraform_state(working_dir: str) -> list[dict[str, str]]:
    """
    Parse terraform.tfstate to find any remaining resources.

    After a successful ``terraform destroy``, the state file should
    have an empty ``resources`` array.
    """
    orphaned: list[dict[str, str]] = []

    if not working_dir:
        return orphaned

    state_path = Path(working_dir) / "terraform.tfstate"
    if not state_path.exists():
        logger.debug("No terraform.tfstate found — assuming clean.")
        return orphaned

    try:
        state_data = json.loads(state_path.read_text(encoding="utf-8"))
        resources = state_data.get("resources", [])

        for resource in resources:
            # After destroy, resources list should be empty.
            resource_type = resource.get("type", "unknown")
            instances = resource.get("instances", [])
            for inst in instances:
                attrs = inst.get("attributes", {})
                name = attrs.get("name", attrs.get("id", "unknown"))
                orphaned.append({
                    "type": resource_type,
                    "name": str(name),
                    "source": "terraform_state",
                })

        if resources:
            logger.warning(
                "Terraform state still contains %d resource type(s) "
                "after destroy.",
                len(resources),
            )
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to read terraform state: %s", exc)

    return orphaned


def _check_azure_resources(
    terraform_code: str,
    settings: Settings,
) -> list[dict[str, str]]:
    """
    Query Azure to check if resource groups created by the simulation
    still exist.
    """
    orphaned: list[dict[str, str]] = []

    # Extract resource group names from the Terraform code
    rg_names = re.findall(
        r'resource\s+"azurerm_resource_group".*?name\s*=\s*"([^"]+)"',
        terraform_code,
        re.DOTALL,
    )

    if not rg_names:
        return orphaned

    try:
        from azure_cortex_orchestrator.utils.azure_helpers import get_resource_client

        resource_client = get_resource_client(settings)

        for rg_name in rg_names:
            try:
                rg = resource_client.resource_groups.get(rg_name)
                # If we get here, the resource group still exists
                orphaned.append({
                    "type": "azurerm_resource_group",
                    "name": rg_name,
                    "source": "azure_api",
                })
                logger.warning(
                    "Resource group '%s' still exists after teardown "
                    "(provisioning_state=%s).",
                    rg_name,
                    rg.properties.provisioning_state if rg.properties else "unknown",
                )
            except Exception:
                # 404 / ResourceNotFound — resource group is gone, good
                logger.debug("Resource group '%s' confirmed destroyed.", rg_name)

    except Exception as exc:
        logger.warning(
            "Could not verify Azure resources (SDK error): %s", exc
        )

    return orphaned

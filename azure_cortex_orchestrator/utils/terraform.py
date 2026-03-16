"""
Terraform subprocess wrapper for Azure-Cortex Orchestrator.

Manages per-run Terraform workspaces, init/plan/apply/destroy lifecycle,
and structured error capture.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from azure_cortex_orchestrator.utils.observability import get_logger

logger = get_logger("terraform")


class TerraformError(Exception):
    """Raised when a Terraform command fails."""

    def __init__(self, command: str, returncode: int, stderr: str) -> None:
        self.command = command
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(f"terraform {command} failed (rc={returncode}): {stderr[:500]}")


class TerraformRunner:
    """
    Wraps Terraform CLI operations for a single simulation run.

    Each run gets an isolated working directory and Terraform workspace
    to prevent state conflicts between concurrent/sequential runs.
    """

    def __init__(
        self,
        run_id: str,
        base_tmp_dir: Path,
        azure_env: dict[str, str] | None = None,
    ) -> None:
        """
        Args:
            run_id: Unique run identifier (used for workspace naming).
            base_tmp_dir: Base directory under which the per-run dir is created.
            azure_env: Azure credential env vars to inject into subprocess.
        """
        self.run_id = run_id
        self.workspace_name = f"cortex-sim-{run_id[:8]}"
        self.working_dir = base_tmp_dir / run_id
        self.working_dir.mkdir(parents=True, exist_ok=True)
        self._azure_env = azure_env or {}
        self._initialized = False

        logger.info(
            "TerraformRunner created: workspace=%s dir=%s",
            self.workspace_name,
            self.working_dir,
        )

    @property
    def _env(self) -> dict[str, str]:
        """Build environment dict for subprocess calls."""
        env = os.environ.copy()
        env.update(self._azure_env)
        env["TF_IN_AUTOMATION"] = "1"
        env["TF_INPUT"] = "0"
        return env

    def write_tf_files(self, terraform_code: str) -> Path:
        """
        Write generated Terraform HCL to the working directory.

        Args:
            terraform_code: Complete Terraform HCL string.

        Returns:
            Path to the written main.tf file.
        """
        tf_file = self.working_dir / "main.tf"
        tf_file.write_text(terraform_code, encoding="utf-8")
        logger.info("Wrote Terraform code to %s (%d bytes)", tf_file, len(terraform_code))
        return tf_file

    def _run(
        self,
        args: list[str],
        *,
        timeout: int = 300,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        """Run a terraform command and return the result."""
        cmd = ["terraform"] + args
        logger.debug("Running: %s (cwd=%s)", " ".join(cmd), self.working_dir)

        result = subprocess.run(
            cmd,
            cwd=str(self.working_dir),
            env=self._env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if check and result.returncode != 0:
            logger.error(
                "terraform %s failed (rc=%d):\nSTDOUT: %s\nSTDERR: %s",
                args[0],
                result.returncode,
                result.stdout[:500],
                result.stderr[:500],
            )
            raise TerraformError(args[0], result.returncode, result.stderr)

        return result

    def init(self) -> str:
        """Run ``terraform init``."""
        logger.info("Running terraform init")
        result = self._run(["init", "-no-color"])
        self._initialized = True
        logger.info("terraform init completed")
        return result.stdout

    def plan(self) -> str:
        """
        Run ``terraform plan`` and return the plan output.

        Returns:
            The full plan output string.
        """
        if not self._initialized:
            self.init()

        logger.info("Running terraform plan")
        # Added -lock=false to avoid improved concurrency issues on Windows
        result = self._run(["plan", "-no-color", "-detailed-exitcode", "-lock=false"], check=False)

        # Exit code 0 = no changes, 1 = error, 2 = changes present
        if result.returncode == 1:
            raise TerraformError("plan", result.returncode, result.stderr)

        logger.info("terraform plan completed (exit_code=%d)", result.returncode)
        return result.stdout

    def plan_json(self) -> dict:
        """
        Run ``terraform plan`` and return the structured JSON output.

        Creates a plan file, then runs ``terraform show -json`` to
        produce machine-readable output with resolved resource values.

        Returns:
            Parsed JSON dict of the plan.
        """
        import json as _json

        if not self._initialized:
            self.init()

        plan_file = self.working_dir / "tfplan.bin"

        logger.info("Running terraform plan -out (for JSON analysis)")
        result = self._run(
            ["plan", "-no-color", "-detailed-exitcode", "-lock=false", f"-out={plan_file}"],
            check=False,
        )
        if result.returncode == 1:
            raise TerraformError("plan", result.returncode, result.stderr)

        logger.info("Running terraform show -json on plan file")
        show_result = self._run(["show", "-json", str(plan_file)])

        try:
            return _json.loads(show_result.stdout)
        except _json.JSONDecodeError as exc:
            logger.error("Failed to parse plan JSON: %s", exc)
            return {}

    def apply(self, auto_approve: bool = False) -> str:
        """
        Run ``terraform apply``.

        Args:
            auto_approve: If True, skip confirmation prompt.
                          If False, print plan and ask for confirmation.

        Returns:
            Apply output string.
        """
        if not self._initialized:
            self.init()

        if not auto_approve:
            plan_output = self.plan()
            print("\n" + "=" * 60)
            print("TERRAFORM PLAN OUTPUT")
            print("=" * 60)
            print(plan_output)
            print("=" * 60)
            confirmation = input("\nProceed with terraform apply? [y/N]: ").strip().lower()
            if confirmation not in ("y", "yes"):
                logger.info("User declined terraform apply")
                raise TerraformError("apply", -1, "User declined apply")

        logger.info("Running terraform apply (auto_approve=%s)", auto_approve)
        result = self._run(
            ["apply", "-auto-approve", "-no-color", "-lock=false"],
            timeout=600,
        )
        logger.info("terraform apply completed")
        return result.stdout

    def destroy(self, auto_approve: bool = True) -> str:
        """
        Run ``terraform destroy``.

        Args:
            auto_approve: If True, skip confirmation (default for teardown).

        Returns:
            Destroy output string.
        """
        if not self._initialized:
            self.init()

        args = ["destroy", "-no-color", "-lock=false"]
        if auto_approve:
            args.append("-auto-approve")

        logger.info("Running terraform destroy (auto_approve=%s)", auto_approve)
        result = self._run(args, timeout=600)
        logger.info("terraform destroy completed")
        return result.stdout

    def get_output(self, key: str) -> str:
        """Get a Terraform output value by key."""
        result = self._run(["output", "-raw", key])
        return result.stdout.strip()

    def cleanup(self) -> None:
        """Remove the working directory."""
        if self.working_dir.exists():
            shutil.rmtree(self.working_dir, ignore_errors=True)
            logger.info("Cleaned up working directory: %s", self.working_dir)

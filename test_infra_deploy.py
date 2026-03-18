"""
Standalone script to test infrastructure generation + deployment in isolation.

Usage:
    python test_infra_deploy.py                          # uses default prompt
    python test_infra_deploy.py --dry-run                # generate TF only, skip apply
    python test_infra_deploy.py --prompt "your prompt"   # custom prompt
    python test_infra_deploy.py --scenario iam_privilege_escalation  # use known template
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import uuid
from pathlib import Path

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from azure_cortex_orchestrator.config import load_settings
from azure_cortex_orchestrator.nodes import (
    _call_openai,
    _extract_hcl,
    _sanitize_terraform_code,
)
from azure_cortex_orchestrator.prompts import (
    FIX_TERRAFORM_SYSTEM_PROMPT,
    build_generate_infrastructure_prompt,
)
from azure_cortex_orchestrator.scenarios.registry import ScenarioRegistry
from azure_cortex_orchestrator.utils.terraform import TerraformError, TerraformRunner

# ── Template alias map (same as in nodes.py) ──────────────────────
_SCENARIO_TEMPLATE_ALIASES: dict[str, str] = {
    "azure_low_privilege_role_assignment": "iam_privilege_escalation",
    "low_privilege_role_assignment": "iam_privilege_escalation",
    "azure_iam_privilege_escalation": "iam_privilege_escalation",
    "azure_role_escalation": "iam_privilege_escalation",
    "privilege_escalation": "iam_privilege_escalation",
    "role_assignment_escalation": "iam_privilege_escalation",
    "azure_storage_data_exfil": "storage_data_exfil",
    "azure_storage_exfiltration": "storage_data_exfil",
    "blob_data_exfiltration": "storage_data_exfil",
    "azure_vm_identity_log_deletion": "vm_identity_log_deletion",
    "vm_log_deletion": "vm_identity_log_deletion",
    "azure_vm_log_tampering": "vm_identity_log_deletion",
}

DEFAULT_PROMPT = (
    "Simulate an attacker who has a low-privilege Azure identity with a "
    "custom role that includes Microsoft.Authorization/roleAssignments/write. "
    "The attacker uses this foothold to assign themselves the Owner role."
)


def _print_header(text: str) -> None:
    bar = "=" * 60
    print(f"\n{bar}\n  {text}\n{bar}")


def _print_step(n: int, text: str) -> None:
    print(f"\n── Step {n}: {text} {'─' * max(1, 50 - len(text))}")


def generate_tf_from_template(
    scenario_id: str, settings, run_id: str
) -> str | None:
    """Try to render a Jinja2 template for the given scenario ID."""
    from jinja2 import Environment, FileSystemLoader

    templates_dir = Path(__file__).resolve().parent / "azure_cortex_orchestrator" / "templates"
    resolved_id = _SCENARIO_TEMPLATE_ALIASES.get(scenario_id, scenario_id)
    template_path = templates_dir / f"{resolved_id}.tf.j2"

    if not template_path.is_file():
        return None

    jinja_env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        keep_trailing_newline=True,
    )
    template = jinja_env.get_template(f"{resolved_id}.tf.j2")

    print(f"  ✅ Found template: {resolved_id}.tf.j2")

    return template.render(
        resource_group_name=f"{settings.resource_group_prefix}{run_id[:8]}",
        subscription_id=settings.azure_subscription_id or "SUBSCRIPTION_ID",
        run_id=run_id,
        location="eastus",
        vm_name=f"sim-vm-{run_id[:8]}",
        admin_username="simadmin",
    )


def generate_tf_from_llm(prompt: str, goal: str) -> str:
    """Generate Terraform via the LLM."""
    system_prompt = build_generate_infrastructure_prompt()
    user_prompt = (
        f"Attack goal: {goal}\n\n"
        f"User prompt: {prompt}\n\n"
        "Generate the complete Terraform HCL code."
    )

    print("  Calling OpenAI to generate Terraform...")
    response, usage = _call_openai(
        system_prompt, user_prompt, node_name="test_generate_infra"
    )
    print(
        f"  ✅ LLM responded: {usage.total_tokens} tokens, "
        f"${usage.estimated_cost_usd:.4f}, {usage.duration_ms:.0f}ms"
    )
    return _extract_hcl(response)


def fix_tf_with_llm(code: str, error: str) -> str:
    """Ask the LLM to fix a Terraform error."""
    user_prompt = f"Error:\n{error}\n\nCode:\n```hcl\n{code}\n```"
    print("  Calling OpenAI to fix Terraform error...")
    response, usage = _call_openai(
        FIX_TERRAFORM_SYSTEM_PROMPT, user_prompt, node_name="test_fix_infra"
    )
    print(
        f"  ✅ LLM fix response: {usage.total_tokens} tokens, "
        f"${usage.estimated_cost_usd:.4f}"
    )
    return _extract_hcl(response)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Test infrastructure generation and deployment"
    )
    parser.add_argument(
        "--prompt", type=str, default=DEFAULT_PROMPT, help="Attack prompt"
    )
    parser.add_argument(
        "--scenario",
        type=str,
        default="",
        help="Scenario ID (e.g. iam_privilege_escalation) to use template",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate + plan only, skip apply",
    )
    parser.add_argument(
        "--retries", type=int, default=3, help="Max deploy retries"
    )
    args = parser.parse_args()

    _print_header("Infrastructure Deploy Test")

    # ── Step 1: Load settings ─────────────────────────────────────
    _print_step(1, "Loading settings")
    settings = load_settings()
    run_id = str(uuid.uuid4())
    print(f"  Run ID:          {run_id}")
    print(f"  Subscription:    {settings.azure_subscription_id}")
    print(f"  Client ID:       {settings.azure_client_id}")
    print(f"  OpenAI Model:    {settings.openai_model}")

    if not settings.azure_client_id or not settings.azure_client_secret:
        print("\n  ❌ Azure credentials missing in .env — aborting.")
        sys.exit(1)
    if not settings.openai_api_key:
        print("\n  ❌ OPENAI_API_KEY missing in .env — aborting.")
        sys.exit(1)
    print("  ✅ Settings loaded")

    # ── Step 2: Generate Terraform ────────────────────────────────
    _print_step(2, "Generating Terraform code")
    scenario_id = args.scenario
    terraform_code = None

    # Try template first
    if scenario_id:
        terraform_code = generate_tf_from_template(scenario_id, settings, run_id)
    if terraform_code is None:
        # Also try for common alias
        for alias, real_id in _SCENARIO_TEMPLATE_ALIASES.items():
            if alias in args.prompt.lower().replace(" ", "_"):
                print(f"  💡 Detected template match via prompt: {real_id}")
                terraform_code = generate_tf_from_template(real_id, settings, run_id)
                if terraform_code:
                    break

    if terraform_code is None:
        print("  No template found — using LLM generation")
        terraform_code = generate_tf_from_llm(args.prompt, args.prompt)

    # ── Step 3: Sanitize ──────────────────────────────────────────
    _print_step(3, "Sanitizing Terraform code")
    terraform_code = _sanitize_terraform_code(terraform_code)
    print(f"  Code length: {len(terraform_code)} chars")
    print(f"  First 500 chars:\n{terraform_code[:500]}")

    # ── Step 4: Write + Init + Plan ───────────────────────────────
    for attempt in range(1, args.retries + 1):
        _print_step(4, f"Terraform init + plan (attempt {attempt}/{args.retries})")

        tf_runner = TerraformRunner(
            run_id=run_id,
            base_tmp_dir=settings.terraform_tmp_dir,
            azure_env={
                "ARM_CLIENT_ID": settings.azure_client_id,
                "ARM_CLIENT_SECRET": settings.azure_client_secret,
                "ARM_TENANT_ID": settings.azure_tenant_id,
                "ARM_SUBSCRIPTION_ID": settings.azure_subscription_id,
            },
        )
        tf_runner.write_tf_files(terraform_code)
        tf_path = tf_runner.working_dir / "main.tf"
        print(f"  Written to: {tf_path}")

        try:
            print("  Running terraform init...")
            tf_runner.init()
            print("  ✅ terraform init OK")

            print("  Running terraform plan...")
            plan_output = tf_runner.plan()
            print("  ✅ terraform plan OK")

            if args.dry_run:
                print("\n  🏁 DRY RUN — skipping apply. Plan succeeded!")
                _write_code_to_file(tf_path, terraform_code)
                sys.exit(0)

            # ── Step 5: Apply ─────────────────────────────────────
            _print_step(5, "Terraform apply")
            print("  Running terraform apply...")
            apply_output = tf_runner.apply()
            print("  ✅ terraform apply OK!")

            outputs = tf_runner.output()
            if outputs:
                print("\n  Outputs:")
                for k, v in outputs.items():
                    val = v.get("value", v) if isinstance(v, dict) else v
                    print(f"    {k} = {val}")

            _print_header("SUCCESS — Infrastructure deployed!")
            print(f"  Run ID: {run_id}")
            print(f"  Working dir: {tf_runner.working_dir}")
            print(
                "\n  To destroy: "
                f"cd {tf_runner.working_dir} && terraform destroy -auto-approve"
            )
            sys.exit(0)

        except TerraformError as e:
            error_msg = str(e)
            print(f"\n  ❌ Terraform failed: {error_msg[:300]}")

            if attempt < args.retries:
                print(f"\n  Attempting AI fix (retry {attempt})...")
                terraform_code = fix_tf_with_llm(terraform_code, error_msg)
                terraform_code = _sanitize_terraform_code(terraform_code)
                print(f"  Fixed code length: {len(terraform_code)} chars")
            else:
                _print_header("FAILED — All retries exhausted")
                print(f"  Last error: {error_msg[:500]}")
                print(f"\n  Terraform code saved at: {tf_path}")
                sys.exit(1)

    sys.exit(1)


def _write_code_to_file(path: Path, code: str) -> None:
    path.write_text(code, encoding="utf-8")


if __name__ == "__main__":
    main()

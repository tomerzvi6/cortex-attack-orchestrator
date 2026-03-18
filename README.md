# Azure-Cortex Orchestrator

An agentic, multi-cloud attack simulation system built with **LangGraph**. It plans attacks using MITRE ATT&CK mappings, generates vulnerable cloud infrastructure (Azure / AWS) via Terraform, executes simulated attacks using cloud SDKs (Azure SDK, boto3), validates detection via Cortex XDR (with polling) or simulated rules, and produces structured reports.

## Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                     LangGraph StateGraph                      │
│                                                               │
│  START                                                        │
│    │                                                          │
│    ▼                                                          │
│  ┌──────────────────────────────────────┐                     │
│  │        fetch_cobra_intel             │                     │
│  │  (GitHub API · SHA cache · CDN fetch)│                     │
│  └──────────────────────┬───────────────┘                     │
│                         │                                     │
│                         ▼                                     │
│  ┌──────────────────────────────────────┐                     │
│  │        fetch_mitre_intel             │                     │
│  │  (mitre/cti · cloud techniques)      │                     │
│  └──────────────────────┬───────────────┘                     │
│    │                    │                                     │
│    ├── [--prompt provided] ──▶ ┌───────────────────┐          │
│    │                           │ generate_scenario  │          │
│    │                           │ (OpenAI → Scenario)│          │
│    │                           └────────┬──────────┘          │
│    │                                    │                     │
│    ▼◀───────────────────────────────────┘                     │
│  ┌──────────────┐  ┌──────────────────────┐                   │
│  │ plan_attack   │─▶│ fetch_terraform_     │                   │
│  │ (OpenAI+ATT&CK)│ │ schema               │                   │
│  └──────────────┘  │ (azurerm provider    │                   │
│                    │  schema · SHA cache) │                   │
│                    └──────────┬───────────┘                   │
│                               ▼                               │
│                    ┌─────────────────────────┐  ◀─┐          │
│                    │ generate_infrastructure  │    │ retry   │
│                    │ (OpenAI+Terraform)       │    │         │
│                    └──────────┬──────────────┘    │         │
│                                  │                  │         │
│                                  ▼                  │         │
│                       ┌──────────────────┐          │         │
│                       │  safety_check    │          │         │
│                       │  (2-layer guard) │          │         │
│                       └────────┬─────────┘          │         │
│                     ┌──────────┼──────────┐         │         │
│                     │          │          │         │         │
│              [dry-run]    [unsafe]    [safe]        │         │
│                     │          │          │         │         │
│                     ▼          ▼          ▼         │         │
│                  report     report   ┌─────────────┐│         │
│                                     │deploy_infra  ├┘         │
│                                     │(terraform)   │          │
│                                     └──────┬───────┘          │
│                                            │                  │
│                                            ▼                  │
│                                   ┌────────────────┐          │
│                                   │execute_simulator│         │
│                                   │(Azure/AWS SDK) │          │
│                                   └───────┬────────┘          │
│                                           │                   │
│                                           ▼                   │
│                                   ┌────────────────┐          │
│                                   │   validator     │         │
│                                   │(Cortex/Simulated)│        │
│                                   └───────┬────────┘          │
│                                           │                   │
│                                           ▼                   │
│                                   ┌────────────────┐          │
│                                   │   teardown     │          │
│                                   │(tf destroy)    │          │
│                                   └───────┬────────┘          │
│                                           │                   │
│                                           ▼                   │
│                                   ┌────────────────┐          │
│                                   │erasure_validator│         │
│                                   │(verify cleanup) │         │
│                                   └───────┬────────┘          │
│                                           │                   │
│                                           ▼                   │
│                                   ┌────────────────┐          │
│                                   │generate_report │          │
│                                   │(Markdown+JSON) │          │
│                                   └───────┬────────┘          │
│                                           │                   │
│                                          END                  │
└───────────────────────────────────────────────────────────────┘
```

## Features

- **Live cobra-tool Intel** — On every run the orchestrator fetches the latest attack definitions from [PaloAltoNetworks/cobra-tool](https://github.com/PaloAltoNetworks/cobra-tool) via the GitHub API. The LLM receives real-world offensive tooling patterns as supplementary reference alongside its built-in MITRE ATT&CK knowledge. A two-level cache (TTL + commit SHA) keeps overhead minimal; GitHub being unreachable never blocks a run.
- **Live MITRE ATT&CK Intel** — The `fetch_mitre_intel` node downloads the official [mitre/cti](https://github.com/mitre/cti) STIX bundle, filters for cloud/IaaS techniques (Azure, AWS, IaaS, SaaS), and injects authoritative technique IDs into the attack-planning prompt — the LLM never invents non-existent technique IDs. SHA-cached with a 1-hour TTL; gracefully skipped if GitHub is unreachable.
- **Live Terraform Schema Intel** — The `fetch_terraform_schema` node fetches current resource documentation from [hashicorp/terraform-provider-azurerm](https://github.com/hashicorp/terraform-provider-azurerm), parses deprecated/removed argument names, and supplements the infrastructure-generation prompt with a precise schema reference — eliminating a whole class of outdated-argument errors. SHA-cached with a 1-hour TTL.
- **Free-Text Prompt Mode** — Describe an attack scenario in natural language; the AI generates a full scenario (cloud provider, MITRE techniques, simulation steps, Terraform hints) on the fly
- **MITRE ATT&CK Mapping** — AI-powered attack planning with authoritative technique IDs sourced live from the official STIX bundle
- **Multi-Cloud** — Azure and AWS scenarios with pluggable cloud provider layer
- **Terraform IaC** — Auto-generated vulnerable cloud infrastructure
- **Two-Layer Safety Guardrails** — Regex on HCL source + `terraform plan -json` resolved-value analysis; cloud-aware checks for both Azure (resource group prefix, subscription allowlist, AAD blocklist) and AWS (organizations blocklist, wildcard IAM policy, public S3 ACL, bucket naming)
- **Pluggable Validators** — Cortex XDR API (polling with exponential backoff) or simulated rule-based detection
- **Scenario Registry** — Extensible plugin framework; add new attack scenarios by dropping a Python file
- **Dry-Run Mode** — Test the full flow without deploying cloud resources
- **Structured Reporting** — Markdown + JSON reports with timeline, ATT&CK mapping, and Navigator layer
- **Observability** — JSON-structured logging with per-run log files
- **Auto-Teardown + Erasure Validation** — Infrastructure is destroyed after validation, then verified via cloud API
- **Self-Healing Deploys** — Up to 3 retries with AI-assisted Terraform fix (re-checked by safety guardrails)
- **Crash Recovery** — Persistent run manifest tracks deployment lifecycle; orphaned infrastructure is detected on startup
- **OpenAI Resilience** — Exponential backoff and timeout on all LLM calls

## Prerequisites

- **Python 3.10+**
- **Terraform** (installed and on PATH)
- **OpenAI API Key**
- For Azure scenarios: **Azure Subscription** with a Service Principal
- For AWS scenarios: **AWS Account** with IAM access keys or role-based credentials
- (Optional) **Cortex XDR** API key and FQDN

## Quick Start

### 1. Clone and install

```bash
git clone https://github.com/tomerzvi6/cortex-attack-orchestrator.git
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env with your credentials
```

### 3. List available scenarios

```bash
python -m azure_cortex_orchestrator.main --list-scenarios
```

### 4. Dry-run (no cloud resources)

```bash
python -m azure_cortex_orchestrator.main --dry-run --scenario vm_identity_log_deletion
```

This tests the full LangGraph flow: `fetch_cobra_intel → fetch_mitre_intel → plan_attack → fetch_terraform_schema → generate_infrastructure → safety_check → generate_report`, without deploying anything.

### 5. Full live run (Azure)

```bash
python -m azure_cortex_orchestrator.main --scenario vm_identity_log_deletion
```

### 6. Full live run (AWS)

```bash
python -m azure_cortex_orchestrator.main --scenario aws_s3_public_bucket
```

A live run will:
1. Plan the attack (MITRE ATT&CK mapping via OpenAI)
2. Generate Terraform for a vulnerable cloud environment
3. Run two-layer safety guardrail checks (regex + plan-JSON)
4. Deploy infrastructure (with confirmation prompt)
5. Execute the simulated attack via the cloud SDK (Azure SDK or boto3)
6. Validate detection (Cortex XDR polling or simulated)
7. Tear down all infrastructure
8. Verify erasure (cloud API check for orphaned resources)
9. Generate a Markdown + JSON report

### 7. Free-text prompt (AI-generated scenario)

```bash
python -m azure_cortex_orchestrator.main --dry-run \
  --prompt "Test if Cortex detects an attacker using a compromised IAM user to disable CloudTrail logging and exfiltrate data from S3 buckets"
```

The AI will generate a complete scenario (cloud provider, MITRE techniques, simulation steps, Terraform hints) from your description, register it dynamically, and then run the full pipeline.

### 8. Custom goal (pre-defined scenario)

```bash
python -m azure_cortex_orchestrator.main \
  --scenario vm_identity_log_deletion \
  --goal "Exploit a VM's Managed Identity to exfiltrate data from a Storage Account"
```

## Demo Dashboard

The project includes a Streamlit-based **Demo Cockpit** for running and reviewing attack simulations through a visual interface.

```bash
pip install streamlit
streamlit run dashboard/app.py
```

The dashboard provides:

- **Dashboard tab** — Run simulations with live status updates, view MITRE ATT&CK mappings, simulation timelines, detection verdicts, and generated Terraform code. Supports both **Scenario Library** and **Free-Text Prompt** input modes.
- **Reports tab** — Browse and review past simulation reports (Markdown + JSON download).
- **Scenario Library tab** — Explore all registered attack scenarios with MITRE technique badges, simulation step counts, and Terraform resource types.

> **Note:** The dashboard calls the same orchestration logic as the CLI (`compile_graph()` + `create_initial_state()` + graph invoke), so results are identical.

## Multi-Cloud Support

The orchestrator uses a **provider abstraction layer** (`cloud_providers/`) so that
the same LangGraph graph, scenario definitions, and reporting pipeline can target
multiple cloud platforms. The `execute_simulator` node dynamically dispatches actions
through the appropriate cloud provider based on the scenario's `cloud_provider` field.

| Provider | Status | Scenarios |
|----------|--------|-----------|
| **Azure** | ✅ Fully implemented | `vm_identity_log_deletion`, `storage_data_exfil`, `iam_privilege_escalation` |
| **AWS** | ✅ Fully implemented (boto3) | `aws_s3_public_bucket`, `aws_storage_data_exfil`, `aws_iam_privilege_escalation`, `aws_ec2_cloudtrail_deletion` |

Each cloud provider implements the `CloudProvider` abstract base class
(`cloud_providers/base.py`) which exposes:

- `authenticate(settings)` — cloud-specific credential setup
- `execute_action(action, target_resource_type, parameters)` — SDK action dispatch
- `get_terraform_provider_block()` — HCL provider block for IaC generation
- `get_terraform_env_vars(settings)` — env vars for the Terraform subprocess

Scenarios declare their target cloud via the `cloud_provider` field (default `"azure"`).

## Project Structure

```
azure_cortex_orchestrator/
├── main.py                  # CLI entry point (with orphaned-run detection)
├── state.py                 # LangGraph state (TypedDict)
├── nodes.py                 # All graph node functions
├── graph.py                 # StateGraph construction & compilation
├── config.py                # Settings from env vars
├── cloud_providers/
│   ├── base.py              # Abstract CloudProvider interface
│   ├── azure_provider.py    # Azure SDK implementation
│   └── aws_provider.py      # AWS boto3 implementation
├── prompts/
│   ├── plan_attack.py       # System prompt for attack planning
│   ├── generate_infrastructure.py  # System prompt for Terraform generation
│   └── generate_scenario.py # System prompt + SDK allowlist for free-text mode
├── scenarios/
│   ├── registry.py          # Scenario registry with auto-discovery
│   ├── vm_identity_log_deletion.py     # Azure: delete activity logs
│   ├── storage_data_exfil.py           # Azure: storage exfiltration
│   ├── iam_privilege_escalation.py     # Azure: privilege escalation
│   ├── aws_s3_public_bucket.py         # AWS: public bucket exposure
│   ├── aws_storage_data_exfil.py       # AWS: S3 exfiltration via keys
│   ├── aws_iam_privilege_escalation.py # AWS: IAM policy attachment
│   └── aws_ec2_cloudtrail_deletion.py  # AWS: CloudTrail log deletion
├── validators/
│   ├── base.py              # Abstract validator interface
│   ├── cortex_xdr.py        # Cortex XDR API validator (polling + backoff)
│   ├── simulated.py         # Rule-based simulated validator
│   └── erasure.py           # Post-teardown resource erasure verifier
├── utils/
│   ├── observability.py          # Structured logging + tracing
│   ├── terraform.py              # Terraform CLI wrapper (incl. plan_json)
│   ├── azure_helpers.py          # Azure SDK helpers
│   ├── run_manifest.py           # Crash-recovery run manifest persistence
│   ├── reporting.py              # Report generation
│   ├── cobra_tool.py             # Live GitHub fetcher for cobra-tool intel (SHA cache + CDN)
│   ├── mitre_tool.py             # Live fetcher for MITRE ATT&CK cloud techniques (mitre/cti)
│   └── terraform_schema_tool.py  # Live fetcher for azurerm provider schema reference
├── templates/
│   ├── base_infra.tf.j2     # Jinja2 Terraform template (Azure)
│   └── base_infra_aws.tf.j2 # Jinja2 Terraform template (AWS)
└── reports/                 # Generated reports (per run_id)

# Root-level utility scripts
create_service_principal.py  # Helper: create Azure Service Principal for simulations
fix_permissions.py           # Helper: fix Azure SP role assignments
test_infra_deploy.py         # Helper: smoke-test Terraform deploy/destroy cycle
```

## Adding a New Scenario

1. Create a new file in `scenarios/`, e.g. `scenarios/storage_data_exfil.py`
2. Define a `SCENARIO` constant of type `Scenario`:

```python
from azure_cortex_orchestrator.scenarios.registry import Scenario, SimulationStep

SCENARIO = Scenario(
    id="storage_data_exfil",
    name="Storage Account Data Exfiltration",
    description="...",
    goal_template="...",
    expected_mitre_techniques=[...],
    terraform_hints={...},
    simulation_steps=[...],
    detection_expectations={...},
)
```

3. The scenario is auto-discovered on startup. Run:

```bash
python -m azure_cortex_orchestrator.main --list-scenarios
```

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `OPENAI_API_KEY` | Yes | — | OpenAI API key |
| `OPENAI_MODEL` | No | `gpt-5-mini` | Model for reasoning nodes |
| `AZURE_CLIENT_ID` | Live runs | — | Service Principal client ID |
| `AZURE_CLIENT_SECRET` | Live runs | — | Service Principal secret |
| `AZURE_TENANT_ID` | Live runs | — | Azure AD tenant ID |
| `AZURE_SUBSCRIPTION_ID` | Live runs | — | Target subscription |
| `CORTEX_XDR_API_KEY` | No | — | Cortex XDR API key |
| `CORTEX_XDR_FQDN` | No | — | Cortex XDR FQDN |
| `AWS_ACCESS_KEY_ID` | AWS runs | — | AWS IAM access key |
| `AWS_SECRET_ACCESS_KEY` | AWS runs | — | AWS IAM secret key |
| `AWS_DEFAULT_REGION` | No | `us-east-1` | AWS target region |
| `RESOURCE_GROUP_PREFIX` | No | `cortex-sim-` | Safety: RG name prefix |
| `ALLOWED_SUBSCRIPTIONS` | No | — | Safety: allowed sub IDs |
| `MAX_TERRAFORM_RESOURCES` | No | `15` | Safety: max resource count |
| `LOG_LEVEL` | No | `INFO` | Logging verbosity |
| `COBRA_TOOL_ENABLED` | No | `true` | Enable/disable live cobra-tool intel |
| `COBRA_GITHUB_TOKEN` | No | — | GitHub PAT — raises API rate limit 60→5000/hr |
| `COBRA_TOOL_CACHE_TTL` | No | `300` | Seconds before re-checking cobra-tool commit SHA |
| `MITRE_TOOL_ENABLED` | No | `true` | Enable/disable live MITRE ATT&CK intel |
| `MITRE_GITHUB_TOKEN` | No | — | GitHub PAT for mitre/cti (falls back to `COBRA_GITHUB_TOKEN`) |
| `MITRE_TOOL_CACHE_TTL` | No | `3600` | Seconds before re-checking MITRE commit SHA |
| `TF_SCHEMA_TOOL_ENABLED` | No | `true` | Enable/disable live Terraform schema intel |
| `TF_SCHEMA_GITHUB_TOKEN` | No | — | GitHub PAT for azurerm repo (falls back to `COBRA_GITHUB_TOKEN`) |
| `TF_SCHEMA_CACHE_TTL` | No | `3600` | Seconds before re-checking azurerm provider commit SHA |

## Live cobra-tool Integration

The orchestrator maintains a **live connection** to [PaloAltoNetworks/cobra-tool](https://github.com/PaloAltoNetworks/cobra-tool), an open-source offensive security framework. At the start of every run, the `fetch_cobra_intel` node:

1. Calls the GitHub API to retrieve the latest commit SHA (1 API call)
2. If the SHA changed, downloads updated attack definition files via raw CDN (no API quota cost)
3. Injects the content into `OrchestratorState` as `cobra_intel`

Downstream nodes `plan_attack` and `generate_scenario` automatically append the cobra-tool content to their LLM prompts as a **"Supplementary Reference"** section — the AI draws inspiration from real offensive tool implementations without being constrained to them. The primary planning framework (MITRE ATT&CK mapping, scenario registry) is untouched.

**Two-level cache** prevents redundant work:
- **TTL cache** — no network calls at all if last fetch was < `COBRA_TOOL_CACHE_TTL` seconds ago
- **SHA cache** — repo unchanged? TTL is refreshed without re-downloading files

**Graceful degradation** — if GitHub is unreachable, rate-limited, or the token is missing, the run continues exactly as before with no cobra intel. The integration is also disableable via `COBRA_TOOL_ENABLED=false`.

## Live MITRE ATT&CK Integration

The orchestrator maintains a **live connection** to [mitre/cti](https://github.com/mitre/cti), the official MITRE ATT&CK STIX repository. At the start of every run (after `fetch_cobra_intel`), the `fetch_mitre_intel` node:

1. Calls the GitHub API to retrieve the latest commit SHA on the `master` branch (1 API call)
2. If the SHA changed, downloads the `enterprise-attack.json` STIX bundle via raw CDN (no API quota cost)
3. Filters for cloud/IaaS-relevant techniques covering Azure, AWS, IaaS, SaaS, and Office 365 platforms
4. Stores structured technique data (IDs, names, tactics, descriptions) in `OrchestratorState` as `mitre_intel`

The `plan_attack` node injects these authoritative technique IDs into the LLM prompt, ensuring the model uses only real, current MITRE ATT&CK identifiers — never hallucinated ones.

**Two-level cache** (TTL default 1 hour + commit SHA) ensures the 50 MB STIX bundle is only re-downloaded when MITRE actually updates it.

**Graceful degradation** — any network or parsing error is caught and logged. The run continues with LLM training-data fallback. Disable via `MITRE_TOOL_ENABLED=false`.

## Live Terraform Schema Integration

The orchestrator fetches live resource documentation from [hashicorp/terraform-provider-azurerm](https://github.com/hashicorp/terraform-provider-azurerm) to prevent the LLM from generating outdated or invalid Terraform argument names. The `fetch_terraform_schema` node runs between `review_plan` and `generate_infrastructure`:

1. Calls the GitHub API to retrieve the latest provider repo commit SHA (1 API call)
2. If the SHA changed, downloads markdown documentation pages for the most commonly used `azurerm` resources via raw CDN
3. Parses deprecation warnings, removed arguments, and required/optional argument lists
4. Stores the structured schema reference in `OrchestratorState` as `terraform_schema_intel`

The `generate_infrastructure` node appends this schema reference to the LLM prompt, so the model uses only valid argument names for the current provider version — eliminating the need for hardcoded workarounds and reducing Terraform apply errors.

**Resources covered by default:** `resource_group`, `storage_account`, `storage_container`, `storage_blob`, `linux_virtual_machine`, `virtual_network`, `subnet`, `network_interface`, `network_security_group`, `role_assignment`, `user_assigned_identity`, `key_vault`, `key_vault_secret`, `monitor_diagnostic_setting`, `log_analytics_workspace`.

**Graceful degradation** — any network or parsing error is caught and logged. The run continues with existing hardcoded constraints in the prompt. Disable via `TF_SCHEMA_TOOL_ENABLED=false`.

## Reports

Each run generates reports in `azure_cortex_orchestrator/reports/{run_id}/`:

- `report.md` — Human-readable Markdown with ATT&CK mapping, timeline, and verdict
- `report.json` — Machine-readable JSON with full state data
- `attack_navigator_layer.json` — MITRE ATT&CK Navigator layer — import into the [Navigator](https://mitre-attack.github.io/attack-navigator/) to visualize technique coverage and detection gaps
- `execution.log` — Structured JSON log of the entire run

## Safety

The `safety_check` node enforces guardrails through a **two-layer** approach before any infrastructure is deployed:

**Layer 1 — Static HCL analysis (regex):**

*Azure checks:*
- Resource groups must use the configured prefix (`cortex-sim-` by default)
- Subscription IDs must be in the allowlist (if configured)
- No AAD / tenant-level resource modifications
- Resource count cannot exceed the configured maximum

*AWS checks:*
- No `aws_organizations_` resources
- No wildcard (`"*"`) IAM policy actions
- Public S3 ACLs limited to 1 bucket
- S3 bucket names must start with `cortex-sim-`
- Resource count cannot exceed the configured maximum

**Layer 2 — Plan-JSON analysis (resolved values):**
- Runs `terraform plan -json` and inspects the resolved `resource_changes`
- Catches dynamic references and variable interpolation that regex misses
- Validates resource group names, subscription scopes, and role assignment scopes from the plan output

If any violation is detected, the graph skips deployment and generates a report with the violations listed.

On deploy retries (self-healing), the AI-regenerated Terraform code is **re-checked by safety_check** before reaching `deploy_infrastructure` again.

## Crash Recovery

Each deployment writes a persistent **run manifest** (`reports/run-{id}.manifest.json`) tracking lifecycle state. On startup, the CLI scans for manifests where `deploy_status=success` but `teardown_completed=false` — indicating orphaned infrastructure from a previous crash. These are surfaced as warnings so the operator can manually recover or destroy.

## License

Internal use — Palo Alto Networks interview project.

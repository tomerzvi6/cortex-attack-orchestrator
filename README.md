# Azure-Cortex Orchestrator

An agentic cloud attack simulation system built with **LangGraph**. It plans attacks using MITRE ATT&CK mappings, generates vulnerable Azure infrastructure via Terraform, executes simulated attacks using the Azure SDK, validates detection (via Cortex XDR or simulated rules), and produces structured reports.

## Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                     LangGraph StateGraph                      │
│                                                               │
│  START                                                        │
│    │                                                          │
│    ▼                                                          │
│  ┌──────────────┐     ┌─────────────────────────┐             │
│  │ plan_attack   │────▶│ generate_infrastructure │◀─┐         │
│  │ (OpenAI+ATT&CK)│    │ (OpenAI+Terraform)      │  │ retry  │
│  └──────────────┘     └──────────┬──────────────┘  │         │
│                                  │                  │         │
│                                  ▼                  │         │
│                       ┌──────────────────┐          │         │
│                       │  safety_check    │          │         │
│                       │  (guardrails)    │          │         │
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
│                                   │(Azure SDK)      │         │
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
│                                   │generate_report │          │
│                                   │(Markdown+JSON) │          │
│                                   └───────┬────────┘          │
│                                           │                   │
│                                          END                  │
└───────────────────────────────────────────────────────────────┘
```

## Features

- **MITRE ATT&CK Mapping** — AI-powered attack planning with technique IDs
- **Terraform IaC** — Auto-generated vulnerable Azure infrastructure
- **Safety Guardrails** — Resource group prefix, subscription allowlist, resource count limits
- **Pluggable Validators** — Cortex XDR API or simulated rule-based detection
- **Scenario Registry** — Extensible framework; add new attack scenarios as plugins
- **Dry-Run Mode** — Test the full flow without deploying cloud resources
- **Structured Reporting** — Markdown + JSON reports with timeline and ATT&CK mapping
- **Observability** — JSON-structured logging with per-run log files
- **Auto-Teardown** — Infrastructure is automatically destroyed after validation
- **Self-Healing Deploys** — Up to 3 retries with AI-assisted Terraform fix

## Prerequisites

- **Python 3.10+**
- **Terraform** (installed and on PATH)
- **Azure Subscription** with a Service Principal
- **OpenAI API Key**
- (Optional) **Cortex XDR** API key and FQDN

## Quick Start

### 1. Clone and install

```bash
cd palo_alto_interview
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

This tests the full LangGraph flow: plan_attack → generate_infrastructure → safety_check → generate_report, without deploying anything to Azure.

### 5. Full live run

```bash
python -m azure_cortex_orchestrator.main --scenario vm_identity_log_deletion
```

This will:
1. Plan the attack (MITRE ATT&CK mapping via OpenAI)
2. Generate Terraform for a vulnerable Azure environment
3. Run safety guardrail checks
4. Deploy infrastructure (with confirmation prompt)
5. Execute the simulated attack (delete diagnostic settings)
6. Validate detection (Cortex XDR or simulated)
7. Tear down all infrastructure
8. Generate a Markdown + JSON report

### 6. Custom goal

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

- **Dashboard tab** — Run simulations with live status updates, view MITRE ATT&CK mappings, simulation timelines, detection verdicts, and generated Terraform code.
- **Reports tab** — Browse and review past simulation reports (Markdown + JSON download).
- **Scenario Library tab** — Explore all registered attack scenarios with MITRE technique badges, simulation step counts, and Terraform resource types.

> **Note:** The dashboard calls the same orchestration logic as the CLI (`compile_graph()` + `create_initial_state()` + graph invoke), so results are identical.

## Multi-Cloud Support

The orchestrator uses a **provider abstraction layer** (`cloud_providers/`) so that
the same LangGraph graph, scenario definitions, and reporting pipeline can target
multiple cloud platforms.

| Provider | Status | Scenarios |
|----------|--------|-----------|
| **Azure** | ✅ Fully implemented | `vm_identity_log_deletion`, `storage_data_exfil`, `iam_privilege_escalation` |
| **AWS** | 🔜 Scaffolded | `aws_s3_public_bucket` |

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
├── main.py                  # CLI entry point
├── state.py                 # LangGraph state (TypedDict)
├── nodes.py                 # All graph node functions
├── graph.py                 # StateGraph construction & compilation
├── config.py                # Settings from env vars
├── cloud_providers/
│   ├── base.py              # Abstract CloudProvider interface
│   ├── azure_provider.py    # Azure implementation
│   └── aws_provider.py      # AWS scaffold (coming soon)
├── scenarios/
│   ├── registry.py          # Scenario registry with auto-discovery
│   ├── vm_identity_log_deletion.py  # Azure scenario
│   ├── storage_data_exfil.py        # Azure scenario
│   ├── iam_privilege_escalation.py  # Azure scenario
│   └── aws_s3_public_bucket.py      # AWS scenario (scaffold)
├── validators/
│   ├── base.py              # Abstract validator interface
│   ├── cortex_xdr.py        # Cortex XDR API validator
│   └── simulated.py         # Rule-based simulated validator
├── utils/
│   ├── observability.py     # Structured logging + tracing
│   ├── terraform.py         # Terraform CLI wrapper
│   ├── azure_helpers.py     # Azure SDK helpers
│   └── reporting.py         # Report generation
├── templates/
│   └── base_infra.tf.j2     # Jinja2 Terraform template
└── reports/                 # Generated reports (per run_id)
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
| `OPENAI_MODEL` | No | `gpt-4` | Model for reasoning nodes |
| `AZURE_CLIENT_ID` | Live runs | — | Service Principal client ID |
| `AZURE_CLIENT_SECRET` | Live runs | — | Service Principal secret |
| `AZURE_TENANT_ID` | Live runs | — | Azure AD tenant ID |
| `AZURE_SUBSCRIPTION_ID` | Live runs | — | Target subscription |
| `CORTEX_XDR_API_KEY` | No | — | Cortex XDR API key |
| `CORTEX_XDR_FQDN` | No | — | Cortex XDR FQDN |
| `RESOURCE_GROUP_PREFIX` | No | `cortex-sim-` | Safety: RG name prefix |
| `ALLOWED_SUBSCRIPTIONS` | No | — | Safety: allowed sub IDs |
| `MAX_TERRAFORM_RESOURCES` | No | `15` | Safety: max resource count |
| `LOG_LEVEL` | No | `INFO` | Logging verbosity |

## Reports

Each run generates reports in `azure_cortex_orchestrator/reports/{run_id}/`:

- `report.md` — Human-readable Markdown with ATT&CK mapping, timeline, and verdict
- `report.json` — Machine-readable JSON with full state data
- `attack_navigator_layer.json` — MITRE ATT&CK Navigator layer — import into the [Navigator](https://mitre-attack.github.io/attack-navigator/) to visualize technique coverage and detection gaps
- `execution.log` — Structured JSON log of the entire run

## Safety

The `safety_check` node enforces guardrails before any infrastructure is deployed:

- Resource groups must use the configured prefix (`cortex-sim-` by default)
- Subscription IDs must be in the allowlist (if configured)
- No AAD / tenant-level resource modifications
- Resource count cannot exceed the configured maximum

If any violation is detected, the graph skips deployment and generates a report with the violations listed.

## License

Internal use — Palo Alto Networks interview project.

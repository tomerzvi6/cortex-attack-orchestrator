"""
Prompt management module for Azure-Cortex Orchestrator.

Centralises all LLM system prompts used across graph nodes.
Separating prompts from node logic enables:
- Independent versioning and review of prompt text
- Unit-testable prompt construction
- Easy A/B testing or model-specific tuning
"""

from azure_cortex_orchestrator.prompts.plan_attack import (
    PLAN_ATTACK_SYSTEM_PROMPT,
    build_plan_attack_prompt,
)
from azure_cortex_orchestrator.prompts.generate_infrastructure import (
    FIX_TERRAFORM_SYSTEM_PROMPT,
    GENERATE_INFRA_SYSTEM_PROMPT,
    build_generate_infrastructure_prompt,
)
from azure_cortex_orchestrator.prompts.generate_scenario import (
    GENERATE_SCENARIO_SYSTEM_PROMPT,
    build_generate_scenario_prompt,
)

__all__ = [
    "PLAN_ATTACK_SYSTEM_PROMPT",
    "build_plan_attack_prompt",
    "FIX_TERRAFORM_SYSTEM_PROMPT",
    "GENERATE_INFRA_SYSTEM_PROMPT",
    "build_generate_infrastructure_prompt",
    "GENERATE_SCENARIO_SYSTEM_PROMPT",
    "build_generate_scenario_prompt",
]

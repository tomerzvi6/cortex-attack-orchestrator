"""
Prompt management module for Azure-Cortex Orchestrator.

Centralises all LLM system prompts used across graph nodes.
Separating prompts from node logic enables:
- Independent versioning and review of prompt text
- Unit-testable prompt construction
- Easy A/B testing or model-specific tuning
"""

from azure_cortex_orchestrator.prompts.plan_attack import PLAN_ATTACK_SYSTEM_PROMPT
from azure_cortex_orchestrator.prompts.generate_infrastructure import (
    FIX_TERRAFORM_SYSTEM_PROMPT,
    GENERATE_INFRA_SYSTEM_PROMPT,
)

__all__ = [
    "PLAN_ATTACK_SYSTEM_PROMPT",
    "FIX_TERRAFORM_SYSTEM_PROMPT",
    "GENERATE_INFRA_SYSTEM_PROMPT",
]

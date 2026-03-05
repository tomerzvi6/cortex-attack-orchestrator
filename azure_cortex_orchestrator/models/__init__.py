"""
Pydantic response models for LLM structured output validation.

These models enforce the expected schema on OpenAI responses at parse
time, catching hallucinated keys, wrong types, or missing fields
immediately — rather than letting them surface as KeyErrors downstream.

Used together with ``response_format={"type": "json_object"}`` on the
OpenAI API call to guarantee valid JSON without markdown fences.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


# ═══════════════════════════════════════════════════════════════════
#  plan_attack response schema
# ═══════════════════════════════════════════════════════════════════

class MITRETechnique(BaseModel):
    """A single MITRE ATT&CK technique referenced in the attack plan."""

    id: str = Field(..., description="MITRE technique ID, e.g. T1078")
    name: str = Field(..., description="Human-readable technique name")
    tactic: str = Field(..., description="ATT&CK tactic, e.g. 'Privilege Escalation'")
    description: str = Field(default="", description="How this technique applies")
    url: str = Field(default="", description="Link to attack.mitre.org page")


class AttackStep(BaseModel):
    """A single step in the planned attack sequence."""

    step_number: int = Field(..., description="Ordinal step number")
    description: str = Field(..., description="What the attacker does")
    mitre_technique_id: str = Field(default="", description="Associated technique ID")
    mitre_technique_name: str = Field(default="", description="Associated technique name")
    kill_chain_phase: str = Field(default="", description="Cyber kill-chain phase")
    details: str = Field(default="", description="Technical implementation details")


class AttackPlanResponse(BaseModel):
    """
    Validated schema for the ``plan_attack`` LLM response.

    If the LLM returns JSON that does not conform to this schema,
    Pydantic raises ``ValidationError`` which the node catches
    and falls back to a safe default.
    """

    goal: str = Field(..., description="Original attack goal")
    scenario_id: str = Field(default="", description="Scenario registry key")
    summary: str = Field(default="", description="Brief summary of the attack")
    mitre_techniques: list[MITRETechnique] = Field(
        default_factory=list,
        description="MITRE ATT&CK techniques mapped to this attack",
    )
    steps: list[AttackStep] = Field(
        default_factory=list,
        description="Ordered attack execution steps",
    )

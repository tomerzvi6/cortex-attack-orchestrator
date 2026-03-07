"""
Pydantic response models for LLM structured output validation.

These models enforce the expected schema on OpenAI responses at parse
time, catching hallucinated keys, wrong types, or missing fields
immediately — rather than letting them surface as KeyErrors downstream.

Used together with ``response_format={"type": "json_object"}`` on the
OpenAI API call to guarantee valid JSON without markdown fences.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


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


# ═══════════════════════════════════════════════════════════════════
#  generate_scenario response schema
# ═══════════════════════════════════════════════════════════════════

class ScenarioSimulationStep(BaseModel):
    """A single simulation step in a generated scenario."""

    order: int = Field(..., description="Execution order (1-based)")
    name: str = Field(..., description="Snake_case step identifier")
    description: str = Field(..., description="What this step does")
    sdk_action: str = Field(..., description="SDK action from the supported list")
    target_resource_type: str = Field(..., description="Cloud resource type being targeted")


class ScenarioTerraformHints(BaseModel):
    """Terraform generation hints for a scenario."""

    resource_types: list[str] = Field(default_factory=list)
    misconfigurations: list[str] = Field(default_factory=list)
    role_assignments: list[str] = Field(default_factory=list)
    region: str = Field(default="eastus")


class ScenarioDetectionExpectations(BaseModel):
    """What the validator should look for."""

    expected_activity_log_operations: list[str] = Field(default_factory=list)
    expected_alert_types: list[str] = Field(default_factory=list)
    cortex_xdr_expected_alerts: list[str] = Field(default_factory=list)
    detection_window_minutes: int = Field(default=10)


class ScenarioResponse(BaseModel):
    """
    Validated schema for the ``generate_scenario`` LLM response.

    Mirrors the Scenario dataclass so the output can be directly
    converted to a Scenario and registered dynamically.
    """

    id: str = Field(..., description="Short snake_case scenario ID")
    name: str = Field(..., description="Human-readable scenario name")
    description: str = Field(..., description="2-3 sentence description")
    goal_template: str = Field(..., description="Natural language goal for the planner")
    cloud_provider: str = Field(default="azure", description="'azure' or 'aws'")
    expected_mitre_techniques: list[MITRETechnique] = Field(default_factory=list)
    terraform_hints: ScenarioTerraformHints = Field(default_factory=ScenarioTerraformHints)
    simulation_steps: list[ScenarioSimulationStep] = Field(default_factory=list)
    detection_expectations: ScenarioDetectionExpectations = Field(
        default_factory=ScenarioDetectionExpectations,
    )

    @field_validator("cloud_provider")
    @classmethod
    def validate_cloud_provider(cls, v: str) -> str:
        allowed = {"azure", "aws"}
        if v.lower() not in allowed:
            raise ValueError(f"cloud_provider must be one of {allowed}, got '{v}'")
        return v.lower()

    @field_validator("id")
    @classmethod
    def validate_id_format(cls, v: str) -> str:
        """Ensure ID is snake_case-ish (no spaces, lowercase)."""
        return v.lower().replace(" ", "_").replace("-", "_")

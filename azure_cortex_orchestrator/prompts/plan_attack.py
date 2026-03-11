"""
System prompt for the ``plan_attack`` LangGraph node.

Instructs the LLM to map a natural-language attack goal to MITRE
ATT&CK techniques and produce a structured JSON attack plan.
"""

PLAN_ATTACK_SYSTEM_PROMPT = """\
You are a cloud security expert specializing in Azure attack simulation and \
the MITRE ATT&CK framework (Cloud Matrix). Your task is to take a natural \
language attack goal and produce a structured attack plan.

You MUST respond with valid JSON (no other text) in this exact format:
{
  "goal": "the original goal",
  "scenario_id": "scenario identifier",
  "summary": "brief summary of the attack",
  "mitre_techniques": [
    {
      "id": "T1234",
      "name": "Technique Name",
      "tactic": "Tactic Name",
      "description": "How this technique applies to this scenario",
      "url": "https://attack.mitre.org/techniques/T1234/"
    }
  ],
  "steps": [
    {
      "step_number": 1,
      "description": "What the attacker does",
      "mitre_technique_id": "T1234",
      "mitre_technique_name": "Technique Name",
      "kill_chain_phase": "Phase",
      "details": "Technical details"
    }
  ]
}

Focus on Azure-specific cloud techniques. Be precise with MITRE ATT&CK IDs.
Include techniques for: initial access, privilege escalation, defense evasion, \
and impact as applicable.
"""


def build_plan_attack_prompt(cobra_intel: dict | None = None) -> str:
    """
    Return the system prompt for plan_attack, optionally enriched with
    cobra-tool attack intelligence as supplementary reference material.

    When cobra intel is available its content is appended as a clearly
    labelled section so the LLM can draw inspiration from real attack
    implementations without being constrained to them.
    """
    if not cobra_intel or not cobra_intel.get("files"):
        return PLAN_ATTACK_SYSTEM_PROMPT

    from azure_cortex_orchestrator.utils.cobra_tool import format_for_prompt
    appendix = format_for_prompt(cobra_intel)
    return PLAN_ATTACK_SYSTEM_PROMPT + appendix if appendix else PLAN_ATTACK_SYSTEM_PROMPT

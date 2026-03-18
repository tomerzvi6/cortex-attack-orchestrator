"""
terraform_schema_tool.py — Live azurerm provider schema reference.

Fetches resource documentation from the hashicorp/terraform-provider-azurerm
GitHub repo. On every orchestrator run this module:
  1. Checks the latest commit SHA on the repo's main branch (1 API call).
  2. If the SHA changed (or the TTL cache expired), fetches markdown doc pages
     for commonly-used azurerm resources directly from raw.githubusercontent.com
     (CDN — no API quota impact).
  3. Parses deprecation warnings and required/optional argument lists so the
     LLM receives a precise schema reference rather than relying on training data.
  4. Returns identical cached intel if nothing has changed.

The caller (fetch_terraform_schema node in nodes.py) catches all exceptions so
that GitHub being unreachable never blocks an orchestrator run.

Environment variables (all optional):
  TF_SCHEMA_GITHUB_TOKEN  GitHub PAT — raises rate limit from 60 → 5000 req/hr.
  TF_SCHEMA_TOOL_ENABLED  Set to "false" to disable integration entirely.
  TF_SCHEMA_CACHE_TTL     Seconds before re-checking commit SHA (default 3600).
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Optional

import requests

from azure_cortex_orchestrator.utils.observability import get_logger

logger = get_logger("terraform_schema")

# ── Repo / CDN constants ──────────────────────────────────────────
_REPO = "hashicorp/terraform-provider-azurerm"
_GH_API = "https://api.github.com"
_RAW_BASE = "https://raw.githubusercontent.com"
_DOCS_PATH = "website/docs/r"  # resource docs live here in the repo

# Resources to always fetch docs for — cover the most common simulation scenarios.
# Extend this list as new scenario types are added.
_CORE_RESOURCES = [
    "resource_group",
    "storage_account",
    "storage_container",
    "storage_blob",
    "linux_virtual_machine",
    "virtual_network",
    "subnet",
    "network_interface",
    "network_security_group",
    "role_assignment",
    "user_assigned_identity",
    "key_vault",
    "key_vault_secret",
    "monitor_diagnostic_setting",
    "log_analytics_workspace",
]

# ── Module-level TTL cache ────────────────────────────────────────
_cache: Optional[dict] = None
_cache_sha: str = ""
_cache_time: float = 0.0


# ── Internal helpers ──────────────────────────────────────────────

def _headers(token: Optional[str]) -> dict[str, str]:
    h = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "azure-cortex-orchestrator/terraform-schema",
    }
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _get_latest_sha(token: Optional[str]) -> Optional[str]:
    """Return the latest commit SHA on main branch."""
    url = f"{_GH_API}/repos/{_REPO}/git/ref/heads/main"
    try:
        resp = requests.get(url, headers=_headers(token), timeout=10)
        if resp.status_code == 200:
            return resp.json()["object"]["sha"]
    except requests.RequestException:
        pass
    return None


def _fetch_resource_doc(resource_name: str, sha: str) -> Optional[str]:
    """
    Fetch markdown documentation for a single azurerm resource from CDN.
    Does NOT consume GitHub API quota.
    """
    url = f"{_RAW_BASE}/{_REPO}/{sha}/{_DOCS_PATH}/{resource_name}.html.markdown"
    try:
        resp = requests.get(url, timeout=10)
        if resp.ok:
            return resp.text
    except requests.RequestException:
        pass
    return None


def _parse_arguments(doc: str) -> dict[str, list[str]]:
    """
    Extract argument metadata from a Terraform resource doc page.

    Returns:
        {
          "deprecated": [list of deprecated argument descriptions],
          "required":   [list of required argument names],
          "optional":   [list of optional argument names],
        }
    """
    deprecated: list[str] = []
    required: list[str] = []
    optional: list[str] = []

    # Isolate the "Argument Reference" section
    arg_section = re.search(
        r"##\s+Argument Reference(.*?)(?=\n##\s|\Z)",
        doc,
        re.DOTALL | re.IGNORECASE,
    )
    if not arg_section:
        return {"deprecated": deprecated, "required": required, "optional": optional}

    arg_text = arg_section.group(1)

    # Match bullet-point argument entries: * `arg_name` - description...
    for m in re.finditer(
        r"\*\s+`([^`]+)`\s*[–\-]\s*(.*?)(?=\n\s*\*\s+`|\Z)",
        arg_text,
        re.DOTALL,
    ):
        arg_name = m.group(1).strip()
        desc = " ".join(m.group(2).split())  # collapse whitespace
        desc_lower = desc.lower()

        if "deprecated" in desc_lower:
            deprecated.append(f"`{arg_name}`: {desc[:250]}")
        elif desc_lower.startswith("(required)"):
            required.append(arg_name)
        elif desc_lower.startswith("(optional)"):
            optional.append(arg_name)

    # Also capture explicit ~> Deprecated notices (provider uses both styles)
    for m in re.finditer(
        r"~>\s+\*?\*?[Dd]eprecated\*?\*?\s*[:\-]?\s*([^\n]+)",
        arg_text,
    ):
        notice = m.group(1).strip()
        entry = f"DEPRECATED: {notice[:250]}"
        if entry not in deprecated:
            deprecated.append(entry)

    return {"deprecated": deprecated, "required": required, "optional": optional}


# ── Public API ────────────────────────────────────────────────────

def fetch(
    github_token: Optional[str] = None,
    cache_ttl: int = 3600,
) -> Optional[dict]:
    """
    Fetch or return cached azurerm provider schema reference.

    Uses a two-level cache:
      - TTL check: skip all network calls if last fetch was < cache_ttl ago.
      - SHA check: skip doc fetches if the commit SHA hasn't changed.

    Args:
        github_token: Optional GitHub PAT (boosts rate limit 60 → 5000/hr).
        cache_ttl:    Seconds to treat cached intel as fresh (default 1 hour).

    Returns:
        A dict with per-resource argument data, or None on failure.
    """
    global _cache, _cache_sha, _cache_time

    now = time.monotonic()

    # ── Level 1: TTL — skip all network calls if cache is fresh ──
    if _cache and (now - _cache_time) < cache_ttl:
        logger.debug("terraform-schema cache hit (TTL), sha=%s", _cache_sha[:8])
        return _cache

    # ── Resolve latest commit SHA (1 API call) ────────────────────
    sha = _get_latest_sha(github_token)
    if not sha:
        logger.warning(
            "terraform-schema: could not reach GitHub API — returning stale cache"
        )
        return _cache

    # ── Level 2: SHA — repo unchanged, refresh TTL and return ─────
    if sha == _cache_sha and _cache:
        logger.info("terraform-schema cache hit (SHA unchanged), sha=%s", sha[:8])
        _cache_time = now
        return _cache

    logger.info(
        "terraform-schema: new SHA detected %s — fetching provider docs...", sha[:8]
    )

    # ── Fetch doc pages for each core resource ────────────────────
    resources: dict[str, dict] = {}
    for resource_name in _CORE_RESOURCES:
        doc = _fetch_resource_doc(resource_name, sha)
        if doc:
            args = _parse_arguments(doc)
            resources[f"azurerm_{resource_name}"] = args
            logger.debug(
                "Fetched schema for azurerm_%s: %d deprecated, %d required, %d optional",
                resource_name,
                len(args["deprecated"]),
                len(args["required"]),
                len(args["optional"]),
            )
        else:
            logger.debug("No doc found for azurerm_%s at sha=%s", resource_name, sha[:8])

    intel = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "commit_sha": sha,
        "provider": "hashicorp/azurerm",
        "resources": resources,
        "summary": f"azurerm schema @ {sha[:8]}: {len(resources)} resources loaded",
    }

    _cache = intel
    _cache_sha = sha
    _cache_time = now

    logger.info("terraform-schema intel updated: %s", intel["summary"])
    return intel


def format_for_prompt(
    intel: dict,
    resource_filter: list[str] | None = None,
) -> str:
    """
    Format schema intel as a prompt section that tells the LLM which
    argument names are deprecated or removed and therefore must not be used.

    Args:
        intel:           Result from fetch().
        resource_filter: If provided, only include these resource types
                         (e.g. ["azurerm_storage_account"]).
    """
    resources = intel.get("resources", {})
    if not resources:
        return ""

    if resource_filter:
        resources = {k: v for k, v in resources.items() if k in resource_filter}

    sha_short = intel.get("commit_sha", "unknown")[:8]
    lines = [
        "",
        "",
        "---",
        "## Authoritative azurerm Provider Schema Reference",
        f"Source: hashicorp/terraform-provider-azurerm (commit {sha_short}).",
        "CRITICAL: Do NOT use any deprecated argument listed below.",
        "Only use argument names that are valid for azurerm provider ~> 3.0.",
        "",
    ]

    any_content = False
    for resource, args in sorted(resources.items()):
        deprecated = args.get("deprecated", [])
        required = args.get("required", [])
        if not deprecated and not required:
            continue
        any_content = True
        lines.append(f"### `{resource}`")
        if deprecated:
            lines.append("**DEPRECATED / REMOVED (DO NOT USE):**")
            for d in deprecated[:10]:
                lines.append(f"  - {d}")
        if required:
            lines.append(f"**Required arguments:** {', '.join(f'`{a}`' for a in required[:15])}")
        lines.append("")

    if not any_content:
        return ""

    return "\n".join(lines)

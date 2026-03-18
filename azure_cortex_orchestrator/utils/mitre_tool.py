"""
mitre_tool.py — Live MITRE ATT&CK Cloud technique integration.

On every orchestrator run this module:
  1. Checks the latest commit SHA on the mitre/cti GitHub repo (1 API call).
  2. If the SHA changed (or the TTL cache expired), fetches the enterprise-attack
     STIX bundle from raw.githubusercontent.com (CDN — no API quota impact).
  3. Parses the bundle, filters for cloud/IaaS-relevant techniques, and returns
     a structured dict with accurate technique IDs, names, and tactics.
  4. Returns identical cached intel if nothing has changed.

The caller (fetch_mitre_intel node in nodes.py) catches all exceptions so
that GitHub being unreachable never blocks an orchestrator run.

Environment variables (all optional):
  MITRE_GITHUB_TOKEN   GitHub PAT — raises rate limit from 60 → 5000 req/hr.
  MITRE_TOOL_ENABLED   Set to "false" to disable integration entirely.
  MITRE_TOOL_CACHE_TTL Seconds before re-checking commit SHA (default 3600).
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Optional

import requests

from azure_cortex_orchestrator.utils.observability import get_logger

logger = get_logger("mitre_tool")

# ── Repo / CDN constants ──────────────────────────────────────────
_REPO = "mitre/cti"
_GH_API = "https://api.github.com"
_RAW_BASE = "https://raw.githubusercontent.com"
_STIX_PATH = "enterprise-attack/enterprise-attack.json"

# Cloud/IaaS platforms to keep (filter out pure endpoint techniques)
_CLOUD_PLATFORMS = {"Azure", "IaaS", "SaaS", "Office 365", "Google Workspace", "AWS"}

# ── Module-level TTL cache ────────────────────────────────────────
_cache: Optional[dict] = None
_cache_sha: str = ""
_cache_time: float = 0.0


# ── Internal helpers ──────────────────────────────────────────────

def _headers(token: Optional[str]) -> dict[str, str]:
    h = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "azure-cortex-orchestrator/mitre-intel",
    }
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _get_latest_sha(token: Optional[str]) -> Optional[str]:
    """Return the latest commit SHA on mitre/cti master branch."""
    url = f"{_GH_API}/repos/{_REPO}/git/ref/heads/master"
    try:
        resp = requests.get(url, headers=_headers(token), timeout=10)
        if resp.status_code == 200:
            return resp.json()["object"]["sha"]
    except requests.RequestException:
        pass
    return None


def _fetch_and_parse(sha: str) -> dict:
    """
    Fetch the STIX bundle from CDN and parse cloud-relevant techniques.

    The full enterprise-attack.json is ~50 MB; subsequent calls use the cache.
    Only techniques that target at least one cloud/IaaS platform are kept.

    Returns:
        Structured dict with techniques list and tactic groupings.
    """
    url = f"{_RAW_BASE}/{_REPO}/{sha}/{_STIX_PATH}"
    logger.info(
        "Fetching MITRE ATT&CK STIX bundle from CDN (may take a moment on first run)..."
    )

    try:
        resp = requests.get(url, timeout=90)
        if not resp.ok:
            logger.error("Failed to fetch STIX bundle: HTTP %d", resp.status_code)
            return {}
        bundle = resp.json()
    except (requests.RequestException, json.JSONDecodeError) as exc:
        logger.error("Failed to fetch/parse STIX bundle: %s", exc)
        return {}

    techniques: list[dict] = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        platforms = set(obj.get("x_mitre_platforms", []))
        cloud_platforms = platforms & _CLOUD_PLATFORMS
        if not cloud_platforms:
            continue

        # Extract MITRE technique ID (e.g. T1078, T1562.008)
        mitre_id = ""
        url_ref = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id", "")
                url_ref = ref.get("url", "")
                break
        if not mitre_id:
            continue

        # Extract tactic(s) from kill chain phases
        tactics = [
            phase["phase_name"].replace("-", " ").title()
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        techniques.append({
            "id": mitre_id,
            "name": obj.get("name", ""),
            "tactics": tactics,
            "platforms": sorted(cloud_platforms),
            "description": obj.get("description", "")[:400],
            "url": url_ref or f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}/"
        })

    # Group techniques by tactic for easier prompt injection
    by_tactic: dict[str, list[dict]] = {}
    for t in techniques:
        for tactic in (t.get("tactics") or ["Uncategorized"]):
            by_tactic.setdefault(tactic, []).append(t)

    logger.info(
        "MITRE ATT&CK: parsed %d cloud/IaaS techniques across %d tactics",
        len(techniques), len(by_tactic),
    )

    return {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "commit_sha": sha,
        "technique_count": len(techniques),
        "techniques": techniques,
        "by_tactic": by_tactic,
        "summary": f"MITRE ATT&CK @ {sha[:8]}: {len(techniques)} cloud techniques loaded",
    }


# ── Public API ────────────────────────────────────────────────────

def fetch(
    github_token: Optional[str] = None,
    cache_ttl: int = 3600,
) -> Optional[dict]:
    """
    Fetch or return cached MITRE ATT&CK cloud technique intel.

    Uses a two-level cache:
      - TTL check: skip all network calls if last fetch was < cache_ttl ago.
      - SHA check: skip the large STIX download if the commit SHA hasn't changed.

    Args:
        github_token: Optional GitHub PAT (boosts rate limit 60 → 5000/hr).
        cache_ttl:    Seconds to treat cached intel as fresh (default 1 hour).

    Returns:
        A structured dict of cloud techniques, or None on failure.
    """
    global _cache, _cache_sha, _cache_time

    now = time.monotonic()

    # ── Level 1: TTL — skip all network calls if cache is fresh ──
    if _cache and (now - _cache_time) < cache_ttl:
        logger.debug("MITRE cache hit (TTL), sha=%s", _cache_sha[:8])
        return _cache

    # ── Resolve latest commit SHA (1 API call) ────────────────────
    sha = _get_latest_sha(github_token)
    if not sha:
        logger.warning("mitre-tool: could not reach GitHub API — returning stale cache")
        return _cache

    # ── Level 2: SHA — repo unchanged, refresh TTL and return ─────
    if sha == _cache_sha and _cache:
        logger.info("MITRE cache hit (SHA unchanged), sha=%s", sha[:8])
        _cache_time = now
        return _cache

    logger.info("MITRE: new commit detected sha=%s — fetching techniques...", sha[:8])

    intel = _fetch_and_parse(sha)
    if not intel:
        return _cache  # return stale rather than nothing

    _cache = intel
    _cache_sha = sha
    _cache_time = now

    logger.info("MITRE intel updated: %s", intel["summary"])
    return intel


def format_for_prompt(intel: dict) -> str:
    """
    Format MITRE ATT&CK cloud technique intel as a prompt appendix.

    The section is labelled as AUTHORITATIVE so the LLM uses real IDs
    instead of hallucinating them. Techniques are grouped by tactic.
    Each tactic is capped at 25 entries to keep the prompt size manageable.
    """
    techniques = intel.get("techniques", [])
    if not techniques:
        return ""

    sha_short = intel.get("commit_sha", "unknown")[:8]
    total = intel.get("technique_count", len(techniques))

    lines = [
        "",
        "",
        "---",
        "## Authoritative MITRE ATT&CK Cloud Techniques Reference",
        f"Source: mitre/cti (commit {sha_short}). Total cloud techniques: {total}.",
        "CRITICAL: Use ONLY these exact technique IDs in your output. Never invent IDs.",
        "",
    ]

    by_tactic: dict[str, list[dict]] = {}
    for t in techniques:
        for tactic in (t.get("tactics") or ["Uncategorized"]):
            by_tactic.setdefault(tactic, []).append(t)

    for tactic, techs in sorted(by_tactic.items()):
        lines.append(f"### {tactic}")
        for t in techs[:25]:  # cap per tactic
            platforms_str = ", ".join(t.get("platforms", []))
            lines.append(f"- **{t['id']}** — {t['name']} [{platforms_str}]")
        lines.append("")

    return "\n".join(lines)

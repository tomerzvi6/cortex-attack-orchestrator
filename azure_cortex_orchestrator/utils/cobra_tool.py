"""
cobra_tool.py — Live GitHub integration for PaloAltoNetworks/cobra-tool.

On every orchestrator run this module:
  1. Calls the GitHub API to check the latest commit SHA on the repo's
     default branch.
  2. If the SHA changed (or the TTL cache expired), fetches file contents
     directly from raw.githubusercontent.com (CDN — no API quota impact).
  3. Parses YAML/JSON attack definitions into a structured CobraIntel dict.
  4. Returns identical cached intel if nothing has changed.

The caller (fetch_cobra_intel node in nodes.py) catches all exceptions so
that GitHub being unreachable never blocks an orchestrator run.

Environment variables (all optional):
  COBRA_GITHUB_TOKEN   GitHub PAT — raises rate limit from 60 → 5000 req/hr.
  COBRA_TOOL_ENABLED   Set to "false" to disable integration entirely.
  COBRA_TOOL_CACHE_TTL Seconds before re-checking commit SHA (default 300).
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Optional

import requests

from azure_cortex_orchestrator.utils.observability import get_logger

logger = get_logger("cobra_tool")

# ── Repo constants ────────────────────────────────────────────────
_REPO = "PaloAltoNetworks/cobra-tool"
_GH_API = "https://api.github.com"
_RAW_BASE = "https://raw.githubusercontent.com"

# Extensions considered attack-definition files
_FETCH_EXTS = (".yaml", ".yml", ".json")

# Path prefixes to skip — unlikely to contain attack intel
_SKIP_PREFIXES = ("docs/", "tests/", ".github/", "node_modules/", "venv/")

# Upper bound on files fetched per run (keeps prompt size and latency bounded)
_MAX_FILES = 40

# ── Module-level TTL cache ────────────────────────────────────────
_cache: Optional[dict] = None
_cache_sha: str = ""
_cache_time: float = 0.0


# ── Internal helpers ──────────────────────────────────────────────

def _headers(token: Optional[str]) -> dict[str, str]:
    h = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "azure-cortex-orchestrator/cobra-intel",
    }
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _get_latest_sha(token: Optional[str]) -> Optional[str]:
    """Return the latest commit SHA, trying 'main' then 'master'."""
    for branch in ("main", "master"):
        url = f"{_GH_API}/repos/{_REPO}/git/ref/heads/{branch}"
        try:
            resp = requests.get(url, headers=_headers(token), timeout=10)
            if resp.status_code == 200:
                return resp.json()["object"]["sha"]
        except requests.RequestException:
            pass
    return None


def _get_tree(sha: str, token: Optional[str]) -> list[dict]:
    """Return the flat recursive file tree for the repo at ``sha``."""
    url = f"{_GH_API}/repos/{_REPO}/git/trees/{sha}?recursive=1"
    try:
        resp = requests.get(url, headers=_headers(token), timeout=15)
        if resp.ok:
            return resp.json().get("tree", [])
    except requests.RequestException:
        pass
    return []


def _fetch_raw(path: str, sha: str) -> Optional[str]:
    """
    Fetch a file's raw text from raw.githubusercontent.com (CDN).
    These requests do NOT consume GitHub API rate-limit quota.
    """
    url = f"{_RAW_BASE}/{_REPO}/{sha}/{path}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.ok:
            return resp.text
    except requests.RequestException:
        pass
    return None


# ── Public API ────────────────────────────────────────────────────

def fetch(
    github_token: Optional[str] = None,
    cache_ttl: int = 300,
) -> Optional[dict]:
    """
    Fetch or return cached cobra-tool attack intelligence.

    Uses a two-level cache:
      - TTL check: skip all network calls if last fetch was < cache_ttl ago.
      - SHA check: skip file fetches if the commit SHA hasn't changed.

    Args:
        github_token: Optional GitHub PAT (boosts rate limit 60 → 5000/hr).
        cache_ttl:    Seconds to treat cached intel as fresh (default 5 min).

    Returns:
        A dict matching the CobraIntel TypedDict shape, or None on failure.
    """
    global _cache, _cache_sha, _cache_time

    now = time.monotonic()

    # ── Level 1: TTL — skip all network calls if cache is fresh ──
    if _cache and (now - _cache_time) < cache_ttl:
        logger.debug("cobra-tool cache hit (TTL), sha=%s", _cache_sha[:8])
        return _cache

    # ── Resolve latest commit SHA (1 API call) ────────────────────
    sha = _get_latest_sha(github_token)
    if not sha:
        logger.warning(
            "cobra-tool: could not reach GitHub API — returning stale cache"
        )
        return _cache  # may be None on very first failure

    # ── Level 2: SHA — repo unchanged, refresh TTL and return ─────
    if sha == _cache_sha and _cache:
        logger.info(
            "cobra-tool cache hit (SHA unchanged), sha=%s", sha[:8]
        )
        _cache_time = now
        return _cache

    logger.info(
        "cobra-tool: new commit detected sha=%s — fetching intel ...", sha[:8]
    )

    # ── Tree walk (1 API call) ────────────────────────────────────
    tree = _get_tree(sha, github_token)
    candidates = [
        item for item in tree
        if item.get("type") == "blob"
        and item["path"].endswith(_FETCH_EXTS)
        and not any(item["path"].startswith(p) for p in _SKIP_PREFIXES)
        and item.get("size", 0) < 100_000  # skip enormous generated files
    ][:_MAX_FILES]

    logger.info(
        "cobra-tool: found %d candidate files to fetch", len(candidates)
    )

    # ── Fetch file contents via CDN (no API quota) ────────────────
    files: list[dict] = []
    for item in candidates:
        content = _fetch_raw(item["path"], sha)
        if content is not None:
            files.append({
                "path": item["path"],
                "name": item["path"].split("/")[-1],
                "content": content,
            })

    intel = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "commit_sha": sha,
        "repo_url": f"https://github.com/{_REPO}",
        "files": files,
        "summary": f"cobra-tool @ {sha[:8]}: {len(files)} files loaded",
    }

    _cache = intel
    _cache_sha = sha
    _cache_time = now

    logger.info("cobra-tool intel updated: %s", intel["summary"])
    return intel


def format_for_prompt(intel: dict) -> str:
    """
    Convert CobraIntel into a compact prompt appendix.

    The section is clearly labelled as SUPPLEMENTARY REFERENCE so the
    LLM draws inspiration from cobra-tool without being constrained to it.
    """
    files = intel.get("files", [])
    if not files:
        return ""

    sha_short = intel.get("commit_sha", "unknown")[:8]
    lines = [
        "",
        "",
        "---",
        "## Supplementary Reference: cobra-tool Attack Modules",
        f"Source: PaloAltoNetworks/cobra-tool (commit {sha_short}).",
        "The following attack definitions are provided as ADDITIONAL INSPIRATION.",
        "Use them to enrich your output, but you are NOT limited to or required",
        "to follow them. Your primary framework is the task instructions above.",
        "",
    ]

    for f in files:
        path = f.get("path", "")
        content = f.get("content", "").strip()
        if not content:
            continue
        lines.append(f"### [{path}]")
        # Cap each file to keep total prompt size manageable
        if len(content) > 3000:
            content = content[:3000] + "\n... [content truncated]"
        lines.append(content)
        lines.append("")

    return "\n".join(lines)

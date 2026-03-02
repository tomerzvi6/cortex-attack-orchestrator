"""
Observability utilities for Azure-Cortex Orchestrator.

Provides structured JSON logging, a NodeLogger context manager for
automatic node entry/exit logging, and tracing integration.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator


class JSONFormatter(logging.Formatter):
    """Structured JSON log formatter."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Attach extra fields if present
        for key in ("run_id", "node", "duration_ms", "state_keys_updated"):
            val = getattr(record, key, None)
            if val is not None:
                log_entry[key] = val

        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)


def setup_logging(
    run_id: str,
    log_level: str = "INFO",
    reports_dir: Path | None = None,
) -> logging.Logger:
    """
    Configure root logger with structured JSON output.

    Logs to both console (stderr) and a per-run log file.

    Args:
        run_id: Unique run identifier, embedded in every log record.
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR).
        reports_dir: Base directory for report output. Log file is
                     written to ``{reports_dir}/{run_id}/execution.log``.

    Returns:
        Configured root logger.
    """
    root_logger = logging.getLogger("azure_cortex_orchestrator")
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Remove existing handlers to avoid duplicates on re-init
    root_logger.handlers.clear()

    json_formatter = JSONFormatter()

    # Console handler (stderr)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(json_formatter)
    root_logger.addHandler(console_handler)

    # File handler (per-run log)
    if reports_dir is not None:
        run_dir = reports_dir / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(run_dir / "execution.log", encoding="utf-8")
        file_handler.setFormatter(json_formatter)
        root_logger.addHandler(file_handler)

    # Inject run_id into all records via a filter
    class RunIDFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            record.run_id = run_id  # type: ignore[attr-defined]
            return True

    root_logger.addFilter(RunIDFilter())

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Get a child logger under the orchestrator namespace."""
    return logging.getLogger(f"azure_cortex_orchestrator.{name}")


@contextmanager
def node_logger(
    node_name: str,
    run_id: str = "",
) -> Generator[logging.Logger, None, None]:
    """
    Context manager that logs node entry/exit with duration.

    Usage::

        with node_logger("plan_attack", run_id=state["run_id"]) as logger:
            logger.info("Planning attack for goal: %s", goal)
            # ... node logic ...

    On exit, automatically logs duration and success/failure.
    """
    logger = get_logger(node_name)

    # Create an adapter that injects node name
    start = time.perf_counter()
    logger.info(
        "Node started",
        extra={"node": node_name, "run_id": run_id},
    )
    error_occurred: BaseException | None = None
    try:
        yield logger
    except BaseException as exc:
        error_occurred = exc
        raise
    finally:
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        if error_occurred:
            logger.error(
                "Node failed after %.2f ms: %s",
                duration_ms,
                error_occurred,
                extra={
                    "node": node_name,
                    "run_id": run_id,
                    "duration_ms": duration_ms,
                },
            )
        else:
            logger.info(
                "Node completed in %.2f ms",
                duration_ms,
                extra={
                    "node": node_name,
                    "run_id": run_id,
                    "duration_ms": duration_ms,
                },
            )

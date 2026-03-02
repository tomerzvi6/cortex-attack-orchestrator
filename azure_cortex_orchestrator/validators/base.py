"""
Abstract base class for validators in Azure-Cortex Orchestrator.

All validator backends must implement this interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from azure_cortex_orchestrator.state import OrchestratorState


@dataclass
class ValidationResult:
    """Structured result from a validator."""

    detected: bool
    source: str                       # "cortex_xdr" | "simulated"
    details: str = ""
    confidence: float = 0.0           # 0.0 - 1.0
    raw_data: Any = field(default=None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "detected": self.detected,
            "source": self.source,
            "details": self.details,
            "confidence": self.confidence,
            "raw_data": self.raw_data,
        }


class BaseValidator(ABC):
    """
    Abstract validator interface.

    Subclasses implement ``validate()`` to check whether the simulated
    attack was detected by the defense layer.
    """

    @abstractmethod
    def validate(
        self,
        state: OrchestratorState,
    ) -> ValidationResult:
        """
        Check if the simulation was detected.

        Args:
            state: The current orchestrator state, including
                   simulation_results, scenario details, etc.

        Returns:
            A ValidationResult with the detection verdict.
        """
        ...

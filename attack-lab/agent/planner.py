"""Recon-to-exploit planner backed by the local AttackEnvironment.

The planner provides candidate endpoint/action pairs and state transitions. It
does not call a model API, construct payloads, or send network requests.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# ``attack-lab`` contains a hyphen, so Python cannot import it as a package
# name. Add its directory for both direct-script and repository-root use.
_ATTACK_LAB_ROOT = str(Path(__file__).resolve().parents[1])
if _ATTACK_LAB_ROOT not in sys.path:
    sys.path.insert(0, _ATTACK_LAB_ROOT)

from environment import AttackEnvironment, AttackGraph  # noqa: E402


class AttackPlanner:
    """Build and navigate an offline plan from a Task 10.1 ReconReport."""

    def __init__(self, source: str | Path | dict[str, Any], max_steps: int = 32) -> None:
        self.graph = AttackGraph.from_file(source) if isinstance(source, (str, Path)) else AttackGraph.from_dict(source)
        self.environment = AttackEnvironment(self.graph, max_steps=max_steps)

    def reset(self) -> dict[str, Any]:
        """Begin a planning episode and return the first endpoint/action set."""
        state = self.environment.reset()
        return self._plan(state)

    def candidates(self) -> list[dict[str, Any]]:
        """List applicable endpoint/action pairs without executing them."""
        node = self.environment.current_node
        return [
            {
                "endpoint_id": node.node_id,
                "method": node.method,
                "path": node.path,
                "primary_category": node.primary_category,
                "parameters": list(node.parameters),
                "target_params": list(node.target_params),
                "action_index": action.index,
                "action_id": action.action_id,
                "technique": action.technique,
                "transformation": action.transformation,
                "phase": action.phase,
            }
            for action in self.environment.available_actions()
        ]

    def step(self, action: int | str, response: dict[str, Any] | None = None) -> dict[str, Any]:
        """Advance the state machine using optional telemetry supplied by runner."""
        result = self.environment.step(action, response=response)
        plan = self._plan(result.observation)
        plan.update({"reward": result.reward, "terminated": result.terminated, "info": result.info})
        return plan

    def _plan(self, state: Any) -> dict[str, Any]:
        return {
            "state": state.to_dict(),
            "candidates": self.candidates(),
            "target_url": self.graph.target_url,
            "spec_source": self.graph.spec_source,
        }

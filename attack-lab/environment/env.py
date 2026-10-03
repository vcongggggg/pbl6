"""Offline state machine and reward adapter for the attack-planning agent.

This module never opens a socket. A caller supplies normalized response
telemetry from the authorized lab runner to ``step``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .actions import ACTIONS, ActionSpec, get_action
from .attack_graph import AttackGraph, AttackNode

FAMILIES = tuple(dict.fromkeys(action.family for action in ACTIONS))
STATE_FEATURE_NAMES = (
    "episode_progress",
    "normalized_endpoint_index",
    "endpoint_count_fraction",
    "method_get",
    "method_post",
    "method_put",
    "method_patch",
    "method_delete",
    "requires_auth",
    "parameter_count",
    "target_parameter_count",
    "action_index",
    "previous_403",
    "previous_confirmed_bypass",
    "previous_other_4xx",
    "previous_5xx",
    "attempt_fraction",
) + tuple(f"category_{family.lower()}" for family in FAMILIES) + tuple(
    f"action_available_{action.action_id}" for action in ACTIONS
)


@dataclass(frozen=True, slots=True)
class AttackState:
    """Serializable observation plus fixed-width DQN feature encoding."""

    endpoint_id: str
    phase: str
    available_action_ids: tuple[str, ...]
    last_status_code: int | None
    last_outcome: str
    attempt_count: int
    feature_names: tuple[str, ...]
    features: tuple[float, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint_id": self.endpoint_id,
            "phase": self.phase,
            "available_action_ids": list(self.available_action_ids),
            "last_status_code": self.last_status_code,
            "last_outcome": self.last_outcome,
            "attempt_count": self.attempt_count,
            "feature_names": list(self.feature_names),
            "features": list(self.features),
        }


@dataclass(frozen=True, slots=True)
class StepResult:
    """Gym-like transition result compatible with a future PyTorch DQN loop."""

    observation: AttackState
    reward: float
    terminated: bool
    info: dict[str, Any]

    def __iter__(self):
        """Allow conventional ``state, reward, done, info = env.step(...)`` unpacking."""
        yield self.observation
        yield self.reward
        yield self.terminated
        yield self.info


class AttackEnvironment:
    """Recon-to-exploit episode state machine with deterministic action masking."""

    def __init__(self, graph: AttackGraph, max_steps: int = 32) -> None:
        if not graph.nodes:
            raise ValueError("Attack graph must contain at least one endpoint")
        if max_steps < 1:
            raise ValueError("max_steps must be positive")
        self.graph = graph
        self.max_steps = max_steps
        self.endpoint_index = 0
        self.attempt_count = 0
        self.last_status_code: int | None = None
        self.last_outcome = "not_started"
        self._done = False
        self._last_action: ActionSpec | None = None
        self._visited = {0}

    @property
    def action_space(self) -> tuple[ActionSpec, ...]:
        """Ordered discrete action vocabulary; indices stay stable for model use."""
        return ACTIONS

    @property
    def current_node(self) -> AttackNode:
        return self.graph.nodes[self.endpoint_index]

    def reset(self) -> AttackState:
        """Start a fresh episode at the first endpoint in recon report order."""
        self.endpoint_index = 0
        self.attempt_count = 0
        self.last_status_code = None
        self.last_outcome = "not_started"
        self._last_action = None
        self._done = False
        self._visited = {0}
        return self._observation()

    def step(self, action: int | str | ActionSpec, response: dict[str, Any] | None = None) -> StepResult:
        """Apply an action and optional normalized runner telemetry.

        ``response`` accepts ``status_code`` and the explicit boolean
        ``confirmed_bypass``. A non-403 response alone is never considered a
        bypass. With no response, this advances a planning-only transition and
        returns zero reward.
        """
        if self._done:
            raise RuntimeError("Episode has terminated; call reset() before stepping again")

        selected = get_action(action)
        valid = self.available_actions()
        if selected.action_id not in {item.action_id for item in valid}:
            raise ValueError(f"Action {selected.action_id!r} does not apply to {self.current_node.node_id}")

        if selected.action_id == "select_next_endpoint":
            next_index = self._next_endpoint_index()
            if next_index is None:
                raise ValueError("No unvisited endpoint remains in the attack graph")
            self.attempt_count += 1
            self.endpoint_index = next_index
            self._visited.add(next_index)
            self.last_status_code = None
            self.last_outcome = "endpoint_selected"
            self._last_action = selected
            self._done = self.attempt_count >= self.max_steps
            return StepResult(
                observation=self._observation(),
                reward=0.0,
                terminated=self._done,
                info={
                    "action_id": selected.action_id,
                    "endpoint_id": self.current_node.node_id,
                    "outcome": self.last_outcome,
                    "target_url": self.graph.target_url,
                },
            )

        if selected.action_id == "record_endpoint":
            self.attempt_count += 1
            self.last_status_code = None
            self.last_outcome = "surface_recorded"
            self._last_action = selected
            self._done = self.attempt_count >= self.max_steps
            return StepResult(
                observation=self._observation(),
                reward=0.0,
                terminated=self._done,
                info={
                    "action_id": selected.action_id,
                    "endpoint_id": self.current_node.node_id,
                    "outcome": self.last_outcome,
                    "target_url": self.graph.target_url,
                },
            )

        telemetry = response or {}
        status = telemetry.get("status_code")
        if status is not None and (isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599):
            raise ValueError("response.status_code must be an HTTP status code")
        confirmed = telemetry.get("confirmed_bypass", False)
        if not isinstance(confirmed, bool):
            raise ValueError("response.confirmed_bypass must be a boolean")
        if status == 403 and confirmed:
            raise ValueError("A 403 response cannot be marked as a confirmed bypass")

        reward = -1.0 if status == 403 else 10.0 if confirmed else 0.0
        if status == 403:
            outcome = "waf_blocked"
        elif confirmed:
            outcome = "confirmed_bypass"
        elif status is None:
            outcome = "planned"
        elif status >= 500:
            outcome = "server_error"
        elif status >= 400:
            outcome = "other_client_error"
        else:
            outcome = "response_received_unconfirmed"

        self.attempt_count += 1
        self.last_status_code = status
        self.last_outcome = outcome
        self._last_action = selected
        self._done = (confirmed and status != 403) or self.attempt_count >= self.max_steps
        return StepResult(
            observation=self._observation(),
            reward=reward,
            terminated=self._done,
            info={
                "action_id": selected.action_id,
                "endpoint_id": self.current_node.node_id,
                "status_code": status,
                "outcome": outcome,
                "target_url": self.graph.target_url,
            },
        )

    def available_actions(self) -> tuple[ActionSpec, ...]:
        """Return applicable actions in stable global action-index order."""
        categories = set(self.current_node.categories)
        applicable = tuple(action for action in ACTIONS if action.family in categories)
        if not applicable:
            applicable = (ACTIONS[13],)
        if len(self._visited) < len(self.graph.nodes):
            applicable += (ACTIONS[12],)
        return applicable

    def _next_endpoint_index(self) -> int | None:
        """Choose the first unvisited graph neighbor, with report-order fallback."""
        index_by_id = {node.node_id: index for index, node in enumerate(self.graph.nodes)}
        outgoing = [edge.target for edge in self.graph.edges if edge.source == self.current_node.node_id]
        for target in outgoing:
            index = index_by_id[target]
            if index not in self._visited:
                return index
        return next((index for index in range(len(self.graph.nodes)) if index not in self._visited), None)

    def _observation(self) -> AttackState:
        node = self.current_node
        actions = self.available_actions()
        count = len(self.graph.nodes)
        index = self.endpoint_index
        method = node.method.upper()
        status = self.last_status_code
        action_index = self._last_action.index if self._last_action else -1
        base_features = (
            index / max(count - 1, 1),
            index / max(count, 1),
            min(count / 100.0, 1.0),
            float(method == "GET"),
            float(method == "POST"),
            float(method == "PUT"),
            float(method == "PATCH"),
            float(method == "DELETE"),
            float(node.requires_auth),
            float(len(node.parameters)),
            float(len(node.target_params)),
            float(action_index),
            float(status == 403),
            float(self.last_outcome == "confirmed_bypass"),
            float(status is not None and 400 <= status < 500 and status != 403),
            float(status is not None and status >= 500),
            min(self.attempt_count / self.max_steps, 1.0),
        )
        category_features = tuple(float(family in node.categories) for family in FAMILIES)
        available_ids = {action.action_id for action in actions}
        action_mask = tuple(float(action.action_id in available_ids) for action in ACTIONS)
        features = base_features + category_features + action_mask
        return AttackState(
            endpoint_id=node.node_id,
            phase="complete" if self._done else (self._last_action.phase if self._last_action else "recon"),
            available_action_ids=tuple(action.action_id for action in actions),
            last_status_code=status,
            last_outcome=self.last_outcome,
            attempt_count=self.attempt_count,
            feature_names=STATE_FEATURE_NAMES,
            features=features,
        )

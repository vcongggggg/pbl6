"""Finite, stable action vocabulary shared by the planner and future RL agent.

Actions are descriptors only. They do not generate request payloads or perform
network I/O; execution belongs to the explicitly configured lab runner.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ActionSpec:
    """One discrete action suitable for a DQN action index."""

    index: int
    action_id: str
    family: str
    technique: str
    phase: str
    transformation: str = "none"


# Tuple order is a public contract: do not reorder without changing model metadata.
ACTIONS: tuple[ActionSpec, ...] = (
    ActionSpec(0, "sqli_probe", "SQL_INJECTION", "baseline_probe", "probe"),
    ActionSpec(1, "sqli_encoding", "SQL_INJECTION", "encoding_variation", "mutate", "percent_encoding"),
    ActionSpec(2, "xss_probe", "XSS", "baseline_probe", "probe"),
    ActionSpec(3, "xss_encoding", "XSS", "encoding_variation", "mutate", "html_entity_encoding"),
    ActionSpec(4, "path_traversal_probe", "PATH_TRAVERSAL", "baseline_probe", "probe"),
    ActionSpec(5, "path_traversal_encoding", "PATH_TRAVERSAL", "encoding_variation", "mutate", "percent_encoding"),
    ActionSpec(6, "command_injection_probe", "COMMAND_INJECTION", "baseline_probe", "probe"),
    ActionSpec(7, "command_injection_encoding", "COMMAND_INJECTION", "encoding_variation", "mutate", "whitespace_variation"),
    ActionSpec(8, "bola_authorization_check", "BOLA_IDOR", "authorization_check", "validate"),
    ActionSpec(9, "auth_boundary_check", "AUTH_BYPASS", "authentication_check", "validate"),
    ActionSpec(10, "ssrf_boundary_check", "SSRF", "destination_validation_check", "validate"),
    ActionSpec(11, "mass_assignment_check", "MASS_ASSIGNMENT", "field_boundary_check", "validate"),
    ActionSpec(12, "select_next_endpoint", "GENERAL", "advance_attack_graph", "recon"),
    ActionSpec(13, "record_endpoint", "GENERAL", "record_surface_only", "recon"),
)

_ACTION_BY_ID = {action.action_id: action for action in ACTIONS}


def get_action(action: int | str | ActionSpec) -> ActionSpec:
    """Resolve a DQN index or action id; reject unknown actions explicitly."""
    if isinstance(action, ActionSpec):
        if action.index < len(ACTIONS) and ACTIONS[action.index] == action:
            return action
        raise ValueError(f"Action is not part of the registered action space: {action!r}")
    if isinstance(action, int):
        if 0 <= action < len(ACTIONS):
            return ACTIONS[action]
        raise ValueError(f"Action index out of range: {action}")
    try:
        return _ACTION_BY_ID[action]
    except KeyError as exc:
        raise ValueError(f"Unknown action id: {action}") from exc

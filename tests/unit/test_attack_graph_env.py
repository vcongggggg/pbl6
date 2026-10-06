import sys
from pathlib import Path

import pytest

# Ensure attack-lab is on sys.path
attack_lab_path = str(Path(__file__).parents[2] / "attack-lab")
if attack_lab_path not in sys.path:
    sys.path.insert(0, attack_lab_path)

from agent.planner import AttackPlanner  # noqa: E402
from environment import (  # noqa: E402
    ACTIONS,
    AttackEnvironment,
    AttackGraph,
    AttackState,
    StepResult,
    get_action,
)

# Test attack surface dictionary matching Task 10.1 schema
SAMPLE_ATTACK_SURFACE = {
    "target_url": "http://127.0.0.1:8000",
    "spec_source": "mock_spec.json",
    "endpoints": [
        {
            "path": "/api/v1/vulnerable/auth/login/",
            "method": "POST",
            "primary_category": "AUTH_BYPASS",
            "potential_vulnerabilities": [
                {"vuln_type": "AUTH_BYPASS", "confidence": "HIGH", "target_params": ["username", "password"]},
                {"vuln_type": "SQL_INJECTION", "confidence": "HIGH", "target_params": ["username"]},
            ],
            "parameters": [],
            "request_body": {
                "content_type": "application/json",
                "fields": [
                    {"name": "username", "field_type": "string"},
                    {"name": "password", "field_type": "string"},
                ],
            },
            "requires_auth": False,
            "tags": ["auth"],
        },
        {
            "path": "/api/v1/vulnerable/books/search/",
            "method": "GET",
            "primary_category": "SQL_INJECTION",
            "potential_vulnerabilities": [
                {"vuln_type": "SQL_INJECTION", "confidence": "HIGH", "target_params": ["q"]},
            ],
            "parameters": [{"name": "q", "location": "query", "param_type": "string"}],
            "requires_auth": False,
            "tags": ["books"],
        },
        {
            "path": "/api/v1/vulnerable/files/download/",
            "method": "GET",
            "primary_category": "PATH_TRAVERSAL",
            "potential_vulnerabilities": [
                {"vuln_type": "PATH_TRAVERSAL", "confidence": "HIGH", "target_params": ["file"]},
            ],
            "parameters": [{"name": "file", "location": "query", "param_type": "string"}],
            "requires_auth": False,
            "tags": ["files"],
        },
    ],
}


def test_action_space_vocabulary_and_resolution():
    """Verify action space tuple stability, indexing, and lookup."""
    assert len(ACTIONS) == 14
    for idx, action in enumerate(ACTIONS):
        assert action.index == idx
        assert get_action(idx) == action
        assert get_action(action.action_id) == action
        assert get_action(action) == action

    with pytest.raises(ValueError, match="Action index out of range"):
        get_action(99)

    with pytest.raises(ValueError, match="Unknown action id"):
        get_action("invalid_action_id")


def test_attack_graph_construction_and_edges():
    """Verify attack graph nodes, category resolution, and edge relationships."""
    graph = AttackGraph.from_dict(SAMPLE_ATTACK_SURFACE)
    assert len(graph.nodes) == 3
    assert len(graph.edges) >= 2  # recon_order edges between adjacent endpoints

    login_node = graph.node("POST:/api/v1/vulnerable/auth/login/")
    assert login_node.primary_category == "AUTH_BYPASS"
    assert "SQL_INJECTION" in login_node.categories
    assert "username" in login_node.parameters
    assert "password" in login_node.parameters

    with pytest.raises(KeyError):
        graph.node("NON_EXISTENT_NODE")


def test_attack_environment_lifecycle_and_rewards():
    """Verify reset, stepping, action masking, and reward contracts."""
    graph = AttackGraph.from_dict(SAMPLE_ATTACK_SURFACE)
    env = AttackEnvironment(graph, max_steps=10)

    obs = env.reset()
    assert isinstance(obs, AttackState)
    assert obs.endpoint_id == "POST:/api/v1/vulnerable/auth/login/"
    assert len(obs.features) == 40
    assert obs.attempt_count == 0

    available = env.available_actions()
    available_ids = {a.action_id for a in available}
    assert "sqli_probe" in available_ids
    assert "auth_boundary_check" in available_ids
    assert "select_next_endpoint" in available_ids

    # Step 1: 403 Forbidden penalty
    step1 = env.step("sqli_probe", response={"status_code": 403})
    assert isinstance(step1, StepResult)
    assert step1.reward == -1.0
    assert not step1.terminated
    assert step1.info["outcome"] == "waf_blocked"

    # Step 2: Transition to next endpoint
    step2 = env.step("select_next_endpoint")
    assert step2.reward == 0.0
    assert step2.observation.endpoint_id == "GET:/api/v1/vulnerable/books/search/"

    # Step 3: Confirmed bypass terminal reward
    step3 = env.step("sqli_probe", response={"status_code": 200, "confirmed_bypass": True})
    assert step3.reward == 10.0
    assert step3.terminated
    assert step3.info["outcome"] == "confirmed_bypass"

    # Stepping after termination raises RuntimeError
    with pytest.raises(RuntimeError, match="Episode has terminated"):
        env.step("select_next_endpoint")


def test_attack_environment_validation_guards():
    """Verify invalid telemetry or mismatched actions are rejected."""
    graph = AttackGraph.from_dict(SAMPLE_ATTACK_SURFACE)
    env = AttackEnvironment(graph)
    env.reset()

    # Reject unavailable action for current endpoint
    with pytest.raises(ValueError, match="does not apply"):
        env.step("path_traversal_probe")

    # Reject invalid status codes
    with pytest.raises(ValueError, match="must be an HTTP status code"):
        env.step("sqli_probe", response={"status_code": 999})

    # Reject 403 combined with confirmed_bypass: True
    with pytest.raises(ValueError, match="cannot be marked as a confirmed bypass"):
        env.step("sqli_probe", response={"status_code": 403, "confirmed_bypass": True})


def test_attack_planner_integration():
    """Verify AttackPlanner wrapper functionality and plan formatting."""
    planner = AttackPlanner(SAMPLE_ATTACK_SURFACE, max_steps=5)
    plan = planner.reset()

    assert "state" in plan
    assert "candidates" in plan
    assert len(plan["candidates"]) > 0

    first_candidate = plan["candidates"][0]
    res = planner.step(first_candidate["action_id"], response={"status_code": 403})
    assert res["reward"] == -1.0
    assert "state" in res

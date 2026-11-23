"""Unit and Integration tests for hardened AI Arena endpoints (Task 10.4 + Blue Team v2.0)."""

from fastapi.testclient import TestClient

from app.api import arena

ADMIN_HEADERS = {"X-API-Key": "dev-admin-secret-key-change-me"}


def test_arena_requires_admin_auth(client: TestClient):
    """RED-PBL6-001: Verifies all Arena endpoints enforce X-API-Key authentication."""
    assert client.get("/dashboard/arena/live").status_code == 401
    assert client.get("/dashboard/arena/history").status_code == 401
    assert client.post("/dashboard/arena/battle", json={}).status_code == 401
    assert client.post("/api/dashboard/arena/battle", json={}).status_code == 401


def test_arena_initial_state(client: TestClient):
    """Verifies live and history endpoints on clean/initial state."""
    arena._BATTLE_HISTORY.clear()
    arena._CURRENT_OR_LAST_BATTLE = None

    res_live = client.get("/dashboard/arena/live", headers=ADMIN_HEADERS)
    assert res_live.status_code == 200
    live_data = res_live.json()
    assert live_data["status"] == "idle"
    assert live_data["battle_id"] is None
    assert live_data["rounds"] == []

    res_api_live = client.get("/api/dashboard/arena/live", headers=ADMIN_HEADERS)
    assert res_api_live.status_code == 200
    assert res_api_live.json()["status"] == "idle"

    res_hist = client.get("/dashboard/arena/history", headers=ADMIN_HEADERS)
    assert res_hist.status_code == 200
    hist_data = res_hist.json()
    assert hist_data["total_battles"] == 0
    assert hist_data["red_wins"] == 0
    assert hist_data["blue_wins"] == 0
    assert hist_data["red_team_win_rate"] == 0.0
    assert hist_data["blue_team_defense_rate"] == 0.0
    assert hist_data["battles"] == []


def test_arena_battle_default_campaign(client: TestClient):
    """Verifies running battle with default settings (campaign='all', max_rounds=4, target_mode='waf')."""
    res = client.post("/api/dashboard/arena/battle", json={}, headers=ADMIN_HEADERS)
    assert res.status_code == 200
    data = res.json()

    assert data["battle_id"].startswith("battle-")
    assert data["campaign"] == "all"
    assert data["total_rounds"] == 4
    assert data["blocked_count"] + data["bypass_count"] == 4
    assert data["winner"] in ("RED_TEAM", "BLUE_TEAM", "DRAW")
    assert 0.0 <= data["avg_threat_score"] <= 100.0
    assert len(data["rounds"]) == 4

    round_numbers = []
    attack_types = []
    for rd in data["rounds"]:
        round_numbers.append(rd["round_num"])
        attack_types.append(rd["attack_type"])
        assert rd["response_status"] in (200, 403)
        assert 0.0 <= rd["waf_threat_score"] <= 100.0
        assert rd["waf_decision"] in ("BLOCK", "ALLOW")
        assert rd["latency_ms"] > 0
        assert rd["winner"] in ("RED_TEAM", "BLUE_TEAM")
        assert rd["endpoint"] != ""
        assert rd["technique"] != ""
        assert rd["payload"] != ""
        assert rd["original_payload"] != ""

    assert round_numbers == [1, 2, 3, 4]
    assert set(attack_types) == {"SQL_INJECTION", "XSS", "PATH_TRAVERSAL", "COMMAND_INJECTION"}


def test_arena_battle_sqli_campaign(client: TestClient):
    """Verifies targeted SQL Injection campaign with multi-round evasion mutations."""
    res = client.post(
        "/api/dashboard/arena/battle",
        json={"campaign": "sqli", "max_rounds": 4, "target_mode": "waf"},
        headers=ADMIN_HEADERS,
    )
    assert res.status_code == 200
    data = res.json()

    assert data["campaign"] == "sqli"
    assert data["total_rounds"] == 4
    assert len(data["rounds"]) == 4

    techniques = [rd["technique"] for rd in data["rounds"]]
    assert len(set(techniques)) == 4
    for rd in data["rounds"]:
        assert rd["attack_type"] == "SQL_INJECTION"
        assert 0.0 <= rd["waf_threat_score"] <= 100.0


def test_arena_battle_xss_campaign(client: TestClient):
    """Verifies targeted XSS campaign."""
    res = client.post(
        "/api/dashboard/arena/battle",
        json={"campaign": "xss", "max_rounds": 3, "target_mode": "waf"},
        headers=ADMIN_HEADERS,
    )
    assert res.status_code == 200
    data = res.json()

    assert data["campaign"] == "xss"
    assert data["total_rounds"] == 3
    assert len(data["rounds"]) == 3
    for rd in data["rounds"]:
        assert rd["attack_type"] == "XSS"
        assert 0.0 <= rd["waf_threat_score"] <= 100.0


def test_arena_battle_path_and_cmd_campaigns(client: TestClient):
    """Verifies targeted Path Traversal and Command Injection campaigns."""
    res_path = client.post(
        "/api/dashboard/arena/battle",
        json={"campaign": "path", "max_rounds": 2, "target_mode": "waf"},
        headers=ADMIN_HEADERS,
    )
    assert res_path.status_code == 200
    data_path = res_path.json()
    assert all(rd["attack_type"] == "PATH_TRAVERSAL" for rd in data_path["rounds"])

    res_cmd = client.post(
        "/api/dashboard/arena/battle",
        json={"campaign": "cmd", "max_rounds": 2, "target_mode": "waf"},
        headers=ADMIN_HEADERS,
    )
    assert res_cmd.status_code == 200
    data_cmd = res_cmd.json()
    assert all(rd["attack_type"] == "COMMAND_INJECTION" for rd in data_cmd["rounds"])


def test_arena_battle_direct_mode(client: TestClient):
    """Verifies direct mode where WAF is bypassed and Red Team wins all rounds."""
    res = client.post(
        "/api/dashboard/arena/battle",
        json={"campaign": "all", "max_rounds": 4, "target_mode": "direct"},
        headers=ADMIN_HEADERS,
    )
    assert res.status_code == 200
    data = res.json()

    assert data["target_mode"] == "direct"
    assert data["blocked_count"] == 0
    assert data["bypass_count"] == 4
    assert data["winner"] == "RED_TEAM"
    assert data["avg_threat_score"] == 0.0
    for rd in data["rounds"]:
        assert rd["response_status"] == 200
        assert rd["waf_decision"] == "ALLOW"
        assert rd["waf_threat_score"] == 0.0
        assert rd["winner"] == "RED_TEAM"


def test_arena_live_and_history_persistence(client: TestClient):
    """Verifies that battles update live state and accumulate in history statistics."""
    arena._BATTLE_HISTORY.clear()
    arena._CURRENT_OR_LAST_BATTLE = None

    client.post(
        "/api/dashboard/arena/battle",
        json={"campaign": "sqli", "max_rounds": 2, "target_mode": "waf"},
        headers=ADMIN_HEADERS,
    )

    res_live = client.get("/dashboard/arena/live", headers=ADMIN_HEADERS)
    assert res_live.status_code == 200
    live_data = res_live.json()
    assert live_data["status"] == "completed"
    assert live_data["campaign"] == "sqli"
    assert len(live_data["rounds"]) == 2

    client.post(
        "/api/dashboard/arena/battle",
        json={"campaign": "xss", "max_rounds": 2, "target_mode": "direct"},
        headers=ADMIN_HEADERS,
    )

    res_hist = client.get("/dashboard/arena/history", headers=ADMIN_HEADERS)
    assert res_hist.status_code == 200
    hist = res_hist.json()
    assert hist["total_battles"] == 2
    assert len(hist["battles"]) == 2
    assert hist["red_team_wins"] >= 1
    assert hist["red_wins"] == hist["red_team_wins"]
    assert hist["blue_wins"] == hist["blue_team_wins"]
    assert 0.0 <= hist["red_team_win_rate"] <= 100.0
    assert 0.0 <= hist["blue_team_defense_rate"] <= 100.0


def test_arena_history_cache_cap(client: TestClient):
    """Verifies that in-memory history cache respects max entries limit."""
    arena._BATTLE_HISTORY.clear()
    for _ in range(55):
        client.post(
            "/api/dashboard/arena/battle",
            json={"campaign": "all", "max_rounds": 1, "target_mode": "direct"},
            headers=ADMIN_HEADERS,
        )

    res_hist = client.get("/dashboard/arena/history", headers=ADMIN_HEADERS)
    hist = res_hist.json()
    assert hist["total_battles"] == 50
    assert len(hist["battles"]) == 50

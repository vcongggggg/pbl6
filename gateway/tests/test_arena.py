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


def test_arena_pentest_run_hybrid_v3(client: TestClient):
    """Verifies injection pentest evaluation under hybrid_v3 defense tier where Blue Team dominates."""
    res = client.post(
        "/api/dashboard/arena/pentest/run",
        json={"scope": "injection", "max_rounds": 4, "defense_tier": "hybrid_v3", "sync_to_soc": True},
        headers=ADMIN_HEADERS,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["battle_id"].startswith("pentest-")
    assert data["defense_tier"] == "hybrid_v3"
    assert data["total_rounds"] == 4
    assert data["winner"] == "BLUE_TEAM"
    assert data["blocked_count"] == 4
    assert data["bypass_count"] == 0
    assert 0.0 <= data["avg_threat_score"] <= 100.0

    for rd in data["rounds"]:
        assert rd["response_status"] == 403
        assert rd["waf_decision"] == "BLOCK"
        assert rd["winner"] == "BLUE_TEAM"
        assert len(rd["dqn_q_values"]) == 5
        assert "Chế độ Hybrid" in rd["reasoning_vi"]


def test_arena_pentest_run_full_scope(client: TestClient):
    """Verifies full 8/8 OWASP Web + API pentest evaluation under hybrid_v3 defense tier."""
    from app.db.models import SecurityEvent
    from app.db.session import SessionLocal

    res = client.post(
        "/api/dashboard/arena/pentest/run",
        json={"scope": "full_pentest", "max_rounds": 8, "defense_tier": "hybrid_v3", "sync_to_soc": True},
        headers=ADMIN_HEADERS,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["total_rounds"] == 8
    assert data["blocked_count"] == 8
    assert data["bypass_count"] == 0
    assert data["winner"] == "BLUE_TEAM"
    assert isinstance(data["attack_graph"], list) and len(data["attack_graph"]) == 8

    # Verify UI-compatible numeric fields and real Dueling-DQN Q-values
    for rd in data["rounds"]:
        assert rd["waf_blocked"] is True
        assert isinstance(rd["threat_score"], (int, float))
        assert isinstance(rd["ml_score"], (int, float))
        assert isinstance(rd["anomaly_score"], (int, float))
        assert isinstance(rd["dqn_q_values"], list) and len(rd["dqn_q_values"]) >= 1
        assert "q_value" in rd["dqn_q_values"][0]

    # Verify canonical BLOCKED action & session_id/kill_chain_stage in SOC DB
    with SessionLocal() as db:
        ev = (
            db.query(SecurityEvent)
            .filter(SecurityEvent.action == "BLOCKED")
            .order_by(SecurityEvent.id.desc())
            .first()
        )
        assert ev is not None
        assert ev.session_id is not None
        assert ev.kill_chain_stage is not None


def test_arena_pentest_run_no_waf(client: TestClient):
    """Verifies pentest evaluation under no_waf defense tier where red team wins 100%."""
    res = client.post(
        "/api/dashboard/arena/pentest/run",
        json={"scope": "injection", "max_rounds": 4, "defense_tier": "no_waf", "sync_to_soc": False},
        headers=ADMIN_HEADERS,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["defense_tier"] == "no_waf"
    assert data["winner"] == "RED_TEAM"
    assert data["bypass_count"] == 4
    assert data["blocked_count"] == 0
    assert data["avg_threat_score"] == 0.0

    for rd in data["rounds"]:
        assert rd["response_status"] == 200
        assert rd["waf_decision"] == "ALLOW"
        assert rd["winner"] == "RED_TEAM"


def test_arena_pentest_run_rules_only(client: TestClient):
    """Verifies pentest evaluation under rules_only defense tier."""
    res = client.post(
        "/api/dashboard/arena/pentest/run",
        json={"scope": "injection", "max_rounds": 4, "defense_tier": "rules_only", "sync_to_soc": False},
        headers=ADMIN_HEADERS,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["defense_tier"] == "rules_only"
    assert data["total_rounds"] == 4


def test_arena_pentest_stream_sse(client: TestClient):
    """Verifies live SSE streaming endpoint (/dashboard/arena/pentest/stream)."""
    with client.stream(
        "GET",
        "/api/dashboard/arena/pentest/stream?max_rounds=2&defense_tier=hybrid_v3",
        headers=ADMIN_HEADERS,
    ) as response:
        assert response.status_code == 200
        assert "text/event-stream" in response.headers.get("content-type", "")

        events_seen = set()
        for line in response.iter_lines():
            if line.startswith("event: "):
                event_name = line.replace("event: ", "").strip()
                events_seen.add(event_name)

        assert "recon" in events_seen
        assert "attack_graph" in events_seen
        assert "round" in events_seen
        assert "verdict" in events_seen
        assert "done" in events_seen


def test_arena_pentest_default_sync_to_soc_is_false(client: TestClient):
    """Phase A4.1: Verifies default sync_to_soc is False so exploratory Arena runs do not pollute SOC table."""
    from app.db.models import SecurityEvent
    from app.db.session import SessionLocal

    with SessionLocal() as db:
        before_cnt = db.query(SecurityEvent).count()

    res = client.post(
        "/api/dashboard/arena/pentest/run",
        json={"scope": "injection", "max_rounds": 2, "defense_tier": "hybrid_v3"},
        headers=ADMIN_HEADERS,
    )
    assert res.status_code == 200

    with SessionLocal() as db:
        after_cnt = db.query(SecurityEvent).count()
    assert after_cnt == before_cnt


def test_arena_pentest_live_http_mode_and_cwe918_guard(client: TestClient):
    """Phase C1: Verifies end-to-end live_http execution mode through /api/proxy and CWE-918 target_url guard."""
    res = client.post(
        "/api/dashboard/arena/pentest/run",
        json={
            "scope": "injection",
            "max_rounds": 4,
            "defense_tier": "hybrid_v3",
            "execution_mode": "live_http",
            "target_url": "http://127.0.0.1:5000",
        },
        headers=ADMIN_HEADERS,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["execution_mode"] == "live_http"
    assert data["blocked_count"] == 4
    assert data["winner"] == "BLUE_TEAM"
    for rd in data["rounds"]:
        assert rd["response_status"] == 403
        assert rd["rule_score"] > 0.0

    # Reject external internet target_url (CWE-918 protection)
    res_bad = client.post(
        "/api/dashboard/arena/pentest/run",
        json={"scope": "sqli", "max_rounds": 1, "target_url": "https://attacker.example.com"},
        headers=ADMIN_HEADERS,
    )
    assert res_bad.status_code == 400


def test_arena_pentest_catalog_and_live_http_custom_payload(client: TestClient):
    """Phase F1: Verifies attack catalog, custom_payload + selected_families, and SSE live_http stream."""
    cat_res = client.get("/api/dashboard/arena/pentest/catalog", headers=ADMIN_HEADERS)
    assert cat_res.status_code == 200
    cat = cat_res.json()
    families = {item["family"]: item for item in cat["families"]}
    assert "SQL_INJECTION" in families
    assert families["SQL_INJECTION"]["baseline_payload"]
    assert len(families["SQL_INJECTION"]["techniques"]) >= 4

    custom_sqli = "' UNION SELECT username, password FROM users--"
    run_res = client.post(
        "/api/dashboard/arena/pentest/run",
        json={
            "scope": "full_pentest",
            "selected_families": ["SQL_INJECTION"],
            "custom_payload": custom_sqli,
            "max_rounds": 2,
            "defense_tier": "hybrid_v3",
            "execution_mode": "live_http",
            "target_url": "http://127.0.0.1:5000",
        },
        headers=ADMIN_HEADERS,
    )
    assert run_res.status_code == 200
    data = run_res.json()
    assert data["execution_mode"] == "live_http"
    assert data["total_rounds"] == 2
    assert data["blocked_count"] == 2
    assert data["rounds"][0]["attack_type"] == "SQL_INJECTION"
    assert data["rounds"][0]["original_payload"] == custom_sqli
    assert data["rounds"][0]["mutated_payload"] == custom_sqli
    assert data["rounds"][0]["response_status"] == 403

    # Also verify SSE streaming endpoint supports execution_mode=live_http
    with client.stream(
        "GET",
        "/api/dashboard/arena/pentest/stream?scope=sqli&max_rounds=2&defense_tier=hybrid_v3&execution_mode=live_http",
        headers=ADMIN_HEADERS,
    ) as stream_res:
        assert stream_res.status_code == 200
        events_seen = set()
        for line in stream_res.iter_lines():
            if line.startswith("event: "):
                events_seen.add(line.replace("event: ", "").strip())
        assert {"recon", "attack_graph", "round", "verdict", "done"}.issubset(events_seen)


def test_arena_pentest_replay_matching_verdicts(client: TestClient):
    """Phase F1: Verifies deterministic traffic replay and replay_comparison match rate."""
    arena._BATTLE_HISTORY.clear()
    arena._CURRENT_OR_LAST_PENTEST = None

    # 404 when no recorded traffic exists
    empty_replay = client.post("/api/dashboard/arena/pentest/replay", json={}, headers=ADMIN_HEADERS)
    assert empty_replay.status_code == 404

    run_res = client.post(
        "/api/dashboard/arena/pentest/run",
        json={
            "scope": "injection",
            "max_rounds": 4,
            "defense_tier": "hybrid_v3",
            "execution_mode": "live_http",
            "target_url": "http://127.0.0.1:5000",
        },
        headers=ADMIN_HEADERS,
    )
    assert run_res.status_code == 200
    orig = run_res.json()

    replay_res = client.post(
        "/api/dashboard/arena/pentest/replay",
        json={
            "battle_id": orig["battle_id"],
            "defense_tier": "hybrid_v3",
            "execution_mode": "live_http",
            "target_url": "http://127.0.0.1:5000",
        },
        headers=ADMIN_HEADERS,
    )
    assert replay_res.status_code == 200
    replayed = replay_res.json()
    assert replayed["battle_id"].startswith("replay-")
    assert replayed["execution_mode"] == "live_http"
    comp = replayed["replay_comparison"]
    assert comp["replay_of"] == orig["battle_id"]
    assert comp["total_replayed"] == 4
    assert comp["matched_verdicts"] == 4
    assert comp["match_rate_pct"] == 100.0
    assert comp["mismatches"] == []


def test_arena_pentest_export_d4_evidence(client: TestClient, tmp_path, monkeypatch):
    """Phase F1: Verifies D4 immutable evidence export and SHA-256 digest without polluting repo."""
    monkeypatch.setattr(arena, "_REPO_ROOT", tmp_path)
    monkeypatch.setattr(arena, "_GATEWAY_ROOT", tmp_path / "gateway")

    run_res = client.post(
        "/api/dashboard/arena/pentest/run",
        json={
            "scope": "sqli",
            "max_rounds": 2,
            "defense_tier": "hybrid_v3",
            "execution_mode": "live_http",
        },
        headers=ADMIN_HEADERS,
    )
    assert run_res.status_code == 200
    report = run_res.json()

    # 1. Without docs/reports/history -> safely writes to tmp_path/data/arena_evidence
    exp1 = client.post(
        "/api/dashboard/arena/pentest/export",
        json={"battle_id": report["battle_id"], "report": report},
        headers=ADMIN_HEADERS,
    )
    assert exp1.status_code == 200
    d1 = exp1.json()
    assert d1["filename"].startswith("arena_live_") and d1["filename"].endswith(".json")
    assert len(d1["sha256"]) == 64
    assert "arena_evidence" in d1["artifact_path"]
    assert d1["evidence"]["metadata"]["task_id"] == "pbl6-v3-4-phase-f-001"
    assert d1["evidence"]["metadata"]["sha256_digest"] == d1["sha256"]
    assert d1["evidence"]["metadata"]["execution_mode"] == "live_http"
    assert (tmp_path / "data" / "arena_evidence" / d1["filename"]).is_file()

    # 2. With docs/reports/history present -> writes to docs/reports/history
    history_dir = tmp_path / "docs" / "reports" / "history"
    history_dir.mkdir(parents=True, exist_ok=True)
    exp2 = client.post(
        "/api/dashboard/arena/pentest/export",
        json={"report": report},
        headers=ADMIN_HEADERS,
    )
    assert exp2.status_code == 200
    d2 = exp2.json()
    assert (history_dir / d2["filename"]).is_file()


def test_arena_docker_isolation_without_attack_lab(client: TestClient, monkeypatch):
    """Phase F1/F2: Ensures Arena works seamlessly when ./attack-lab is absent in Docker."""
    monkeypatch.setattr(arena, "_PENTEST_ADVISOR", None)
    monkeypatch.setattr(arena, "get_valid_actions_for_case", None)
    monkeypatch.setattr(arena, "encode_pentest_state_64d", None)
    monkeypatch.setattr(arena, "APIReconAgent", None)
    monkeypatch.setattr(arena, "OpenAPIPayloadSynthesizer", None)

    for mode in ("in_process", "live_http"):
        res = client.post(
            "/api/dashboard/arena/pentest/run",
            json={
                "scope": "injection",
                "max_rounds": 4,
                "defense_tier": "hybrid_v3",
                "execution_mode": mode,
            },
            headers=ADMIN_HEADERS,
        )
        assert res.status_code == 200
        data = res.json()
        assert data["execution_mode"] == mode
        assert data["total_rounds"] == 4
        assert data["blocked_count"] == 4
        assert data["rounds"][0]["technique"] == "baseline_probe"



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


def test_arena_pentest_replay_benchmark_100_requests(client: TestClient):
    """F1a: Verifies 100-request benchmark replay matches fp_v3_measurement.json (0.0% operational FPR)."""
    # 1. balanced_100 on csic2010: 50 benign + 50 attacks = 100 requests
    res_bal = client.post(
        "/api/dashboard/arena/pentest/replay-benchmark",
        json={
            "dataset": "csic2010",
            "sample_count": 100,
            "mode": "balanced_100",
            "execution_mode": "in_process",
            "defense_tier": "hybrid_v3",
        },
        headers=ADMIN_HEADERS,
    )
    assert res_bal.status_code == 200
    bal = res_bal.json()
    assert bal["dataset"] == "csic2010"
    assert bal["mode"] == "balanced_100"
    assert bal["total_requests"] == 100
    assert bal["benign_count"] == 50
    assert bal["attack_count"] == 50
    assert len(bal["verdicts"]) == 100
    assert bal["fp_count"] == 0
    assert bal["tn_count"] == 50
    assert bal["tp_count"] > 0
    assert bal["operational_fpr_pct"] == 0.0
    assert bal["reference_operational_fpr_pct"] == 0.0
    assert bal["matches_fp_measurement"] is True
    assert bal["avg_latency_ms"] >= 0.0

    first_v = bal["verdicts"][0]
    for key in (
        "index",
        "method",
        "path",
        "label",
        "attack_type",
        "waf_blocked",
        "waf_decision",
        "http_status",
        "threat_score",
        "latency_ms",
        "matched_rules",
    ):
        assert key in first_v

    # 2. benign_100 on csic2010: 100 benign = 100 requests, 0 FP
    res_ben = client.post(
        "/api/dashboard/arena/pentest/replay-benchmark",
        json={
            "dataset": "csic2010",
            "sample_count": 100,
            "mode": "benign_100",
            "execution_mode": "in_process",
            "defense_tier": "hybrid_v3",
        },
        headers=ADMIN_HEADERS,
    )
    assert res_ben.status_code == 200
    ben = res_ben.json()
    assert ben["total_requests"] == 100
    assert ben["benign_count"] == 100
    assert ben["attack_count"] == 0
    assert len(ben["verdicts"]) == 100
    assert ben["fp_count"] == 0
    assert ben["tn_count"] == 100
    assert ben["operational_fpr_pct"] == 0.0
    assert ben["matches_fp_measurement"] is True


def test_arena_export_digest_reproducible_and_git_sha(client: TestClient, tmp_path, monkeypatch):
    """E1: Verifies real 40-char git_head_sha and byte-exact reproducible canonical SHA-256."""
    import hashlib
    import json
    import re
    from pathlib import Path

    real_repo_root = Path(__file__).resolve().parents[2]
    expected_sha, _ = arena._get_git_head_sha()
    assert re.fullmatch(r"[0-9a-fA-F]{40}", expected_sha), f"Expected 40-char git SHA, got {expected_sha!r}"

    # Verify .git/HEAD direct fallback returns same 40-char SHA even if git binary fails
    monkeypatch.setattr(
        arena.subprocess,
        "check_output",
        lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError("no git")),
    )
    monkeypatch.setattr(arena, "_REPO_ROOT", real_repo_root)
    fallback_sha, _ = arena._get_git_head_sha()
    assert fallback_sha == expected_sha

    # Verify linked git worktree (.git file with gitdir + commondir) resolves cleanly without git binary
    wt_root = tmp_path / "linked_worktree"
    wt_root.mkdir()
    common_git = tmp_path / "main_repo_git"
    wt_git = common_git / "worktrees" / "audit-wt"
    (common_git / "refs" / "heads").mkdir(parents=True)
    wt_git.mkdir(parents=True)
    (wt_root / ".git").write_text(f"gitdir: {wt_git}\n", encoding="utf-8")
    (wt_git / "HEAD").write_text("ref: refs/heads/feat/test-wt\n", encoding="utf-8")
    (wt_git / "commondir").write_text("../..\n", encoding="utf-8")
    (common_git / "refs" / "heads" / "feat" / "test-wt").parent.mkdir(parents=True, exist_ok=True)
    (common_git / "refs" / "heads" / "feat" / "test-wt").write_text(f"{expected_sha}\n", encoding="utf-8")
    monkeypatch.setattr(arena, "_REPO_ROOT", wt_root)
    wt_fallback_sha, wt_short = arena._get_git_head_sha()
    assert wt_fallback_sha == expected_sha
    assert wt_short == expected_sha[:7]

    # Redirect artifact writes to tmp_path so repo stays clean
    monkeypatch.setattr(arena, "_REPO_ROOT", tmp_path)
    monkeypatch.setattr(arena, "_GATEWAY_ROOT", tmp_path / "gateway")
    monkeypatch.setenv("GIT_HEAD_SHA", expected_sha)

    run_res = client.post(
        "/api/dashboard/arena/pentest/run",
        json={"scope": "sqli", "max_rounds": 2, "defense_tier": "hybrid_v3", "execution_mode": "in_process"},
        headers=ADMIN_HEADERS,
    )
    assert run_res.status_code == 200
    report = run_res.json()

    exp_res = client.post(
        "/api/dashboard/arena/pentest/export",
        json={"battle_id": report["battle_id"], "report": report},
        headers=ADMIN_HEADERS,
    )
    assert exp_res.status_code == 200
    exp_data = exp_res.json()

    artifact_file = Path(exp_data["artifact_path"])
    assert artifact_file.is_file()
    raw_bytes = artifact_file.read_bytes()
    assert b"\r\n" not in raw_bytes

    loaded = json.loads(raw_bytes.decode("utf-8"))
    assert loaded["metadata"]["git_head_sha"] == expected_sha
    assert "sha256_reproduce_cmd" in loaded["metadata"]

    exp_digest = loaded["metadata"].pop("sha256_digest")
    actual_digest = hashlib.sha256(
        json.dumps(loaded, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert exp_digest == exp_data["sha256"]
    assert actual_digest == exp_digest


def test_arena_phase_e_mutators_complete_36_action_coverage():
    """LOGIC-PBL6-301: All 36 PENTEST_ACTIONS resolve in _MUTATOR_FUNCTIONS and Phase E mutators transform payloads."""
    from environment.pentest_env import PENTEST_ACTIONS

    assert len(PENTEST_ACTIONS) == 36
    for spec in PENTEST_ACTIONS:
        fn = arena._MUTATOR_FUNCTIONS.get(spec.transformation)
        assert fn is not None, f"Missing mutator for {spec.action_id} ({spec.transformation})"
        assert callable(fn)

    phase_e_samples = {
        "hpp_query_pollution": "' OR 1=1--",
        "sqli_scientific_float": "' UNION SELECT 1,2--",
        "sqli_char_chr_concat": "' OR 'admin'='admin'--",
        "xss_json_unicode_escape": "<script>alert(1)</script>",
        "json_duplicate_key_tamper": "<script>alert(1)</script>",
        "xss_svg_mathml_onbegin": "<script>alert(1)</script>",
        "cmd_dollar_at_split": "127.0.0.1; cat /etc/passwd",
        "cmd_wildcard_glob": "127.0.0.1; cat /etc/passwd",
        "path_overlong_mixed_slash": "../../../../etc/passwd",
        "nosql_nin_exists_blind": "admin",
    }
    for tech, sample in phase_e_samples.items():
        mutated = arena._MUTATOR_FUNCTIONS[tech](sample)
        assert isinstance(mutated, str)
        assert mutated != ""
        assert mutated != sample


def test_arena_build_http_surface_args_preserves_hpp_and_duplicate_json_keys():
    """LOGIC-PBL6-301: Preserves duplicate query params for HPP and duplicate JSON keys for JSON pollution."""
    import json
    import urllib.parse

    hpp_payload = arena._MUTATOR_FUNCTIONS["hpp_query_pollution"]("' OR 1=1--")
    resolved_path, params_dict, json_obj, query_str, body_text, body_bytes = arena._build_http_surface_args(
        endpoint_tpl="/api/v1/vulnerable/books/search/",
        method="GET",
        param="q",
        rtype="query",
        extra={"limit": "5"},
        payload_str=hpp_payload,
    )
    assert resolved_path == "/api/v1/vulnerable/books/search/"
    assert params_dict is None
    assert json_obj is None
    assert query_str is not None
    parsed_pairs = urllib.parse.parse_qsl(query_str, keep_blank_values=True)
    assert [v for k, v in parsed_pairs if k == "q"] == ["1", "' OR 1=1--"]
    assert ("limit", "5") in parsed_pairs

    dup_payload = arena._MUTATOR_FUNCTIONS["json_duplicate_key_tamper"]("<script>alert(1)</script>")
    _rp, p_dict2, j_obj2, q_str2, b_text2, b_bytes2 = arena._build_http_surface_args(
        endpoint_tpl="/api/v1/vulnerable/reviews/",
        method="POST",
        param="comment",
        rtype="json",
        extra={"book_id": 1},
        payload_str=dup_payload,
    )
    assert p_dict2 is None
    assert q_str2 is None
    assert j_obj2 is None
    assert b_text2 is not None and b_bytes2 == b_text2.encode("utf-8")
    assert b_text2.count('"comment":') == 2
    assert '"book_id": 1' in b_text2
    assert json.loads(b_text2)["comment"] == "<script>alert(1)</script>"

    # Adapts default "comment" key when target param is different
    _, _, j_obj3, _, b_text3, _ = arena._build_http_surface_args(
        endpoint_tpl="/api/v1/vulnerable/reviews/",
        method="POST",
        param="title",
        rtype="json",
        extra={},
        payload_str=dup_payload,
    )
    assert j_obj3 is None
    assert b_text3 is not None and b_text3.count('"title":') == 2

    # Non-duplicate JSON payloads (e.g. NoSQL) remain structured json_obj
    _, _, j_obj4, _, _, _ = arena._build_http_surface_args(
        endpoint_tpl="/api/v1/vulnerable/users/login/",
        method="POST",
        param="username",
        rtype="json",
        extra={},
        payload_str='{"$ne": ""}',
    )
    assert j_obj4 == {"username": '{"$ne": ""}'}


def test_arena_live_http_lock_serializes_concurrent_runs(monkeypatch):
    """SEC-PBL6-302: _LIVE_HTTP_ARENA_LOCK serializes concurrent live_http evaluations and restores tier on error."""
    import asyncio
    from types import SimpleNamespace

    from app.main import app

    assert isinstance(arena._LIVE_HTTP_ARENA_LOCK, asyncio.Lock)
    active = 0
    max_active = 0
    tier_calls: list[tuple[str, object]] = []

    def fake_enter(tier: str):
        tier_calls.append(("enter", tier))
        return "MONITOR_ONLY", "hybrid"

    def fake_exit(prev_waf_mode, prev_ablation):
        tier_calls.append(("exit", (prev_waf_mode, prev_ablation)))

    async def fake_round(**kwargs):
        nonlocal active, max_active
        assert arena._LIVE_HTTP_ARENA_LOCK.locked()
        active += 1
        max_active = max(max_active, active)
        await asyncio.sleep(0.02)
        active -= 1
        return {
            "round_num": kwargs["round_num"],
            "round": kwargs["round_num"],
            "attack_type": kwargs["case"]["family"],
            "waf_blocked": True,
            "waf_decision": "BLOCK",
            "waf_threat_score": 90.0,
            "latency_ms": 1.0,
            "matched_rules": ["SQLI-001"],
        }

    monkeypatch.setattr(arena, "_enter_live_http_tier", fake_enter)
    monkeypatch.setattr(arena, "_exit_live_http_tier", fake_exit)
    monkeypatch.setattr(arena, "_execute_single_live_http_round", fake_round)

    req = SimpleNamespace(app=app)
    body = arena.PentestRunRequest(scope="sqli", max_rounds=1, defense_tier="hybrid_v3", execution_mode="live_http")

    async def _run_concurrent():
        return await asyncio.gather(
            arena._run_live_http_pentest_evaluation(req, body, "127.0.0.1"),
            arena._run_live_http_pentest_evaluation(req, body, "127.0.0.1"),
        )

    results = asyncio.run(_run_concurrent())
    assert len(results) == 2
    assert max_active == 1
    assert [c[0] for c in tier_calls] == ["enter", "exit", "enter", "exit"]


def test_proxy_403_and_arena_live_http_populate_matched_rules(client: TestClient):
    """LOGIC-PBL6-303: HTTP 403 /api/proxy blocks include matched_rules and Arena live_http populates badges."""
    from app.api.proxy import invalidate_waf_mode_cache
    from app.db.models import WafConfigModel
    from app.db.session import SessionLocal

    prev_mode: str | None = None
    with SessionLocal() as db:
        row = db.query(WafConfigModel).filter(WafConfigModel.key == "waf_mode").first()
        prev_mode = row.value if row else None
        if row:
            row.value = "ACTIVE_BLOCKING"
        else:
            db.add(WafConfigModel(key="waf_mode", value="ACTIVE_BLOCKING"))
        db.commit()
    invalidate_waf_mode_cache()

    try:
        proxy_res = client.get(
            "/api/proxy/rest/products/search?q=apple%27%20UNION%20SELECT%20null%2Cnull--"
        )
        assert proxy_res.status_code == 403
        proxy_json = proxy_res.json()
        assert isinstance(proxy_json.get("matched_rules"), list)
        assert any(r.startswith("SQLI-") for r in proxy_json["matched_rules"])
    finally:
        with SessionLocal() as db:
            row = db.query(WafConfigModel).filter(WafConfigModel.key == "waf_mode").first()
            if prev_mode is None and row is not None:
                db.delete(row)
            elif row is not None:
                row.value = prev_mode
            db.commit()
        invalidate_waf_mode_cache()

    arena_res = client.post(
        "/api/dashboard/arena/pentest/run",
        json={
            "scope": "injection",
            "max_rounds": 2,
            "defense_tier": "hybrid_v3",
            "execution_mode": "live_http",
            "target_url": "http://127.0.0.1:5000",
        },
        headers=ADMIN_HEADERS,
    )
    assert arena_res.status_code == 200
    rounds = arena_res.json()["rounds"]
    assert len(rounds) == 2
    for rd in rounds:
        assert rd["waf_blocked"] is True
        assert isinstance(rd["matched_rules"], list) and len(rd["matched_rules"]) > 0


def test_arena_in_process_waf_uses_predict_http_with_fallback(monkeypatch):
    """LOGIC-PBL6-304: _inspect_in_process_waf uses predict_http when available and keeps vec_26 for anomaly."""
    predict_http_calls: list[tuple[str, str | None, str | None]] = []
    anomaly_vecs: list[list[float] | None] = []

    orig_predict_http = arena._ml_detector.predict_http
    orig_anomaly_predict = arena._anomaly_detector.predict

    def spy_predict_http(*, path: str, query_params: str | None = None, body: str | None = None):
        predict_http_calls.append((path, query_params, body))
        return orig_predict_http(path=path, query_params=query_params, body=body)

    def spy_anomaly_predict(payload: str, feature_vector=None):
        anomaly_vecs.append(feature_vector)
        return orig_anomaly_predict(payload, feature_vector=feature_vector)

    monkeypatch.setattr(arena._ml_detector, "predict_http", spy_predict_http)
    monkeypatch.setattr(arena._anomaly_detector, "predict", spy_anomaly_predict)

    res = arena._inspect_in_process_waf(
        family="SQL_INJECTION",
        endpoint_tpl="/api/v1/vulnerable/books/search/",
        resolved_path="/api/v1/vulnerable/books/search/",
        method="GET",
        query_str="q=%27%20OR%201%3D1--",
        body_text=None,
        body_bytes=None,
        tech_name="baseline_probe",
        tier="hybrid_v3",
        client_ip="127.0.0.1",
    )
    assert res["waf_blocked"] is True
    assert predict_http_calls == [("/api/v1/vulnerable/books/search/", "q=%27%20OR%201%3D1--", None)]
    assert len(anomaly_vecs) == 1 and isinstance(anomaly_vecs[0], list) and len(anomaly_vecs[0]) == 26

    # Verify fallback path when predict_http is absent/non-callable
    monkeypatch.setattr(arena._ml_detector, "predict_http", None)
    res_fb = arena._inspect_in_process_waf(
        family="SQL_INJECTION",
        endpoint_tpl="/api/v1/vulnerable/books/search/",
        resolved_path="/api/v1/vulnerable/books/search/",
        method="GET",
        query_str="q=%27%20OR%201%3D1--",
        body_text=None,
        body_bytes=None,
        tech_name="baseline_probe",
        tier="hybrid_v3",
        client_ip="127.0.0.1",
    )
    assert res_fb["waf_blocked"] is True
    assert len(anomaly_vecs) == 2 and len(anomaly_vecs[1]) == 26




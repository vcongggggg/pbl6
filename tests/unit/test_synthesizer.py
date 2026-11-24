"""Unit tests for OpenAPIPayloadSynthesizer (Sprint 2 / Cyber Range Target-Agnostic)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# Ensure attack-lab and repository root are on sys.path
_REPO_ROOT = Path(__file__).resolve().parents[2]
_ATTACK_LAB_DIR = _REPO_ROOT / "attack-lab"
for p in [str(_REPO_ROOT), str(_ATTACK_LAB_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from agent.synthesizer import (  # noqa: E402
    FALLBACK_TEST_CASES,
    OpenAPIPayloadSynthesizer,
    SynthesizedTestCase,
)
from runner import run_campaign  # noqa: E402


def test_run_campaign_with_dynamic_surface(tmp_path: Path):
    """Verify run_campaign can execute against a dynamic surface specification."""
    surface_file = tmp_path / "custom_surface.json"
    custom_surface: dict[str, Any] = {
        "endpoints": [
            {
                "path": "/api/v2/search",
                "method": "GET",
                "parameters": [{"name": "query", "location": "query", "param_type": "string"}],
                "potential_vulnerabilities": [
                    {
                        "vuln_type": "SQL_INJECTION",
                        "confidence": "HIGH",
                        "reason": "Direct SQL concatenation",
                        "target_params": ["query"],
                    }
                ],
            }
        ]
    }
    surface_file.write_text(json.dumps(custom_surface), encoding="utf-8")

    out_file = tmp_path / "dynamic_campaign_report.json"
    report = run_campaign(
        mode="replay",
        campaign="all",
        dry_run=True,
        surface=surface_file,
        output=out_file,
        quiet=True,
    )
    assert out_file.is_file()
    assert report["dry_run"] is True
    assert report["summary"]["total_endpoints"] == 1
    assert report["results"][0]["endpoint"] == "/api/v2/search"


def test_synthesized_test_case_to_dict():
    """Verify SynthesizedTestCase serializes correctly to dict."""
    tc = SynthesizedTestCase(
        endpoint="/api/v1/vulnerable/test/",
        method="POST",
        family="SQL_INJECTION",
        campaign="sqli",
        param_name="input_val",
        request_type="json",
        baseline_payload="admin' OR '1'='1",
        extra_fields={"key": "val"},
        bypass_keywords=["token", "admin"],
    )
    d = tc.to_dict()
    assert d["endpoint"] == "/api/v1/vulnerable/test/"
    assert d["method"] == "POST"
    assert d["family"] == "SQL_INJECTION"
    assert d["campaign"] == "sqli"
    assert d["param_name"] == "input_val"
    assert d["request_type"] == "json"
    assert d["baseline_payload"] == "admin' OR '1'='1"
    assert d["extra_fields"] == {"key": "val"}
    assert "admin" in d["bypass_keywords"]


def test_synthesizer_default_loading():
    """Verify OpenAPIPayloadSynthesizer loads attack_surface.json by default."""
    synthesizer = OpenAPIPayloadSynthesizer()
    cases = synthesizer.synthesize_test_cases(campaign="all")
    assert len(cases) >= 5

    # Check presence of standard families
    families = {c["family"] for c in cases}
    assert "SQL_INJECTION" in families
    assert "XSS" in families
    assert "PATH_TRAVERSAL" in families
    assert "COMMAND_INJECTION" in families


def test_synthesizer_campaign_filtering():
    """Verify filtering by specific campaign names."""
    synthesizer = OpenAPIPayloadSynthesizer()

    sqli_cases = synthesizer.synthesize_test_cases(campaign="sqli")
    assert len(sqli_cases) >= 1
    for c in sqli_cases:
        assert c["campaign"] == "sqli" or c["family"] in ("SQL_INJECTION", "AUTH_BYPASS")

    xss_cases = synthesizer.synthesize_test_cases(campaign="xss")
    assert len(xss_cases) >= 1
    for c in xss_cases:
        assert c["campaign"] == "xss" or c["family"] == "XSS"

    traversal_cases = synthesizer.synthesize_test_cases(campaign="traversal")
    assert len(traversal_cases) >= 1
    for c in traversal_cases:
        assert c["campaign"] == "traversal" or c["family"] == "PATH_TRAVERSAL"


def test_synthesizer_extended_owasp_api_categories():
    """Verify synthesized cases cover extended OWASP API categories."""
    synthesizer = OpenAPIPayloadSynthesizer()
    all_cases = synthesizer.synthesize_test_cases(campaign="all")
    families = {c["family"] for c in all_cases}

    # If attack_surface.json contains them, verify they are extracted
    if "SSRF" in families:
        ssrf_cases = [c for c in all_cases if c["family"] == "SSRF"]
        assert len(ssrf_cases) >= 1
        assert ssrf_cases[0]["param_name"] == "url"

    if "BOLA_IDOR" in families:
        bola_cases = [c for c in all_cases if c["family"] == "BOLA_IDOR"]
        assert len(bola_cases) >= 1
        assert bola_cases[0]["request_type"] in ("path", "json")


def test_synthesizer_fallback_when_empty():
    """Verify fallback when attack surface is empty or invalid."""
    synthesizer = OpenAPIPayloadSynthesizer(attack_surface_source={})
    fallback_cases = synthesizer.synthesize_test_cases(campaign="all")
    assert len(fallback_cases) == len(FALLBACK_TEST_CASES)


def test_synthesizer_from_custom_dict():
    """Verify synthesizing from a custom minimal OpenAPI attack surface."""
    custom_surface: dict[str, Any] = {
        "endpoints": [
            {
                "path": "/api/v2/search",
                "method": "GET",
                "parameters": [{"name": "query", "location": "query", "param_type": "string"}],
                "potential_vulnerabilities": [
                    {
                        "vuln_type": "SQL_INJECTION",
                        "confidence": "HIGH",
                        "reason": "Direct SQL concatenation",
                        "target_params": ["query"],
                    }
                ],
            },
            {
                "path": "/api/v2/orders/{id}/",
                "method": "GET",
                "parameters": [{"name": "id", "location": "path", "param_type": "integer"}],
                "potential_vulnerabilities": [
                    {
                        "vuln_type": "BOLA_IDOR",
                        "confidence": "HIGH",
                        "reason": "Missing authorization check",
                        "target_params": ["id"],
                    }
                ],
            },
        ]
    }

    synthesizer = OpenAPIPayloadSynthesizer(attack_surface_source=custom_surface)
    cases = synthesizer.synthesize_test_cases(campaign="all")
    assert len(cases) == 2

    # Check search endpoint
    search_case = next(c for c in cases if c["endpoint"] == "/api/v2/search")
    assert search_case["method"] == "GET"
    assert search_case["param_name"] == "query"
    assert search_case["request_type"] == "query"
    assert "UNION" in search_case["baseline_payload"]

    # Check order BOLA endpoint
    order_case = next(c for c in cases if c["endpoint"] == "/api/v2/orders/{id}/")
    assert order_case["method"] == "GET"
    assert order_case["param_name"] == "id"
    assert order_case["request_type"] == "path"


def test_canonical_campaign_report_protected_when_output_omitted():
    """Phase A4.2: Verifies calling run_campaign(dry_run=True) without output never touches campaign_report.json."""
    import hashlib

    live_report = _ATTACK_LAB_DIR / "artifacts" / "campaign_report.json"
    before_hash = hashlib.sha256(live_report.read_bytes()).hexdigest()

    run_campaign(mode="replay", campaign="sqli", dry_run=True, quiet=True)

    after_hash = hashlib.sha256(live_report.read_bytes()).hexdigest()
    assert before_hash == after_hash

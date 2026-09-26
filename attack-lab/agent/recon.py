"""API Reconnaissance Module (Task 10.1).

Automates OpenAPI 3.0 / Swagger specification discovery and attack surface mapping
for vulnerable targets (e.g. Vulnerable API behind WAF Gateway on Machine 1).

Delivers structured endpoint profiles and vulnerability heuristics for downstream
Attack Graph Planning (Task 10.2) and Reinforcement Learning Evasion (Task 10.3).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [ReconAgent] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("ReconAgent")


# Common candidate paths for OpenAPI / Swagger specs
DEFAULT_SPEC_CANDIDATE_PATHS = [
    "/api/proxy/api/v1/vulnerable/openapi.json",
    "/api/proxy/openapi.json",
    "/api/v1/vulnerable/openapi.json",
    "/openapi.json",
    "/api/v1/openapi.json",
    "/swagger.json",
    "/v2/swagger.json",
]


@dataclass
class ParameterSpec:
    """Specification for an endpoint parameter (query, path, header, cookie)."""
    name: str
    location: str  # query, path, header, cookie
    param_type: str = "string"
    required: bool = False
    description: str = ""
    example: Any = None


@dataclass
class RequestBodyField:
    """Field specification inside a request body."""
    name: str
    field_type: str = "string"
    required: bool = False
    example: Any = None
    description: str = ""


@dataclass
class RequestBodySpec:
    """Specification for an HTTP request body."""
    content_type: str = "application/json"
    required: bool = False
    fields: list[RequestBodyField] = field(default_factory=list)
    raw_schema: dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnerabilityIndicator:
    """Heuristic assessment of a potential security weakness surface."""
    vuln_type: str  # SQLI, XSS, PATH_TRAVERSAL, COMMAND_INJECTION, SSRF, BOLA_IDOR, MASS_ASSIGNMENT, AUTH_BYPASS
    confidence: str  # HIGH, MEDIUM, LOW
    reason: str
    target_params: list[str] = field(default_factory=list)


@dataclass
class EndpointProfile:
    """Structured profile of an API endpoint for offensive/defensive modeling."""
    path: str
    method: str  # GET, POST, PUT, PATCH, DELETE, etc.
    summary: str = ""
    description: str = ""
    tags: list[str] = field(default_factory=list)
    requires_auth: bool = False
    parameters: list[ParameterSpec] = field(default_factory=list)
    request_body: RequestBodySpec | None = None
    responses: dict[str, str] = field(default_factory=dict)
    potential_vulnerabilities: list[VulnerabilityIndicator] = field(default_factory=list)
    primary_category: str = "GENERAL"


@dataclass
class ReconReport:
    """Aggregated attack surface reconnaissance report."""
    target_url: str
    spec_source: str
    scanned_at: str
    openapi_version: str
    api_title: str
    api_version: str
    summary: dict[str, Any]
    endpoints: list[EndpointProfile]

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary."""
        return asdict(self)

    def save_json(self, output_path: str) -> None:
        """Save report to a JSON file."""
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
        logger.info("Saved reconnaissance report to: %s", output_path)


class APIReconAgent:
    """Reconnaissance agent that pulls OpenAPI specs and constructs an attack surface profile."""

    def __init__(
        self,
        target_base_url: str = "http://127.0.0.1:8000",
        spec_url_or_path: str | None = None,
        timeout: float = 10.0,
        verify_ssl: bool = False,
    ):
        self.target_base_url = target_base_url.rstrip("/")
        self.spec_url_or_path = spec_url_or_path
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.raw_spec: dict[str, Any] = {}
        self.resolved_components: dict[str, Any] = {}

    def fetch_spec_from_network(self) -> tuple[dict[str, Any], str]:
        """Attempt to fetch OpenAPI spec from target network endpoint."""
        candidates = []
        if self.spec_url_or_path:
            if self.spec_url_or_path.startswith("http://") or self.spec_url_or_path.startswith("https://"):
                candidates.append(self.spec_url_or_path)
            else:
                candidates.append(urljoin(self.target_base_url + "/", self.spec_url_or_path.lstrip("/")))
        else:
            for path in DEFAULT_SPEC_CANDIDATE_PATHS:
                candidates.append(urljoin(self.target_base_url + "/", path.lstrip("/")))

        logger.info("Probing target for OpenAPI specification across %d candidates...", len(candidates))

        last_error = None
        for candidate_url in candidates:
            try:
                logger.debug("Probing spec at: %s", candidate_url)
                data = self._http_get_json(candidate_url)
                if data and ("openapi" in data or "swagger" in data or "paths" in data):
                    logger.info("Successfully discovered OpenAPI spec at: %s", candidate_url)
                    return data, candidate_url
            except Exception as exc:
                last_error = exc
                logger.debug("Candidate %s failed: %s", candidate_url, exc)

        raise ConnectionError(
            f"Failed to retrieve OpenAPI specification from {self.target_base_url}. "
            f"Last error: {last_error}. Candidates probed: {candidates}"
        )

    def load_spec_from_file(self, filepath: str) -> tuple[dict[str, Any], str]:
        """Load OpenAPI spec from a local JSON or YAML file."""
        logger.info("Loading local OpenAPI spec from: %s", filepath)
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data, os.path.abspath(filepath)

    def _http_get_json(self, url: str) -> dict[str, Any]:
        """Perform HTTP GET request and parse JSON response."""
        headers = {
            "User-Agent": "PBL6-ReconAgent/1.0 (Machine2-AttackLab)",
            "Accept": "application/json, text/plain, */*",
        }

        if HTTPX_AVAILABLE:
            with httpx.Client(timeout=self.timeout, verify=self.verify_ssl) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    return resp.json()
                raise ValueError(f"HTTP {resp.status_code}: {resp.text[:200]}")
        elif REQUESTS_AVAILABLE:
            resp = requests.get(url, headers=headers, timeout=self.timeout, verify=self.verify_ssl)
            if resp.status_code == 200:
                return resp.json()
            raise ValueError(f"HTTP {resp.status_code}: {resp.text[:200]}")
        else:
            import urllib.request
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                if response.status == 200:
                    return json.loads(response.read().decode("utf-8"))
                raise ValueError(f"HTTP {response.status}")

    def resolve_ref(self, ref_path: str) -> dict[str, Any]:
        """Resolve an internal JSON reference ($ref) such as '#/components/schemas/User'."""
        if not ref_path or not ref_path.startswith("#/"):
            return {}

        parts = ref_path.lstrip("#/").split("/")
        curr: Any = self.raw_spec
        for part in parts:
            if isinstance(curr, dict) and part in curr:
                curr = curr[part]
            else:
                return {}

        if isinstance(curr, dict) and "$ref" in curr:
            return self.resolve_ref(curr["$ref"])
        return curr if isinstance(curr, dict) else {}

    def _extract_schema_properties(self, schema: dict[str, Any]) -> list[RequestBodyField]:
        """Extract field definitions from an OpenAPI schema object."""
        if "$ref" in schema:
            schema = self.resolve_ref(schema["$ref"])

        fields: list[RequestBodyField] = []
        properties = schema.get("properties", {})
        required_list = schema.get("required", [])

        for prop_name, prop_def in properties.items():
            if "$ref" in prop_def:
                prop_def = self.resolve_ref(prop_def["$ref"])

            prop_type = prop_def.get("type", "string")
            example = prop_def.get("example", prop_def.get("default", None))
            desc = prop_def.get("description", "")
            fields.append(
                RequestBodyField(
                    name=prop_name,
                    field_type=str(prop_type),
                    required=prop_name in required_list,
                    example=example,
                    description=desc,
                )
            )
        return fields

    def parse_endpoint(
        self,
        path: str,
        method: str,
        operation_data: dict[str, Any],
        path_item: dict[str, Any] | None = None,
    ) -> EndpointProfile:
        """Parse an OpenAPI operation into a structured EndpointProfile."""
        summary = operation_data.get("summary", "")
        description = operation_data.get("description", "")
        tags = operation_data.get("tags", [])
        # An operation-level `security` (including an empty list) overrides
        # inherited defaults. Accept path-item security as a defensive extension.
        security = operation_data.get(
            "security",
            (path_item or {}).get("security", self.raw_spec.get("security", [])),
        )
        requires_auth = bool(security)

        # Parse Parameters
        # OpenAPI allows path-item parameters shared by every operation. An
        # operation parameter with the same (name, in) pair overrides it.
        inherited_params = (path_item or {}).get("parameters", [])
        operation_params = operation_data.get("parameters", [])
        params_by_key: dict[tuple[str, str], dict[str, Any]] = {}
        for param in inherited_params:
            if isinstance(param, dict):
                resolved = self.resolve_ref(param["$ref"]) if "$ref" in param else param
                params_by_key[(resolved.get("name", ""), resolved.get("in", "query"))] = param
        for param in operation_params:
            if isinstance(param, dict):
                resolved = self.resolve_ref(param["$ref"]) if "$ref" in param else param
                params_by_key[(resolved.get("name", ""), resolved.get("in", "query"))] = param
        raw_params = list(params_by_key.values())
        parameters: list[ParameterSpec] = []
        for p in raw_params:
            if "$ref" in p:
                p = self.resolve_ref(p["$ref"])

            p_name = p.get("name", "")
            p_in = p.get("in", "query")
            p_req = p.get("required", False)
            p_desc = p.get("description", "")

            # OpenAPI 3.0 schema vs Swagger 2.0 type
            schema = p.get("schema", {})
            if "$ref" in schema:
                schema = self.resolve_ref(schema["$ref"])
            p_type = schema.get("type", p.get("type", "string"))
            p_example = schema.get("example", p.get("example", None))

            parameters.append(
                ParameterSpec(
                    name=p_name,
                    location=p_in,
                    param_type=str(p_type),
                    required=bool(p_req),
                    description=p_desc,
                    example=p_example,
                )
            )

        # Parse Request Body (OpenAPI 3.0)
        request_body_spec: RequestBodySpec | None = None
        raw_body = operation_data.get("requestBody")
        if raw_body:
            if "$ref" in raw_body:
                raw_body = self.resolve_ref(raw_body["$ref"])

            content = raw_body.get("content", {})
            is_req = raw_body.get("required", False)

            # Determine dominant content type (JSON preferred)
            chosen_ct = "application/json"
            if chosen_ct not in content and content:
                chosen_ct = next(iter(content.keys()))

            body_fields: list[RequestBodyField] = []
            raw_schema_dict = {}
            if chosen_ct in content:
                raw_schema_dict = content[chosen_ct].get("schema", {})
                body_fields = self._extract_schema_properties(raw_schema_dict)

            request_body_spec = RequestBodySpec(
                content_type=chosen_ct,
                required=bool(is_req),
                fields=body_fields,
                raw_schema=raw_schema_dict,
            )

        # Parse Swagger 2.0 body parameters if present
        for p in raw_params:
            if p.get("in") == "body":
                b_schema = p.get("schema", {})
                b_fields = self._extract_schema_properties(b_schema)
                request_body_spec = RequestBodySpec(
                    content_type="application/json",
                    required=p.get("required", False),
                    fields=b_fields,
                    raw_schema=b_schema,
                )
                break

        # Responses
        responses = {}
        for code, resp_def in operation_data.get("responses", {}).items():
            if isinstance(resp_def, dict):
                responses[str(code)] = resp_def.get("description", "")

        # Analyze surface heuristics
        indicators = self._evaluate_vulnerability_indicators(
            path=path,
            method=method.upper(),
            summary=summary,
            description=description,
            parameters=parameters,
            request_body=request_body_spec,
        )

        primary_category = self._determine_primary_category(indicators, path, method.upper())

        return EndpointProfile(
            path=path,
            method=method.upper(),
            summary=summary,
            description=description,
            tags=tags,
            requires_auth=requires_auth,
            parameters=parameters,
            request_body=request_body_spec,
            responses=responses,
            potential_vulnerabilities=indicators,
            primary_category=primary_category,
        )

    def _evaluate_vulnerability_indicators(
        self,
        path: str,
        method: str,
        summary: str,
        description: str,
        parameters: list[ParameterSpec],
        request_body: RequestBodySpec | None,
    ) -> list[VulnerabilityIndicator]:
        """Perform heuristic rule-based attack surface weakness mapping."""
        indicators: list[VulnerabilityIndicator] = []
        text_context = f"{path} {summary} {description}".lower()

        param_names = [p.name.lower() for p in parameters]
        body_field_names = [f.name.lower() for f in (request_body.fields if request_body else [])]
        all_inputs = param_names + body_field_names

        # Helper for word-boundary matching in text
        def has_word(pattern: str) -> bool:
            return bool(re.search(rf"\b{pattern}\b", text_context))

        # 1. Broken Object Level Authorization (BOLA / IDOR)
        path_params = [p.name.lower() for p in parameters if p.location == "path"]
        idor_keywords = ["id", "order_id", "user_id", "account_id", "book_id", "item_id"]
        matched_idor = [name for name in path_params if name in idor_keywords or name.endswith("_id")]
        if matched_idor or has_word("idor") or has_word("bola"):
            indicators.append(
                VulnerabilityIndicator(
                    vuln_type="BOLA_IDOR",
                    confidence="HIGH",
                    reason="Direct reference to object/record identifier via URI path parameter without verified ACL.",
                    target_params=matched_idor,
                )
            )

        # 2. Authentication Bypass / Credential Stuffing
        is_auth_route = bool(re.search(r"/(auth|login|signin|session)/", path)) or has_word("login") or has_word("signin") or has_word("authenticate")
        has_cred_inputs = ("username" in all_inputs and "password" in all_inputs) or ("token" in all_inputs and method == "POST")
        if is_auth_route or has_cred_inputs:
            indicators.append(
                VulnerabilityIndicator(
                    vuln_type="AUTH_BYPASS",
                    confidence="HIGH",
                    reason="Authentication gateway processing user credentials; susceptible to auth bypass and brute-force.",
                    target_params=[n for n in all_inputs if n in ["username", "password", "email", "token"]],
                )
            )

        # 3. SQL Injection / Query abuse
        sqli_query_keywords = ["q", "query", "search", "keyword", "filter", "sort", "order", "category"]
        matched_sqli = [name for name in param_names if name in sqli_query_keywords]
        if has_word("sql") or has_word("sqli") or (matched_sqli and method == "GET"):
            conf = "HIGH" if (has_word("sql") or "q" in matched_sqli) else "MEDIUM"
            indicators.append(
                VulnerabilityIndicator(
                    vuln_type="SQL_INJECTION",
                    confidence=conf,
                    reason="Accepts query/filter input parameters commonly susceptible to SQL syntax manipulation.",
                    target_params=matched_sqli,
                )
            )

        # 4. Path Traversal / Local File Inclusion (LFI)
        traversal_params = ["file", "filename", "filepath", "doc", "document", "download"]
        matched_traversal = [name for name in all_inputs if name in traversal_params]
        if has_word("traversal") or has_word("lfi") or matched_traversal:
            indicators.append(
                VulnerabilityIndicator(
                    vuln_type="PATH_TRAVERSAL",
                    confidence="HIGH" if (matched_traversal or has_word("traversal")) else "MEDIUM",
                    reason="File retrieval mechanism accepting path/filename identifiers.",
                    target_params=matched_traversal,
                )
            )

        # 5. Command Injection (RCE)
        rce_keywords = ["ping", "host", "cmd", "command", "exec", "shell"]
        matched_rce = [name for name in all_inputs if name in rce_keywords]
        if has_word("ping") or has_word("rce") or has_word("exec") or matched_rce:
            indicators.append(
                VulnerabilityIndicator(
                    vuln_type="COMMAND_INJECTION",
                    confidence="HIGH" if (has_word("ping") or has_word("rce") or "cmd" in matched_rce) else "MEDIUM",
                    reason="Executes diagnostic or system-level routines utilizing user parameters.",
                    target_params=matched_rce,
                )
            )

        # 6. Stored / Reflected Cross-Site Scripting (XSS)
        xss_fields = ["comment", "review", "feedback", "message", "body", "bio", "title"]
        matched_xss = [name for name in all_inputs if name in xss_fields]
        if method in ["POST", "PUT"] and (matched_xss or has_word("xss")):
            indicators.append(
                VulnerabilityIndicator(
                    vuln_type="XSS",
                    confidence="HIGH" if (has_word("xss") or "comment" in matched_xss) else "MEDIUM",
                    reason="Accepts text input rendered or stored within application views.",
                    target_params=matched_xss,
                )
            )

        # 7. Server-Side Request Forgery (SSRF)
        ssrf_params = ["url", "target", "link", "dest", "destination", "fetch", "webhook", "proxy"]
        matched_ssrf = [name for name in all_inputs if name in ssrf_params]
        if has_word("ssrf") or matched_ssrf:
            indicators.append(
                VulnerabilityIndicator(
                    vuln_type="SSRF",
                    confidence="HIGH" if (matched_ssrf or has_word("ssrf")) else "MEDIUM",
                    reason="Processes remote resource locators (URLs), susceptible to server-side request forgery.",
                    target_params=matched_ssrf,
                )
            )

        # 8. Mass Assignment / Privilege Escalation
        if method in ["POST", "PUT", "PATCH"] and ("profile" in text_context or "user" in text_context):
            indicators.append(
                VulnerabilityIndicator(
                    vuln_type="MASS_ASSIGNMENT",
                    confidence="MEDIUM",
                    reason="Updates entity/profile states via multi-field payload, susceptible to unvalidated attribute binding.",
                    target_params=body_field_names,
                )
            )

        # 9. File Upload
        if request_body and ("multipart/form-data" in request_body.content_type):
            indicators.append(
                VulnerabilityIndicator(
                    vuln_type="FILE_UPLOAD",
                    confidence="HIGH",
                    reason="Multipart file upload interface.",
                    target_params=["multipart/form-data"],
                )
            )

        return indicators

    def _determine_primary_category(
        self, indicators: list[VulnerabilityIndicator], path: str, method: str
    ) -> str:
        """Derive the primary attack classification for state machine navigation."""
        if not indicators:
            return "INFORMATIONAL"

        priority_order = [
            "AUTH_BYPASS",
            "COMMAND_INJECTION",
            "SQL_INJECTION",
            "PATH_TRAVERSAL",
            "SSRF",
            "BOLA_IDOR",
            "XSS",
            "MASS_ASSIGNMENT",
            "FILE_UPLOAD",
        ]

        # Prioritize by confidence tier first (HIGH -> MEDIUM -> LOW)
        for confidence_tier in ["HIGH", "MEDIUM", "LOW"]:
            tier_vulns = {ind.vuln_type for ind in indicators if ind.confidence == confidence_tier}
            for p in priority_order:
                if p in tier_vulns:
                    return p

        return indicators[0].vuln_type

    def run(self, local_file: str | None = None) -> ReconReport:
        """Execute full reconnaissance pipeline: Fetch -> Parse -> Map -> Profile."""
        logger.info("Starting API Reconnaissance Pipeline...")

        if local_file:
            self.raw_spec, spec_source = self.load_spec_from_file(local_file)
        else:
            self.raw_spec, spec_source = self.fetch_spec_from_network()

        # Cache components for ref resolution
        self.resolved_components = self.raw_spec.get("components", {})

        info = self.raw_spec.get("info", {})
        openapi_version = self.raw_spec.get("openapi", self.raw_spec.get("swagger", "3.0.0"))
        paths = self.raw_spec.get("paths", {})

        logger.info("Analyzing %d paths from API '%s' (v%s)...", len(paths), info.get("title", "Unknown"), info.get("version", "1.0"))

        endpoints: list[EndpointProfile] = []
        valid_methods = {"get", "post", "put", "patch", "delete", "options", "head"}

        category_counts: dict[str, int] = {}
        vuln_counts: dict[str, int] = {}

        for path_str, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            for method_str, operation in path_item.items():
                if method_str.lower() not in valid_methods or not isinstance(operation, dict):
                    continue

                profile = self.parse_endpoint(path_str, method_str, operation, path_item)
                endpoints.append(profile)

                # Track metrics
                category_counts[profile.primary_category] = category_counts.get(profile.primary_category, 0) + 1
                for ind in profile.potential_vulnerabilities:
                    vuln_counts[ind.vuln_type] = vuln_counts.get(ind.vuln_type, 0) + 1

        summary = {
            "total_paths": len(paths),
            "total_endpoints": len(endpoints),
            "vulnerability_breakdown": vuln_counts,
            "category_breakdown": category_counts,
            "endpoints_requiring_auth": sum(1 for ep in endpoints if ep.requires_auth),
            "endpoints_with_body": sum(1 for ep in endpoints if ep.request_body is not None),
        }

        report = ReconReport(
            target_url=self.target_base_url,
            spec_source=spec_source,
            scanned_at=datetime.now(timezone.utc).isoformat(),
            openapi_version=openapi_version,
            api_title=info.get("title", "Target API"),
            api_version=info.get("version", "1.0.0"),
            summary=summary,
            endpoints=endpoints,
        )

        logger.info("Reconnaissance complete: %d endpoints profiled across %d categories.", len(endpoints), len(category_counts))
        return report


def print_cli_summary(report: ReconReport) -> None:
    """Format and print an executive CLI summary of the attack surface."""
    term_width = 80
    print("\n" + "=" * term_width)
    print("[+] PBL6 OFFENSIVE AI - API RECONNAISSANCE REPORT (Task 10.1)")
    print(f"Target Base URL: {report.target_url}")
    print(f"Spec Source:     {report.spec_source}")
    print(f"Specification:   OpenAPI {report.openapi_version} | Title: {report.api_title} ({report.api_version})")
    print(f"Timestamp:       {report.scanned_at}")
    print("=" * term_width)

    print("\n[*] ATTACK SURFACE SUMMARY:")
    print(f"  - Total Endpoints Mapped: {report.summary['total_endpoints']}")
    print(f"  - Endpoints with Body:    {report.summary['endpoints_with_body']}")
    print(f"  - Auth-Guarded Routes:    {report.summary['endpoints_requiring_auth']}")

    print("\n[!] POTENTIAL VULNERABILITY WEAKNESS MAPPING:")
    for vuln, count in sorted(report.summary["vulnerability_breakdown"].items(), key=lambda x: x[1], reverse=True):
        print(f"  [{vuln:<20}] : {count} surface(s)")

    print("\n[#] PROFILED ENDPOINTS (ACTION SPACE FOR ATTACK GRAPH):")
    print(f"{'METHOD':<7} | {'CATEGORY':<18} | {'PATH':<35} | {'INPUTS'}")
    print("-" * term_width)

    for ep in report.endpoints:
        inputs = [p.name for p in ep.parameters]
        if ep.request_body:
            inputs.extend([f.name for f in ep.request_body.fields])
        inputs_str = ", ".join(inputs[:4])
        if len(inputs) > 4:
            inputs_str += f" (+{len(inputs) - 4} more)"

        print(f"{ep.method:<7} | {ep.primary_category:<18} | {ep.path:<35} | {inputs_str or '-'}")

    print("=" * term_width + "\n")


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="API Reconnaissance & Attack Surface Profiler (PBL6 Machine 2 Red Team)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--target",
        "-t",
        default="http://127.0.0.1:8000",
        help="Target base URL (e.g. http://192.168.1.15:8000 for Machine 1 over LAN)",
    )
    parser.add_argument(
        "--spec-path",
        "-s",
        default=None,
        help="Direct path or candidate URL to OpenAPI JSON (Gateway: /api/proxy/api/v1/vulnerable/openapi.json)",
    )
    parser.add_argument(
        "--file",
        "-f",
        default=None,
        help="Load OpenAPI spec from a local JSON file instead of network",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="attack-lab/scenarios/attack_surface.json",
        help="Output JSON path for the structured reconnaissance report",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Network connection timeout in seconds",
    )
    return parser.parse_args()


def main() -> int:
    """CLI Entry point."""
    args = parse_arguments()

    agent = APIReconAgent(
        target_base_url=args.target,
        spec_url_or_path=args.spec_path,
        timeout=args.timeout,
    )

    try:
        report = agent.run(local_file=args.file)
        print_cli_summary(report)

        if args.output:
            report.save_json(args.output)

        return 0
    except Exception as exc:
        logger.error("Reconnaissance execution failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())

"""Universal Web API Protocol Sniffer & Protocol-Specific Payload Extractor.

This module elevates the PBL6 WAF Gateway to a true Multi-Protocol Web API Security Platform.
It dynamically classifies incoming HTTP requests into concrete Web API architectures:
  1. RESTful API (JSON, Form-data, URL Query parameters)
  2. GraphQL API (POST /graphql, application/graphql, JSON with query/mutation)
  3. SOAP / XML Web Services (text/xml, application/soap+xml, XML Envelope, WSDL)
  4. JSON-RPC Web Services ({"jsonrpc": "2.0", "method": ..., "params": ...})
  5. Generic Web / Microservice Endpoints

It applies protocol-specific parsing to strip protocol envelopes and extract raw canonical
payloads into the unified 17-dimensional ML feature extraction pipeline.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from app.security.normalizer import InputNormalizer

logger = logging.getLogger("waf.gateway.security.protocol")


class ApiProtocol(str, Enum):
    """Canonical Web API Protocol Taxonomy."""
    REST = "REST"
    GRAPHQL = "GRAPHQL"
    SOAP_XML = "SOAP_XML"
    JSON_RPC = "JSON_RPC"
    GENERIC_WEB = "GENERIC_WEB"


@dataclass(slots=True)
class ExtractedApiPayload:
    """Protocol-specific extraction outcome ready for ML and Rule evaluation."""
    protocol: ApiProtocol
    canonical_payload: str
    raw_payload: str
    metadata: dict[str, Any] = field(default_factory=dict)
    is_protocol_anomaly: bool = False
    protocol_alert: str | None = None


class ApiProtocolDetector:
    """Intelligent Sniffer that automatically classifies incoming HTTP traffic by API Protocol."""

    @staticmethod
    def classify_protocol(
        path: str,
        headers: Mapping[str, str] | None = None,
        body_bytes: bytes | None = None,
        query_params: str | None = None,
    ) -> ApiProtocol:
        """Classifies request into REST, GraphQL, SOAP, JSON-RPC or Generic Web."""
        headers_lower = {k.lower(): v.lower() for k, v in (headers or {}).items()}
        content_type = headers_lower.get("content-type", "")
        clean_path = path.lower().strip()
        body_prefix = body_bytes[:1024].decode("utf-8", errors="replace").strip().lower() if body_bytes else ""

        # 1. Check query string first for protocol-specific embedded queries/envelopes
        if query_params:
            unquoted_query = urllib.parse.unquote(query_params).lower()
            if "<?xml" in unquoted_query or "<soap" in unquoted_query or "xmlns:" in unquoted_query:
                return ApiProtocol.SOAP_XML
            if ("query=" in unquoted_query or "mutation=" in unquoted_query) and ("graphql" in clean_path or "gql" in clean_path):
                return ApiProtocol.GRAPHQL
            if "jsonrpc" in unquoted_query:
                return ApiProtocol.JSON_RPC

        # 2. SOAP / XML Web Services Identification
        if (
            "text/xml" in content_type
            or "application/soap+xml" in content_type
            or "soapaction" in headers_lower
            or body_prefix.startswith("<?xml")
            or "<soap:envelope" in body_prefix
            or "<soapenv:envelope" in body_prefix
            or clean_path.endswith(".wsdl")
            or clean_path.endswith(".asmx")
        ):
            return ApiProtocol.SOAP_XML

        # 2. GraphQL Identification
        if (
            "application/graphql" in content_type
            or clean_path.endswith("/graphql")
            or clean_path.endswith("/gql")
            or clean_path.startswith("/graphql")
        ):
            return ApiProtocol.GRAPHQL

        # Inspect JSON body for GraphQL signatures
        if "application/json" in content_type and body_bytes:
            try:
                raw_json = json.loads(body_bytes.decode("utf-8", errors="replace"))
                if isinstance(raw_json, dict):
                    # GraphQL requests contain 'query' or 'mutation' (as GraphQL string)
                    query_val = raw_json.get("query") or raw_json.get("mutation")
                    if isinstance(query_val, str):
                        is_graphql_syntax = ("{" in query_val and "}" in query_val) or bool(
                            re.search(r"^\s*(?:query|mutation|subscription)\b[^{]*\{", query_val, re.IGNORECASE)
                        )
                        if is_graphql_syntax:
                            return ApiProtocol.GRAPHQL
                    if "graphql" in clean_path or "gql" in clean_path:
                        return ApiProtocol.GRAPHQL
                    # JSON-RPC requests contain 'jsonrpc' or 'method' + 'params'
                    if "jsonrpc" in raw_json or ("method" in raw_json and "params" in raw_json):
                        return ApiProtocol.JSON_RPC
            except Exception:
                pass

        # 3. JSON-RPC by header or path
        if "application/json-rpc" in content_type or clean_path.endswith("/jsonrpc") or clean_path.endswith("/rpc"):
            return ApiProtocol.JSON_RPC

        # 4. RESTful API (Default for modern HTTP APIs with JSON/Form/Path resources)
        if (
            "application/json" in content_type
            or "application/x-www-form-urlencoded" in content_type
            or "multipart/form-data" in content_type
            or clean_path.startswith("/api/")
            or clean_path.startswith("/v1/")
            or clean_path.startswith("/v2/")
        ):
            return ApiProtocol.REST

        return ApiProtocol.GENERIC_WEB


class UniversalPayloadExtractor:
    """Extracts, decapsulates, and normalizes payloads according to the detected API Protocol."""

    @classmethod
    def extract(
        cls,
        protocol: ApiProtocol,
        path: str,
        query_params: str | None = None,
        headers: Mapping[str, str] | None = None,
        body_bytes: bytes | None = None,
    ) -> ExtractedApiPayload:
        """Dispatches extraction to protocol-specific decapsulator."""
        if protocol == ApiProtocol.GRAPHQL:
            return cls._extract_graphql(path, query_params, body_bytes)
        elif protocol == ApiProtocol.SOAP_XML:
            return cls._extract_soap_xml(path, query_params, headers, body_bytes)
        elif protocol == ApiProtocol.JSON_RPC:
            return cls._extract_json_rpc(path, query_params, body_bytes)
        else:
            return cls._extract_rest(path, query_params, body_bytes)

    @classmethod
    def _extract_rest(
        cls,
        path: str,
        query_params: str | None,
        body_bytes: bytes | None,
    ) -> ExtractedApiPayload:
        """Extracts RESTful components: path tokens, query params, recursive JSON keys/values."""
        tokens = [path]
        if query_params:
            tokens.append(urllib.parse.unquote(query_params))

        body_text = ""
        if body_bytes:
            try:
                body_str = body_bytes.decode("utf-8", errors="replace")
                # Attempt to extract recursive JSON text leaves
                try:
                    parsed = json.loads(body_str)
                    leaves = cls._flatten_json_leaves(parsed)
                    body_text = " ".join(leaves)
                except Exception:
                    body_text = body_str
            except Exception:
                pass

        if body_text:
            tokens.append(body_text)

        raw_joined = " ".join(tokens)
        canonical = InputNormalizer.normalize(raw_joined)
        return ExtractedApiPayload(
            protocol=ApiProtocol.REST,
            canonical_payload=canonical,
            raw_payload=raw_joined,
            metadata={"endpoint_path": path, "has_body": bool(body_bytes)},
        )

    @classmethod
    def _extract_graphql(
        cls,
        path: str,
        query_params: str | None,
        body_bytes: bytes | None,
    ) -> ExtractedApiPayload:
        """Extracts GraphQL operations, arguments, variable values and evaluates query depth."""
        tokens = [path]
        query_str = ""
        variables_str = ""
        query_depth = 0
        is_anomaly = False
        alert = None

        if body_bytes:
            try:
                body_decoded = body_bytes.decode("utf-8", errors="replace").strip()
                if body_decoded.startswith("{") and body_decoded.endswith("}"):
                    data = json.loads(body_decoded)
                    query_str = data.get("query", "") or data.get("mutation", "")
                    variables = data.get("variables")
                    if variables and isinstance(variables, (dict, list)):
                        variables_str = " ".join(cls._flatten_json_leaves(variables))
                else:
                    # Raw GraphQL query string (Content-Type: application/graphql)
                    query_str = body_decoded
            except Exception:
                query_str = body_bytes.decode("utf-8", errors="replace")

        # Fallback to GET query params for GraphQL (e.g. /graphql?query=...)
        if not query_str and query_params:
            parsed_qs = urllib.parse.parse_qs(query_params)
            query_str = parsed_qs.get("query", [""])[0]

        if query_str:
            # Measure query nesting depth to detect Recursive DoS
            query_depth = cls._calculate_graphql_depth(query_str)
            if query_depth > 7:
                is_anomaly = True
                alert = f"GraphQL Deep Nesting Denial-of-Service Risk (Depth: {query_depth} > 7)"

            # Extract literal argument values inside quotes or brackets: field(id: "PAYLOAD")
            literals = re.findall(r'[:=]\s*(?:"([^"]+)"|\'([^\']+)\'|(\w+))', query_str)
            flattened_literals = " ".join(
                item for sublist in literals for item in sublist if item
            )
            tokens.append(query_str)
            if flattened_literals:
                tokens.append(flattened_literals)

        if variables_str:
            tokens.append(variables_str)

        raw_joined = " ".join(tokens)
        canonical = InputNormalizer.normalize(raw_joined)
        return ExtractedApiPayload(
            protocol=ApiProtocol.GRAPHQL,
            canonical_payload=canonical,
            raw_payload=raw_joined,
            metadata={
                "graphql_depth": query_depth,
                "has_variables": bool(variables_str),
                "operation_type": "MUTATION" if "mutation" in query_str.lower() else "QUERY",
            },
            is_protocol_anomaly=is_anomaly,
            protocol_alert=alert,
        )

    @classmethod
    def _extract_soap_xml(
        cls,
        path: str,
        query_params: str | None,
        headers: Mapping[str, str] | None,
        body_bytes: bytes | None,
    ) -> ExtractedApiPayload:
        """Decapsulates SOAP Envelopes, extracts element text and detects XXE risks."""
        tokens = [path]
        if query_params:
            tokens.append(urllib.parse.unquote(query_params))

        headers_lower = {k.lower(): v for k, v in (headers or {}).items()}
        soap_action = headers_lower.get("soapaction", "").strip('"\'')
        if soap_action:
            tokens.append(f"SOAPAction:{soap_action}")

        is_xxe = False
        alert = None
        extracted_text_nodes = []

        xxe_pattern = re.compile(r"(?i)<!(?:DOCTYPE|ENTITY)\b[^>]*\b(?:SYSTEM|PUBLIC)\b|<!ENTITY\b")
        if query_params:
            unquoted_qp = urllib.parse.unquote(query_params)
            if xxe_pattern.search(unquoted_qp):
                is_xxe = True
                alert = "XML External Entity (XXE) Injection Attempt Detected"

        if body_bytes:
            raw_xml = body_bytes.decode("utf-8", errors="replace")
            # XXE Check before XML parsing to avoid local entity expansion (LOGIC-PBL6-002)
            if xxe_pattern.search(raw_xml):
                is_xxe = True
                alert = "XML External Entity (XXE) Injection Attempt Detected"

            try:
                # Strip XML tags, namespaces, and extract text leaves and CDATA contents
                # Using regex-based text extraction to be fully secure against XML entity bombs
                text_matches = re.findall(r">([^<>]+)<", raw_xml)
                for tm in text_matches:
                    clean_tm = tm.strip()
                    if clean_tm:
                        extracted_text_nodes.append(clean_tm)

                # Extract CDATA
                cdata_matches = re.findall(r"<!\[CDATA\[(.*?)\]\]>", raw_xml, re.DOTALL)
                for cd in cdata_matches:
                    clean_cd = cd.strip()
                    if clean_cd:
                        extracted_text_nodes.append(clean_cd)
            except Exception:
                extracted_text_nodes.append(raw_xml)

            if extracted_text_nodes:
                tokens.append(" ".join(extracted_text_nodes))
            else:
                tokens.append(raw_xml)

        raw_joined = " ".join(tokens)
        canonical = InputNormalizer.normalize(raw_joined)
        return ExtractedApiPayload(
            protocol=ApiProtocol.SOAP_XML,
            canonical_payload=canonical,
            raw_payload=raw_joined,
            metadata={
                "soap_action": soap_action,
                "is_xxe_detected": is_xxe,
                "xml_text_nodes_count": len(extracted_text_nodes),
                "extracted_text": " ".join(extracted_text_nodes),
            },
            is_protocol_anomaly=is_xxe,
            protocol_alert=alert,
        )

    @classmethod
    def _extract_json_rpc(
        cls,
        path: str,
        query_params: str | None,
        body_bytes: bytes | None,
    ) -> ExtractedApiPayload:
        """Extracts JSON-RPC RPC methods and nested parameters."""
        tokens = [path]
        method_name = ""
        params_str = ""

        if body_bytes:
            try:
                data = json.loads(body_bytes.decode("utf-8", errors="replace"))
                if isinstance(data, dict):
                    method_name = str(data.get("method", ""))
                    params = data.get("params")
                    if params is not None:
                        params_str = " ".join(cls._flatten_json_leaves(params))
                elif isinstance(data, list):
                    # Batch JSON-RPC
                    for item in data:
                        if isinstance(item, dict):
                            tokens.append(str(item.get("method", "")))
                            if "params" in item:
                                tokens.append(" ".join(cls._flatten_json_leaves(item["params"])))
            except Exception:
                tokens.append(body_bytes.decode("utf-8", errors="replace"))

        if method_name:
            tokens.append(f"rpc_method:{method_name}")
        if params_str:
            tokens.append(params_str)

        raw_joined = " ".join(tokens)
        canonical = InputNormalizer.normalize(raw_joined)
        return ExtractedApiPayload(
            protocol=ApiProtocol.JSON_RPC,
            canonical_payload=canonical,
            raw_payload=raw_joined,
            metadata={"rpc_method": method_name},
        )

    @staticmethod
    def _flatten_json_leaves(obj: Any) -> list[str]:
        """Recursively traverses JSON dictionaries and lists to extract all string/number leaf values."""
        results = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                results.append(str(k))
                results.extend(UniversalPayloadExtractor._flatten_json_leaves(v))
        elif isinstance(obj, list):
            for elem in obj:
                results.extend(UniversalPayloadExtractor._flatten_json_leaves(elem))
        elif obj is not None:
            results.append(str(obj))
        return results

    @staticmethod
    def _calculate_graphql_depth(query: str) -> int:
        """Calculates nesting depth of a GraphQL query using curly braces tracking."""
        max_depth = 0
        current_depth = 0
        for char in query:
            if char == "{":
                current_depth += 1
                if current_depth > max_depth:
                    max_depth = current_depth
            elif char == "}":
                if current_depth > 0:
                    current_depth -= 1
        return max_depth


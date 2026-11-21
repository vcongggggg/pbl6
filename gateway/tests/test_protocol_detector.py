"""Comprehensive Unit & Integration Tests for Multi-Protocol Web API Sniffer & Extractor.

Tests verification of:
1. Dynamic API Protocol Classification (REST, GraphQL, SOAP/XML, JSON-RPC)
2. Decapsulation of protocol envelopes and extraction of canonical payload tokens
3. Cross-protocol attack detection using PBL6 Machine Learning and Rule Engines
4. Protocol-specific anomaly flagging (GraphQL Recursive DoS & XML XXE injections)
"""

import respx
from fastapi.testclient import TestClient
from httpx import Response

from app.db.models import WafConfigModel
from app.db.session import SessionLocal
from app.security.ml_detector import MLDetector, extract_26_from_http
from app.security.protocol_detector import (
    ApiProtocol,
    ApiProtocolDetector,
    UniversalPayloadExtractor,
)


def test_protocol_classification_rest():
    # Standard RESTful API
    p1 = ApiProtocolDetector.classify_protocol(
        path="/api/v1/books/search/",
        headers={"Content-Type": "application/json"},
        body_bytes=b'{"q": "python"}',
    )
    assert p1 == ApiProtocol.REST

    p2 = ApiProtocolDetector.classify_protocol(
        path="/api/v1/auth/login/",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body_bytes=b"username=admin&password=123",
    )
    assert p2 == ApiProtocol.REST


def test_protocol_classification_graphql():
    # 1. By path
    p1 = ApiProtocolDetector.classify_protocol(
        path="/api/proxy/graphql",
        headers={"Content-Type": "application/json"},
        body_bytes=b'{"query": "{ books { id title } }"}',
    )
    assert p1 == ApiProtocol.GRAPHQL

    # 2. By Content-Type
    p2 = ApiProtocolDetector.classify_protocol(
        path="/api/v1/query",
        headers={"Content-Type": "application/graphql"},
        body_bytes=b"{ users { id } }",
    )
    assert p2 == ApiProtocol.GRAPHQL

    # 3. By JSON body mutation
    p3 = ApiProtocolDetector.classify_protocol(
        path="/api/endpoint",
        headers={"Content-Type": "application/json"},
        body_bytes=b'{"mutation": "mutation { addReview(id: 1) }"}',
    )
    assert p3 == ApiProtocol.GRAPHQL


def test_protocol_classification_soap():
    # 1. By Content-Type text/xml and SOAP envelope
    soap_body = b"""<?xml version="1.0"?>
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
       <soapenv:Body>
          <GetBookDetails><BookID>123</BookID></GetBookDetails>
       </soapenv:Body>
    </soapenv:Envelope>"""

    p1 = ApiProtocolDetector.classify_protocol(
        path="/ws/BookService",
        headers={"Content-Type": "text/xml; charset=utf-8", "SOAPAction": '"GetBookDetails"'},
        body_bytes=soap_body,
    )
    assert p1 == ApiProtocol.SOAP_XML

    # 2. By WSDL path
    p2 = ApiProtocolDetector.classify_protocol(
        path="/services/OrderService.wsdl",
        headers={},
    )
    assert p2 == ApiProtocol.SOAP_XML


def test_protocol_classification_json_rpc():
    rpc_body = b'{"jsonrpc": "2.0", "method": "subtract", "params": [42, 23], "id": 1}'
    p1 = ApiProtocolDetector.classify_protocol(
        path="/api/rpc",
        headers={"Content-Type": "application/json"},
        body_bytes=rpc_body,
    )
    assert p1 == ApiProtocol.JSON_RPC


@respx.mock
def test_graphql_sqli_payload_decapsulation_and_ml_detection(client: TestClient):
    # Attacker injects SQLi into GraphQL argument inside full HTTP POST request context
    graphql_sqli = b'{"query": "query { book(id: \\"1\' UNION SELECT username, password FROM users--\\") { title } }"}'
    headers = {
        "Content-Type": "application/json",
        "Host": "api.bookie.store",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PBL6-Attacker/1.0",
    }
    extracted = UniversalPayloadExtractor.extract(
        protocol=ApiProtocol.GRAPHQL,
        path="/api/v1/graphql",
        headers=headers,
        body_bytes=graphql_sqli,
    )
    assert extracted.protocol == ApiProtocol.GRAPHQL
    assert "UNION SELECT" in extracted.canonical_payload
    assert "users" in extracted.canonical_payload

    # Feed into ML Detector with full HTTP context
    detector = MLDetector()
    if detector.is_loaded:
        res = detector.predict(extracted.canonical_payload)
        assert res.is_attack is True
        assert res.attack_type in ("SQLI", "SQL_INJECTION")
        assert res.confidence > 0.80

        # Also verify with end-to-end 26-D HTTP feature extraction
        fv = extract_26_from_http(path="/api/v1/graphql", query_params=None, body=graphql_sqli)
        res_http = detector.predict(extracted.canonical_payload, feature_vector=fv.tolist())
        assert res_http.is_attack is True
        assert res_http.attack_type in ("SQLI", "SQL_INJECTION")
        assert res_http.confidence > 0.80

    # Verify end-to-end WAF Gateway HTTP pipeline blocks this GraphQL SQLi attack
    with SessionLocal() as db:
        cfg = db.query(WafConfigModel).filter(WafConfigModel.key == "waf_mode").first()
        if not cfg:
            db.add(WafConfigModel(key="waf_mode", value="ACTIVE_BLOCKING"))
        else:
            cfg.value = "ACTIVE_BLOCKING"
        db.commit()

    respx.post("http://vulnerable-api:5000/api/v1/graphql").mock(
        return_value=Response(200, json={"data": {"book": None}})
    )
    response = client.post(
        "/api/proxy/api/v1/graphql",
        headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0 PBL6-Attacker/1.0"},
        content=graphql_sqli,
    )
    assert response.status_code == 403
    assert response.headers.get("X-WAF-Action") in ("BLOCK", "BLOCKED")
    assert response.headers.get("X-WAF-Decision") == "BLOCK"


@respx.mock
def test_soap_xss_payload_decapsulation_and_ml_detection(client: TestClient):
    # Attacker injects XSS into SOAP body element inside full HTTP POST request context
    soap_xss = b"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
       <soapenv:Body>
          <AddComment>
             <Content><![CDATA[<script>alert(document.cookie)</script>]]></Content>
          </AddComment>
       </soapenv:Body>
    </soapenv:Envelope>"""
    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": '"http://api.bookie.store/ws/AddComment"',
        "Host": "api.bookie.store",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PBL6-Attacker/1.0",
    }
    extracted = UniversalPayloadExtractor.extract(
        protocol=ApiProtocol.SOAP_XML,
        path="/ws/CommentService",
        headers=headers,
        body_bytes=soap_xss,
    )
    assert extracted.protocol == ApiProtocol.SOAP_XML
    assert "<script>alert(document.cookie)</script>" in extracted.canonical_payload

    # Feed into ML Detector with full HTTP context
    detector = MLDetector()
    if detector.is_loaded:
        res = detector.predict(extracted.canonical_payload)
        assert res.is_attack is True
        assert res.attack_type in ("XSS", "XSS_ATTACK")
        assert res.confidence > 0.80

        # Also verify with end-to-end 26-D HTTP feature extraction
        fv_soap = extract_26_from_http(path="/ws/CommentService", query_params=None, body=soap_xss)
        res_http = detector.predict(extracted.canonical_payload, feature_vector=fv_soap.tolist())
        assert res_http.is_attack is True
        assert res_http.attack_type in ("XSS", "XSS_ATTACK")
        assert res_http.confidence > 0.80

    # Verify end-to-end WAF Gateway HTTP pipeline blocks this SOAP XSS attack
    with SessionLocal() as db:
        cfg = db.query(WafConfigModel).filter(WafConfigModel.key == "waf_mode").first()
        if not cfg:
            db.add(WafConfigModel(key="waf_mode", value="ACTIVE_BLOCKING"))
        else:
            cfg.value = "ACTIVE_BLOCKING"
        db.commit()

    respx.post("http://vulnerable-api:5000/ws/CommentService").mock(
        return_value=Response(200, text="<ok/>")
    )
    response = client.post(
        "/api/proxy/ws/CommentService",
        headers={
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": '"http://api.bookie.store/ws/AddComment"',
            "User-Agent": "Mozilla/5.0 PBL6-Attacker/1.0",
        },
        content=soap_xss,
    )
    assert response.status_code == 403
    assert response.headers.get("X-WAF-Action") in ("BLOCK", "BLOCKED")
    assert response.headers.get("X-WAF-Decision") == "BLOCK"


def test_graphql_deep_recursion_dos_anomaly():
    # Excessive nesting query designed to crash backend engine (Depth: 9 > 7)
    deep_query = b'{"query": "{ a { b { c { d { e { f { g { h { i { target } } } } } } } } } }"}'
    extracted = UniversalPayloadExtractor.extract(
        protocol=ApiProtocol.GRAPHQL,
        path="/graphql",
        body_bytes=deep_query,
    )
    assert extracted.is_protocol_anomaly is True
    assert "Deep Nesting" in (extracted.protocol_alert or "")
    assert extracted.metadata.get("graphql_depth") >= 8


def test_soap_xxe_injection_anomaly():
    # XXE injection vector attempting to read /etc/passwd via XML DTD
    xxe_body = b"""<?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
      <!ELEMENT foo ANY >
      <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>"""

    extracted = UniversalPayloadExtractor.extract(
        protocol=ApiProtocol.SOAP_XML,
        path="/ws/UploadXml",
        body_bytes=xxe_body,
    )
    assert extracted.is_protocol_anomaly is True
    assert "XXE" in (extracted.protocol_alert or "")


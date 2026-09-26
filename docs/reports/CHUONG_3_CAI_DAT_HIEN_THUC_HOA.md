# CHƯƠNG 3: CÀI ĐẶT VÀ HIỆN THỰC HÓA HỆ THỐNG

---

## 3.1. Môi Trường Phát Triển và Công Nghệ Sử Dụng

Nhằm hiện thực hóa các phân hệ đã thiết kế trong Chương 2, hệ thống được xây dựng dựa trên ngăn xếp công nghệ hiện đại, tối ưu hóa cho bài toán an ninh mạng, xử lý đồng thời bất đồng bộ và suy luận học máy thời gian thực (Bảng 3.1):

*Bảng 3.1: Ngăn xếp công nghệ và môi trường phát triển của hệ thống*

| Thành Phần Hệ Thống | Công Nghệ / Thư Viện Cốt Lõi | Phiên Bản | Vai Trò & Chức Năng Kỹ Thuật |
| :--- | :--- | :---: | :--- |
| **Ngôn ngữ Lập trình** | Python | 3.11.x | Ngôn ngữ trung tâm xây dựng WAF Gateway, Target API, ML Engine và Red Team Agent. |
| | TypeScript / JavaScript | ES2022 | Xây dựng giao diện điều hành an ninh SOC Dashboard. |
| **Khung WAF & Web API** | FastAPI / Starlette | 0.110.x | Xây dựng Cổng WAF Reverse Proxy và ứng dụng Bookie Bookstore bất đồng bộ (Asynchronous ASGI). |
| | Uvicorn | 0.28.x | Máy chủ HTTP ASGI hiệu năng cao chạy đa luồng sự kiện (Event Loop). |
| | HTTPX | 0.27.x | Thư viện HTTP Client bất đồng bộ chuyển tiếp request giữa WAF Gateway và Upstream API. |
| **Trí Tuệ Nhân Tạo & ML** | Scikit-learn | 1.4.x | Huấn luyện và suy luận mô hình Random Forest Classifier và Isolation Forest Anomaly. |
| | NumPy / Pandas | 1.26.x | Xử lý mảng ma trận, vector hóa tính toán 17 đặc trưng hình thái. |
| | Joblib | 1.3.x | Tuần tự hóa, nén và nạp nhanh mô hình học máy vào bộ nhớ RAM. |
| **Học Tăng Cường Red Team** | PyTorch | 2.2.x | Xây dựng và huấn luyện mạng nơ-ron sâu Deep Q-Network (DQN) né tránh WAF nội bộ (`evasion_agent.pt`). |
| **Giao Diện SOC Dashboard** | Next.js 14 | 14.2.x | Khung ứng dụng React với App Router kết xuất giao diện giám sát hiệu năng cao. |
| | Tailwind CSS | 3.4.x | Hệ thống thiết kế giao diện Dark Mode phong cách SOC chuyên nghiệp. |
| | Recharts & Lucide Icons | Mới nhất | Trực quan hóa dữ liệu biểu đồ sóng Area Chart, Donut Chart và hệ thống biểu tượng an ninh. |
| **Cơ Sở Dữ Liệu & Lưu Trữ** | SQLite3 / aiosqlite | 3.45.x | CSDL quan hệ lưu vết telemetry lưu lượng `requests` và sự kiện `security_events`. |
| **Đóng Gói & Triển Khai** | Docker & Docker Compose | 25.x | Đóng gói cô lập các dịch vụ, bảo đảm tính nhất quán trên 2 máy vật lý độc lập. |

---

## 3.2. Cài Đặt Phân Hệ Cổng WAF Gateway (Phòng Thủ Chủ Động)

### 3.2.1. Cài đặt Module Chuẩn hóa Dữ liệu Đầu vào (`InputNormalizer`)
Để triệt tiêu các kỹ thuật làm rối mã hóa (Obfuscation Evasion) [Ref 12], module `InputNormalizer` được cài đặt tại `gateway/app/core/normalizer.py` tích hợp giải thuật 3 lớp:

1. **Giải mã URL Đệ quy (Recursive URL Decoding):**
```python
def recursive_url_decode(text: str, max_depth: int = 5) -> str:
    # Giai ma long nhau de quy cho den khi chuoi dat trang thai dung
    current = text
    for _ in range(max_depth):
        decoded = urllib.parse.unquote(current)
        if decoded == current:
            break
        current = decoded
    return current
```

2. **Khử Thực thể HTML (HTML Entity Unescaping):**
```python
def unescape_html(text: str) -> str:
    # Chuyen doi toan bo thuc the HTML so hoac ten ve ky tu nguyen ban
    return html.unescape(text)
```

3. **Chuẩn hóa Unicode NFC:**
```python
def canonicalize_unicode(text: str) -> str:
    # Khu cac ky tu fullwidth hoac visual spoofing ve dang chuan NFC
    return unicodedata.normalize('NFC', text)
```

Toàn bộ chuỗi bề mặt request $S = 	ext{Path} + 	ext{"?"} + 	ext{Query} + 	ext{" "} + 	ext{Headers} + 	ext{" "} + 	ext{Body}$ được đưa qua hàm chuẩn hóa tổng hợp:
$$S_{norm} = 	ext{Normalize}(S) = 	ext{Canonicalize}(	ext{Unescape}(	ext{RecursiveDecode}(S)))$$

---

### 3.2.2. Cài đặt Động cơ Luật Chữ ký Tất định (`RuleEngine`)
Động cơ luật được cài đặt tại `gateway/app/core/rule_engine.py`. Nhằm đảm bảo độ trễ xử lý ở mức micro-giây ($< 0.05	ext{ ms}$), toàn bộ 16 mẫu biểu thức chính quy (Regex) được biên dịch sẵn (Pre-compiled) ngay khi khởi động ứng dụng:

```python
RULES_CONFIG = [
    {"id": "SQLI_AUTH_BYPASS", "family": "SQLI", "score": 95, "pattern": re.compile(r"('|")\s*(or|and)\s*('|")?(\d+)\s*=\s*('|")?", re.I)},
    {"id": "SQLI_UNION_SELECT", "family": "SQLI", "score": 95, "pattern": re.compile(r"union\s+(all\s+)?select\s+", re.I)},
    {"id": "XSS_SCRIPT_TAG", "family": "XSS", "score": 95, "pattern": re.compile(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", re.I | re.S)},
    {"id": "PATH_DOT_DOT_SLASH", "family": "PATH", "score": 90, "pattern": re.compile(r"(\.\.[/\])+", re.I)},
    {"id": "CMD_CHAINING_SEMI", "family": "CMD", "score": 95, "pattern": re.compile(r";\s*(ls|dir|cat|whoami|id|uname|sh|bash|cmd|powershell)", re.I)},
    # ... va 11 quy tac chuan hoa khac
]
```

Khi một request đến, `RuleEngine.evaluate(text)` duyệt qua danh sách các luật đã biên dịch:
$$S_{rule} = \max_{\{r \in 	ext{Rules} \mid 	ext{Match}(r, S_{norm})\}} 	ext{Score}(r)$$
Nếu không có luật nào khớp, $S_{rule} = 0.0$.

---

### 3.2.3. Cài đặt Bộ Trích xuất Vector 17 Đặc trưng Hình thái (`FeatureExtractor`)
Module `FeatureExtractor` được cài đặt tại `gateway/app/ml/features.py`. Thuật toán biến đổi chuỗi chuẩn hóa thành vector số học 17 chiều dựa trên công thức Shannon Entropy và thống kê ký tự [Ref 08]:

```python
def extract_17_features(raw_text: str, path: str, body: str, params: dict) -> np.ndarray:
    norm_text = normalize_text(raw_text)
    length = max(len(norm_text), 1)
    
    # 1. Tinh toan Shannon Entropy H(S)
    counts = collections.Counter(norm_text)
    entropy = -sum((cnt / length) * math.log2(cnt / length) for cnt in counts.values())
    
    # 2. Mat do va tan suat hinh thai
    digits = sum(c.isdigit() for c in norm_text) / length
    specials = sum(not c.isalnum() and not c.isspace() for c in norm_text) / length
    uppers = sum(c.isupper() for c in norm_text) / length
    whitespaces = sum(c.isspace() for c in norm_text) / length
    non_asciis = sum(ord(c) > 127 for c in norm_text) / length
    
    # 3. Dem tu khoa an ninh
    sql_kws = len(re.findall(r"(select|union|insert|update|delete|drop|where|or|and)", norm_text, re.I))
    xss_tags = len(re.findall(r"<\s*(script|iframe|img|svg|body|input)", norm_text, re.I))
    path_dots = norm_text.count("..") + norm_text.count("/")
    cmd_ops = sum(norm_text.count(op) for op in [";", "|", "&", "`", "$("])
    quotes = norm_text.count("'") + norm_text.count('"')
    angle_brackets = norm_text.count("<") + norm_text.count(">")
    
    # 4. Chieu dai chuoi ky tu dac biet lien tiep cuc dai
    max_consec = max((len(match.group()) for match in re.finditer(r"[^\w\s]+", norm_text)), default=0)
    
    return np.array([
        length, len(path), len(body), len(params),
        entropy, digits, specials, uppers,
        sql_kws, xss_tags, path_dots, cmd_ops,
        quotes, angle_brackets, whitespaces, non_asciis, max_consec
    ], dtype=np.float32)
```

---

### 3.2.4. Cài đặt và Đóng gói Mô hình Học máy (`MLClassifier`)
Hai mô hình học máy được đóng gói bằng thư viện `joblib` và nạp vào bộ nhớ RAM tại thời điểm khởi động máy chủ WAF Gateway:
1. `champion_rf.joblib`: Mô hình Random Forest 100 cây quyết định được huấn luyện trên 20.000 mẫu [Ref 13].
2. `iso_forest.joblib`: Mô hình Isolation Forest phát hiện dị biệt huấn luyện trên tập mẫu chuẩn hợp lệ Benign [Ref 14].

Hàm suy luận song song trong `MLClassifier`:
```python
def predict_threat(self, feature_vector: np.ndarray) -> tuple[str, float, float]:
    X = feature_vector.reshape(1, -1)
    
    # Du doan Random Forest
    rf_probs = self.rf_model.predict_proba(X)[0]
    pred_idx = np.argmax(rf_probs)
    pred_class = self.classes_[pred_idx]
    
    # Tinh diem rui ro RF (loai tru nhan BENIGN)
    benign_idx = self.class_to_idx_.get("BENIGN", 0)
    rf_risk_score = (1.0 - rf_probs[benign_idx]) * 100.0
    
    # Du doan Isolation Forest (Anomaly Score)
    raw_if_score = self.if_model.score_samples(X)[0] # Cang am cang di biet
    if_risk_score = max(0.0, min(100.0, (-raw_if_score - 0.45) * 200.0))
    
    return pred_class, rf_risk_score, if_risk_score
```

---

### 3.2.5. Cài đặt Động cơ Ra Quyết định Đa tầng (`HybridDecisionEngine`)
Module `HybridDecisionEngine` tổng hợp toàn bộ tri thức từ Rule, Random Forest và Isolation Forest thành quyết định bảo vệ theo thuật toán Bảng 3.2:

```python
def make_decision(self, s_rule: float, s_rf: float, s_if: float) -> tuple[str, float]:
    # Trong so hoc may: 70% Supervised RF + 30% Unsupervised IF
    ml_combined = 0.70 * s_rf + 0.30 * s_if
    
    # Diem so rui ro tong hop (Fast-path rule override)
    s_hybrid = max(s_rule, ml_combined)
    
    if s_hybrid >= 70.0:
        action = "BLOCK"
    elif s_hybrid >= 40.0:
        action = "MONITOR"
    else:
        action = "ALLOW"
        
    return action, s_hybrid
```

Khi quyết định là `BLOCK`, Gateway chặn đứng kết nối và trả về phản hồi chuẩn RFC 7807 [Ref 19]:
```json
{
  "type": "https://api.pbl6.dut.udn.vn/errors/security-violation",
  "title": "Forbidden Request - Blocked by WAF Security Gateway",
  "status": 403,
  "detail": "Request has been identified as malicious and terminated.",
  "instance": "/api/proxy/vulnerable/books/search/",
  "request_id": "c1f7b9e2-3490-41fa-8a71-f9589d98a001",
  "threat_score": 95.0,
  "action": "BLOCK"
}
```

---

### 3.2.6. Cài đặt Bộ Điều tiết Tần suất Token Bucket (`TokenBucketRateLimiter`)
Được cài đặt trong `gateway/app/core/rate_limiter.py` sử dụng cấu trúc dữ liệu trong bộ nhớ (In-memory Thread-Safe Store):

```python
class TokenBucketRateLimiter:
    def __init__(self, capacity: int = 60, refill_rate: float = 1.0):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.buckets = {}
        self.lock = threading.Lock()

    def is_allowed(self, client_ip: str) -> bool:
        now = time.time()
        with self.lock:
            if client_ip not in self.buckets:
                self.buckets[client_ip] = {"tokens": self.capacity, "last_updated": now}
                return True
            
            b = self.buckets[client_ip]
            elapsed = now - b["last_updated"]
            b["tokens"] = min(self.capacity, b["tokens"] + elapsed * self.refill_rate)
            b["last_updated"] = now
            
            if b["tokens"] >= 1.0:
                b["tokens"] -= 1.0
                return True
            return False
```

---

## 3.3. Cài Đặt Phân Hệ Ứng Dụng Mục Tiêu (`vulnerable-api` - Bookie Bookstore)

Ứng dụng `vulnerable-api` được xây dựng bằng Python FastAPI tại thư mục `vulnerable-api/app/`. Hệ thống triển khai đầy đủ các endpoint mô phỏng lỗ hổng nghiệp vụ thực tế:

### 3.3.1. Cài đặt Lỗ hổng SQL Injection Authentication Bypass
```python
@router.post("/auth/login/")
async def vulnerable_login(payload: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    # Lo hong: Ghep chuoi SQL truc tiep ma khong dung Parameterized Query
    query = f"SELECT id, username, role FROM users WHERE username = '{payload.username}' AND password = '{payload.password}'"
    cursor = db.cursor()
    cursor.execute(query)
    user = cursor.fetchone()
    if user:
        return {"status": "success", "user": {"id": user[0], "username": user[1], "role": user[2]}}
    raise HTTPException(status_code=401, detail="Invalid credentials")
```

### 3.3.2. Cài đặt Lỗ hổng SQL Injection UNION-based Data Exfiltration
```python
@router.get("/books/search/")
async def search_books(q: str, db: sqlite3.Connection = Depends(get_db)):
    # Lo hong: Noi suy chuoi tim kiem truc tiep vao menh de LIKE
    query = f"SELECT id, title, author, price FROM books WHERE title LIKE '%{q}%'"
    cursor = db.cursor()
    cursor.execute(query)
    books = cursor.fetchall()
    return [{"id": b[0], "title": b[1], "author": b[2], "price": b[3]} for b in books]
```

### 3.3.3. Cài đặt Lỗ hổng Path Traversal / Local File Inclusion
```python
@router.get("/files/download/")
async def download_file(file: str):
    # Lo hong: Khong chan ky tu .. va khong kiem tra duong dan thu muc goc
    base_dir = Path("/app/static/files")
    target_path = base_dir / file
    if target_path.exists() and target_path.is_file():
        return FileResponse(target_path)
    raise HTTPException(status_code=404, detail="File not found")
```

### 3.3.4. Cài đặt Lỗ hổng OS Command Injection
```python
@router.post("/admin/ping/")
async def admin_ping(payload: PingRequest):
    # Lo hong: Chay truc tiep qua shell he dieu hanh voi toan tu noi lenh
    cmd = f"ping -c 1 {payload.target}"
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
    return {"stdout": proc.stdout, "stderr": proc.stderr, "returncode": proc.returncode}
```

---

## 3.4. Cài Đặt Phân Hệ Tác Tử Tấn Công Tự Động (`attack-lab` - Offensive AI Red Team)

Triển khai độc lập trên **Máy 2 (`naocavang08`)**, phân hệ bao gồm 3 module phối hợp:

### 3.4.1. Cài đặt Module Tự động Trinh sát (OpenAPI Reconnaissance)
Module `attack-lab/recon.py` gửi truy vấn `GET /api/proxy/vulnerable/openapi.json`, trích xuất cấu trúc các API và ánh xạ các tham số vào từ điển tấn công tương ứng:

```python
def map_attack_surface(openapi_spec: dict) -> list[dict]:
    targets = []
    for path, methods in openapi_spec.get("paths", {}).items():
        for method, details in methods.items():
            targets.append({
                "endpoint": path,
                "method": method.upper(),
                "params": details.get("parameters", []),
                "request_body": details.get("requestBody", {})
            })
    return targets
```

### 3.4.2. Cài đặt Mạng Nơ-ron PyTorch DQN Né Tránh WAF (`evasion_agent.pt`)
Được xây dựng thuần túy bằng thư viện PyTorch tại `attack-lab/models/dqn_agent.py`:

```python
class DQNEvasionNetwork(nn.Module):
    def __init__(self, input_dim: int = 17, action_dim: int = 6):
        super().__init__()
        self.fc = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, action_dim)
        )
        
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.fc(x)
```

Quy trình chọn hành vi biến dị theo chiến lược $\epsilon$-greedy:
$$a_t = egin{cases} 
	ext{Random Action} \in A & 	ext{với xác suất } \epsilon \
rg\max_a Q(s_t, a; 	heta) & 	ext{với xác suất } 1 - \epsilon
\end{cases}$$

---

## 3.5. Cài Đặt Phân Hệ Giám Sát SOC Dashboard

Được xây dựng bằng Next.js 14 tại `dashboard/`, hệ thống kết nối trực tiếp với các điểm cuối API Telemetry của Gateway (`/api/v1/waf/telemetry/stats`, `/api/v1/waf/telemetry/events`):

1. **5 Thẻ Chỉ Số An Ninh (Metric KPI Cards):**
   - `Total Traffic`: Tổng số request đã bóc tách.
   - `Attacks Detected`: Tổng số cuộc tấn công đã nhận diện và vô hiệu hóa.
   - `Average Threat Score`: Điểm đe dọa trung bình trên toàn hệ thống.
   - `Clean Traffic Ratio`: Tỷ lệ phần trăm lưu lượng an toàn.
   - `Quick Simulator`: Công cụ bắn thử nghiệm payload trực quan từ giao diện web.

2. **Biểu đồ Sóng Đôi Area Chart & Donut Chart:**
   - Sử dụng thư viện `Recharts` trực quan hóa phân bố thời gian thực của 2 luồng: `Clean Requests` (xanh ngọc lục bảo) và `Blocked Attacks` (đỏ cờ).
   - Biểu đồ tròn Donut Chart hiển thị tỷ trọng phân bố 4 họ tấn công: SQLi, XSS, Path Traversal, Command Injection.

3. **Bảng Sự Kiện & Ngăn Kéo Bằng Chứng (Evidence Drawer):**
   - Cho phép chuyên viên an ninh nhấp vào bất kỳ sự kiện an ninh nào để mở ngăn kéo bên phải, hiển thị song song: Chuỗi Payload thô (Raw) và Chuỗi sau khi qua Bộ chuẩn hóa (Canonical Normalized), kèm theo chi tiết các luật bị kích hoạt và đóng góp đặc trưng (Feature Attribution).

---

## 3.6. Tóm Tắt Chương 3

Chương 3 đã hoàn thiện trọn vẹn việc cài đặt và hiện thực hóa các phân hệ của đề tài:
1. **Hoàn thiện Cổng WAF Gateway:** Cài đặt thành công toàn bộ đường ống 7 bước với module chuẩn hóa chuỗi đệ quy, động cơ 16 luật chữ ký tất định, bộ trích xuất vector 17 đặc trưng hình thái, cơ chế suy luận mô hình học máy kép (Random Forest + Isolation Forest), động cơ đánh giá rủi ro thích ứng Hybrid Decision và bộ điều tiết tần suất Token Bucket.
2. **Xây dựng Ứng dụng Mục tiêu Bookie Bookstore:** Hiện thực hóa trọn vẹn 8 kịch bản lỗ hổng nghiêm trọng chuẩn OWASP Web & API Top 10 kèm điểm cuối xuất bản lược đồ OpenAPI 3.0.
3. **Hiện thực hóa Tác tử Tấn công Tự động Red Team:** Cài đặt module tự động trinh sát và mạng nơ-ron học tăng cường sâu PyTorch DQN (`evasion_agent.pt`) vận hành độc lập trên Máy 2.
4. **Xây dựng Trung tâm Giám sát SOC Dashboard:** Hoàn thành giao diện giám sát thời gian thực Next.js 14 với 5 thẻ KPI, biểu đồ sóng lưu lượng và ngăn kéo đối soát bằng chứng số.

Toàn bộ các phân hệ đã cài đặt tạo thành một hệ sinh thái an ninh hoàn chỉnh, sẵn sàng cho công tác thử nghiệm và đánh giá hiệu năng trong Chương 4.

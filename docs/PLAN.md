# PBL6 — PLAN TRIỂN KHAI CHI TIẾT
## Đề tài: Xây dựng hệ thống phát hiện và ngăn chặn tấn công Web API thông minh sử dụng Machine Learning

> Mục đích tài liệu: Đây là PLAN + SPECIFICATION để đưa trực tiếp cho AI Agent triển khai dự án. Agent phải đọc toàn bộ tài liệu trước khi code, lập implementation checklist, sau đó triển khai theo từng phase và kiểm thử sau mỗi phase.

---

# 1. TẦM NHÌN DỰ ÁN (PROJECT VISION)

Xây dựng một nền tảng an ninh thông minh hai chiều (**Web API Security & Autonomous Red Teaming Platform**) trong môi trường lab, kết hợp hài hòa hai trụ cột chiến lược theo định hướng học thuật của Giảng viên hướng dẫn:
1. **AI trong An toàn thông tin (Defense AI):** Đóng vai trò WAF/IDS/IPS thông minh đứng trước Web API, tích hợp bộ lọc tất định (Rule Engine) cùng mô hình máy học có giám sát (Random Forest) và phát hiện dị biệt (Isolation Forest) để đánh giá rủi ro và ngăn chặn tấn công API theo thời gian thực.
2. **Sử dụng AI để lập kế hoạch tấn công (Offensive AI — AI Attack Planner):** Đóng vai trò Red Team tự hành (`attack-lab/`), sử dụng AI để tự động phân tích mục tiêu, lập kế hoạch chuỗi tấn công và áp dụng kỹ thuật né tránh thích ứng (Adaptive Adversarial Evasion) khi bị WAF chặn để kiểm thử độ bền vững của hệ thống phòng thủ.

Hệ thống sở hữu các năng lực cốt lõi:
- Tiếp nhận và phân tích toàn diện bề mặt request (URL path, query parameters, headers, body payload, và hành vi IP).
- Chuẩn hóa dữ liệu chống bypass đa tầng (Input Normalizer).
- Phát hiện tấn công theo dấu hiệu tĩnh bằng **Rule Engine (16 rules tất định)**.
- Trích xuất **17 đặc trưng** payload và ngữ cảnh HTTP phục vụ Machine Learning.
- Phát hiện tấn công đã biết bằng **Random Forest (Supervised ML)**.
- Phát hiện hành vi dị biệt và đòn tấn công mới lạ bằng **Isolation Forest (Anomaly Detection)**.
- Tổng hợp điểm rủi ro đa nguồn thành **Weighted Hybrid Risk Score (0–100)**.
- Đưa ra quyết định phòng thủ tự động: **ALLOW / MONITOR / RATE LIMIT (429) / BLOCK (403)**.
- Reverse Proxy bất đồng bộ chuyển tiếp an toàn tới Target Web API tự xây dựng (`vulnerable-api`: Port 5000).
- Thiết lập mô hình **Thao trường Đối kháng Phân tán (Distributed Cyber Range)** giữa 2 máy vật lý qua mạng LAN: Máy 1 (Blue Team: WAF Gateway + Target API + SOC UI) đối đầu với Máy 2 (Red Team: AI Attack Planner + Adaptive Evasion).
- Lưu vết toàn diện với khả năng truy vết 100% qua `X-Request-ID` vào cơ sở dữ liệu SQLite (`requests` & `security_events`).
- Hiển thị trung tâm chỉ huy an ninh trực quan **SOC Command Center Dashboard (Next.js 14)** với đồ thị thời gian thực, bảng nhật ký và hộp Quick Simulator 1-click test.
- Cung cấp **AI Attack Planner Agent** phục vụ diễn tập đối kháng tự động (Autonomous Cyber Range).
- Đánh giá thực nghiệm so sánh đa phương pháp (Rule vs ML vs Anomaly vs Hybrid) và kiểm thử độ bền vững trước đòn tấn công né tránh (Adversarial Robustness).

---

# 2. CƠ SỞ VÀ PHẠM VI PBL6

Đề tài tham khảo PBL6 xác định Đề tài 2 là:

“Phát hiện và ngăn chặn tấn công Web API bằng Machine Learning”.

Kiến trúc tham khảo:
User → API Gateway/WAF → Detection Model → Web API → Database.

Các nhóm tấn công tham khảo:
- SQL Injection
- XSS
- Command Injection
- Path Traversal
- Brute Force
- API Abuse
- Credential Stuffing
- Abnormal Request Patterns

Các nhóm đặc trưng tham khảo:
- Request frequency
- HTTP method
- URL length
- Payload characteristics
- Status code
- Response time
- IP/request behavior
- User behavior

Đề tài khuyến nghị so sánh:
- Rule-based Detection
- Machine Learning
- Hybrid Detection

Các thuật toán có thể nghiên cứu:
- Random Forest
- XGBoost
- SVM
- Autoencoder
- LSTM

Đồ án này ưu tiên Random Forest làm supervised model chính và Isolation Forest làm anomaly model chính vì phù hợp phạm vi PBL, dễ giải thích và triển khai.

---

# 2A. RELATED WORK VÀ CƠ SỞ HỌC THUẬT

Phần này phục vụ báo cáo và bảo vệ, không nhất thiết phải trở thành thêm một module runtime.

## 2A.1. Nhóm hệ thống cần nghiên cứu

AI Agent phải chuẩn bị một bảng related work tối thiểu gồm:

- WAF rule-based truyền thống.
- WAF/IDS có Machine Learning.
- Hybrid detection.
- Behavior/anomaly-based API security.

Với mỗi hệ thống, ghi:
- mục tiêu;
- phương pháp detection;
- loại feature;
- ưu điểm;
- hạn chế;
- điểm khác biệt của đồ án.

## 2A.2. Benchmark dataset

AI Agent phải khảo sát ít nhất 2 nguồn dữ liệu công khai có liên quan tới HTTP/Web attack để dùng cho phần related work hoặc validation.

Các tên được đề xuất trong giai đoạn lập kế hoạch:
- CSIC 2010 HTTP dataset;
- các HTTP attack datasets công khai khác phù hợp.

Không được đưa dataset vào báo cáo như “benchmark chính thức” nếu chưa kiểm tra:
- license;
- format;
- nhãn;
- mức độ phù hợp;
- khả năng tải/khai thác;
- dữ liệu có trùng với dataset tự sinh hay không.

Nếu benchmark không phù hợp với feature schema hiện tại, chỉ dùng ở phần related work/thảo luận và nêu rõ limitation.

## 2A.3. Mục tiêu học thuật

Báo cáo phải trả lời được:

> “Đồ án khác gì so với WAF rule-based thông thường và tại sao cần kết hợp ML + behavior analysis?”

Không được biến phần related work thành danh sách công nghệ; phải dùng nó để hình thành research gap và lý do thiết kế hệ thống.

---

# 3. MỤC TIÊU KỸ THUẬT

## 3.1. Core objectives — bắt buộc

1. Xây dựng API Gateway/Reverse Proxy bằng FastAPI.
2. Tích hợp target Web API trong môi trường lab.
3. Xây dựng Rule-based Detection.
4. Xây dựng Feature Extraction.
5. Xây dựng dataset phục vụ ML.
6. Huấn luyện Random Forest.
7. Tích hợp model vào Gateway.
8. Xây dựng Anomaly Detection bằng Isolation Forest.
9. Xây dựng Risk Scoring Engine.
10. Xây dựng các action:
   - ALLOW
   - MONITOR
   - RATE_LIMIT
   - BLOCK
11. Ghi security logs.
12. Xây dựng Dashboard.
13. Xây dựng Attack Lab.
14. So sánh Rule-based / ML / Anomaly / Hybrid.
15. Đánh giá Precision, Recall, F1, FPR, Detection Time.
16. Test unseen/obfuscated attack payloads.

## 3.2. Advanced objectives — chỉ triển khai nếu core ổn định

- Explainable AI / Feature Importance.
- SHAP.
- Adaptive threshold.
- Model comparison với XGBoost.
- Security scoring cho từng attack scenario.
- Incident/alert workflow.
- Feedback loop để bổ sung dữ liệu.
- Model drift / retraining workflow.
- Adaptive evasion test.
- External benchmark validation.
- Export báo cáo CSV/JSON.

Không được hy sinh Core Objectives để chạy theo Advanced Objectives.

## 3.3. Nguyên tắc kiểm soát phạm vi

Nếu tiến độ bị trễ, phải cắt theo thứ tự:

1. P2/Advanced trước.
2. Tính năng UI phụ trước.
3. Campaign nâng cao trước.
4. Không được cắt P0:
   Gateway, Rule Detection, Feature Engineering, Dataset, Random Forest, Risk Engine,
   Blocking, Logging, Dashboard cơ bản và Evaluation.

Mục tiêu là có một hệ thống P0 hoàn chỉnh trước giữa/cuối dự án, thay vì có nhiều module dở dang.

---

# 4. KIẾN TRÚC HỆ THỐNG MỤC TIÊU

```text
                         CLIENT / ATTACK LAB
                                  |
                                  v
                    +---------------------------+
                    |      FASTAPI WAF GATEWAY  |
                    |     Reverse Proxy Layer   |
                    +-------------+-------------+
                                  |
                    +-------------v-------------+
                    |     Request Parser        |
                    | URL / Query / Body        |
                    | Headers / Method / IP     |
                    +-------------+-------------+
                                  |
                    +-------------v-------------+
                    |    Feature Extraction     |
                    +-------------+-------------+
                                  |
             +--------------------+--------------------+
             |                    |                    |
             v                    v                    v
      Rule Engine          Random Forest        Isolation Forest
             |                    |                    |
             +--------------------+--------------------+
                                  |
                                  v
                    +---------------------------+
                    |     RISK SCORING ENGINE   |
                    +-------------+-------------+
                                  |
               +------------------+------------------+
               |                  |                  |
               v                  v                  v
             ALLOW             MONITOR          RATE LIMIT
                                                   / BLOCK
               |                  |                  |
               +------------------+------------------+
                                  |
                                  v
                          TARGET WEB API
                     (vulnerable-api: Port 5000)
                                  |
                                  v
                              DATABASE

Gateway / Detection Logs
          |
          v
       SQLite
          |
          v
   Next.js Dashboard
```

---

# 5. MONOREPO STRUCTURE

Đề xuất:

```text
pbl6-api-security-ml/
│
├── docker-compose.yml
├── README.md
├── .env.example
├── .gitignore
│
├── gateway/
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── proxy.py
│   │   ├── middleware.py
│   │   ├── database.py
│   │   ├── schemas.py
│   │   │
│   │   ├── detection/
│   │   │   ├── rules.py
│   │   │   ├── features.py
│   │   │   ├── ml_detector.py
│   │   │   ├── anomaly_detector.py
│   │   │   ├── risk_engine.py
│   │   │   └── decision_engine.py
│   │   │
│   │   ├── security/
│   │   │   ├── rate_limiter.py
│   │   │   ├── attack_tracker.py
│   │   │   └── ip_tracker.py
│   │   │
│   │   └── api/
│   │       ├── logs.py
│   │       ├── stats.py
│   │       ├── config.py
│   │       └── attack_lab.py
│   │
│   ├── models/
│   │   ├── random_forest.joblib
│   │   ├── isolation_forest.joblib
│   │   └── metadata.json
│   │
│   ├── requirements.txt
│   └── Dockerfile
│
├── ml-engine/
│   ├── data/
│   │   ├── raw/
│   │   ├── processed/
│   │   └── evaluation/
│   │
│   ├── src/
│   │   ├── generate_dataset.py
│   │   ├── collect_lab_traffic.py
│   │   ├── features.py
│   │   ├── train_rf.py
│   │   ├── train_anomaly.py
│   │   ├── evaluate.py
│   │   ├── compare_models.py
│   │   └── generate_report.py
│   │
│   ├── notebooks/
│   │   └── experiments.ipynb
│   │
│   └── requirements.txt
│
├── attack-lab/
│   ├── scenarios/
│   │   ├── sqli.json
│   │   ├── xss.json
│   │   ├── traversal.json
│   │   ├── command_injection.json
│   │   ├── brute_force.json
│   │   ├── api_abuse.json
│   │   └── obfuscated.json
│   │
│   └── runner.py
│
├── dashboard/
│   ├── src/
│   │   └── app/
│   │       ├── page.tsx
│   │       ├── layout.tsx
│   │       ├── components/
│   │       │   ├── StatCards.tsx
│   │       │   ├── TrafficChart.tsx
│   │       │   ├── AttackDistribution.tsx
│   │       │   ├── SecurityEvents.tsx
│   │       │   ├── RequestDetail.tsx
│   │       │   ├── RiskScore.tsx
│   │       │   ├── ModelExplain.tsx
│   │       │   └── AttackLab.tsx
│   │       └── api/
│   ├── package.json
│   └── Dockerfile
│
├── vulnerable-api/
│   ├── app/
│   │   ├── main.py
│   │   ├── core/
│   │   │   ├── config.py
│   │   │   └── database.py
│   │   └── routes/
│   │       ├── auth.py         # SQLi Auth Bypass & Brute Force
│   │       ├── products.py     # SQLi UNION-based Search
│   │       ├── comments.py     # Stored/Reflected XSS
│   │       ├── documents.py    # Path Traversal / LFI
│   │       └── tools.py        # Command Injection Ping
│   ├── requirements.txt
│   └── Dockerfile
│
└── docs/
    ├── ARCHITECTURE.md
    ├── DATASET.md
    ├── ML_MODEL.md
    ├── API.md
    ├── SECURITY.md
    ├── EVALUATION.md
    └── DEMO.md
```

Agent có thể điều chỉnh cấu trúc nếu có lý do kỹ thuật, nhưng không được làm mất các module chức năng chính.

---

# 6. TARGET WEB API (VULNERABLE-API TỰ XÂY DỰNG)

Theo chỉ đạo học thuật trực tiếp từ Giảng viên hướng dẫn, nhóm **không sử dụng OWASP Juice Shop** (do là sản phẩm bên thứ ba có sẵn), mà **tự xây dựng một ứng dụng mục tiêu Web API (`vulnerable-api`)** viết bằng Python / FastAPI.

Target chạy độc lập với Gateway tại cổng nội bộ `5000` (chỉ cho phép Gateway kết nối).

Mục tiêu & Đặc điểm kỹ thuật:
- Đảm bảo tính khách quan và minh bạch 100% về mã nguồn, cấu trúc dữ liệu và logic nghiệp vụ.
- Cài cắm có chủ đích **5 nhóm lỗ hổng OWASP Top 10** kinh điển trên Web API:
  1. `POST /api/v1/auth/login`: SQL Injection Auth Bypass (`' OR '1'='1`) & Brute Force.
  2. `GET /api/v1/products/search`: SQL Injection UNION-based khai thác trích xuất dữ liệu.
  3. `POST /api/v1/comments`: Stored & Reflected Cross-Site Scripting (XSS).
  4. `GET /api/v1/documents/view`: Path Traversal / Local File Inclusion (LFI).
  5. `POST /api/v1/tools/ping`: Command Injection (RCE).
- Tự động sinh tài liệu chuẩn **OpenAPI / Swagger UI** (`/docs` và `/openapi.json`) để **AI Attack Planner (trên Máy 2)** có thể tự động trinh sát (Reconnaissance), phân tích tham số và lập kế hoạch tấn công.

---

# 7. REQUEST PIPELINE

Mọi request đi qua Gateway phải theo pipeline:

```text
Receive Request
    ↓
Normalize Request
    ↓
Extract metadata
    ↓
Extract payload features
    ↓
Rule Detection
    ↓
ML Detection
    ↓
Anomaly Detection
    ↓
Behavior Analysis
    ↓
Risk Scoring
    ↓
Decision
    ↓
Allow / Monitor / Rate Limit / Block
    ↓
Log
    ↓
Proxy nếu được phép
```

Không được để ML engine bypass Gateway.

---

# 8. FEATURE ENGINEERING

## 8.1. Payload features — giữ nhóm 17 đặc trưng ban đầu

Structural:
1. length
2. entropy

Special character:
3. count_single_quote
4. count_double_quote
5. count_less_than
6. count_greater_than
7. count_semicolon
8. count_hyphen
9. count_slash
10. count_backslash
11. count_parenthesis
12. special_char_ratio

Context:
13. sql_keyword_count
14. xss_keyword_count

Regex:
15. sqli_regex_matches
16. xss_regex_matches
17. path_traversal_matches

## 8.2. HTTP features

Bổ sung:
- HTTP method
- URL length
- query length
- body length
- number of query parameters
- number of headers
- content type
- response status
- response time

## 8.3. Behavior features

Bổ sung:
- requests_per_ip_window
- unique_endpoints_per_ip
- repeated_endpoint_count
- failed_requests_per_ip
- failed_login_count
- request_rate
- endpoint_scan_score
- IP anomaly score

Các behavior features phải được tính theo time window, ví dụ 10 giây / 60 giây.

---

# 9. RULE ENGINE

Rule engine phải có ít nhất:

### SQL Injection
- UNION SELECT
- OR 1=1
- SQL comments
- common SQL keywords in suspicious combinations
- quote-based patterns

### XSS
- script tags
- javascript:
- event handlers như onerror/onload
- common encoded variants

### Path Traversal
- ../
- ..\
- encoded traversal variants

### Command Injection
- suspicious shell operators
- command execution patterns

### Brute Force
- nhiều failed login trong time window

### API Abuse
- request rate vượt threshold
- endpoint enumeration
- repeated abnormal requests

Rule result phải trả về:
```json
{
  "detected": true,
  "attack_type": "SQLI",
  "score": 0.9,
  "matched_rules": ["SQLI_UNION", "SQLI_COMMENT"]
}
```

---

# 10. SUPERVISED ML — RANDOM FOREST

Random Forest là model chính.

Initial configuration:

```text
n_estimators = 100
max_depth = 10
random_state = 42
class_weight = balanced
```

Có thể tune sau khi baseline hoạt động.

Không hard-code Accuracy 100%.

Phải train trên dataset thực tế đã tạo.

## Labels

Ít nhất:
- BENIGN
- SQLI
- XSS
- PATH_TRAVERSAL
- COMMAND_INJECTION
- BRUTE_FORCE
- API_ABUSE

Có thể dùng multiclass.

Đồng thời có thể quy đổi thành:
- benign
- malicious

cho binary evaluation.

---

# 11. DATASET STRATEGY

Dataset phải được tạo từ hai nguồn:

## A. Synthetic dataset

Generate các payload có nhiều biến thể:

- plain
- URL encoded
- mixed case
- whitespace variations
- comments
- parameter variations
- length variations
- benign strings chứa special characters

## B. Lab traffic

Attack Lab gửi request thực tế qua Gateway và lưu:
- raw request metadata
- extracted features
- label
- timestamp
- scenario

Mục tiêu là dataset có tính thực nghiệm chứ không chỉ copy một vài payload.

Target ban đầu có thể khoảng 10k–20k samples nếu thời gian cho phép.

Không bắt buộc chính xác số lượng trên; ưu tiên:
- cân bằng tương đối;
- đa dạng biến thể;
- không duplicate quá nhiều.

---

# 12. DATA SPLIT

Không chỉ random split.

Phải có:

### Experiment A — Random Stratified Split
80/20 để baseline.

### Experiment B — Unseen Payload Split
Các pattern/biến thể cụ thể chỉ xuất hiện ở test.

### Experiment C — Attack Family Split
Một số biến thể attack không xuất hiện trong training.

Mục đích chứng minh model không chỉ memorization.

---

# 13. ANOMALY DETECTION

Sử dụng Isolation Forest.

Input ưu tiên behavior features.

Ví dụ:

```text
request_rate
unique_endpoints
failed_requests
endpoint_scan_score
response_time
status_code_distribution
```

Output:

```text
anomaly_score
is_anomaly
```

Không dùng anomaly detection để thay thế supervised model.

Nó là một nguồn tín hiệu bổ sung cho Hybrid Detection.

---

# 14. RISK SCORING ENGINE

Chuẩn hóa các detector về 0–100.

Ví dụ:

```text
rule_score
ml_score
anomaly_score
behavior_score
```

Initial weighted score:

```text
risk =
    0.30 * rule_score
  + 0.35 * ml_score
  + 0.20 * anomaly_score
  + 0.15 * behavior_score
```

Các weight phải để trong config, không hard-code vào business logic.

## Threshold

```text
0–29   LOW       → ALLOW
30–59  MEDIUM    → MONITOR
60–79  HIGH      → RATE_LIMIT
80–100 CRITICAL  → BLOCK
```

Đây là baseline.

Sau evaluation có thể tune threshold.

---

# 15. DECISION ENGINE

Decision engine nhận Risk Score + WAF Mode.

Modes:

### OFF
Không detection/blocking.

### MONITOR_ONLY
Phát hiện + log nhưng không block.

### ACTIVE_BLOCKING
Phát hiện và áp dụng action.

### HYBRID
Sử dụng toàn bộ Rule + ML + Anomaly.

Decision phải trả:

```json
{
  "action": "BLOCK",
  "risk_score": 92,
  "severity": "CRITICAL",
  "attack_type": "SQLI",
  "detectors": {
    "rule": 100,
    "ml": 94,
    "anomaly": 51,
    "behavior": 20
  }
}
```

---

# 16. RATE LIMITING

Phải có IP-based rate limiter.

Ví dụ baseline:
- 60 requests / minute / IP.

Có thể có endpoint-specific threshold:
- login: thấp hơn;
- public GET: cao hơn.

Nếu vượt:
- RATE_LIMIT;
- ghi log;
- trả HTTP 429.

Không được dùng rate limiting để thay thế ML detection.

---

# 17. SECURITY LOGGING

Mỗi security event phải lưu:

- timestamp
- request_id
- client_ip
- method
- URL
- query
- body hash hoặc payload phù hợp
- attack_type
- rule_score
- ml_score
- anomaly_score
- behavior_score
- risk_score
- severity
- action
- response_status
- response_time
- waf_mode

Nếu lưu raw payload, phải giới hạn và sanitize dữ liệu.

---

# 18. DATABASE

SQLite đủ cho PBL.

Tables tối thiểu:

### security_events

```text
id
timestamp
request_id
client_ip
method
url
attack_type
risk_score
severity
action
response_status
response_time
waf_mode
```

### detection_details

```text
id
event_id
detector
score
matched_rules
prediction
```

### waf_config

```text
id
mode
ml_enabled
anomaly_enabled
rate_limit_enabled
updated_at
```

### attack_runs

```text
id
scenario
started_at
ended_at
total_requests
detected
blocked
false_positive
```

---

# 19. FASTAPI ADMIN API

Tối thiểu:

```text
GET  /api/waf/logs
GET  /api/waf/stats
GET  /api/waf/config
POST /api/waf/config
GET  /api/waf/events/{id}

POST /api/attack-lab/run
GET  /api/attack-lab/scenarios

GET  /api/health
GET  /api/model/info
```

Gateway catch-all:

```text
/{path:path}
```

phải proxy request an toàn tới target.

---

# 20. DASHBOARD

Dashboard phải có 5 khu vực.

## A. Overview

Cards:
- Total Requests
- Attacks Detected
- Requests Blocked
- Current Risk
- Detection Rate

## B. Attack Timeline

Line/Area chart:
- requests
- attacks
- blocks

## C. Attack Distribution

- SQLi
- XSS
- Traversal
- Command Injection
- Brute Force
- API Abuse

## D. Security Events

Table:
- time
- IP
- endpoint
- attack
- risk
- action

Click row → Request Detail.

## E. Detection Explain

Hiển thị:
- prediction
- confidence
- risk score
- rule matches
- top features
- action

---

# 21. ATTACK LAB

Attack Lab phải có UI buttons:

```text
SQL Injection
XSS
Path Traversal
Command Injection
Brute Force
API Abuse
Obfuscated SQLi
Obfuscated XSS
Benign Special Characters
```

Mỗi scenario có:
- description
- target endpoint
- payload/request
- expected attack type

Attack Lab chỉ được chạy target lab/local.

---

# 22. BENIGN TEST CASES

Bắt buộc có benign cases chứa các ký tự dễ gây false positive:

Ví dụ:
- tên người có apostrophe;
- text có `<` và `>`;
- comment có `--`;
- JSON string chứa quotes;
- URL có slash;
- search query bình thường.

Mục tiêu:
đo False Positive Rate.

---

# 23. BYPASS / OBFUSCATION TEST

Phải test:

- URL encoding
- mixed case
- whitespace changes
- SQL comments
- equivalent payload forms
- encoded traversal
- HTML entity/encoding variants

Mục tiêu:
đánh giá robustness.

Không tuyên bố model chống mọi bypass.

---

# 24. MODEL EVALUATION

Bắt buộc báo cáo:

- Accuracy
- Precision
- Recall
- F1-score
- Confusion Matrix
- False Positive Rate
- False Negative Rate
- Detection Time / Inference Time

Với hệ thống:
1. Rule-based
2. Random Forest
3. Isolation Forest
4. Hybrid

Tạo bảng:

```text
Method | Precision | Recall | F1 | FPR | Detection Time
```

Và confusion matrix cho supervised classifier.

---

# 25. SYSTEM PERFORMANCE

Đo:

- Gateway latency baseline
- Feature extraction time
- ML inference time
- Anomaly inference time
- total detection latency
- request throughput
- block response latency

So sánh:

```text
Direct API
vs
Gateway without ML
vs
Gateway + Rule
vs
Gateway + ML
vs
Gateway + Hybrid
```

Mục tiêu chứng minh security layer không gây overhead quá lớn trong lab.

---

# 25A. MODEL DRIFT VÀ RETRAIN WORKFLOW

Không bắt buộc triển khai automated retraining trong P0.

Tuy nhiên hệ thống phải có thiết kế rõ ràng:

```text
New Lab Traffic
      ↓
Validate / Label
      ↓
Append to Dataset
      ↓
Data Quality Check
      ↓
Train Candidate Model
      ↓
Evaluate on Fixed Test Set
      ↓
Compare with Current Model
      ↓
Promote only if metrics improve
```

Quy tắc:
- Không retrain tự động từ raw production traffic.
- Traffic phải được review/label trước khi đưa vào training.
- Fixed hold-out test set phải được giữ nguyên để so sánh các model.
- Metadata model phải lưu:
  - version;
  - training timestamp;
  - dataset version;
  - feature version;
  - metrics.

Trong báo cáo phải có mục “Limitations & Future Work” mô tả model drift và retraining workflow, kể cả khi chưa tự động hóa.

---

# 26. SO SÁNH PHƯƠNG PHÁP

Đây là phần quan trọng nhất của báo cáo.

Phải trả lời:

### Rule-based
- mạnh ở đâu?
- yếu ở đâu?
- false positive thế nào?
- bypass thế nào?

### Random Forest
- mạnh ở đâu?
- loại attack nào tốt?
- unseen payload ra sao?

### Isolation Forest
- phát hiện behavior anomaly thế nào?
- có false positive không?

### Hybrid
- có cải thiện Recall?
- có giảm FPR?
- latency tăng bao nhiêu?

Không được kết luận Hybrid tốt hơn nếu thực nghiệm không chứng minh.

---

# 27. XAI

Mức tối thiểu:
- Random Forest Feature Importance.

Hiển thị:
- top 5 features;
- feature value;
- importance.

Ví dụ:

```text
Prediction: SQLI
Confidence: 96%

Top Features:
1. sqli_regex_matches
2. sql_keyword_count
3. special_char_ratio
4. payload_length
5. entropy
```

SHAP là Advanced Objective, chỉ làm sau khi hệ thống chính ổn định.

---

# 28. SECURITY SCORING / ATTACK CAMPAIGN

Attack Lab có thể chạy một campaign:

```text
Campaign: Basic Web Attack

1. SQLi
2. XSS
3. Traversal
4. Brute Force
5. API Abuse
6. Obfuscated Attack
```

Sau campaign:

```text
Detection Rate
Blocking Rate
False Positive Rate
Average Detection Time
```

Tính:

```text
Security Score = weighted evaluation
```

Chỉ dùng như demo/analytics, không thay thế ML metrics.

---

# 29. DEMO KỊCH BẢN BẢO VỆ

## Scenario 1 — Normal traffic

Benign requests.

Expected:
- ALLOW
- risk LOW
- Dashboard normal.

## Scenario 2 — SQLi

Monitor Only.

Expected:
- detect SQLi;
- request vẫn đi qua;
- log xuất hiện.

## Scenario 3 — XSS

Active Blocking.

Expected:
- detect;
- risk CRITICAL;
- HTTP 403.

## Scenario 4 — False Positive

Benign text có special characters.

So sánh:
- Rule-only;
- ML;
- Hybrid.

## Scenario 5 — API Abuse

Rapid requests.

Expected:
- behavior anomaly;
- rate limiting;
- HTTP 429.

## Scenario 6 — Brute Force

Repeated failed login.

Expected:
- behavior detector;
- rate limit/block.

## Scenario 7 — Obfuscated Attack

Payload biến đổi/encoded.

Expected:
- test robustness;
- ghi nhận detector nào bắt được.

## Scenario 8 — Dashboard

Hiển thị:
- timeline;
- distribution;
- security events;
- risk;
- detector details.

---

# 30. DOCKER

Services:

```text
gateway
dashboard
vulnerable-api
```

Optional:
```text
ml-engine
```

ML training không bắt buộc chạy như production service; có thể train offline và mount model vào gateway.

Tất cả phải chạy bằng:

```bash
docker compose up --build
```

Một lệnh phải khởi động được toàn bộ lab.

---

# 31. CONFIGURATION

Không hard-code:

- target URL
- thresholds
- WAF mode
- rate limit
- ML enabled
- anomaly enabled

Dùng environment/config.

Ví dụ:

```text
TARGET_API_URL
WAF_MODE
ML_ENABLED
ANOMALY_ENABLED
RATE_LIMIT_ENABLED
RATE_LIMIT_PER_MINUTE
RISK_BLOCK_THRESHOLD
RISK_RATE_LIMIT_THRESHOLD
```

---

# 31A. BẢO MẬT CHO CHÍNH HỆ THỐNG WAF

Đây là yêu cầu bắt buộc vì hệ thống đang bảo vệ Web API nhưng bản thân các admin API cũng có thể trở thành mục tiêu.

## Admin authentication

Các endpoint quản trị phải yêu cầu xác thực:

```text
GET/POST /api/waf/config
GET /api/waf/logs
GET /api/waf/stats
GET /api/waf/events/{id}
POST /api/attack-lab/run
```

Có thể dùng:
- API Key đơn giản trong môi trường lab; hoặc
- JWT nếu implementation đã có auth layer.

Ưu tiên API Key để giảm complexity PBL.

## Security requirements

- Admin credential phải nằm trong environment variable/secret config.
- Không hard-code secret vào source.
- Có response 401/403 rõ ràng.
- Endpoint public chỉ expose health/status tối thiểu.
- Không cho unauthenticated client đổi threshold/rules/WAF mode.
- Dashboard phải gửi credential khi gọi admin API.

## Audit

Mọi thay đổi:
- WAF mode;
- threshold;
- ML enabled/disabled;
- anomaly enabled/disabled;
- rate limit;

phải được ghi audit log với:
- timestamp;
- actor;
- action;
- old value;
- new value.

---

# 32. TESTING STRATEGY

## Unit tests

- feature extraction
- rule detection
- risk scoring
- decision engine
- rate limiter

## Integration tests

- Gateway → Target API
- Gateway → ML
- Gateway → DB
- Dashboard → Gateway

## Security tests

- SQLi
- XSS
- Traversal
- Command Injection
- Brute Force
- API Abuse
- Obfuscation
- Benign false positives
- Unseen payload
- Unseen attack-family variant
- Admin API unauthenticated access
- Invalid/expired admin credential
- Unauthorized configuration change

## Adversarial / Evasion tests

Bổ sung ít nhất một scenario “adaptive attacker” trong lab:

```text
Known malicious payload
        ↓
Add benign-looking tokens/noise
        ↓
Re-score
        ↓
Compare Rule vs ML vs Hybrid
```

Mục tiêu không phải xây một hệ thống bypass WAF production mà là đánh giá robustness của detector.

Báo cáo phải ghi:
- payload gốc;
- payload biến đổi;
- detector nào bị suy giảm;
- detector nào vẫn phát hiện;
- ảnh hưởng tới Risk Score;
- giới hạn của phương pháp.

Không được gọi đây là “feature poisoning” nếu không thực sự sửa training data/model. Nếu chỉ thay đổi request tại inference time, dùng thuật ngữ “evasion/adversarial input”.

## Regression tests

Mọi bug được sửa phải có test tương ứng.

---

# 33. DEVELOPMENT PHASES (TIẾN ĐỘ THỰC HIỆN CÁC GIAI ĐOẠN)

Hệ thống được chia thành 13 giai đoạn phát triển tuần tự, đã được bẻ nhỏ thành **50 Subtasks chi tiết** và quản lý trực tiếp trên GitHub Project Kanban của nhóm.

## PHASE 0 — Analysis & Foundation (COMPLETED ✅)
- Khởi tạo cấu trúc monorepo, FastAPI backend foundation, SQLite models, Next.js base, Docker Compose, CI workflow tự động, và thiết lập bộ Pull Request Templates.
- Deliverable: Môi trường hoàn chỉnh, CI pass.

## PHASE 1 — Infrastructure & Async Proxy (COMPLETED ✅)
- Xây dựng Dynamic Reverse Proxy (`/api/proxy/{path:path}`), Request ID resolver, Hop-by-hop header filtering, SQLite traffic persistence có khử nhạy cảm, chống Open Proxy/SSRF, và endpoint kiểm tra kết nối target `GET /health/target`.
- Deliverable: Reverse proxy hoạt động trơn tru với độ trễ thấp.

## PHASE 2 — Rule Engine & Signature Detection (COMPLETED ✅)
- Triển khai **16 rules tĩnh tất định** (SQLi, XSS, Path Traversal, Command Injection), bộ chuẩn hóa an toàn `InputNormalizer`, chấm điểm rủi ro tất định `RuleScorer` (0–100), lưu vết sự kiện bảo mật `security_events`. Hoạt động ở chế độ **Detection Only (Non-blocking)**.
- Deliverable: 33/33 Pytest unit tests pass 100%, 0 lỗi Ruff linter, live verification thành công.

## PHASE 3 — Feature Engineering (IN PROGRESS 🚀 — Next Up)
- Trích xuất **17 đặc trưng** payload (độ dài, Shannon entropy, tỷ lệ ký tự đặc biệt), tần suất từ khóa tấn công (SQLi, XSS, Path, Cmd), và ngữ cảnh HTTP/hành vi metadata.
- Phụ trách: `naocavang08` (Thành viên B).
- Deliverable: `ml-engine/features/` pipeline trích xuất vector đặc trưng kèm test suite.

## PHASE 4 — Dataset Generation & Lab Traffic (PLANNED ⏳)
- Thu thập và sinh tập dữ liệu cân bằng: Benign HTTP traffic từ vulnerable-api crawler + Attack payloads từ SecLists/PayloadsAllTheThings.
- Phụ trách: `naocavang08` (Thành viên B).
- Deliverable: Bộ dataset chuẩn hóa CSV/Parquet chia Train/Test sạch sẽ.

## PHASE 5 — Random Forest Supervised ML (PLANNED ⏳)
- Huấn luyện mô hình Random Forest phân loại đa lớp (Multi-class: Benign, SQLi, XSS, Path, Cmd), đánh giá Accuracy/F1, xuất file model `.joblib`, và tích hợp suy luận vào Gateway.
- Phụ trách: `naocavang08` (Thành viên B).
- Deliverable: Mô hình ML có độ trễ suy luận $< 5\text{ms}$.

## PHASE 6 — Anomaly Detection — Isolation Forest (PLANNED ⏳)
- Xây dựng mô hình Isolation Forest học phân phối lưu lượng sạch để phát hiện các dị biệt và biến thể tấn công mới lạ (Zero-day / Novel attacks).
- Phụ trách: `naocavang08` (Thành viên B).
- Deliverable: Bộ tính Anomaly Score chuẩn hóa $0.0 - 1.0$.

## PHASE 7 — Hybrid Risk Engine & Decision (PLANNED ⏳)
- Tổng hợp điểm số từ Rule Engine, Random Forest và Isolation Forest thành **Weighted Risk Score (0–100)**. Đưa ra 4 quyết định phòng thủ: **ALLOW / MONITOR / RATE_LIMIT / BLOCK (403)**.
- Phụ trách: `vcongggggg` (Thành viên A).
- Deliverable: Module ra quyết định phòng thủ chủ động (Active Defense).

## PHASE 8 — Rate Limiting & Behavior Tracker (PLANNED ⏳)
- Xây dựng bộ đếm tần suất Sliding Window theo IP trong bộ nhớ, tự động chặn và trả về `HTTP 429 Too Many Requests` khi vượt ngưỡng cho phép (chống Brute-force/DoS).
- Phụ trách: `vcongggggg` (Thành viên A).
- Deliverable: Rate limiter module bảo vệ ngưỡng gọi API.

## PHASE 9 — SOC Dashboard UI & Real-Time Threat Visualization (COMPLETED Task 9.1 & 9.2 ✅)
- Xây dựng trung tâm chỉ huy an ninh trực quan **SOC Command Center** chuẩn Dark Cyber Glassmorphism (Next.js 14 + Recharts):
  * **6 REST APIs thật trên Gateway** (`GET /api/dashboard/stats`, `/events`, `/timeline`, `/distribution`, `POST /simulate`, `POST /reset-demo`).
  * **5 Thẻ KPI:** Total Traffic (RPS), Attacks Detected, Threat Score (Rule Engine Phase 2), Safe Request Rate (Forwarded 200 OK).
  * **Hộp Quick Simulator 1-click:** 5 nút bấm thử nghiệm (SQLi, XSS, Path, Cmd, Benign) nhảy số thật trên UI ngay lập tức.
  * **Biểu đồ sóng kép Area Chart & Donut Chart:** Hiển thị lưu lượng Benign vs Attacks và tỷ lệ % phân bố các họ tấn công.
  * **Bảng Live Security Events & Payload Evidence Drawer:** Phân tích đối chiếu Raw vs Canonical Input và tab chờ sẵn 17-Feature Vector cho Phase 3.
- Phụ trách: `vcongggggg` (Thành viên A).
- Deliverable: Giao diện web hoàn chỉnh chạy tại port 3000, 38/38 backend tests pass, production build thành công (125 kB).

## PHASE 10 — Offensive AI — AI Attack Planner & Autonomous Red Teaming (PLANNED ⏳)
- Nâng cấp `attack-lab/` theo chỉ đạo học thuật của Thầy hướng dẫn: Xây dựng **AI Attack Planner Agent** tự động lập kế hoạch và thực thi chuỗi tấn công Web API có mục tiêu.
- Tích hợp **Adaptive Evasion Engine**: Khi bị Gateway chặn 403, AI Agent sẽ tự động biến đổi payload (Obfuscation, URL encode, token mixing) để thử nghiệm vượt rào và đánh giá độ bền vững (Robustness) của hệ thống phòng thủ.
- Phụ trách: `naocavang08` (Thành viên B).
- Deliverable: Agent đối kháng tự động chạy kịch bản thử nghiệm Red Team.

## PHASE 11 — System Evaluation & Adversarial Benchmark (PLANNED ⏳)
- Thực nghiệm đo đạc và lập bảng so sánh hiệu năng giữa 4 phương pháp: **Rule-based vs ML vs Anomaly vs Hybrid**.
- Đánh giá khả năng chống chịu trước đòn tấn công né tránh (Adversarial Robustness) do AI Attack Planner tạo ra.
- Phụ trách: `naocavang08` (Thành viên B).
- Deliverable: Bảng số liệu thực nghiệm khoa học, biểu đồ ROC/PR curve, Confusion Matrix.

## PHASE 12 — Final Hardening, Audit Logs & Thesis Defense Report (PLANNED ⏳)
- Đóng gói toàn bộ hệ thống bằng Docker Compose một lệnh chạy (`docker compose up --build`).
- Tổng duyệt kịch bản demo trực tiếp (Demo Rehearsal) và hoàn thiện báo cáo đồ án, slide thuyết trình.
- Phụ trách: Cả hai bạn (`vcongggggg` & `naocavang08`).
- Deliverable: Hệ thống chạy ổn định 100%, slide và báo cáo tốt nghiệp đồ án.

---

# 33A. TIMELINE VẬN HÀNH THỰC TẾ (12 TUẦN)

| Tuần | Trọng tâm | Deliverable | Trạng thái |
| :---: | :--- | :--- | :---: |
| **1** | Phân tích yêu cầu + Kiến trúc Monorepo | Monorepo layout, Docker, CI workflow | **HOÀN THÀNH ✅** |
| **2** | Infrastructure & Reverse Proxy Gateway | Dynamic Proxy, Request ID, Target Probe | **HOÀN THÀNH ✅** |
| **3** | Rule Engine & Signature Detection | 16 Rules tất định, Normalizer, Scorer | **HOÀN THÀNH ✅** |
| **4** | SOC Dashboard UI & Gateway REST APIs | Next.js Dashboard, Recharts, Quick Simulator | **HOÀN THÀNH ✅** |
| **5** | Feature Engineering (17 Features) | Vector pipeline, extractor unit tests | **TIẾP THEO 🚀** |
| **6** | Dataset Collection & Synthetic Generation | Tập dữ liệu sạch + tấn công (CSV/Parquet) | Kế hoạch ⏳ |
| **7** | Random Forest Supervised ML | Mô hình ML, offline metrics, model inference | Kế hoạch ⏳ |
| **8** | Anomaly Detection (Isolation Forest) | Phát hiện dị biệt, novel attack detection | Kế hoạch ⏳ |
| **9** | Hybrid Risk Engine & Rate Limiting | Decision ALLOW/BLOCK, HTTP 429 limiter | Kế hoạch ⏳ |
| **10** | Offensive AI — AI Attack Planner | Autonomous Red Team Agent, Evasion engine | Kế hoạch ⏳ |
| **11** | Evaluation & Adversarial Robustness | Bảng so sánh 4 phương pháp, ROC curves | Kế hoạch ⏳ |
| **12** | Final Hardening & Slide Báo Cáo | Docker 1-click, Demo rehearsal, Báo cáo đồ án | Kế hoạch ⏳ |

---

# 33B. PHÂN CÔNG TRÁCH NHIỆM NHÓM 2 THÀNH VIÊN (CHÍNH THỨC)

Phân chia trách nhiệm minh bạch, bám sát ma trận 50 GitHub Issues trong tài liệu [docs/TASKS_BREAKDOWN.md](file:///c:/Study/HocKy6/PBL6/docs/TASKS_BREAKDOWN.md):

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│             PHÂN CÔNG TRÁCH NHIỆM: CYBER RANGE 2 MÁY ĐỐI KHÁNG (PBL6)            │
├────────────────────────────────────────┬─────────────────────────────────────────┤
│ THÀNH VIÊN A: vcongggggg               │ THÀNH VIÊN B: naocavang08               │
│ Vai trò: Tech Lead / Blue Team (Phòng) │ Vai trò: Red Team Lead (Tấn) & AI Eng   │
│ Vị trí: MÁY 1 (Target API, WAF, SOC UI)│ Vị trí: MÁY 2 (AI Attack Planner Agent) │
├────────────────────────────────────────┼─────────────────────────────────────────┤
│ • Xây dựng vulnerable-api (6 endpoints)│ • Feature Engineering (17 Features)     │
│ • Reverse Proxy Gateway (0.0.0.0:8000) │ • Thu thập & sinh Dataset (vulnerable)  │
│ • Rule Engine (16 Rules tất định)      │ • Huấn luyện Random Forest (Supervised) │
│ • Input Normalizer & Scorer            │ • Huấn luyện Isolation Forest (Anomaly) │
│ • Hybrid Decision Engine (Phase 7)     │ • Xây dựng AI Attack Planner (Phase 10) │
│ • IP Rate Limiting - 429 (Phase 8)     │ • Adaptive Evasion Engine qua mạng LAN  │
│ • SOC Dashboard UI & Recharts (Phase 9)│ • Đánh giá thực nghiệm so sánh (Phase 11)│
│ • Docker Compose Hardening (Phase 12)  │ • Soạn thảo Slide & Báo cáo đồ án       │
└────────────────────────────────────────┴─────────────────────────────────────────┘
```

---

# 34. DEFINITION OF DONE (TIÊU CHUẨN HOÀN THÀNH ĐỒ ÁN)

- [x] `docker compose up --build` chạy được toàn bộ stack.
- [x] Target API (`vulnerable-api`: Port 5000) truy cập và phản hồi tốt qua `/health/target`.
- [x] Gateway Reverse Proxy chuyển tiếp request an toàn kèm `X-Request-ID`.
- [x] Rule Engine phát hiện chính xác 16 signature tấn công tĩnh.
- [x] Cơ sở dữ liệu SQLite ghi log đầy đủ vào bảng `requests` và `security_events`.
- [x] SOC Dashboard Next.js hiển thị số liệu thật, không mock data.
- [x] Quick Simulator 1-click test hoạt động và nhảy số thời gian thực.
- [x] SQLi test pass (100%).
- [x] XSS test pass (100%).
- [x] Path Traversal test pass (100%).
- [x] Command Injection test pass (100%).
- [x] Benign false-positive test pass (0 false alarms).
- [x] Có tài liệu `README.md`.
- [x] Có tài liệu `ARCHITECTURE.md`.
- [x] Có tài liệu `RULE_ENGINE.md`.
- [x] Có tài liệu `DASHBOARD_SPEC.md`.
- [x] Có tài liệu `TASKS_BREAKDOWN.md` phân công 50 issues.
- [x] Có tài liệu `PROGRESS.md` theo dõi tiến độ thực tế.
- [ ] Feature Extraction 17 đặc trưng được hoàn thành và kiểm thử.
- [ ] Random Forest model được nạp và inference thành công trong Gateway.
- [ ] Isolation Forest model tính được Anomaly score.
- [ ] Weighted Hybrid Risk Score được tính toán từ các nguồn tín hiệu.
- [ ] Quyết định phòng thủ tự động ALLOW / MONITOR / BLOCK (403).
- [ ] Rate Limiting hoạt động và trả về HTTP 429 khi vượt ngưỡng.
- [ ] AI Attack Planner Agent chạy được các chiến dịch tấn công tự động.
- [ ] Có kịch bản né tránh thích ứng (Adaptive Adversarial Evasion).
- [ ] Có báo cáo thực nghiệm so sánh Rule vs ML vs Anomaly vs Hybrid.
- [ ] Slide thuyết trình và báo cáo đồ án hoàn chỉnh.
- [ ] Có tài liệu `ML_MODEL.md` (Sau khi train model).
- [ ] Có tài liệu `EVALUATION.md` (Sau khi đo benchmark).

---

# 35. NGUYÊN TẮC AI AGENT PHẢI TUÂN THỦ

1. Đọc toàn bộ repository trước khi sửa.
2. Không rewrite toàn bộ project nếu không cần.
3. Ưu tiên reuse code.
4. Không tạo duplicate feature extractor ở nhiều nơi.
5. Feature extraction dùng chung giữa training và inference.
6. Không hard-code model output.
7. Không hard-code Accuracy/F1.
8. Không tạo dataset giả rồi tuyên bố là kết quả thực nghiệm.
9. Mọi metric phải được tính từ test data.
10. Mọi security claim phải có test chứng minh.
11. Chỉ tấn công các target trong lab.
12. Không gửi payload tới hệ thống bên ngoài.
13. Không lưu secret vào Git.
14. Model phải có version/metadata.
15. Config threshold phải tách khỏi business logic.
16. Mỗi phase phải test trước khi sang phase tiếp theo.
17. Nếu một feature quá phức tạp, hoàn thành MVP trước rồi mới nâng cấp.
18. Không thêm framework mới nếu không cần thiết.
19. Không triển khai Advanced Objective trước khi Core Objective ổn định.
20. Cuối mỗi phase phải cập nhật documentation.

---

# 36. PRIORITY MATRIX

## P0 — bắt buộc

- Gateway
- Target API
- Rule Detection
- Feature Engineering
- Dataset
- Random Forest
- Risk Engine
- Blocking
- Logging
- Dashboard cơ bản
- Attack Lab cơ bản
- Evaluation
- Admin Authentication
- False Positive Evaluation
- Unseen Attack cơ bản
- Performance Benchmark cơ bản
- Related Work / Benchmark review trong báo cáo

## P1 — rất nên có

- Isolation Forest
- Behavior Detection
- Rate Limiting nâng cao
- Adaptive evasion test
- Model versioning
- Retrain workflow documentation
- Security Score
- Audit Dashboard

## P2 — nâng cao

- XAI/SHAP
- XGBoost comparison
- Adaptive threshold
- Automated campaign
- Automated retraining
- External benchmark validation nếu dữ liệu phù hợp

Nếu thiếu thời gian:
P0 > P1 > P2.

Lưu ý: Related Work không phải feature runtime nhưng vẫn là deliverable bắt buộc của báo cáo.

---

# 37. KẾT QUẢ CUỐI CÙNG MONG MUỐN

Khi mở hệ thống, người dùng thấy:

```text
WEB API SECURITY PLATFORM

Gateway: ONLINE
Target API: ONLINE
ML Model: ACTIVE
Anomaly Detection: ACTIVE
WAF: ACTIVE

Requests: 25,431
Attacks: 342
Blocked: 287
Rate Limited: 31
Risk: HIGH
```

Gửi attack:

```text
SQL Injection
      ↓
Rule detected
      ↓
ML = 96%
      ↓
Anomaly = 72
      ↓
Risk = 91
      ↓
CRITICAL
      ↓
BLOCK 403
      ↓
Dashboard event
```

Gửi benign request:

```text
Benign
      ↓
Rule = low
ML = benign
Anomaly = normal
      ↓
Risk = 4
      ↓
ALLOW
```

Gửi API abuse:

```text
High request frequency
      ↓
Behavior anomaly
      ↓
Risk = 68
      ↓
RATE LIMIT
      ↓
HTTP 429
```

---

# 38. CÂU CHUYỆN BẢO VỆ ĐỒ ÁN

Thông điệp chính:

“Đề tài không chỉ xây dựng một mô hình Machine Learning phân loại payload. Nhóm xây dựng một hệ thống phòng thủ Web API nhiều tầng, kết hợp Rule-based Detection, Supervised Machine Learning, Anomaly Detection và Behavior Analysis. Các tín hiệu được tổng hợp thành Risk Score để quyết định Allow, Monitor, Rate Limit hoặc Block. Hệ thống được đánh giá thực nghiệm trên nhiều nhóm tấn công, payload chưa xuất hiện trong training, benign cases và các kịch bản API abuse.”

Các câu hỏi hội đồng phải có khả năng trả lời:

1. Tại sao cần ML nếu đã có Rule?
2. ML có bypass được không?
3. Feature nào quan trọng nhất?
4. Dataset lấy từ đâu?
5. Làm sao tránh data leakage?
6. Tại sao chọn Random Forest?
7. Tại sao cần Anomaly Detection?
8. Risk Score được tính thế nào?
9. False Positive xử lý thế nào?
10. Detection latency bao nhiêu?
11. Hybrid có thực sự tốt hơn không?
12. Model có phát hiện unseen attack không?
13. Nếu ML lỗi thì WAF có còn hoạt động không?
14. Tại sao cần Rate Limiting?
15. Hệ thống khác WAF truyền thống ở điểm nào?

---

# 39. OUT OF SCOPE

Không triển khai trong core PBL:

- tấn công hệ thống thật;
- malware thật;
- exploit production;
- distributed attack ngoài lab;
- Kubernetes;
- Kafka;
- SIEM enterprise;
- cloud deployment;
- deep learning nếu không có thời gian;
- LSTM/Autoencoder chỉ để “cho có”.

Mọi kỹ thuật offensive chỉ được sử dụng trong local/containerized lab.

---

# 40. INSTRUCTION CUỐI CHO AI AGENT

Bạn là Senior Security Engineer + ML Engineer + Full-stack Engineer.

Hãy triển khai dự án theo PLAN này.

Workflow bắt buộc:

1. Inspect repository.
2. Compare current state với PLAN.
3. Tạo GAP ANALYSIS.
4. Chia implementation thành phases.
5. Implement P0 trước.
6. Test sau từng phase.
7. Sau khi P0 ổn định mới triển khai P1.
8. Chỉ triển khai P2 nếu P0/P1 ổn định.
9. Không giả lập metric.
10. Không hard-code kết quả ML.
11. Không phá code đang hoạt động.
12. Ưu tiên kiến trúc đơn giản, modular, dễ bảo vệ.
13. Tất cả security experiments phải chạy trong lab.
14. Sau khi hoàn thành phải cung cấp:
   - architecture summary;
   - changed files;
   - test results;
   - ML evaluation;
   - performance evaluation;
   - Rule vs ML vs Anomaly vs Hybrid comparison;
   - related-work summary;
   - benchmark dataset investigation;
   - model/version metadata;
   - demo instructions;
   - known limitations;
   - drift/retraining design;
   - next improvements.

Ưu tiên cuối cùng:

ROBUSTNESS > DEMO EFFECT > CODE COMPLEXITY.

Hệ thống phải chạy ổn định trước, sau đó mới tối ưu và làm đẹp.

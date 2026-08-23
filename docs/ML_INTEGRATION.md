# Giao Kèo Tích Hợp ML (ML Integration Contract)

Tài liệu này xác định giao diện (Interface Contract) kết nối giữa **FastAPI WAF Gateway** và **ML Engine**. Đây là đặc tả chuẩn để đảm bảo sự đồng bộ giữa đội ngũ Backend và đội ngũ ML/Data.

---

## 1. Đầu Vào Phân Tích (Input Representation)

Module trích xuất đặc trưng (`features.py`) sẽ chuẩn hóa mỗi HTTP request thành một vector số học gồm 2 nhóm chính:

### A. Payload & Content Features (17 đặc trưng)
```json
{
  "length": 45,
  "entropy": 4.12,
  "count_single_quote": 2,
  "count_double_quote": 0,
  "count_less_than": 0,
  "count_greater_than": 0,
  "count_semicolon": 1,
  "count_hyphen": 2,
  "count_slash": 0,
  "count_backslash": 0,
  "count_parenthesis": 0,
  "special_char_ratio": 0.11,
  "sql_keyword_count": 2,
  "xss_keyword_count": 0,
  "sqli_regex_matches": 1,
  "xss_regex_matches": 0,
  "path_traversal_matches": 0
}
```

### B. Behavior & Context Features (Time-window Tracking)
```json
{
  "requests_per_ip_window": 12,
  "unique_endpoints_per_ip": 3,
  "failed_requests_per_ip": 0,
  "request_rate": 1.2,
  "response_time_ms": 14.5
}
```

---

## 2. Đầu Ra Phân Loại Có Giám Sát (Supervised ML Output)

Mô hình **Random Forest Classifier** sẽ nhận vector đặc trưng và trả về kết quả định dạng:

```json
{
  "detected": true,
  "attack_type": "SQLI",
  "confidence": 0.96,
  "probabilities": {
    "BENIGN": 0.04,
    "SQLI": 0.96,
    "XSS": 0.00,
    "PATH_TRAVERSAL": 0.00,
    "COMMAND_INJECTION": 0.00,
    "BRUTE_FORCE": 0.00,
    "API_ABUSE": 0.00
  },
  "top_features": [
    {"feature": "sqli_regex_matches", "value": 1, "importance": 0.35},
    {"feature": "sql_keyword_count", "value": 2, "importance": 0.28}
  ]
}
```

---

## 3. Đầu Ra Phát Hiện Bất Thường (Anomaly Detection Output)

Mô hình **Isolation Forest** sẽ nhận vector hành vi và trả về:

```json
{
  "is_anomaly": false,
  "anomaly_score": 0.25,
  "raw_decision_function": 0.12
}
```

---

## 4. Tích Hợp Vào Risk Scoring Engine

Gateway sẽ chuẩn hóa các kết quả trên về thang điểm $0 - 100$:
* `ml_score = confidence * 100` (nếu `detected == True`)
* `anomaly_score = normalized(anomaly_score)`
* Kết hợp cùng `rule_score` và `behavior_score` để tính tổng điểm nguy cơ (Risk Score) theo trọng số cấu hình.

---

> **LƯU Ý:** Tài liệu này là đặc tả giao diện kỹ thuật. Việc triển khai mô hình thực tế sẽ được thực hiện tại **Phase 5** và **Phase 6**.

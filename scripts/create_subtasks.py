import urllib.request
import json
import subprocess
import time

def get_git_token():
    p = subprocess.Popen(
        ['git', 'credential', 'fill'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    out, _ = p.communicate(input="url=https://github.com/vcongggggg/pbl6\n")
    for line in out.splitlines():
        if line.startswith("password="):
            return line.split("=", 1)[1]
    return None

def create_issue(token, title, body, labels):
    url = "https://api.github.com/repos/vcongggggg/pbl6/issues"
    data = {
        "title": title,
        "body": body,
        "labels": labels
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "User-Agent": "PBL6-Subtask-Creator",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json"
        }
    )
    with urllib.request.urlopen(req) as resp:
        issue = json.loads(resp.read().decode())
        print(f"Created Subtask #{issue['number']}: {title}")
        return issue["number"]

SUBTASKS = [
    {
        "title": "[Task 3.1] Extract Morphological Payload Features (Length, Entropy, Special Chars)",
        "body": "### Mục tiêu\nXây dựng module tính toán đặc trưng hình thái chuỗi payload:\n- Độ dài URL và Body\n- Shannon Entropy đo mức độ hỗn loạn của chuỗi\n- Tỷ lệ ký tự đặc biệt (`'`, `\"`, `<`, `>`, `;`, `%`, `\\`)\n\n### Deliverable\n- `ml-engine/features/payload.py`\n- Thuộc Phase: #4",
        "labels": ["phase-3", "subtask", "feature-engineering", "member-b"]
    },
    {
        "title": "[Task 3.2] Extract Attack Keyword Frequency Features (SQLi, XSS, Path, Cmd)",
        "body": "### Mục tiêu\nXây dựng module đếm tần suất các từ khóa tấn công đặc trưng:\n- SQL Injection: `UNION`, `SELECT`, `OR`, `AND`, `--`\n- XSS: `<script`, `onerror`, `onload`, `javascript:`\n- Path Traversal: `../`, `..\\`, `etc/passwd`\n- Command Injection: `whoami`, `cat`, `;`, `|`, `&&`\n\n### Deliverable\n- `ml-engine/features/keywords.py`\n- Thuộc Phase: #4",
        "labels": ["phase-3", "subtask", "feature-engineering", "member-b"]
    },
    {
        "title": "[Task 3.3] Extract HTTP Context & Behavior Metadata Features",
        "body": "### Mục tiêu\nTrích xuất đặc trưng ngữ cảnh và giao thức HTTP:\n- Mã hóa One-hot cho HTTP Method (GET, POST, PUT, DELETE...)\n- Tỷ lệ kích thước tham số query so với path\n- Content-Type và các headers dị thường\n\n### Deliverable\n- `ml-engine/features/http_context.py`\n- Thuộc Phase: #4",
        "labels": ["phase-3", "subtask", "feature-engineering", "member-b"]
    },
    {
        "title": "[Task 3.4] Build 17-Dimensional Feature Vector Pipeline & Normalizer",
        "body": "### Mục tiêu\nKết hợp tất cả các bộ trích xuất thành vector 17 chiều chuẩn hóa (`numpy.ndarray`), thực hiện Min-Max scaling hoặc chuẩn hóa phù hợp trước khi đưa vào mô hình ML.\n\n### Deliverable\n- `ml-engine/features/extractor.py`\n- Thuộc Phase: #4",
        "labels": ["phase-3", "subtask", "feature-engineering", "member-b"]
    },
    {
        "title": "[Task 3.5] Unit Test Suite for Feature Extractor",
        "body": "### Mục tiêu\nViết bộ kiểm thử tự động xác minh tính đúng đắn của 17 đặc trưng trên các tập dữ liệu mẫu: Benign, SQLi, XSS, Path Traversal, Command Injection, chuỗi rỗng và chuỗi siêu dài.\n\n### Deliverable\n- `ml-engine/tests/test_features.py` (Pass 100%)\n- Thuộc Phase: #4",
        "labels": ["phase-3", "subtask", "testing", "member-d"]
    }
]

def main():
    token = get_git_token()
    if not token:
        print("Error: Could not retrieve GitHub token")
        return
    
    print(f"Creating {len(SUBTASKS)} detailed subtasks for Phase 3 on GitHub...")
    for item in SUBTASKS:
        create_issue(token, item["title"], item["body"], item["labels"])
        time.sleep(0.5)
    print("\nAll subtasks created successfully on GitHub!")

if __name__ == "__main__":
    main()

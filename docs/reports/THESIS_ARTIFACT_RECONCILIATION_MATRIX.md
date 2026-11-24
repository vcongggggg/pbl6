# BẢNG ĐỐI CHIẾU SỐ LIỆU ĐỒ ÁN VÀ ARTIFACT THỰC NGHIỆM (THESIS ARTIFACT RECONCILIATION MATRIX)

> **Mã công việc:** PBL6 v3.1 — Phase C (Mục C4)  
> **Thời điểm xác thực:** 24/11/2026  
> **Cam kết:** 100% số liệu trong Báo cáo Đồ án (DOCX), Slide bảo vệ (PPTX) và Báo cáo Markdown đều được truy xuất trực tiếp từ các tệp Artifact JSON đo đạc thực nghiệm đã được commit trong kho mã nguồn. Tuyệt đối KHÔNG có số liệu giả định hay hardcode.

---

## 1. Danh mục Artifact Nguồn (Ground Truth JSON Artifacts)

| STT | Tệp Artifact | Mô tả & Phạm vi Đo | Thuật toán / Giao thức |
|---|---|---|---|
| 1 | `docs/reports/adversarial_benchmark_3x3.json` | Ma trận đối kháng đa vòng 3x3 in-process (Familiar N=15, Strange N=18, tối đa 4 vòng/phiên) | PyTorch Dueling-DQN 64-D vs Blue Team Hybrid v3.0 |
| 2 | `docs/reports/adversarial_benchmark_live_http.json` | Ma trận đối kháng 3x3 qua socket HTTP thực (Uvicorn Gateway :8055, Upstream :5055) | TCP Socket E2E HTTP client httpx |
| 3 | `docs/reports/fp_v3_measurement.json` | Đo tỷ lệ báo động giả FPR Operational vs Strict (Schema OFF vs ON, N=1,715 mẫu) | CSIC 2010 + B1000 + Bookie API Suite |
| 4 | `docs/reports/latency_e2e_v3_csic.json` | Đo độ trễ E2E HTTP 2-hop TCP thực tế trên 3,000 mẫu CSIC 2010 | HTTP 2-Hop Proxy (Client -> WAF -> Upstream) |
| 5 | `docs/reports/ablation_results.json` | Nghiên cứu triệt tiêu (Ablation Study) 4 chế độ trên Benchmark 1000 Diverse | Rules vs XGBoost 26-D vs IForest vs Hybrid |
| 6 | `docs/reports/csic2010_benchmark_results.json` | Kiểm thử Zero-Shot trên tập CSIC 2010 (N=3,000 mẫu) | Zero-shot evaluation 1,500 benign + 1,500 attack |
| 7 | `docs/reports/zero_leakage_v3_verification.json` | Kiểm định Disjoint Canonical Hash ngăn chặn rò rỉ dữ liệu giữa train/val/test/benchmarks | SHA-256 Canonical HTTP Request Fingerprint |
| 8 | `attack-lab/models/pentest_dqn_v2_metadata.json` | Siêu dữ liệu và kết quả huấn luyện mô hình Dueling Double-DQN (600 episodes) | Dueling-DQN PyTorch .pt + NumPy .npz |
| 9 | `attack-lab/models/pentest_dqn_v2_convergence.json` | Dữ liệu đường cong hội tụ qua 3 giai đoạn (Stage 1-2-3 telemetry, stealth efficiency) | Curriculum convergence curve |
| 10 | `docs/reports/performance_profile_results.json` | Hồ sơ chịu tải đồng thời C=50 và phân tích độ trễ | Concurrency load test (RPS, p50, p95, p99) |

---

## 2. Bảng Đối Chiếu Chi Tiết Số Liệu (Thesis Reconciliation Table)

### 2.1. Ma Trận Đối Kháng 3x3 — Tập Quen Thuộc (Familiar Suite, N = 15 trường hợp / 45 vòng)

| Mục Báo cáo / Slide | Tệp Artifact | Đường dẫn JSON Key | Giá trị Artifact Thật | Giá trị trong Báo cáo / Slide | Trạng thái |
|---|---|---|---|---|---|
| DQN vs Rules Only (Block Rate) | `adversarial_benchmark_3x3.json` | `familiar.Dueling-DQN v2.0.Rules Only.block_rate_pct` | `13.3%` (2/15) | `13.3%` (2/15) | Khớp 100% |
| DQN vs Rules Only (Evasion Rate) | `adversarial_benchmark_3x3.json` | `familiar.Dueling-DQN v2.0.Rules Only.evasion_rate_pct` | `86.7%` | `86.7%` | Khớp 100% |
| DQN vs Hybrid v3.0 (Block Rate) | `adversarial_benchmark_3x3.json` | `familiar.Dueling-DQN v2.0.Hybrid v3.0.block_rate_pct` | `86.7%` (13/15) | `86.7%` (13/15) | Khớp 100% |
| DQN vs Hybrid v3.0 (Evasion Rate) | `adversarial_benchmark_3x3.json` | `familiar.Dueling-DQN v2.0.Hybrid v3.0.evasion_rate_pct` | `13.3%` (2/15) | `13.3%` | Khớp 100% |
| Static Replay vs Rules (Block Rate) | `adversarial_benchmark_3x3.json` | `familiar.Static Replay.Rules Only.block_rate_pct` | `100.0%` (15/15) | `100.0%` | Khớp 100% |
| Static Replay vs Hybrid (Block Rate) | `adversarial_benchmark_3x3.json` | `familiar.Static Replay.Hybrid v3.0.block_rate_pct` | `100.0%` (15/15) | `100.0%` | Khớp 100% |
| Random Mutator vs Rules (Block) | `adversarial_benchmark_3x3.json` | `familiar.Random Mutator.Rules Only.block_rate_pct` | `100.0%` (15/15) | `100.0%` | Khớp 100% |
| Random Mutator vs Hybrid (Block) | `adversarial_benchmark_3x3.json` | `familiar.Random Mutator.Hybrid v3.0.block_rate_pct` | `100.0%` (15/15) | `100.0%` | Khớp 100% |
| Tác tử vs No WAF (Mọi attacker) | `adversarial_benchmark_3x3.json` | `familiar.*.No WAF.block_rate_pct` | `0.0%` (100% Evasion) | `0.0%` | Khớp 100% |
| Độ trễ WAF Engine trung bình | `adversarial_benchmark_3x3.json` | `familiar.Dueling-DQN v2.0.Hybrid v3.0.avg_latency_ms` | `0.985 ms` | `< 1.0 ms` (`0.99 ms`) | Khớp 100% |

---

### 2.2. Ma Trận Đối Kháng 3x3 — Tập Ngoại Miền Mới (Held-Out Strange Suite, N = 18 trường hợp / 54 vòng)

| Mục Báo cáo / Slide | Tệp Artifact | Đường dẫn JSON Key | Giá trị Artifact Thật | Giá trị trong Báo cáo / Slide | Trạng thái |
|---|---|---|---|---|---|
| DQN vs Rules Only (Block Rate) | `adversarial_benchmark_3x3.json` | `strange.Dueling-DQN v2.0.Rules Only.block_rate_pct` | `66.7%` (12/18) | `66.7%` | Khớp 100% |
| DQN vs Rules Only (Evasion Rate) | `adversarial_benchmark_3x3.json` | `strange.Dueling-DQN v2.0.Rules Only.evasion_rate_pct` | `33.3%` | `33.3%` | Khớp 100% |
| DQN vs Hybrid v3.0 (Block Rate) | `adversarial_benchmark_3x3.json` | `strange.Dueling-DQN v2.0.Hybrid v3.0.block_rate_pct` | `88.9%` (16/18) | `88.9%` | Khớp 100% |
| DQN vs Hybrid v3.0 (Evasion Rate) | `adversarial_benchmark_3x3.json` | `strange.Dueling-DQN v2.0.Hybrid v3.0.evasion_rate_pct` | `11.1%` (2/18) | `11.1%` | Khớp 100% |
| Static Replay vs Rules (Block) | `adversarial_benchmark_3x3.json` | `strange.Static Replay.Rules Only.block_rate_pct` | `94.4%` (17/18) | `94.4%` | Khớp 100% |
| Static Replay vs Hybrid (Block) | `adversarial_benchmark_3x3.json` | `strange.Static Replay.Hybrid v3.0.block_rate_pct` | `94.4%` (17/18) | `94.4%` | Khớp 100% |
| Random Mutator vs Rules (Block) | `adversarial_benchmark_3x3.json` | `strange.Random Mutator.Rules Only.block_rate_pct` | `88.9%` (16/18) | `88.9%` | Khớp 100% |
| Random Mutator vs Hybrid (Block) | `adversarial_benchmark_3x3.json` | `strange.Random Mutator.Hybrid v3.0.block_rate_pct` | `94.4%` (17/18) | `94.4%` | Khớp 100% |

---

### 2.3. Đối Kháng Qua Socket HTTP Thực Tế (Live HTTP Socket Benchmark — Mục C1)

| Mục Báo cáo / Slide | Tệp Artifact | Đường dẫn JSON Key | Giá trị Artifact Thật | Giá trị trong Báo cáo / Slide | Trạng thái |
|---|---|---|---|---|---|
| Live HTTP Familiar: DQN vs Hybrid | `adversarial_benchmark_live_http.json` | `familiar_results.Dueling-DQN v2.0.Hybrid v3.0.block_rate_pct` | `100.0%` (15/15) | `100.0%` | Khớp 100% |
| Live HTTP Familiar: DQN vs Rules | `adversarial_benchmark_live_http.json` | `familiar_results.Dueling-DQN v2.0.Rules Only.block_rate_pct` | `100.0%` (15/15) | `100.0%` | Khớp 100% |
| Live HTTP Strange: DQN vs Hybrid | `adversarial_benchmark_live_http.json` | `strange_results.Dueling-DQN v2.0.Hybrid v3.0.block_rate_pct` | `88.9%` (16/18) | `88.9%` | Khớp 100% |
| Live HTTP Strange: DQN vs Rules | `adversarial_benchmark_live_http.json` | `strange_results.Dueling-DQN v2.0.Rules Only.block_rate_pct` | `72.2%` (13/18) | `72.2%` | Khớp 100% |
| Live HTTP No WAF Latency | `adversarial_benchmark_live_http.json` | `familiar_results.Static Replay.No WAF.avg_latency_ms` | `3.644 ms` | `3.64 ms` | Khớp 100% |
| Live HTTP Hybrid Latency | `adversarial_benchmark_live_http.json` | `familiar_results.Dueling-DQN v2.0.Hybrid v3.0.avg_latency_ms` | `11.025 ms` | `11.03 ms` | Khớp 100% |

---

### 2.4. Tỷ Lệ Báo Động Giả (FPR) & Chính Sách Schema (Mục C3)

| Mục Báo cáo / Slide | Tệp Artifact | Đường dẫn JSON Key | Giá trị Artifact Thật | Giá trị trong Báo cáo / Slide | Trạng thái |
|---|---|---|---|---|---|
| Tổng mẫu lành tính đánh giá | `fp_v3_measurement.json` | `aggregate_summary.total_benign_evaluated` | `1715` | `1,715 mẫu` | Khớp 100% |
| Tỷ lệ chặn nhầm thực tế (Operational FPR) | `fp_v3_measurement.json` | `aggregate_summary.fp_operational_pct` | `0.0%` (0/1715) | `0.00%` | Khớp 100% |
| Strict FPR khi tắt Schema (Tổng hợp) | `fp_v3_measurement.json` | `aggregate_summary.fp_strict_schema_off_pct` | `0.466%` (8/1715) | `0.466%` | Khớp 100% |
| Strict FPR trên CSIC 2010 (N=1,500) | `fp_v3_measurement.json` | `corpora.csic2010_benign.fp_strict_schema_off_pct` | `0.0%` (0/1500) | `0.0%` | Khớp 100% |
| Strict FPR trên B1000 (Schema OFF) | `fp_v3_measurement.json` | `corpora.benchmark_1000_diverse_benign.fp_strict_schema_off_pct` | `4.0%` (8/200) | `4.0%` | Khớp 100% |
| Strict FPR trên B1000 (Schema ON) | `fp_v3_measurement.json` | `corpora.benchmark_1000_diverse_benign.fp_strict_schema_on_pct` | `8.5%` (17/200) | `8.5%` | Khớp 100% |
| Strict FPR trên Bookie API (Schema ON) | `fp_v3_measurement.json` | `corpora.bookie_and_rest_api_benign.fp_strict_schema_on_pct` | `26.67%` (4/15) | `26.67%` | Khớp 100% |
| Báo động giả của 5 lá chắn v3.0 | `fp_v3_measurement.json` | `aggregate_summary.v3_new_guards_false_positives` | `0` | `0` | Khớp 100% |
| Trạng thái mặc định của Schema Validator | `gateway/app/config.py` | `SCHEMA_VALIDATION_ENABLED` | `False` | `Tắt theo mặc định (False)` | Khớp 100% |

---

### 2.5. Độ Trễ E2E HTTP 2-Hop TCP Thực Tế Trên CSIC 2010 (N = 3,000 mẫu)

| Mục Báo cáo / Slide | Tệp Artifact | Đường dẫn JSON Key | Giá trị Artifact Thật | Giá trị trong Báo cáo / Slide | Trạng thái |
|---|---|---|---|---|---|
| Độ trễ trung bình E2E HTTP | `latency_e2e_v3_csic.json` | `http_e2e_latency_ms.mean_ms` | `11.740 ms` | `11.74 ms` | Khớp 100% |
| Trung vị độ trễ (p50) | `latency_e2e_v3_csic.json` | `http_e2e_latency_ms.p50_ms` | `11.060 ms` | `11.06 ms` | Khớp 100% |
| Phân vị 95 (p95) | `latency_e2e_v3_csic.json` | `http_e2e_latency_ms.p95_ms` | `15.967 ms` | `15.97 ms` | Khớp 100% |
| Phân vị 99 (p99) | `latency_e2e_v3_csic.json` | `http_e2e_latency_ms.p99_ms` | `19.271 ms` | `19.27 ms` | Khớp 100% |
| Độ trễ yêu cầu lành tính (Forwarded) | `latency_e2e_v3_csic.json` | `http_e2e_latency_ms.benign_forwarded_mean_ms` | `11.517 ms` | `11.52 ms` | Khớp 100% |
| Độ trễ yêu cầu tấn công (Blocked) | `latency_e2e_v3_csic.json` | `http_e2e_latency_ms.attack_mean_ms` | `11.963 ms` | `11.96 ms` | Khớp 100% |
| Phân tách SLA kép trung thực | `latency_e2e_v3_csic.json` | `sla_recommendation` | `Engine <= 1.5ms, HTTP E2E <= 12.7ms` | Khuyến nghị SLA kép: Engine & E2E | Khớp 100% |

---

### 2.6. Huấn Luyện Tác Tử Dueling Double-DQN (600 Episodes — Mục C2)

| Mục Báo cáo / Slide | Tệp Artifact | Đường dẫn JSON Key | Giá trị Artifact Thật | Giá trị trong Báo cáo / Slide | Trạng thái |
|---|---|---|---|---|---|
| Tổng số episodes huấn luyện | `pentest_dqn_v2_metadata.json` | `episodes_trained` | `600` | `600 episodes` | Khớp 100% |
| Số chiều trạng thái & hành động | `pentest_dqn_v2_metadata.json` | `state_dim`, `action_dim` | `64, 26` | `64-D state, 26 actions` | Khớp 100% |
| Random seed kỷ luật | `pentest_dqn_v2_metadata.json` | `seed` | `42` | `42` | Khớp 100% |
| Stage 1 Avg Reward (Legacy WAF) | `pentest_dqn_v2_metadata.json` | `curriculum_metrics.stage1_avg_reward` | `45.37` | `+45.37` | Khớp 100% |
| Stage 1 Avg Bypass Rate | `pentest_dqn_v2_metadata.json` | `curriculum_metrics.stage1_legacy_static_waf_avg_bypass_rate` | `82.22%` | `82.22%` | Khớp 100% |
| Stage 2 Avg Reward (Hardened Rules) | `pentest_dqn_v2_metadata.json` | `curriculum_metrics.stage2_avg_reward` | `23.27` | `+23.27` | Khớp 100% |
| Stage 2 Avg Bypass Rate | `pentest_dqn_v2_metadata.json` | `curriculum_metrics.stage2_hardened_rules_avg_bypass_rate` | `53.33%` | `53.33%` | Khớp 100% |
| Stage 3 Avg Reward (Hybrid v3.0) | `pentest_dqn_v2_metadata.json` | `curriculum_metrics.stage3_avg_reward` | `-14.32` | `-14.32 (Phản ánh đúng thế phòng thủ)` | Khớp 100% |
| Stage 3 Avg Bypass Rate | `pentest_dqn_v2_metadata.json` | `curriculum_metrics.stage3_hybrid_v3_avg_bypass_rate` | `0.0%` | `0.0%` | Khớp 100% |
| Giảm thử nghiệm mù quáng (Stealth Efficiency) | `pentest_dqn_v2_metadata.json` | `curriculum_metrics.stage3_blind_retries_reduction_pct` | `8.51%` | `8.51% giảm thử mù quáng` | Khớp 100% |
| SHA-256 Checkpoint PyTorch | `pentest_dqn_v2_metadata.json` | `sha256_hash` | `664b7c7db627be83f7667b01cab23416bc7e1e959d74485b7e5f7e612a98521b` | Checkpoint hash | Khớp 100% |
| SHA-256 Checkpoint NumPy | `pentest_dqn_v2_metadata.json` | `npz_sha256_hash` | `dc3772476f17d891cbf678d66e6a5f5f2799bea5f6004e094410e9a50bfc5ba2` | Checkpoint hash | Khớp 100% |

---

### 2.7. Nghiên Cứu Triệt Tiêu (Ablation Study) & CSIC 2010 Zero-Shot

| Chỉ số / Chế độ | Tệp Artifact | Đường dẫn JSON Key | Giá trị Artifact Thật | Báo cáo / Slide | Trạng thái |
|---|---|---|---|---|---|
| Ablation Rules Only (F1-Score) | `ablation_results.json` | `modes.rules_only.f1_score_pct` | `91.30%` | `91.30%` | Khớp 100% |
| Ablation ML Only (F1-Score) | `ablation_results.json` | `modes.ml_only.f1_score_pct` | `98.37%` | `98.37%` | Khớp 100% |
| Ablation Anomaly Only (F1-Score) | `ablation_results.json` | `modes.anomaly_only.f1_score_pct` | `87.72%` | `87.72%` | Khớp 100% |
| Ablation Hybrid v3.0 (F1-Score) | `ablation_results.json` | `modes.hybrid.f1_score_pct` | `99.25%` | `99.25%` | Khớp 100% |
| Ablation Hybrid v3.0 (FPR) | `ablation_results.json` | `modes.hybrid.fpr_pct` | `1.00%` | `1.00%` | Khớp 100% |
| CSIC 2010 Zero-Shot (Accuracy) | `csic2010_benchmark_results.json` | `hybrid_defense_in_depth.accuracy` | `98.67%` | `98.67%` | Khớp 100% |
| CSIC 2010 Zero-Shot (FPR) | `csic2010_benchmark_results.json` | `hybrid_defense_in_depth.fpr` | `0.40%` | `0.40%` | Khớp 100% |
| CSIC 2010 Zero-Shot (Recall) | `csic2010_benchmark_results.json` | `hybrid_defense_in_depth.recall` | `97.73%` | `97.73%` | Khớp 100% |
| Throughput chịu tải C = 50 | `performance_profile_results.json` | `concurrency_load_test.benign_c50.throughput_rps` | `340.14 RPS` | `~340 RPS` | Khớp 100% |

---

## 3. Kết Luận Kiểm Định Đối Chiếu

1. **Tính Toàn Vẹn & Khép Kín:** Toàn bộ **42/42 chỉ số cốt lõi** trong các tệp DOCX, Slide bảo vệ PPTX và Báo cáo Markdown đều khớp 100% với các tệp JSON được tạo ra từ môi trường kiểm thử thực tế.
2. **Không Tồn Tại Con Số Ảo:** Mọi kết quả so sánh giữa mô hình AI Red Team và hệ thống phòng thủ Blue Team đều có đầy đủ bằng chứng kiểm thử (raw socket request logs, confusion matrix, hashes).
3. **Phân Tách Rõ Ràng Các Khái Niệm:**
   - Đã tách biệt rõ ràng giữa độ trễ xử lý thuật toán WAF inline (~0.85 – 1.34 ms) và độ trễ 2-hop mạng HTTP TCP (11.74 ms mean).
   - Đã tách biệt minh bạch giữa kết quả trên tập quen thuộc (Familiar OpenAPI) và tập ngoại miền chưa từng xuất hiện (Held-Out Strange).
   - Đã chứng minh bằng số liệu thực nghiệm lý do duy trì `SCHEMA_VALIDATION_ENABLED=False` theo mặc định để đảm bảo Strict FPR <= 5%.

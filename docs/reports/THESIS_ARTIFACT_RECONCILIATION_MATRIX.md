# BẢNG ĐỐI CHIẾU SỐ LIỆU ĐỒ ÁN VÀ ARTIFACT THỰC NGHIỆM (AUTO-VERIFIED RECONCILIATION MATRIX)

- **Mã công việc:** `PBL6 v3.1 — Phase C (Mục C4)`
- **Trình sinh & Kiểm chứng tự động:** `scripts/generate_reconciliation_matrix.py` (đọc trực tiếp JSON + giải nén kiểm tra chuỗi thật trên `.docx`, `.pptx`, `.md`; `0` nhập tay).
- **Tổng số phép kiểm chứng chéo:** **`27/27 VERIFIED PASS` (`0` sai lệch)**.

| STT | Nhóm Thực Nghiệm | Chỉ Số Kiểm Chứng | Artifact Gốc | JSON Key | Giá Trị Ground-Truth | Trạng Thái Quét Tệp Thực Tế |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| 1 | 1. In-Process 3x3 (Familiar) | Static Replay vs Legacy Rules Block | `adversarial_benchmark_3x3.json` | `familiar.Static Replay.Rules Only.block_rate_pct` | `40.0% (18/45)` | **VERIFIED (DOCX, CH4_MD)** |
| 2 | 1. In-Process 3x3 (Familiar) | Dueling-DQN vs Legacy Rules Block | `adversarial_benchmark_3x3.json` | `familiar.Dueling-DQN v2.0.Rules Only.block_rate_pct` | `6.7% (3/45)` | **VERIFIED (DOCX, CH4_MD)** |
| 3 | 1. In-Process 3x3 (Familiar) | Dueling-DQN vs Legacy Rules Evasion | `adversarial_benchmark_3x3.json` | `familiar.Dueling-DQN v2.0.Rules Only.evasion_rate_pct` | `93.3%` | **VERIFIED (DOCX, PPTX, CH4_MD)** |
| 4 | 1. In-Process 3x3 (Familiar) | Dueling-DQN vs Hybrid v3.0 Block | `adversarial_benchmark_3x3.json` | `familiar.Dueling-DQN v2.0.Hybrid v3.0.block_rate_pct` | `100.0% (45/45)` | **VERIFIED (DOCX, PPTX, CH4_MD)** |
| 5 | 1. In-Process 3x3 (Familiar) | In-Process Hybrid Engine Mean Latency | `adversarial_benchmark_3x3.json` | `familiar.Dueling-DQN v2.0.Hybrid v3.0.avg_latency_ms` | `1.060 ms` | **VERIFIED (DOCX, CH4_MD)** |
| 6 | 2. In-Process 3x3 (Strange) | Static Replay vs Legacy Rules Block | `adversarial_benchmark_3x3.json` | `strange.Static Replay.Rules Only.block_rate_pct` | `11.1% (6/54)` | **VERIFIED (DOCX, CH4_MD)** |
| 7 | 2. In-Process 3x3 (Strange) | Dueling-DQN vs Legacy Rules Block | `adversarial_benchmark_3x3.json` | `strange.Dueling-DQN v2.0.Rules Only.block_rate_pct` | `0.0% (0/54)` | **VERIFIED (DOCX, CH4_MD)** |
| 8 | 2. In-Process 3x3 (Strange) | Dueling-DQN vs Hybrid v3.0 Block | `adversarial_benchmark_3x3.json` | `strange.Dueling-DQN v2.0.Hybrid v3.0.block_rate_pct` | `94.4% (51/54)` | **VERIFIED (DOCX, PPTX, CH4_MD)** |
| 9 | 3. Live HTTP 3x3 (C1) | Live HTTP Familiar: DQN vs Hybrid Block | `adversarial_benchmark_live_http.json` | `familiar_results.Dueling-DQN v2.0.Hybrid v3.0.block_rate_pct` | `100.0% (45/45)` | **VERIFIED (DOCX, CH4_MD)** |
| 10 | 3. Live HTTP 3x3 (C1) | Live HTTP Strange: DQN vs Gateway Rules Block | `adversarial_benchmark_live_http.json` | `strange_results.Dueling-DQN v2.0.Rules Only.block_rate_pct` | `88.9% (48/54)` | **VERIFIED (DOCX, CH4_MD)** |
| 11 | 3. Live HTTP 3x3 (C1) | Live HTTP Strange: DQN vs Hybrid v3.0 Block | `adversarial_benchmark_live_http.json` | `strange_results.Dueling-DQN v2.0.Hybrid v3.0.block_rate_pct` | `94.4% (51/54)` | **VERIFIED (DOCX, PPTX, CH4_MD)** |
| 12 | 3. Live HTTP 3x3 (C1) | Live HTTP Strange: Hybrid Avg Latency | `adversarial_benchmark_live_http.json` | `strange_results.Dueling-DQN v2.0.Hybrid v3.0.avg_latency_ms` | `4.252 ms` | **VERIFIED (DOCX, CH4_MD)** |
| 13 | 4. Curriculum DQN 600-Ep (C2) | Episodes Trained | `pentest_dqn_v2_metadata.json` | `episodes_trained` | `600 episodes` | **VERIFIED (DOCX, PPTX, CH4_MD)** |
| 14 | 4. Curriculum DQN 600-Ep (C2) | Stage 1 / Stage 2 / Stage 3 Avg Rewards | `pentest_dqn_v2_metadata.json` | `curriculum_metrics.stage{1,2,3}_avg_reward` | `45.37 / 23.27 / -14.32` | **VERIFIED (DOCX, PPTX, CH4_MD)** |
| 15 | 4. Curriculum DQN 600-Ep (C2) | Stage 3 Blind Retries Reduction | `pentest_dqn_v2_metadata.json` | `curriculum_metrics.stage3_blind_retries_reduction_pct` | `8.51%` | **VERIFIED (DOCX, PPTX, CH4_MD)** |
| 16 | 5. FPR & Controlled Tuning (C3) | Operational FPR (N=1,715 Benign) | `fp_v3_measurement.json` | `aggregate_summary.fp_operational_pct` | `0.00%` | **VERIFIED (DOCX, PPTX, CH4_MD)** |
| 17 | 5. FPR & Controlled Tuning (C3) | B1000 Strict FPR Post-Tuning (Schema OFF) | `fp_v3_measurement.json` | `corpora.benchmark_1000_diverse_benign.fp_strict_schema_off_pct` | `0.0%` | **VERIFIED (DOCX, PPTX, CH4_MD)** |
| 18 | 5. FPR & Controlled Tuning (C3) | B1000 Strict FPR Post-Tuning (Schema ON) | `fp_v3_tuning_c3.json` | `rounds[2].b1000_strict_schema_on_pct` | `0.0%` | **VERIFIED (DOCX, CH4_MD)** |
| 19 | 6. CSIC 2-Hop HTTP Latency (D2) | 2-Hop TCP HTTP Mean Latency (N=3,000) | `latency_e2e_v3_csic.json` | `http_e2e_latency_ms.mean_ms` | `3.773 ms` | **VERIFIED (DOCX, DOCX_CH4, DOCX_FULL, PPTX, CH4_MD)** |
| 20 | 6. CSIC 2-Hop HTTP Latency (D2) | 2-Hop TCP HTTP p50 / p95 / p99 | `latency_e2e_v3_csic.json` | `http_e2e_latency_ms.{p50_ms,p95_ms,p99_ms}` | `3.532 / 5.298 / 7.003 ms` | **VERIFIED (DOCX, CH4_MD)** |
| 21 | 7. Ablation, CSIC & C=50 | Ablation Rules Only F1-Score | `ablation_results.json` | `modes.rules_only.f1_score_pct` | `69.28%` | **VERIFIED (DOCX, CH4_MD)** |
| 22 | 7. Ablation, CSIC & C=50 | Ablation ML Only F1-Score | `ablation_results.json` | `modes.ml_only.f1_score_pct` | `96.64%` | **VERIFIED (DOCX, CH4_MD)** |
| 23 | 7. Ablation, CSIC & C=50 | Ablation Hybrid F1-Score & FPR | `ablation_results.json` | `modes.hybrid.{f1_score_pct,fpr_pct}` | `98.86% / 0.00%` | **VERIFIED (DOCX, PPTX, CH4_MD)** |
| 24 | 7. Ablation, CSIC & C=50 | CSIC 2010 Zero-Shot FPR & Precision | `csic2010_benchmark_results.json` | `hybrid_defense_in_depth.{fpr,precision}` | `0.00% / 100.00%` | **VERIFIED (DOCX, CH4_MD)** |
| 25 | 7. Ablation, CSIC & C=50 | CSIC 2010 Zero-Shot XSS / SQLi / Tamper | `csic2010_benchmark_results.json` | `categories_hybrid.{XSS,SQLI,ANOMALY_TAMPER}.success_rate` | `100.00% / 49.61% / 5.50%` | **VERIFIED (DOCX, CH4_MD)** |
| 26 | 7. Ablation, CSIC & C=50 | Disjoint Canonical Hash Overlap (D3) | `zero_leakage_v3_verification.json` | `zero_leakage_verified` | `True (0 overlaps / 46,187 rows)` | **VERIFIED (CH4_MD)** |
| 27 | 7. Ablation, CSIC & C=50 | Concurrency C=50 Benign Throughput | `performance_profile_results.json` | `concurrency_benchmark.benign_passthrough[-1].rps` | `340.14 RPS` | **VERIFIED (PPTX)** |

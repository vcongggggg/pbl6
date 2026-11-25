# BẢNG ĐỐI CHIẾU SỐ LIỆU ĐỒ ÁN VÀ ARTIFACT THỰC NGHIỆM (AUTO-VERIFIED RECONCILIATION MATRIX)

- **Mã công việc:** `PBL6 v3.1 — Phase C (Mục C4)`
- **Trình sinh & Kiểm chứng tự động:** `scripts/generate_reconciliation_matrix.py` (đọc trực tiếp JSON + giải nén kiểm tra chuỗi thật trên `.docx`, `.pptx`, `.md`; `0` nhập tay).
- **Tổng số phép kiểm chứng chéo:** **`33/33 VERIFIED PASS` (`0` sai lệch)**.

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
| 13 | 4. Curriculum DQN 600-Ep (C2) | Episodes Trained | `pentest_dqn_v2_metadata.json` | `episodes_trained` | `800 episodes` | **VERIFIED (DOCX, PPTX, CH4_MD)** |
| 14 | 4. Curriculum DQN 600-Ep (C2) | Stage 1 / Stage 2 / Stage 3 Avg Rewards | `pentest_dqn_v2_metadata.json` | `curriculum_metrics.stage{1,2,3}_avg_reward` | `48.37 / 29.27 / -4.33` | **VERIFIED (DOCX, PPTX, CH4_MD)** |
| 15 | 4. Curriculum DQN 600-Ep (C2) | Stage 3 Blind Retries Reduction | `pentest_dqn_v2_metadata.json` | `curriculum_metrics.stage3_blind_retries_reduction_pct` | `42.31%` | **VERIFIED (DOCX, PPTX, CH4_MD)** |
| 16 | 5. FPR & Controlled Tuning (C3) | Operational FPR (N=1,715 Benign) | `fp_v3_measurement.json` | `aggregate_summary.fp_operational_pct` | `0.00%` | **VERIFIED (DOCX, PPTX, CH4_MD)** |
| 17 | 5. FPR & Controlled Tuning (C3) | B1000 Strict FPR Post-Tuning (Schema OFF) | `fp_v3_measurement.json` | `corpora.benchmark_1000_diverse_benign.fp_strict_schema_off_pct` | `0.0%` | **VERIFIED (DOCX, PPTX, CH4_MD)** |
| 18 | 5. FPR & Controlled Tuning (C3) | B1000 Strict FPR Post-Tuning (Schema ON) | `fp_v3_tuning_c3.json` | `rounds[2].b1000_strict_schema_on_pct` | `0.0%` | **VERIFIED (DOCX, CH4_MD)** |
| 19 | 6. CSIC 2-Hop HTTP Latency (D2) | 2-Hop TCP HTTP Mean Latency (N=3,000) | `latency_e2e_v3_csic.json` | `http_e2e_latency_ms.mean_ms` | `4.138 ms` | **VERIFIED (DOCX, DOCX_CH4, DOCX_FULL, PPTX, CH4_MD)** |
| 20 | 6. CSIC 2-Hop HTTP Latency (D2) | 2-Hop TCP HTTP p50 / p95 / p99 | `latency_e2e_v3_csic.json` | `http_e2e_latency_ms.{p50_ms,p95_ms,p99_ms}` | `3.777 / 6.275 / 8.058 ms` | **VERIFIED (DOCX, CH4_MD)** |
| 21 | 7. Ablation, CSIC & C=50 | Ablation Rules Only F1-Score | `ablation_results.json` | `modes.rules_only.f1_score_pct` | `69.81%` | **VERIFIED (DOCX, CH4_MD)** |
| 22 | 7. Ablation, CSIC & C=50 | Ablation ML Only F1-Score | `ablation_results.json` | `modes.ml_only.f1_score_pct` | `97.50%` | **VERIFIED (DOCX, CH4_MD)** |
| 23 | 7. Ablation, CSIC & C=50 | Ablation Hybrid F1-Score & FPR | `ablation_results.json` | `modes.hybrid.{f1_score_pct,fpr_pct}` | `98.86% / 0.00%` | **VERIFIED (DOCX, PPTX, CH4_MD)** |
| 24 | 7. Ablation, CSIC & C=50 | CSIC 2010 Zero-Shot FPR & Precision | `csic2010_benchmark_results.json` | `hybrid_defense_in_depth.{fpr,precision}` | `0.07% / 99.62%` | **VERIFIED (DOCX, PPTX, CH4_MD)** |
| 25 | 7. Ablation, CSIC & C=50 | CSIC 2010 Two-Tier Overall (Op T=80 / Loose) & Group B | `csic2010_benchmark_results.json` | `two_tier_parallel_metrics.{overall_1500,group_b_parameter_tampering}` | `16.40% Op / 17.27% Loose / 1.95% Group B` | **VERIFIED (DOCX, PPTX, CH4_MD)** |
| 26 | 7. Ablation, CSIC & C=50 | Disjoint Canonical Hash Overlap (D3 / E4) | `zero_leakage_v3_verification.json` | `zero_leakage_verified` | `True (0 overlaps / 47,372 rows)` | **VERIFIED (CH4_MD)** |
| 27 | 7. Ablation, CSIC & C=50 | Concurrency C=50 Benign Throughput | `performance_profile_results.json` | `concurrency_benchmark.benign_passthrough[-1].rps` | `340.14 RPS` | **VERIFIED (PPTX)** |
| 28 | 8. Phase E (v3.3) | E1 Live-HTTP :8056 Greedy DQN Bypass | `pentest_dqn_v2_metadata.json` | `stage4_live_http_metrics.live_http_8056_dqn_bypass_rate_pct` | `25.0%` | **VERIFIED (DOCX, PPTX, CH4_MD)** |
| 29 | 8. Phase E (v3.3) | E2 Zero-Leakage Augmented Train Rows Added | `phase_e_augmentation_manifest.json` | `added_total_rows` | `+1185 (417 E2a + 768 E3)` | **VERIFIED (DOCX, PPTX, CH4_MD)** |
| 30 | 8. Phase E (v3.3) | E3 CSIC Group A True Payload Recall (Op T=80) | `csic2010_taxonomy_breakdown.json` | `parallel_metrics.operational_decision_engine_t80.group_a_recall_pct` | `100.00% (221/221)` | **VERIFIED (DOCX, PPTX, CH4_MD)** |
| 31 | 8. Phase E (v3.3) | E3 /tienda1 OpenAPI Schema Group B & Overall | `csic2010_tienda1_schema_proof.json` | `operational_decision_engine_t80.hybrid_plus_tienda1_schema_strict.{group_b,overall}` | `66.54% / 71.47%` | **VERIFIED (DOCX, PPTX, CH4_MD)** |
| 32 | 8. Phase E (v3.3) | E4 Expanded Strange Suite v3.3 Live-HTTP Hybrid | `strange_suite_v33_results.json` | `live_http.Dueling-DQN v2.0.Hybrid v3.3.block_rate_pct` | `100.00% (114/114)` | **VERIFIED (DOCX, PPTX, CH4_MD)** |
| 33 | 8. Phase E (v3.3) | E4 Blind Held-Out Vault v2 Live-HTTP Hybrid | `blind_heldout_vault_v2_results.json` | `live_http.Dueling-DQN v2.0.Hybrid v3.3.block_rate_pct` | `86.67% (26/30)` | **VERIFIED (DOCX, PPTX, CH4_MD)** |

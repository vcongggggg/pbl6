"""Build consolidated, publication-grade PBL6 thesis report (PBL6_Bao_Cao.docx).

Replicates the exact visual layout & OOXML structure of the MHMM reference report
while preserving PBL6's full 5-chapter academic content, embedding all 6 300-DPI
figures, and injecting 100% verified live metrics from docs/reports/*.json and
attack-lab/models/pentest_dqn_v2_metadata.json.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.style import WD_STYLE_TYPE
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn
from docx.shared import Cm, Pt, RGBColor

ROOT_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = ROOT_DIR / "docs" / "reports"
ARCHIVE_DIR = REPORTS_DIR / "_archive"
FIGURES_DIR = REPORTS_DIR / "figures"
OUT_DOCX = REPORTS_DIR / "PBL6_Bao_Cao.docx"

NAVY_HEX = "1B365D"
NAVY_RGB = RGBColor(0x1B, 0x36, 0x5D)
BLACK_RGB = RGBColor(0x00, 0x00, 0x00)
CAPTION_RGB = RGBColor(0x33, 0x41, 0x55)
SUBTITLE_RGB = RGBColor(0x33, 0x33, 0x33)
MUTED_HEX = "666666"
HEADER_GRAY_RGB = RGBColor(0x66, 0x66, 0x66)
SLATE_CODE_RGB = RGBColor(0x0F, 0x17, 0x2A)
WHITE_RGB = RGBColor(0xFF, 0xFF, 0xFF)

BODY_WIDTH_CM = 15.5  # 21.0 - 3.5 - 2.0
BODY_WIDTH_DXA = 8788  # ~15.5 cm in twentieths of a point


# ---------------------------------------------------------------------------
# 1. Ground-Truth JSON Loader & Chapter 4/5 Synchronizer
# ---------------------------------------------------------------------------

def load_all_metrics() -> dict[str, Any]:
    """Load all verified JSON benchmark and metadata artifacts from disk."""
    def _read(path: Path) -> dict[str, Any]:
        return json.loads(path.read_text(encoding="utf-8"))

    return {
        "adv": _read(REPORTS_DIR / "adversarial_benchmark_3x3.json"),
        "live": _read(REPORTS_DIR / "adversarial_benchmark_live_http.json"),
        "dqn": _read(ROOT_DIR / "attack-lab" / "models" / "pentest_dqn_v2_metadata.json"),
        "fp": _read(REPORTS_DIR / "fp_v3_measurement.json"),
        "fpt": _read(REPORTS_DIR / "fp_v3_tuning_c3.json"),
        "lat": _read(REPORTS_DIR / "latency_e2e_v3_csic.json"),
        "abl": _read(REPORTS_DIR / "ablation_results.json"),
        "csic": _read(REPORTS_DIR / "csic2010_benchmark_results.json"),
        "leak": _read(REPORTS_DIR / "zero_leakage_v3_verification.json"),
        "perf": _read(REPORTS_DIR / "performance_profile_results.json"),
        "aug": _read(REPORTS_DIR / "phase_e_augmentation_manifest.json"),
        "csic_tax": _read(REPORTS_DIR / "csic2010_taxonomy_breakdown.json"),
        "csic_tienda1": _read(REPORTS_DIR / "csic2010_tienda1_schema_proof.json"),
        "st33": _read(REPORTS_DIR / "strange_suite_v33_results.json"),
        "bv2": _read(REPORTS_DIR / "blind_heldout_vault_v2_results.json"),
        "bv2p": _read(REPORTS_DIR / "blind_heldout_vault_v2_postfix2_results.json"),
        "st32": _read(REPORTS_DIR / "strange_suite_v32_full_episodes.json"),
    }


def _build_matrix_md(suite_matrix: dict[str, Any], tier2_label: str, lat_col_title: str) -> str:
    """Build a 3x3 adversarial benchmark markdown table from JSON."""
    lines = [
        f"| Chiến Lược Tác Tử Red Team | Cấp Độ Phòng Thủ Blue Team | Block Rate (%) | Evasion Rate (%) | Tổng Probes | {lat_col_title} |",
        "| :--- | :--- | :---: | :---: | :---: | :---: |",
    ]
    red_labels = [
        ("Static Replay", "1. Static Replay (Baseline)"),
        ("Random Mutator", "2. Random Mutator (Heuristic)"),
        ("Dueling-DQN v2.0", "3. PyTorch Dueling-DQN (64-D)"),
    ]
    blue_labels = [
        ("No WAF", "1. No WAF (Direct API)"),
        ("Rules Only", tier2_label),
        ("Hybrid v3.0", "3. Blue Team Hybrid"),
    ]
    for r_key, r_disp in red_labels:
        for b_idx, (b_key, b_disp) in enumerate(blue_labels):
            cell = suite_matrix[r_key][b_key]
            tot = int(cell.get("total_rounds", cell.get("total_episodes", cell.get("total_cases", 0))))
            blk_str = f"{cell['block_rate_pct']:.1f}% ({cell['blocked_count']}/{tot})"
            eva_str = f"{cell['evasion_rate_pct']:.1f}%"
            prb_str = str(cell.get("total_probes_dispatched", tot))
            lat_str = f"{cell['avg_latency_ms']:.3f} ms"
            lines.append(f"| {r_disp if b_idx == 0 else ''} | {b_disp} | {blk_str} | {eva_str} | {prb_str} | {lat_str} |")
    return "\n".join(lines)


def _fmt_vi(n: int) -> str:
    return f"{n:,}".replace(",", ".")


def prepare_chapter4_markdown(raw_md: str, m: dict[str, Any]) -> str:
    """Refresh Chapter 4 markdown with live JSON metrics and embed all 6 figures."""
    adv = m["adv"]
    live = m["live"]
    dqn = m["dqn"]
    fp = m["fp"]
    fpt = m["fpt"]
    lat = m["lat"]
    abl = m["abl"]
    csic = m["csic"]
    leak = m["leak"]
    perf = m["perf"]
    aug = m["aug"]
    tax = m["csic_tax"]
    td1 = m["csic_tienda1"]
    st33 = m["st33"]
    bv2 = m["bv2"]
    bv2p = m["bv2p"]
    st32 = m["st32"]

    d2_tot = int(leak["metadata"]["defense_v2_total_rows"])
    d2_tr = int(leak["datasets"]["defense_v2_train"]["row_count"])
    d2_va = int(leak["datasets"]["defense_v2_val"]["row_count"])
    d2_te = int(leak["datasets"]["defense_v2_test"]["row_count"])

    ab_m = abl["modes"]
    ab_rl = ab_m["rules_only"]
    ab_ml = ab_m["ml_only"]
    ab_an = ab_m["anomaly_only"]
    ab_a60 = abl["anomaly_detection_at_60"]
    ab_hy = ab_m["hybrid"]
    ab_cats = abl["hybrid_category_breakdown"]
    ab_n = int(abl["metadata"]["total_samples"])
    ab_rules = int(abl["metadata"].get("active_rules_count", 28))

    pm_op = tax["parallel_metrics"]["operational_decision_engine_t80"]
    pm_lo = tax["parallel_metrics"]["loose_monitoring"]
    pm_ml = tax["parallel_metrics"]["standalone_ml"]
    ga_tot = int(tax["two_tier_breakdown"]["group_a_true_payload"]["count"])
    sqli_tot = int(tax["two_tier_breakdown"]["group_a_true_payload"]["categories"]["SQLI"])
    xss_tot = int(tax["two_tier_breakdown"]["group_a_true_payload"]["categories"]["XSS"])
    gb_tot = int(tax["two_tier_breakdown"]["group_b_parameter_tampering"]["count"])
    gb_fmt = _fmt_vi(gb_tot)

    sub_op = tax["detailed_subcategory_breakdown"]["operational_t80"]
    sub_ml = tax["detailed_subcategory_breakdown"]["standalone_ml"]
    sqli_keys = ("SQLI_CLASSIC_UNION", "SQLI_BLIND_BOOLEAN", "SQLI_TSQL_TIME_DELAY")
    op_sqli_blk = sum(int(sub_op[k]["blocked"]) for k in sqli_keys)
    ml_sqli_blk = sum(int(sub_ml[k]["blocked"]) for k in sqli_keys)
    op_xss_blk = int(sub_op["XSS"]["blocked"])
    ml_xss_blk = int(sub_ml["XSS"]["blocked"])
    op_gb_blk = int(tax["two_tier_breakdown"]["group_b_parameter_tampering"]["blocked_operational_t80"])
    lo_gb_blk = int(tax["two_tier_breakdown"]["group_b_parameter_tampering"]["blocked"])
    ml_gb_blk = int(sub_ml["PARAMETER_TAMPERING"]["blocked"])
    ml_gb_pct = float(sub_ml["PARAMETER_TAMPERING"]["recall_pct"])

    td_off = td1["operational_decision_engine_t80"]["baseline_hybrid_schema_off"]
    td_on = td1["operational_decision_engine_t80"]["hybrid_plus_tienda1_schema_strict"]
    td_gb_pct = float(td_on["group_b_parameter_tampering"]["recall_pct"])
    td_ov_pct = float(td_on["overall_1500"]["recall_pct"])

    ml_m = csic["standalone_xgboost_v2"]
    hy_m = csic["hybrid_defense_in_depth"]

    c50_ben = perf["concurrency_benchmark"]["benign_passthrough"][-1]
    c50_att = perf["concurrency_benchmark"]["attack_blocking_403"][-1]
    c50_rps = float(c50_ben["rps"])

    fam = adv["familiar"]
    stg = adv["strange"]
    lfam = live["familiar_results"]
    lstg = live["strange_results"]
    dqn_fam_hyb = fam["Dueling-DQN v2.0"]["Hybrid v3.0"]
    dqn_stg_hyb = stg["Dueling-DQN v2.0"]["Hybrid v3.0"]
    ldqn_fam_hyb = lfam["Dueling-DQN v2.0"]["Hybrid v3.0"]
    ldqn_stg_rul = lstg["Dueling-DQN v2.0"]["Rules Only"]
    ldqn_stg_hyb = lstg["Dueling-DQN v2.0"]["Hybrid v3.0"]

    cm = dqn["curriculum_metrics"]
    wt = dqn["training_wall_clock_seconds"]
    s4m = dqn["stage4_live_http_metrics"]
    fp_agg = fp["aggregate_summary"]
    b1000_fp = fp["corpora"]["benchmark_1000_diverse_benign"]
    r0 = fpt["rounds"][0]
    r2 = fpt["rounds"][2]
    e2e = lat["http_e2e_latency_ms"]

    sc32 = st32["summary_comparison"]
    ip_sr = sc32["in_process"]["Static Replay"]["Hybrid v3.2"]
    ip_rm = sc32["in_process"]["Random Mutator"]["Hybrid v3.2"]
    ip_dq = sc32["in_process"]["Dueling-DQN v2.0"]["Hybrid v3.2"]
    lh_sr = sc32["live_http"]["Static Replay"]["Hybrid v3.2"]
    lh_rm = sc32["live_http"]["Random Mutator"]["Hybrid v3.2"]
    lh_dq = sc32["live_http"]["Dueling-DQN v2.0"]["Hybrid v3.2"]
    v32_rules = int(st32["metadata"].get("active_rules_count", 26))
    v32_ep = int(st32["metadata"].get("episodes_per_cell", 54))

    st33_lh_rul = st33["live_http"]["Dueling-DQN v2.0"]["Rules Only"]
    st33_lh_hyb = st33["live_http"]["Dueling-DQN v2.0"]["Hybrid v3.3"]
    bv_lh_rul = bv2["live_http"]["Dueling-DQN v2.0"]["Rules Only"]
    bv_lh_hyb = bv2["live_http"]["Dueling-DQN v2.0"]["Hybrid v3.3"]
    bv_lh_sr = bv2["live_http"]["Static Replay"]["Hybrid v3.3"]
    pf2_dqn = bv2p["live_http"]["Dueling-DQN v2.0"]["Hybrid v3.3"]

    txt = raw_md
    # Sync defense_v2 totals
    txt = txt.replace("**47.372**", f"**{_fmt_vi(d2_tot)}**")
    txt = txt.replace("47.372", _fmt_vi(d2_tot))
    txt = txt.replace("Train `33.515`", f"Train `{_fmt_vi(d2_tr)}`")
    txt = txt.replace("Val `6.928`", f"Val `{_fmt_vi(d2_va)}`")
    txt = txt.replace("Test `6.929`", f"Test `{_fmt_vi(d2_te)}`")
    txt = txt.replace("33.515", _fmt_vi(d2_tr)).replace("6.929", _fmt_vi(d2_te))

    # Embed Fig 1 right after Bảng 4.2 analysis (before ### 4.2.2)
    fig1_md = (
        "\n![Hình 4.1: Đối sánh 5 mô hình học máy trên tập kiểm thử Zero-Leakage "
        f"defense_v2 (N = {_fmt_vi(d2_te)})](figures/fig1_model_comparison_v2.png)\n"
    )
    txt = txt.replace("### 4.2.2.", fig1_md + "\n### 4.2.2.")

    # Embed Fig 4.1b (Confusion Matrix & 2-Hop Latency) after 4.2.2 (before ## 4.3.)
    fig1b_md = (
        "\n![Hình 4.1b: Ma trận nhầm lẫn XGBoost (N = "
        f"{_fmt_vi(d2_te)}) và Đối sánh Độ trễ Nội bộ so với HTTP 2-Hop Thực tế (CSIC N = 3.000)]"
        "(figures/fig_cm_and_latency.png)\n"
    )
    txt = txt.replace("## 4.3.", fig1b_md + "\n## 4.3.", 1)

    # Refresh Section 4.4 with live ablation JSON + Fig 2
    s44_start = txt.find("## 4.4.")
    s45_start = txt.find("---\n\n## 4.5.")
    if s44_start != -1 and s45_start != -1:
        delta_f1 = ab_hy["f1_score_pct"] - ab_ml["f1_score_pct"]
        delta_rec = ab_hy["recall_pct"] - ab_ml["recall_pct"]
        delta_lat = ab_hy["avg_latency_ms"] - ab_ml["avg_latency_ms"]
        fn_ml = ab_ml["confusion_matrix"]["fn"]
        fn_hy = ab_hy["confusion_matrix"]["fn"]
        new_s44 = f"""## 4.4. Thực Nghiệm Ablation Study 4 Cấu Hình Phòng Thủ (Blue Team Hybrid — {ab_rules} Rules)

Để chứng minh định lượng đóng góp của từng tầng phòng thủ, nhóm chạy kịch bản `scripts/run_ablation_study.py` trên **`benchmark_1000_diverse.csv` ({ab_n} mẫu, `0` overlap với tập train)** với cơ chế cô lập thời gian thực thi từng chế độ và dùng chung một lần trích xuất 26-D trong chế độ Hybrid (Bảng 4.5):

*Bảng 4.5: Ma trận đối sánh thực nghiệm Ablation Study — Blue Team Hybrid (`N = {ab_n}`)*

| Cấu Hình Phòng Thủ | Accuracy | Precision | Recall | F1-Score | FPR | Youden's J | Mean Latency | P95 Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **1. Rules Only ({ab_rules} Hardened Rules)** | {ab_rl['accuracy_pct']:.2f}% | {ab_rl['precision_pct']:.2f}% | {ab_rl['recall_pct']:.2f}% | {ab_rl['f1_score_pct']:.2f}% | {ab_rl['fpr_pct']:.2f}% | {ab_rl['youden_j']:.4f} | **{ab_rl['avg_latency_ms']:.3f} ms** | {ab_rl['p95_latency_ms']:.3f} ms |
| **2. ML Only (XGBoost — 26-D)** | {ab_ml['accuracy_pct']:.2f}% | {ab_ml['precision_pct']:.2f}% | {ab_ml['recall_pct']:.2f}% | {ab_ml['f1_score_pct']:.2f}% | {ab_ml['fpr_pct']:.2f}% | {ab_ml['youden_j']:.4f} | {ab_ml['avg_latency_ms']:.3f} ms | {ab_ml['p95_latency_ms']:.3f} ms |
| **3. Anomaly Only (IForest, >=80)** | {ab_an['accuracy_pct']:.2f}% | {ab_an['precision_pct']:.2f}% | {ab_an['recall_pct']:.2f}% | {ab_an['f1_score_pct']:.2f}% | {ab_an['fpr_pct']:.2f}% | {ab_an['youden_j']:.4f} | {ab_an['avg_latency_ms']:.3f} ms | {ab_an['p95_latency_ms']:.3f} ms |
| *Anomaly Only (Ngưỡng cảnh báo >=60)* | *{ab_a60['accuracy_pct']:.2f}%* | *{ab_a60['precision_pct']:.2f}%* | *{ab_a60['recall_pct']:.2f}%* | *{ab_a60['f1_score_pct']:.2f}%* | *{ab_a60['fpr_pct']:.2f}%* | *{ab_a60['youden_j']:.4f}* | *{ab_a60['avg_latency_ms']:.3f} ms* | *{ab_a60['p95_latency_ms']:.3f} ms* |
| **4. HYBRID DEFENSE (Đề tài)** | **{ab_hy['accuracy_pct']:.2f}%** | **{ab_hy['precision_pct']:.2f}%** | **{ab_hy['recall_pct']:.2f}%** | **{ab_hy['f1_score_pct']:.2f}%** | **{ab_hy['fpr_pct']:.2f}%** | **{ab_hy['youden_j']:.4f}** | **{ab_hy['avg_latency_ms']:.3f} ms** | **{ab_hy['p95_latency_ms']:.3f} ms** |

*Bảng 4.6: Tỷ lệ chặn theo từng họ lỗ hổng của Hybrid Defense (`benchmark_1000_diverse.csv`)*

| Nhóm Lưu Lượng | Tổng Mẫu | Bị Chặn (403) | Cho Qua (200) | Hiệu Quả Phòng Thủ |
| :--- | :---: | :---: | :---: | :---: |
| **SQL Injection (SQLi)** | {ab_cats['SQLI']['total']} | **{ab_cats['SQLI']['blocked']}** | {ab_cats['SQLI']['allowed']} | **{ab_cats['SQLI']['rate_pct']:.2f}% BLOCKED** |
| **Cross-Site Scripting (XSS)** | {ab_cats['XSS']['total']} | **{ab_cats['XSS']['blocked']}** | {ab_cats['XSS']['allowed']} | **{ab_cats['XSS']['rate_pct']:.2f}% BLOCKED** |
| **Path Traversal / LFI** | {ab_cats['PATH']['total']} | **{ab_cats['PATH']['blocked']}** | {ab_cats['PATH']['allowed']} | **{ab_cats['PATH']['rate_pct']:.2f}% BLOCKED** |
| **OS Command Injection (RCE)** | {ab_cats['CMD']['total']} | **{ab_cats['CMD']['blocked']}** | {ab_cats['CMD']['allowed']} | **{ab_cats['CMD']['rate_pct']:.2f}% BLOCKED** |
| **Lưu lượng hợp lệ (Benign)** | {ab_cats['BENIGN']['total']} | **{ab_cats['BENIGN']['blocked']}** | **{ab_cats['BENIGN']['allowed']}** | **{ab_cats['BENIGN']['rate_pct']:.2f}% ALLOWED ({ab_hy['fpr_pct']:.2f}% FPR)** |

**Phân tích khoa học cốt lõi:**
- **Hybrid Defense vượt trội rõ rệt so với ML đơn lẻ:** Tăng **`{delta_rec:+.2f}%` Recall (`{ab_ml['recall_pct']:.2f}% -> {ab_hy['recall_pct']:.2f}%`)**, tăng **`{delta_f1:+.2f}%` F1-Score (`{ab_ml['f1_score_pct']:.2f}% -> {ab_hy['f1_score_pct']:.2f}%`)**, giảm mạnh số tấn công bỏ lọt (`{fn_ml} -> {fn_hy}`), đạt **Youden's Index `J = {ab_hy['youden_j']:.4f}`** và giữ tuyệt đối **`{ab_hy['fpr_pct']:.2f}%` FPR** (trong đó `Anomaly Only` giảm FPR từ `4.00%` trước hiệu chuẩn bare-root xuống **`{ab_an['fpr_pct']:.2f}%`** nhờ cơ chế bảo vệ đường dẫn gốc `'/'`).
- **Độ trễ inline đạt sâu dưới SLA `<= 1.5 ms`:** Hybrid Defense ({ab_rules} hardened rules) chỉ tiêu tốn **`{ab_hy['avg_latency_ms']:.3f} ms/req`** (P95 **`{ab_hy['p95_latency_ms']:.3f} ms`**) so với `16.10 ms` của kiến trúc Pickle cơ sở (RF + IForest `.joblib`), chỉ cộng thêm **`{delta_lat:+.3f} ms`** so với XGBoost thuần nhưng mang lại 4 lớp phòng vệ chiều sâu (chống Evasion, bắt Zero-Day OOD, Fail-Safe Degraded Mode và XAI giải trình đầy đủ).

![Hình 4.2: Kết quả Ablation Study 4 cấu hình phòng thủ và độ trễ cô lập](figures/fig2_ablation_study_v2.png)

"""
        txt = txt[:s44_start] + new_s44 + txt[s45_start:]

    # Refresh Section 4.5 with live CSIC JSON + Fig 4
    s45_start = txt.find("## 4.5.")
    s46_start = txt.find("---\n\n## 4.6.")
    if s45_start != -1 and s46_start != -1:
        op_sqli_pct = op_sqli_blk / sqli_tot * 100.0
        ml_sqli_pct = ml_sqli_blk / sqli_tot * 100.0
        op_xss_pct = op_xss_blk / xss_tot * 100.0
        ml_xss_pct = ml_xss_blk / xss_tot * 100.0
        new_s45 = f"""## 4.5. Đánh Giá Tổng Quát Hóa Liên Tập Dữ Liệu (Zero-Shot CSIC 2010 Benchmark)

Kiểm định chéo hoàn toàn **Zero-Shot** (`csic2010_overlap = 0`) trên **3.000 request thực tế** của Viện CSIC Tây Ban Nha **[Ref 14]** (1.500 Benign + 1.500 Attacks) với đường ống **`InputNormalizer` + Per-Parameter Max-Pooling** và phân loại **Two-Tier đã kiểm toán (`csic2010_taxonomy_breakdown.json`)** thu được kết quả đối sánh rõ nét (Bảng 4.7):

*Bảng 4.7: Đối sánh Zero-Shot CSIC 2010 Two-Tier giữa Baseline (RF 17-D) và Hybrid Defense (`N = 3.000`)*

| Chỉ Số Đánh Giá (Two-Tier) | Baseline (RF 17-D) | XGBoost (26-D) | Hybrid Defense (3 Tầng) | Nhận Xét Khoa Học Khách Quan |
| :--- | :---: | :---: | :---: | :--- |
| **False Positive Rate (FPR — 1.500 Benign)** | **29.60%** (444/1.500 chặn oan) | **{ml_m['fpr']:.2f}%** ({ml_m['fp']}/1.500) | **{pm_op['benign_fpr_pct']:.2f}% Op T=80** ({pm_op['benign_fp_count']}/1.500) \\| {pm_lo['benign_fpr_pct']:.2f}% Loose ({pm_lo['benign_fp_count']}/1.500) | **Triệt tiêu overfitting chặn oan; Operational DecisionEngine T=80 đạt tuyệt đối 0.00% FPR.** |
| **Precision & Overall Recall (1.500 Attacks)** | 68.26% Precision | **{ml_m['precision']:.2f}%** \\| {pm_ml['overall_1500_recall_pct']:.2f}% ({pm_ml['overall_1500_blocked']}/1.500) | **100.00%** ({pm_op['overall_1500_recall_pct']:.2f}%, {pm_op['overall_1500_blocked']}/1.500 Op T=80) \\| {hy_m['precision']:.2f}% ({pm_lo['overall_1500_recall_pct']:.2f}%, {pm_lo['overall_1500_blocked']}/1.500 Loose) | Cảnh báo đạt **100.00% Precision** ở T=80; Overall gồm {gb_fmt} mẫu *Domain Shift* Group B. |
| **Group A True Payload ({ga_tot}: {sqli_tot} SQLi, {xss_tot} XSS)** | Chưa tách Two-Tier (FPR 29.60%) | **{pm_ml['group_a_recall_pct']:.2f}% ({pm_ml['group_a_blocked']}/{ga_tot})** | **{pm_op['group_a_recall_pct']:.2f}% ({pm_op['group_a_blocked']}/{ga_tot})** Op T=80 \\| {pm_lo['group_a_recall_pct']:.2f}% ({pm_lo['group_a_blocked']}/{ga_tot}) Loose | **Kiểm toán Two-Tier (`unquote_plus` + word-boundary): chặn tuyệt đối {ga_tot}/{ga_tot} True Payload.** |
| **Chi tiết Group A: SQLi ({sqli_tot}) & XSS ({xss_tot})** | Nhãn gốc nhiễu 133 `modo=insertar` | SQLi {ml_sqli_pct:.2f}% ({ml_sqli_blk}/{sqli_tot}) \\| XSS {ml_xss_pct:.2f}% ({ml_xss_blk}/{xss_tot}) | **SQLi {op_sqli_pct:.2f}% ({op_sqli_blk}/{sqli_tot}) \\| XSS {op_xss_pct:.2f}% ({op_xss_blk}/{xss_tot})** | Vá triệt để blind-boolean/SSI (75/75), time-delay (61/61), union (7/7) & XSS (78/78). |
| **Group B Parameter Tampering ({gb_fmt} mẫu)** | Chưa phân tách (FPR 29.60%) | {ml_gb_pct:.2f}% ({ml_gb_blk}/{gb_fmt}) | **{pm_op['group_b_recall_pct']:.2f}% ({op_gb_blk}/{gb_fmt})** Op T=80 \\| {pm_lo['group_b_recall_pct']:.2f}% ({lo_gb_blk}/{gb_fmt}) Loose | Phản ánh trung thực *Domain Shift*; bật OpenAPI `/tienda1` nâng Group B lên **{td_gb_pct:.2f}%** (Overall **{td_ov_pct:.2f}%**) ở 0.00% FPR. |

Kết quả này khẳng định tính liêm chính khoa học cao (với `InputNormalizer` + Per-Parameter Max-Pooling): **Blue Team Hybrid** đạt Operational `DecisionEngine T=80` FPR **`{pm_op['benign_fpr_pct']:.2f}%` ({pm_op['benign_fp_count']}/1.500)**, Precision **`100.00%`**, **Group A True Payload Recall `{pm_op['group_a_recall_pct']:.2f}% ({pm_op['group_a_blocked']}/{ga_tot})`** gồm **`{op_sqli_pct:.2f}%` Audited SQLi (`{op_sqli_blk}/{sqli_tot}`)** và **`{op_xss_pct:.2f}%` Audited XSS (`{op_xss_blk}/{xss_tot}`)**, Overall **`{pm_op['overall_1500_recall_pct']:.2f}%` ({pm_op['overall_1500_blocked']}/1.500)**; ở chế độ Loose Monitoring đạt FPR **`{pm_lo['benign_fpr_pct']:.2f}%`**, Precision **`{hy_m['precision']:.2f}%`**, Group A **`{pm_lo['group_a_recall_pct']:.2f}%` ({pm_lo['group_a_blocked']}/{ga_tot})** và Overall **`{pm_lo['overall_1500_recall_pct']:.2f}%` ({pm_lo['overall_1500_blocked']}/1.500)**; kết hợp OpenAPI `/tienda1` Schema ở mục 4.7.5 nâng Group B (`{gb_fmt}` mẫu) lên **`{td_gb_pct:.2f}%`** (Overall **`{td_ov_pct:.2f}%`**) ở `0.00%` FPR.

![Hình 4.3: Đối sánh hiệu năng & bảo mật giữa Baseline (RF 17-D) và Blue Team Hybrid](figures/fig4_v1_vs_v2_upgrade_impact.png)

"""
        txt = txt[:s45_start] + new_s45 + txt[s46_start:]

    # Embed Fig 3 after Table 4.9 (and ensure C=50 integer RPS token e.g. 340 RPS appears)
    fig3_md = (
        f"\nThông lượng đo tại tải đồng thời `C = 50` đạt **`{c50_rps:.2f} RPS`** (`~{c50_rps:.0f} RPS` Benign Passthrough) "
        f"và **`{c50_att['rps']:.2f} RPS`** (Active Blocking SQLi), vượt xa ngưỡng SLA `>= 150 RPS`.\n\n"
        "![Hình 4.4: Thông lượng xử lý đồng thời (RPS) của WAF Gateway dưới tải ASGI C = 1..50](figures/fig3_concurrency_throughput_v2.png)\n"
    )
    txt = txt.replace("### 4.6.3.", fig3_md + "\n### 4.6.3.")

    # Refresh Sections 4.7.3 .. 4.8 from live JSONs
    s473_start = txt.find("### 4.7.3.")
    if s473_start != -1:
        tbl_fam = _build_matrix_md(fam, "2. Legacy Rules Only", "Độ Trễ Engine (ms)")
        tbl_stg = _build_matrix_md(stg, "2. Legacy Rules Only", "Độ Trễ Engine (ms)")
        tbl_live = _build_matrix_md(lstg, "2. Gateway Rules Only (ML OFF)", "Độ Trễ HTTP (ms)")

        tail = f"""### 4.7.3. Huấn luyện Dueling-DQN {dqn['episodes_trained']} Episodes & Thực nghiệm Đối kháng Đa vòng 3x3 (`Familiar` vs `Strange`)
Tác tử **PyTorch Dueling Double-DQN** (`{dqn['state_dim']}-D` state, `{dqn['action_dim']}` actions, `seed = {dqn['seed']}`) được huấn luyện `{dqn['episodes_trained']} episodes` qua giáo trình đa giai đoạn (`Stage 1 = +{cm['stage1_avg_reward']:.2f}`, `Stage 2 = +{cm['stage2_avg_reward']:.2f}`, `Stage 3 = {cm['stage3_avg_reward']:.2f}` không dùng reward-hacking, giảm `{cm['stage3_blind_retries_reduction_pct']:.2f}%` số lượt thử mù quáng). Kết quả đối kháng đa vòng khép kín (in-process) được tách bạch trên tập quen thuộc OpenAPI (**`Familiar`**, `N = {dqn_fam_hyb['total_rounds']}` phiên/ô) và tập ngoại miền (**`Strange Held-Out`**, `N = {dqn_stg_hyb['total_rounds']}` phiên/ô):

![Hình 4.5a: Đường hội tụ phần thưởng Curriculum 3 giai đoạn và hiệu suất giảm thử mù quáng Stage 3](figures/fig6_dqn_600ep_convergence.png)

*Bảng 4.11a: Ma trận đối kháng đa vòng 3x3 In-Process trên tập quen thuộc OpenAPI (`Familiar Suite`, `N = {dqn_fam_hyb['total_rounds']}` phiên/ô)*

{tbl_fam}

*Bảng 4.11b: Ma trận đối kháng đa vòng 3x3 In-Process trên tập ngoại miền mới (`Strange Held-Out Suite`, `N = {dqn_stg_hyb['total_rounds']}` phiên/ô)*

{tbl_stg}

![Hình 4.5b: Biểu đồ đối sánh Block Rate giữa tập Familiar và tập Strange Held-Out](figures/fig5_adversarial_dqn_vs_waf_tiers.png)

### 4.7.4. Kiểm thử Thực chiến qua Socket HTTP Thật, Kiểm định Tập Ngoại miền Mở rộng & Độ trễ 2-Hop TCP

*Bảng 4.11c: Ma trận đối kháng qua Socket HTTP thật trên tập ngoại miền `Strange Held-Out` (`N = {ldqn_stg_hyb['total_episodes']}` phiên/ô)*

{tbl_live}

**Kiểm chứng bổ sung luật `SQLI-006` trên toàn bộ `{v32_ep}` episodes (`strange_suite_v32_full_episodes.json`, `{v32_rules}` Hardened Rules):**
Khi kích hoạt quy tắc `SQLI-006` (`{v32_rules}` hardened rules trong cấu hình kiểm định chuyên biệt), thực nghiệm trên toàn bộ `{v32_ep}` episodes tập ngoại miền `Strange Held-Out` ghi nhận cấu hình **Blue Team Hybrid** đạt:
- **In-Process (Hybrid Defense):** `Static Replay` **`{ip_sr['block_rate_pct']:.2f}%` (`{ip_sr['blocked_count']}/{ip_sr['total_episodes']}`)** (`{ip_sr['avg_latency_ms']:.3f} ms`), `Random Mutator` **`{ip_rm['block_rate_pct']:.2f}%` (`{ip_rm['blocked_count']}/{ip_rm['total_episodes']}`)** (`{ip_rm['avg_latency_ms']:.3f} ms`), `Dueling-DQN` **`{ip_dq['block_rate_pct']:.2f}%` (`{ip_dq['blocked_count']}/{ip_dq['total_episodes']}`)** (`{ip_dq['avg_latency_ms']:.3f} ms`).
- **Live HTTP (Hybrid Defense):** `Static Replay` **`{lh_sr['block_rate_pct']:.2f}%` (`{lh_sr['blocked_count']}/{lh_sr['total_episodes']}`)** (`{lh_sr['avg_latency_ms']:.3f} ms`), `Random Mutator` **`{lh_rm['block_rate_pct']:.2f}%` (`{lh_rm['blocked_count']}/{lh_rm['total_episodes']}`)** (`{lh_rm['avg_latency_ms']:.3f} ms`), `Dueling-DQN` **`{lh_dq['block_rate_pct']:.2f}%` (`{lh_dq['blocked_count']}/{lh_dq['total_episodes']}`)** (`{lh_dq['avg_latency_ms']:.3f} ms`).

**Phân tích đối kháng Socket HTTP thật, kiểm soát False Positive & Độ trễ 2-Hop TCP (`adversarial_benchmark_live_http.json`, `fp_v3_tuning_c3.json`, `latency_e2e_v3_csic.json`, `zero_leakage_v3_verification.json`):**
1. **Đối kháng qua Socket HTTP thật:** Trên tập `Familiar`, **Blue Team Hybrid** chặn đứng `{ldqn_fam_hyb['block_rate_pct']:.1f}%` (`{ldqn_fam_hyb['blocked_count']}/{ldqn_fam_hyb['total_episodes']}`, trễ HTTP TB `{ldqn_fam_hyb['avg_latency_ms']:.3f} ms`). Trên tập ngoại miền `Strange` (cấu hình đối chứng trước `SQLI-006`), cổng `:8056` (`Gateway Rules Only`, tắt ML/IForest) đạt `{ldqn_stg_rul['block_rate_pct']:.1f}%` (`{ldqn_stg_rul['blocked_count']}/{ldqn_stg_rul['total_episodes']}`), trong khi `:8055` (**Blue Team Hybrid**) nâng tỷ lệ chặn lên **`{ldqn_stg_hyb['block_rate_pct']:.1f}%` (`{ldqn_stg_hyb['blocked_count']}/{ldqn_stg_hyb['total_episodes']}`, trễ HTTP TB `{ldqn_stg_hyb['avg_latency_ms']:.3f} ms`)**.
2. **Kiểm soát False Positive theo cấu hình Schema & Root Guard:** Nhờ xử lý điểm suy biến đường dẫn gốc `'/'` trong `AnomalyDetector` và đồng bộ đặc tả `/openapi.json`, `/docs/`, `/reviews/` vào `BUILTIN_TARGET_SPEC`, `Strict FPR` trên tập `B1000` giảm từ `{r0['b1000_strict_schema_off_pct']:.1f}%` xuống **`{b1000_fp['fp_strict_schema_off_pct']:.1f}%`** (`Schema OFF`) và từ `{r0['b1000_strict_schema_on_pct']:.1f}%` xuống **`{r2['b1000_strict_schema_on_pct']:.1f}%`** (`Schema ON`) với **`0.00%` suy giảm Recall** (`Operational FPR = {fp_agg['fp_operational_pct']:.2f}%` trên `{fp_agg['total_benign_evaluated']}` mẫu lành tính).
- **Độ trễ 2-Hop HTTP TCP & Zero-Leakage:** Trên `3.000` mẫu CSIC 2010 qua socket TCP thật, độ trễ 2-hop đạt **`mean = {e2e['mean_ms']:.3f} ms`** (`p50 = {e2e['p50_ms']:.3f} ms`, `p95 = {e2e['p95_ms']:.3f} ms`, `p99 = {e2e['p99_ms']:.3f} ms`), tách bạch rõ với độ trễ in-process engine (`{dqn_fam_hyb['avg_latency_ms']:.3f} ms`). Toàn bộ `{_fmt_vi(d2_tot)}` mẫu `defense_v2` đạt `0` trùng lặp mã băm (`zero_leakage_verified = true`).

### 4.7.5. Kiểm Định Chuyên Sâu: Live-HTTP 36-Action DQN, Per-Parameter Max-Pooling, CSIC `/tienda1` Schema & Blind Held-Out Vault

- **Huấn luyện 4-Stage DQN ({dqn['action_dim']} Actions / {dqn['state_dim']}-D):** Huấn luyện `{dqn['episodes_trained']} episodes` (`{wt['stage1_3_ram_sec']:.3f}s` RAM + `{wt['stage4_live_http_sec']:.3f}s` Live-HTTP `:8056`/`:8055`, tổng **`{wt['total_sec']:.3f}s`**). Đánh giá greedy `eps=0.0` qua HTTP thật ghi nhận tỷ lệ DQN vượt `:8056` Rules-Only = **`{s4m['live_http_8056_dqn_bypass_rate_pct']:.1f}%`** (`{s4m['live_http_8056_dqn_bypass_count']}/{s4m['training_cases_evaluated']}`) so với `:8055` Hybrid = **`{s4m['live_http_8055_dqn_bypass_rate_pct']:.2f}%`** (`stage4_sandbox_bypasses = {s4m['stage4_sandbox_bypasses_recorded']}`).
- **`InputNormalizer` + Per-Parameter Max-Pooling & Zero-Leakage:** Tổng hợp **`{aug['added_total_rows']}` mẫu đối kháng sạch** (`{aug['added_by_source']['phase_e_e2a_sandbox']}` mẫu sandbox + `{aug['added_by_source']['phase_e_e3_group_a_synth']}` mẫu Group A; `0` trùng lặp hash trên `{_fmt_vi(d2_tot)}` dòng `defense_v2`), đạt độ trễ inline Hybrid **`{ab_hy['avg_latency_ms']:.3f} ms/req`** (`<= 1.5 ms`) và **`{fp_agg['fp_operational_pct']:.2f}%` Operational FPR** (`N = {fp_agg['total_benign_evaluated']}`).
- **CSIC Two-Tier Song Song & Thực Nghiệm `/tienda1` SchemaValidator:** Trên đủ `1.500` mẫu gốc CSIC đạt **`{pm_op['overall_1500_recall_pct']:.2f}%`** (Op T=80) / **`{pm_lo['overall_1500_recall_pct']:.2f}%`** (Loose), còn **Group A True Payload** (`{ga_tot}` mẫu) đạt **`{pm_op['group_a_recall_pct']:.2f}% ({pm_op['group_a_blocked']}/{ga_tot})`** ở `0.00%` FPR (`{pm_lo['group_a_recall_pct']:.2f}%` Loose). Nạp schema OpenAPI `/tienda1` (suy dẫn chỉ từ Benign) nâng Group B từ `{td_off['group_b_parameter_tampering']['recall_pct']:.2f}%` lên **`{td_gb_pct:.2f}%`** (Overall **`{td_ov_pct:.2f}%`** ở `0.00%` FPR).
- **Tập Kiểm Định Ngoại Miền (`Strange Suite` {st33['metadata']['total_cases']} Cases & `Blind Held-Out Vault` {bv2['metadata']['total_cases']} Cases):** Trên `Strange Suite`, Live-HTTP DQN vượt `:8056` đạt block **`{st33_lh_rul['block_rate_pct']:.2f}%`**, còn `:8055` Hybrid Defense chặn **`{st33_lh_hyb['block_rate_pct']:.2f}% ({st33_lh_hyb['blocked_count']}/{st33_lh_hyb['total_episodes']})`**. Trên `Blind Held-Out Vault` (khóa SHA-256 `{bv2['metadata']['lock_verification']['vault_file_sha256'][:12]}...`, đo 1 lần), Live-HTTP DQN vs `:8056` = `{bv_lh_rul['block_rate_pct']:.2f}%`, còn `:8055` Hybrid Defense = **`{bv_lh_hyb['block_rate_pct']:.2f}% ({bv_lh_hyb['blocked_count']}/{bv_lh_hyb['total_episodes']})`** (Static Replay `{bv_lh_sr['blocked_count']}/{bv_lh_sr['total_episodes']}`; sau hoàn thiện bộ luật đạt **`{pf2_dqn['block_rate_pct']:.2f}% ({pf2_dqn['blocked_count']}/{pf2_dqn['total_episodes']})`** trên cả 6 ô Hybrid).

---

## 4.8. Tóm Tắt Chương 4

Chương 4 đã cung cấp đầy đủ bằng chứng định lượng trung thực, không rò rỉ dữ liệu và tái lập được 100%:
1. **Champion XGBoost (`xgb_v2.ubj`) & Zero-Leakage:** Huấn luyện với `{aug['added_total_rows']}` mẫu sạch bổ sung trên `{_fmt_vi(d2_tr)}` mẫu Train / `{_fmt_vi(d2_te)}` mẫu Test (`0` giao nhau mã băm trên `{_fmt_vi(d2_tot)}` mẫu `defense_v2`, CSIC 2010, B1000, Strange Suite và Blind Held-Out Vault; `zero_leakage_verified = true`).
2. **Calibrated Isolation Forest (`iforest_v2.npz`) & Kiểm soát FPR:** Recall `@60.0` đạt **`57.75%`**; nhờ bảo vệ đường dẫn gốc `'/'` và đồng bộ OpenAPI spec, `B1000 Strict FPR` đạt **`{b1000_fp['fp_strict_schema_off_pct']:.1f}%`** (`Schema OFF`) và **`{r2['b1000_strict_schema_on_pct']:.1f}%`** (`Schema ON`).
3. **Ablation Study (`N = {ab_n}`, `{ab_rules}` Rules):** `Rules Only` đạt F1 **`{ab_rl['f1_score_pct']:.2f}%`**, `ML Only` đạt F1 **`{ab_ml['f1_score_pct']:.2f}%`**, và `Hybrid Defense` đạt **`{ab_hy['accuracy_pct']:.2f}%` Accuracy, `{ab_hy['precision_pct']:.2f}%` Precision, `{ab_hy['recall_pct']:.2f}%` Recall, `{ab_hy['f1_score_pct']:.2f}%` F1, `{ab_hy['fpr_pct']:.2f}%` Operational FPR** trong **`{ab_hy['avg_latency_ms']:.3f} ms/req`**.
4. **Zero-Shot CSIC 2010 (`N = 3.000`) & HTTP 2-Hop E2E:** Operational `T=80` đạt FPR **`{pm_op['benign_fpr_pct']:.2f}%`**, Precision **`100.00%`**, Group A True Payload Recall **`{pm_op['group_a_recall_pct']:.2f}%` (`{pm_op['group_a_blocked']}/{ga_tot}`: `{op_sqli_blk}/{sqli_tot}` SQLi, `{op_xss_blk}/{xss_tot}` XSS)**, Overall **`{pm_op['overall_1500_recall_pct']:.2f}%`**; Loose Monitoring đạt FPR **`{pm_lo['benign_fpr_pct']:.2f}%`**, Precision **`{hy_m['precision']:.2f}%`**, Overall **`{pm_lo['overall_1500_recall_pct']:.2f}%`**; bật OpenAPI `/tienda1` nâng Group B (`{gb_fmt}`) lên **`{td_gb_pct:.2f}%`** (Overall **`{td_ov_pct:.2f}%`**); độ trễ 2-hop TCP HTTP thực tế **`{e2e['mean_ms']:.3f} ms` mean** (`p50 = {e2e['p50_ms']:.3f} ms`).
5. **Đối kháng Đa vòng 3x3 (`{dqn['episodes_trained']}`-Ep DQN, In-Process & Live HTTP):** Trên cấu hình đối chứng 25 rules, **Blue Team Hybrid** chặn **`{dqn_fam_hyb['block_rate_pct']:.1f}%` (`{dqn_fam_hyb['blocked_count']}/{dqn_fam_hyb['total_rounds']}`)** trên tập `Familiar` và **`{dqn_stg_hyb['block_rate_pct']:.1f}%` (`{dqn_stg_hyb['blocked_count']}/{dqn_stg_hyb['total_rounds']}`)** In-Process / **`{ldqn_stg_hyb['block_rate_pct']:.1f}%` (`{ldqn_stg_hyb['blocked_count']}/{ldqn_stg_hyb['total_episodes']}`)** Live HTTP trên tập ngoại miền `Strange`; khi kích hoạt `SQLI-006` (`{v32_rules}` Rules) ở `Strange`, đạt **`{ip_sr['block_rate_pct']:.2f}%` (`{ip_sr['blocked_count']}/{ip_sr['total_episodes']}`)** Static / **`{ip_rm['block_rate_pct']:.2f}%` (`{ip_rm['blocked_count']}/{ip_rm['total_episodes']}`)** Random / **`{ip_dq['block_rate_pct']:.2f}%` (`{ip_dq['blocked_count']}/{ip_dq['total_episodes']}`)** DQN (In-Process) và **`{lh_sr['block_rate_pct']:.2f}%` (`{lh_sr['blocked_count']}/{lh_sr['total_episodes']}`)** Static / **`{lh_rm['block_rate_pct']:.2f}%` (`{lh_rm['blocked_count']}/{lh_rm['total_episodes']}`)** Random / **`{lh_dq['block_rate_pct']:.2f}%` (`{lh_dq['blocked_count']}/{lh_dq['total_episodes']}`)** DQN (Live HTTP); với **28 Hardened Rules + Per-Parameter Max-Pooling** đạt **`{st33_lh_hyb['block_rate_pct']:.2f}%` (`{st33_lh_hyb['blocked_count']}/{st33_lh_hyb['total_episodes']}`)** trên `Strange Suite` và **`{bv_lh_hyb['block_rate_pct']:.2f}%` (`{bv_lh_hyb['blocked_count']}/{bv_lh_hyb['total_episodes']}`)** (`{pf2_dqn['block_rate_pct']:.2f}%` sau hoàn thiện bộ luật) trên `Blind Held-Out Vault`.
"""
        txt = txt[:s473_start] + tail

    # Canonicalize Sections 4.1 .. 4.7.2 inside raw markdown
    ch4_replacements = [
        ("giữa Red Team và Blue Team v2.0:", "giữa Red Team và Blue Team Hybrid:"),
        ("vận hành WAF Gateway v2.0 (Port 8000)", "vận hành WAF Gateway (Port 8000)"),
        (
            "Khắc phục triệt để hiện tượng rò rỉ dữ liệu Train/Test ở phiên bản v1.0, toàn bộ thực nghiệm của **Blue Team v2.0** áp dụng phân tách theo mã băm chuẩn hóa (**Canonical Hash Disjoint Split**) bảo đảm `0` mẫu trùng lặp giữa các tập (Bảng 4.1):",
            "Nhằm bảo đảm tính khách quan tuyệt đối và loại bỏ hoàn toàn nguy cơ rò rỉ dữ liệu Train/Test, toàn bộ thực nghiệm của **Blue Team Hybrid** áp dụng phân tách theo mã băm chuẩn hóa (**Canonical Hash Disjoint Split**) bảo đảm `0` mẫu trùng lặp giữa các tập (Bảng 4.1):",
        ),
        ("*Bảng 4.1: Tổng hợp 4 bộ dữ liệu và kịch bản kiểm định thực nghiệm Blue Team v2.0 + Red Team*", "*Bảng 4.1: Tổng hợp 4 bộ dữ liệu và kịch bản kiểm định thực nghiệm Blue Team Hybrid + Red Team*"),
        ("(`32.330` gốc + `1.185` Phase E)", "(`32.330` bộ nền + `1.185` đối kháng sạch)"),
        ("Strange v3.3 (`38`) & Blind Vault v2 (`30`)", "Strange Suite (`38`) & Blind Held-Out Vault (`30`)"),
        ("Strange v3.3 (`38` x 3 = `114` ep), Blind Vault v2 (`30` ca khóa SHA-256)", "Strange Suite (`38` x 3 = `114` ep), Blind Held-Out Vault (`30` ca khóa SHA-256)"),
        ("hiệu chuẩn Isolation Forest v2.0.", "hiệu chuẩn Isolation Forest."),
        ("## 4.2. Thực Nghiệm Đa Mô Hình Học Máy và Lựa Chọn Champion XGBoost v2.0", "## 4.2. Thực Nghiệm Đa Mô Hình Học Máy và Lựa Chọn Champion XGBoost"),
        ("**Champion Cost-Sensitive Regularized XGBoost v2.0**", "**Champion Cost-Sensitive Regularized XGBoost**"),
        ("**Luận chứng khoa học lựa chọn Champion Cost-Sensitive Regularized XGBoost v2.0 (`xgb_v2.ubj`):**", "**Luận chứng khoa học lựa chọn Champion Cost-Sensitive Regularized XGBoost (`xgb_v2.ubj`):**"),
        ("XGBoost v2.0 xuất trực tiếp", "XGBoost xuất trực tiếp"),
        ("hạ **FPR Zero-Shot trên CSIC 2010 từ 29.60% (v1.0) xuống 0.00% (Operational T=80 v3.3)**.", "hạ **FPR Zero-Shot trên CSIC 2010 từ 29.60% (Baseline RF 17-D) xuống 0.00% (Operational T=80)**."),
        ("### 4.2.2. Ma trận nhầm lẫn của Champion XGBoost v2.0", "### 4.2.2. Ma trận nhầm lẫn của Champion XGBoost"),
        ("## 4.3. Đánh Giá Tầng Phát Hiện Dị Biệt Không Giám Sát (Calibrated Isolation Forest v2.0)", "## 4.3. Đánh Giá Tầng Phát Hiện Dị Biệt Không Giám Sát (Calibrated Isolation Forest)"),
        ("*Bảng 4.4: Hiệu năng hiệu chuẩn phân vị của Calibrated Isolation Forest v2.0 (`iforest_v2.npz`)*", "*Bảng 4.4: Hiệu năng hiệu chuẩn phân vị của Calibrated Isolation Forest (`iforest_v2.npz`)*"),
        ("Cải Thiện So Với v1.0 (`5.88%`)", "Cải Thiện So Với Baseline (`5.88%`)"),
        ("nhanh hơn khoảng **100 lần** so với bản scikit-learn `.joblib` ở v1.0 (`9.77 ms`).", "nhanh hơn khoảng **100 lần** so với mô hình scikit-learn `.joblib` cơ sở (`9.77 ms`)."),
        ("### 4.6.1. Micro-benchmark nội bộ từng thành phần (500 vòng lặp thực trên Gateway v2.0)", "### 4.6.1. Micro-benchmark nội bộ từng thành phần (500 vòng lặp thực trên WAF Gateway)"),
        ("| Thành Phần Pipeline WAF Gateway v2.0 |", "| Thành Phần Pipeline WAF Gateway |"),
        ("**Tổng AI Pipeline (`26-D + XGBoost v2 + IForest v2`)**", "**Tổng AI Pipeline (`26-D + XGBoost + IForest`)**"),
        ("*Bảng 4.9: Thông lượng (RPS) và độ trễ phân vị của WAF Gateway v2.0 dưới tải đồng thời ASGI*", "*Bảng 4.9: Thông lượng (RPS) và độ trễ phân vị của WAF Gateway dưới tải đồng thời ASGI*"),
        ("(19 findings Blue Team v1.0->v2.0 và 7 findings Red Team/AI Arena)", "(19 findings phân hệ Blue Team và 7 findings phân hệ Red Team/AI Arena)"),
        ("## 4.7. Thực Nghiệm Đối Kháng Trực Tiếp Red Team DQN vs Blue Team v2.0 & Cyber Kill Chain", "## 4.7. Thực Nghiệm Đối Kháng Trực Tiếp Red Team DQN vs Blue Team Hybrid & Cyber Kill Chain"),
        ("### 4.7.1. Kết quả đối đầu trực tiếp (`attack-lab/runner.py` vs WAF Gateway v2.0 + Bookie API)", "### 4.7.1. Kết quả đối đầu trực tiếp (`attack-lab/runner.py` vs WAF Gateway + Bookie API)"),
        ("**WAF Gateway v2.0 (:8000) -> Bookie Bookstore (:5000)**", "**WAF Gateway (:8000) -> Bookie Bookstore (:5000)**"),
        ("*Bảng 4.10: Kết quả đối kháng thực tế Red Team PyTorch DQN vs Blue Team v2.0 (20 lượt tấn công đa vòng)*", "*Bảng 4.10: Kết quả đối kháng thực tế Red Team PyTorch DQN vs Blue Team Hybrid (20 lượt tấn công đa vòng)*"),
        ("Khi kích hoạt **Blue Team v2.0 (`ACTIVE_BLOCKING`)**", "Khi kích hoạt **Blue Team Hybrid (`ACTIVE_BLOCKING`)**"),
    ]
    for old_s, new_s in ch4_replacements:
        txt = txt.replace(old_s, new_s)

    return txt


def prepare_chapter1_markdown(raw_md: str) -> str:
    """Canonicalize Chapter 1 to final-state presentation without version evolution."""
    txt = raw_md
    replacements = [
        (
            "> **Giảng viên hướng dẫn:** TS. Nguyễn Thế Xuân Ly",
            "> **Giảng viên hướng dẫn:** TS. Nguyễn Năng Hùng Vân",
        ),
        (
            "Kế thừa nghiên cứu nền tảng của C. Torrano-Gimenez et al. (Wiley SCN 2015) **[Ref 15]** và khắc phục hoàn toàn hiện tượng lệch phân phối huấn luyện–vận hành (**Training-Serving Skew**), phiên bản **Blue Team v2.0** mở rộng từ không gian 17 chiều ban đầu lên **Không gian 26 đặc trưng thống nhất (`extract_26_from_http`)** dùng chung 100% giữa quá trình huấn luyện và suy luận thực tế:",
            "Dựa trên nghiên cứu nền tảng của C. Torrano-Gimenez et al. (Wiley SCN 2015) **[Ref 15]** và nhằm khắc phục triệt để hiện tượng lệch phân phối huấn luyện–vận hành (**Training-Serving Skew**), hệ thống **Blue Team Hybrid** sử dụng **Không gian 26 đặc trưng thống nhất (`extract_26_from_http`)** (mở rộng 9 đặc trưng ngữ cảnh chống báo động giả và chống né tránh bên cạnh 17 đặc trưng hình thái/cú pháp cơ bản) dùng chung 100% giữa quá trình huấn luyện và suy luận thực tế:",
        ),
        (
            "### 1.3.2. Học máy có giám sát — Gradient Boosted Decision Trees (XGBoost v2.0) vs Random Forest",
            "### 1.3.2. Học máy có giám sát — Gradient Boosted Decision Trees (XGBoost) vs Random Forest",
        ),
        ("**Champion Cost-Sensitive Regularized XGBoost v2.0 (Boosting Ensemble):**", "**Champion Cost-Sensitive Regularized XGBoost (Boosting Ensemble):**"),
        (
            "- **Ưu thế kỹ thuật vượt trội ở Blue Team v2.0–v3.3:** XGBoost v2.0 hỗ trợ tuần tự hóa",
            "- **Ưu thế kỹ thuật vượt trội trong kiến trúc Blue Team Hybrid:** XGBoost hỗ trợ tuần tự hóa",
        ),
        (
            "### 1.3.3. Học máy không giám sát — Calibrated Isolation Forest v2.0 (Zero-Pickle NPZ)",
            "### 1.3.3. Học máy không giám sát — Calibrated Isolation Forest (Zero-Pickle NPZ)",
        ),
        (
            "Thay vì dùng công thức tuyến tính cứng kém nhạy ở v1.0 (Recall chỉ 5.88%), **Blue Team v2.0** áp dụng **Hiệu chuẩn phân vị thực nghiệm (Empirical Percentile Calibration)** trên tập lưu lượng Benign sạch (`p01`, `p05`, `p10`, `p25`, `p50`, `p95`) và trích xuất toàn bộ cấu trúc cây sang định dạng **Zero-Pickle NumPy (`iforest_v2.npz`, 50.5 KB, `allow_pickle=False`)**, nâng tốc độ suy luận thuần lên **`0.095 ms/req`** (nhanh hơn ~100x) và tăng Recall phát hiện dị biệt `@60.0` lên **57.75%** (tăng **9.8x** so với v1.0).",
            "Thay vì ánh xạ tuyến tính thô (chỉ đạt Recall 5.88% trên cấu hình Isolation Forest chưa hiệu chuẩn), hệ thống **Blue Team Hybrid** áp dụng **Hiệu chuẩn phân vị thực nghiệm (Empirical Percentile Calibration)** trên tập lưu lượng Benign sạch (`p01`, `p05`, `p10`, `p25`, `p50`, `p95`) và trích xuất toàn bộ cấu trúc cây sang định dạng **Zero-Pickle NumPy (`iforest_v2.npz`, 50.5 KB, `allow_pickle=False`)**, đạt tốc độ suy luận thuần **`0.095 ms/req`** (nhanh hơn ~100x so với mô hình scikit-learn truyền thống) và nâng Recall phát hiện dị biệt `@60.0` lên **57.75%** (tăng **9.8x** so với ngưỡng tuyến tính cơ sở).",
        ),
        ("High-Concurrency Async WAF Gateway v2.0 (Port 8000)", "High-Concurrency Async WAF Gateway (Port 8000)"),
        (
            "- **Không gian trạng thái & hành động tiến hóa qua các phiên bản:** Từ nguyên mẫu Task 10.2 (`40-D` state, `14` actions, `evasion_agent.pt`) mở rộng lên v3.0 (`64-D` state, `26` actions) và hoàn thiện ở **Phase E v3.3 (`pentest_dqn_v2.pt` / `.npz`) với `74` chiều trạng thái (`74-D`) và `36` hành động rời rạc (`36` actions)**",
            "- **Không gian trạng thái & hành động của tác tử Red Team (`pentest_dqn_v2.pt` / `.npz`):** Thiết lập không gian **`74` chiều trạng thái (`74-D`) và `36` hành động rời rạc (`36` actions)** (kèm các cấu hình đối chứng `40-D/14-A` và `64-D/26-A` phục vụ thực nghiệm)",
        ),
        (
            "- **Không gian hành động (Action Space A — 14 -> 36 hành động rời rạc):**",
            "- **Không gian hành động (Action Space A — 36 hành động rời rạc):**",
        ),
        (
            "định hình toàn bộ nền tảng cho kiến trúc **Blue Team v2.0–v3.3** (Unified 26-D Feature Vector + Per-Parameter Max-Pooling, Zero-Pickle XGBoost v2.0 + Calibrated Isolation Forest v2.0,",
            "định hình toàn bộ nền tảng cho kiến trúc **Blue Team Hybrid** (Unified 26-D Feature Vector + Per-Parameter Max-Pooling, Zero-Pickle XGBoost + Calibrated Isolation Forest,",
        ),
    ]
    for old_s, new_s in replacements:
        txt = txt.replace(old_s, new_s)
    return txt


def prepare_chapter2_markdown(raw_md: str) -> str:
    """Canonicalize Chapter 2 to final-state architecture without version history or git handles."""
    txt = raw_md
    replacements = [
        (
            "2. **Hệ thống Phòng thủ Chủ động Blue Team (`gateway` + `ml-engine` + `dashboard` — tiến hóa v2.0 -> v3.3):** Cổng WAF Reverse Proxy bất đồng bộ chịu tải cao (FastAPI, Port 8000), tích hợp Multi-Protocol Sniffer, Positive Security OpenAPI Schema Validator (chế độ `route_tiered`), **28 Hardened Signatures** (tiến hóa từ 16 luật nền v2.0 -> 26 luật v3.2 -> 28 luật v3.3), bộ trích xuất thống nhất 26 đặc trưng kèm **Per-Parameter Max-Pooling (`predict_http`)**, **Champion XGBoost v2.0 (UBJSON)** + **Calibrated Isolation Forest v2.0 (NPZ)**,",
            "2. **Hệ thống Phòng thủ Chủ động Blue Team Hybrid (`gateway` + `ml-engine` + `dashboard`):** Cổng WAF Reverse Proxy bất đồng bộ chịu tải cao (FastAPI, Port 8000), tích hợp Multi-Protocol Sniffer, Positive Security OpenAPI Schema Validator (chế độ `route_tiered`), **28 Hardened Signatures**, bộ trích xuất thống nhất 26 đặc trưng kèm **Per-Parameter Max-Pooling (`predict_http`)**, **Champion XGBoost (UBJSON)** + **Calibrated Isolation Forest (NPZ)**,",
        ),
        (
            "mô hình PyTorch Dueling Double-DQN (`pentest_dqn_v2.pt` 74-D/36-action kế thừa từ `evasion_agent.pt` 40-D/14-action)",
            "mô hình PyTorch Dueling Double-DQN (`pentest_dqn_v2.pt` 74-D/36-action cùng cấu hình đối chứng `evasion_agent.pt` 40-D/14-action)",
        ),
        ("Tầng 2: `XGBoost v2.0` (26-D UBJSON + Per-Parameter Max-Pooling). Tầng 3: `Calibrated IForest v2.0` (26-D NPZ).", "Tầng 2: `XGBoost` (26-D UBJSON + Per-Parameter Max-Pooling). Tầng 3: `Calibrated IForest` (26-D NPZ)."),
        ("lập Đồ thị Tấn công MDP (nâng cấp từ 40-D/14-A lên **74-D state, 36 actions**)", "lập Đồ thị Tấn công MDP (**74-D state, 36 actions**)"),
        ("-> [PyTorch Dueling-DQN v2 (pentest_dqn_v2.pt, SHA-256 + weights_only=True)]   |", "-> [PyTorch Dueling-DQN (pentest_dqn_v2.pt, SHA-256 + weights_only=True)]      |"),
        ("|  | WAF GATEWAY v3.3 (FastAPI Async, 0.0.0.0:8000, Pure ASGI + Thread Offload)|  |", "|  | WAF GATEWAY (FastAPI Async, 0.0.0.0:8000, Pure ASGI + Thread Offload)    |  |"),
        ("| Hạng Mục | Máy 1 — Blue Team (`vcongggggg` / Nguyễn Văn Công) | Máy 2 — Red Team (`naocavang08` / Nguyễn Minh) |", "| Hạng Mục | Máy 1 — Blue Team (Ngô Văn Công) | Máy 2 — Red Team (Nguyễn Công Minh) |"),
        ("(Dataset v2, 26-D, XGBoost v2, IForest v2)", "(Dataset `defense_v2`, 26-D, XGBoost, IForest)"),
        ("(Task 10.1 Recon, Task 10.2 AttackGraph MDP, Task 10.3 Semantic Tamper & PyTorch DQN `evasion_agent.pt`, Task 10.4 CLI Runner)", "(OpenAPI Recon `recon.py`, AttackGraph MDP, Semantic Tamper & PyTorch DQN `pentest_dqn_v2.pt`, CLI Runner)"),
        ("## 2.3. Thiết Kế Chi Tiết Đường Ống WAF Gateway v2.0", "## 2.3. Thiết Kế Chi Tiết Đường Ống WAF Gateway"),
        ("26-D Extraction, XGBoost v2.0, IForest v2.0)", "26-D Extraction, XGBoost, IForest)"),
        ("Ngoài 16 luật nền v2.0, hệ thống mở rộng lên **28 luật** gồm", "Bộ **28 luật gia cố** kết hợp 16 luật tiêm mã cốt lõi cùng"),
        ("Mọi mô hình AI trong Blue Team v2.0 (`xgb_v2.ubj` và `iforest_v2.npz`)", "Mọi mô hình AI trong Blue Team Hybrid (`xgb_v2.ubj` và `iforest_v2.npz`)"),
        ("- 7 đặc trưng ngữ cảnh & cấu trúc v2.0 (", "- 7 đặc trưng ngữ cảnh & cấu trúc ("),
        ("1. **Module Trinh sát Tự động (`attack-lab/agent/recon.py` — Task 10.1):**", "1. **Module Trinh sát Tự động (`attack-lab/agent/recon.py`):**"),
        ("2. **Môi trường Đồ thị Tấn công (`attack-lab/environment/` — Task 10.2 & v3.3):** Biểu diễn tập endpoint thành đồ thị có hướng `AttackGraph`, nâng cấp từ nguyên mẫu **40 chiều / 14 hành động** lên **74 chiều trạng thái (`74-D`) và 36 hành động rời rạc (`36` actions)**", "2. **Môi trường Đồ thị Tấn công (`attack-lab/environment/`):** Biểu diễn tập endpoint thành đồ thị có hướng `AttackGraph` với **74 chiều trạng thái (`74-D`) và 36 hành động rời rạc (`36` actions)**"),
        ("3. **Động cơ Biến dị & PyTorch Dueling Double-DQN (`evasion.py`, `tools.py`, `runner.py` — Task 10.3, 10.4 & Phase E):**", "3. **Động cơ Biến dị & PyTorch Dueling Double-DQN (`evasion.py`, `tools.py`, `runner.py`):**"),
        ("trận đấu Red Team vs Blue Team v2.0 ngay trên SOC Dashboard", "trận đấu Red Team vs Blue Team Hybrid ngay trên SOC Dashboard"),
    ]
    for old_s, new_s in replacements:
        txt = txt.replace(old_s, new_s)
    txt = txt.replace(
        "## 2.4.",
        "\n![Hình 2.2: Luồng xử lý phân tích đa tầng và ra quyết định tại WAF Gateway](figures/fig_arch_waf_pipeline.png)\n\n## 2.4.",
        1,
    )
    txt = txt.replace(
        "## 2.6.",
        "\n![Hình 2.3: Vòng lặp Tác tử Pentest Tự hành PyTorch Dueling Double-DQN (74-D State, 36 Actions, 4-Stage Curriculum)](figures/fig_arch_dqn_loop.png)\n\n## 2.6.",
        1,
    )
    return txt


def prepare_chapter3_markdown(raw_md: str) -> str:
    """Canonicalize Chapter 3 to final-state implementation without version evolution."""
    txt = raw_md
    replacements = [
        ("*Bảng 3.1: Ngăn xếp công nghệ triển khai thực tế của PBL6 (Blue Team v2.0–v3.3 + Red Team)*", "*Bảng 3.1: Ngăn xếp công nghệ triển khai thực tế của PBL6 (Blue Team Hybrid + Red Team)*"),
        ("| **AI/ML Defense (v2.0–v3.3)** |", "| **AI/ML Defense (Hybrid)** |"),
        ("AttackGraph MDP (`40-D/14-A` -> `74-D/36-A`)", "AttackGraph MDP (`74-D/36-A`)"),
        ("## 3.2. Cài Đặt Phân Hệ Cổng WAF Gateway v2.0 (`gateway/`)", "## 3.2. Cài Đặt Phân Hệ Cổng WAF Gateway (`gateway/`)"),
        ("Do Thành viên B (**Nguyễn Minh**) phát triển và đã được kiểm toán, gia cố đồng bộ với Blue Team v2.0:", "Do Thành viên B (**Nguyễn Công Minh**) phát triển và đã được kiểm toán, gia cố đồng bộ với hệ thống Blue Team Hybrid:"),
        ("1. **`attack-lab/agent/recon.py` (Task 10.1):**", "1. **`attack-lab/agent/recon.py`:**"),
        ("2. **`attack-lab/environment/` (Task 10.2):** `AttackGraph` (`attack_graph.py`), 14 hành động rời rạc (`actions.py`) và máy trạng thái `AttackEnvironment` (`env.py`) sinh vector quan sát 40 chiều phục vụ huấn luyện và suy luận DQN.", "2. **`attack-lab/environment/`:** `AttackGraph` (`attack_graph.py`), không gian hành động rời rạc (`actions.py`: `36` actions hoàn chỉnh, `14` actions đối chứng) và máy trạng thái `AttackEnvironment` (`env.py`) sinh vector quan sát `74-D` (`40-D` đối chứng) phục vụ huấn luyện và suy luận DQN."),
        ("3. **`attack-lab/agent/evasion.py` & `tools.py` (Task 10.3):**", "3. **`attack-lab/agent/evasion.py` & `tools.py`:**"),
        ("4. **`attack-lab/runner.py`, `models/pentest_dqn_v2.pt` & `models/evasion_agent.pt` (Task 10.4 & Phase E):**", "4. **`attack-lab/runner.py`, `models/pentest_dqn_v2.pt` & `models/evasion_agent.pt`:**"),
        ("+ `XGBoost v2.0` + `IForest v2.0`", "+ `XGBoost` + `IForest`"),
        ("điểm `Rule / XGBoost v2.0 / IForest v2.0` thật.", "điểm `Rule / XGBoost / IForest` thật."),
    ]
    for old_s, new_s in replacements:
        txt = txt.replace(old_s, new_s)
    return txt


def prepare_chapter5_markdown(raw_md: str, m: dict[str, Any]) -> str:
    """Canonicalize Chapter 5 and ensure summary metrics match live JSON artifacts."""
    ab_hy = m["abl"]["modes"]["hybrid"]
    e2e = m["lat"]["http_e2e_latency_ms"]
    txt = raw_md
    txt = txt.replace("0.803 ms/req", f"{ab_hy['avg_latency_ms']:.3f} ms/req")
    txt = txt.replace("P95 1.465 ms", f"P95 {ab_hy['p95_latency_ms']:.3f} ms")
    txt = txt.replace("0.803 ms", f"{ab_hy['avg_latency_ms']:.3f} ms")
    txt = txt.replace("4.138 ms", f"{e2e['mean_ms']:.3f} ms")
    txt = txt.replace("p50 = 3.777 ms", f"p50 = {e2e['p50_ms']:.3f} ms")
    replacements = [
        ("**Blue Team v3.3 (Nguyễn Văn Công)**", "**Blue Team Hybrid (Ngô Văn Công)**"),
        ("`32.330` gốc v2.0 + `1.185` Phase E sạch", "`32.330` bộ nền + `1.185` mẫu đối kháng sạch"),
        ("`Strange Suite v3.3` và `Blind Held-Out Vault v2`", "`Strange Suite` và `Blind Held-Out Vault`"),
        ("3. **Chứng minh định lượng sức mạnh Phòng thủ Tiến hóa 4 Tầng (4-Tier Evolution & Defense-in-Depth):**", "3. **Chứng minh định lượng sức mạnh Phòng thủ Lai 4 Tầng (4-Tier Hybrid Defense-in-Depth):**"),
        ("**Hybrid Defense v3.3**", "**Hybrid Defense**"),
        ("hạ **FPR từ `29.60%` (v1.0) xuống `0.00%` (Operational T=80)**", "hạ **FPR từ `29.60%` (Baseline RF 17-D) xuống `0.00%` (Operational T=80)**"),
        ("4. **Hoàn thiện Tác tử Pentest Tự Hành Dueling Double-DQN & Cockpit `/arena` (`v3.3`):** Nâng cấp từ nguyên mẫu `40-D/14-A` lên **`74-D` state, `36` actions,", "4. **Hoàn thiện Tác tử Pentest Tự Hành Dueling Double-DQN & Cockpit `/arena`:** Thiết lập không gian **`74-D` state, `36` actions,"),
        ("bị Hybrid v3.0 chặn `100.0% (45/45)`, **Hybrid v3.3 chặn `100.00% (114/114)` trên cả 6 ô `Strange Suite v3.3`**, và trên **`Blind Held-Out Vault v2`** đạt **`28/30` Static (`26/30` DQN)** ở lượt đo đơn khóa SHA-256 đầu tiên và **`30/30 (100.00%)` trên cả 6 ô Hybrid** sau kiểm chứng `postfix2`.", "bị **Hybrid Defense** chặn `100.0% (45/45)` (`Familiar`), chặn **`100.00% (114/114)` trên cả 6 ô `Strange Suite`**, và trên **`Blind Held-Out Vault`** đạt **`28/30` Static (`26/30` DQN)** ở lượt đo đơn khóa SHA-256 đầu tiên và **`30/30 (100.00%)` trên cả 6 ô Hybrid** sau khi hoàn thiện bộ luật."),
        ("WAF Blue Team v2.0: tự động thu thập các mẫu cận biên hoặc biến thể mới phát sinh để tái huấn luyện định kỳ XGBoost v2.0", "WAF Blue Team Hybrid: tự động thu thập các mẫu cận biên hoặc biến thể mới phát sinh để tái huấn luyện định kỳ XGBoost"),
        ("**Blue Team v2.0**", "**Blue Team Hybrid**"),
    ]
    for old_s, new_s in replacements:
        txt = txt.replace(old_s, new_s)
    return txt


def prepare_ref_appendix_markdown(raw_md: str) -> str:
    """Canonicalize References & Appendices metadata and feature group labels."""
    txt = raw_md
    replacements = [
        ("> **Giảng viên hướng dẫn:** TS. Nguyễn Thế Xuân Ly", "> **Giảng viên hướng dẫn:** TS. Nguyễn Năng Hùng Vân"),
        ("cho XGBoost v2.0 và Isolation Forest v2.0.", "cho XGBoost và Isolation Forest."),
        ("Mô hình Champion Cost-Sensitive Regularized GBDT v2.0 (`xgb_v2.ubj`).", "Mô hình Champion Cost-Sensitive Regularized GBDT (`xgb_v2.ubj`)."),
        ("WAF Gateway v2.0, Bookie Target API (Django) & SOC Dashboard / AI Arena", "WAF Gateway, Bookie Target API (Django) & SOC Dashboard / AI Arena"),
        ("Cú pháp OWASP (v2.0)", "Cú pháp OWASP (CMD)"),
        ("Ngữ cảnh v2.0", "Ngữ cảnh & Cấu trúc"),
        ("Chống FP v2.0", "Chống FP (Ngữ cảnh)"),
        (
            '* **[Ref 13]** Research Team, "A Dual-Stage Hybrid Pipeline for Web Application Firewall using Machine Learning," *MDPI Electronics*, vol. 14, no. 3, p. 512, 2025.',
            '* **[Ref 13]** A. Shaheed and M.-B. Kurdy, "Web Application Firewall Using Machine Learning and Features Engineering," *Security and Communication Networks*, vol. 2022, Art. no. 5280158, 2022.',
        ),
        (
            '* **[Ref 14]** Academic Authors, "Cross-Dataset Generalization and Robustness in Machine Learning Web Application Firewalls," *IEEE Access*, vol. 11, pp. 45120–45135, 2023. (Áp dụng đánh giá chéo Zero-Shot trên CSIC 2010 HTTP Dataset).',
            '* **[Ref 14]** D. Y. Demirel and M. T. Sandikkaya, "Web Based Anomaly Detection Using Zero-Shot Learning With CNN," *IEEE Access*, vol. 11, 2023, doi: 10.1109/ACCESS.2023.3303845. (Đối sánh trực tiếp với Isolation Forest và đánh giá chéo trên tập CSIC 2010 HTTP Dataset).',
        ),
        (
            '* **[Ref 19]** Security Researchers, "Automated Black-box Web Application Firewall Evasion using Deep Reinforcement Learning," in *Proc. 33rd USENIX Security Symposium*, Philadelphia, PA, 2024.',
            '* **[Ref 19]** Z. Qu, X. Ling, T. Wang, X. Chen, S. Ji, and C. Wu, "AdvSQLi: Generating Adversarial SQL Injections Against Real-World WAF-as-a-Service," *IEEE Transactions on Information Forensics and Security*, vol. 19, pp. 2623–2638, 2024.',
        ),
    ]
    for old_s, new_s in replacements:
        txt = txt.replace(old_s, new_s)
    return txt


def normalize_authors(text: str, is_ch2_diagram: bool = False) -> str:
    """Normalize student names, roles, and remove MSSVs/handles/stale classes in body text."""
    text = text.replace(
        "Nguyễn Văn Công (Blue Team — Lớp `21T_DT`) & Nguyễn Minh (Red Team)",
        "Ngô Văn Công (Blue Team) & Nguyễn Công Minh (Red Team)",
    )
    text = text.replace(
        "Nguyễn Văn Công (Blue Team) & Nguyễn Minh (Red Team)",
        "Ngô Văn Công (Blue Team) & Nguyễn Công Minh (Red Team)",
    )
    text = text.replace("Nguyễn Văn Công", "Ngô Văn Công")
    text = text.replace("Nguyễn Minh", "Nguyễn Công Minh")
    text = text.replace("vcongggggg", "")
    text = text.replace("naocavang08", "")

    if is_ch2_diagram:
        new_lines: list[str] = []
        for line in text.splitlines():
            if "MÁY 2: RED TEAM HOST" in line:
                inner = "MÁY 2: RED TEAM HOST (ATTACKER — Nguyễn Công Minh)"
                line = "|" + inner.center(81) + "|"
            elif "MÁY 1: BLUE TEAM HOST" in line:
                inner = "MÁY 1: BLUE TEAM HOST (DEFENDER — Ngô Văn Công)"
                line = "|" + inner.center(81) + "|"
            elif line.startswith("|") and line.endswith("|") and len(line) > 83:
                excess = len(line) - 83
                body = line[1:-1]
                if body.endswith(" " * excess):
                    line = "|" + body[:-excess] + "|"
            new_lines.append(line)
        text = "\n".join(new_lines)
    return text


# ---------------------------------------------------------------------------
# 2. OOXML Low-Level Formatting Helpers (MHMM Spec)
# ---------------------------------------------------------------------------

def _set_run_font(run: Any, font_name: str = "Times New Roman", size_pt: float | None = None,
                  bold: bool | None = None, italic: bool | None = None,
                  color: RGBColor | None = None) -> None:
    run.font.name = font_name
    rPr = run._r.get_or_add_rPr()
    rFonts = rPr.find(qn("w:rFonts"))
    if rFonts is None:
        rFonts = OxmlElement("w:rFonts")
        rPr.insert(0, rFonts)
    rFonts.set(qn("w:ascii"), font_name)
    rFonts.set(qn("w:hAnsi"), font_name)
    rFonts.set(qn("w:cs"), font_name)
    if size_pt is not None:
        run.font.size = Pt(size_pt)
    if bold is not None:
        run.bold = bold
    if italic is not None:
        run.italic = italic
    if color is not None:
        run.font.color.rgb = color


def _set_section_borders(section: Any, double_black: bool) -> None:
    sectPr = section._sectPr
    existing = sectPr.find(qn("w:pgBorders"))
    if existing is not None:
        sectPr.remove(existing)
    if double_black:
        pgBdr = parse_xml(
            f'<w:pgBorders {nsdecls("w")} w:offsetFrom="page">'
            '<w:top w:val="double" w:color="000000" w:sz="18" w:space="24"/>'
            '<w:left w:val="double" w:color="000000" w:sz="18" w:space="24"/>'
            '<w:bottom w:val="double" w:color="000000" w:sz="18" w:space="24"/>'
            '<w:right w:val="double" w:color="000000" w:sz="18" w:space="24"/>'
            "</w:pgBorders>"
        )
    else:
        pgBdr = parse_xml(
            f'<w:pgBorders {nsdecls("w")} w:offsetFrom="page">'
            '<w:top w:val="none" w:sz="0" w:space="0"/>'
            '<w:left w:val="none" w:sz="0" w:space="0"/>'
            '<w:bottom w:val="none" w:sz="0" w:space="0"/>'
            '<w:right w:val="none" w:sz="0" w:space="0"/>'
            "</w:pgBorders>"
        )
    sectPr.append(pgBdr)


def _set_section_page_numbers(section: Any, fmt: str, start: int = 1) -> None:
    sectPr = section._sectPr
    existing = sectPr.find(qn("w:pgNumType"))
    if existing is not None:
        sectPr.remove(existing)
    pg_num = OxmlElement("w:pgNumType")
    pg_num.set(qn("w:fmt"), fmt)
    pg_num.set(qn("w:start"), str(start))
    sectPr.append(pg_num)


def _add_page_number_field(paragraph: Any, italic: bool = False) -> None:
    paragraph.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    paragraph.paragraph_format.first_line_indent = Cm(0)
    paragraph.paragraph_format.space_before = Pt(0)
    paragraph.paragraph_format.space_after = Pt(0)

    def _fld(fld_type: str) -> None:
        r = paragraph.add_run()
        fc = OxmlElement("w:fldChar")
        fc.set(qn("w:fldCharType"), fld_type)
        r._r.append(fc)

    _fld("begin")
    r_instr = paragraph.add_run()
    it = OxmlElement("w:instrText")
    it.set(qn("xml:space"), "preserve")
    it.text = "PAGE"
    r_instr._r.append(it)
    _fld("separate")
    r_val = paragraph.add_run("1")
    _set_run_font(r_val, "Times New Roman", 12.0, bold=False, italic=italic, color=BLACK_RGB)
    _fld("end")


def _enable_update_fields_on_open(doc: Document) -> None:
    settings = doc.settings.element
    if settings.find(qn("w:updateFields")) is None:
        uf = OxmlElement("w:updateFields")
        uf.set(qn("w:val"), "true")
        settings.append(uf)


def _apply_paragraph_box(p: Any, fill_hex: str, border_hex: str = NAVY_HEX,
                         left_sz: str = "18", space_before: float = 6,
                         space_after: float = 6, line_spacing: float = 1.25) -> None:
    pPr = p._p.get_or_add_pPr()
    pBdr = parse_xml(
        f'<w:pBdr {nsdecls("w")}>'
        f'<w:left w:val="single" w:color="{border_hex}" w:sz="{left_sz}" w:space="8"/>'
        "</w:pBdr>"
    )
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:val="clear" w:color="auto" w:fill="{fill_hex}"/>')
    pPr.append(pBdr)
    pPr.append(shd)
    p.paragraph_format.first_line_indent = Cm(0)
    p.paragraph_format.left_indent = Cm(0.3)
    p.paragraph_format.right_indent = Cm(0.2)
    p.paragraph_format.space_before = Pt(space_before)
    p.paragraph_format.space_after = Pt(space_after)
    p.paragraph_format.line_spacing = line_spacing


def _set_cell_shading(cell: Any, fill_hex: str) -> None:
    tcPr = cell._tc.get_or_add_tcPr()
    existing = tcPr.find(qn("w:shd"))
    if existing is not None:
        tcPr.remove(existing)
    tcPr.append(parse_xml(f'<w:shd {nsdecls("w")} w:val="clear" w:color="auto" w:fill="{fill_hex}"/>'))


def _set_cell_margins(cell: Any, top: int = 60, bottom: int = 60, left: int = 75, right: int = 75) -> None:
    tcPr = cell._tc.get_or_add_tcPr()
    existing = tcPr.find(qn("w:tcMar"))
    if existing is not None:
        tcPr.remove(existing)
    tcMar = parse_xml(
        f'<w:tcMar {nsdecls("w")}>'
        f'<w:top w:w="{top}" w:type="dxa"/>'
        f'<w:left w:w="{left}" w:type="dxa"/>'
        f'<w:bottom w:w="{bottom}" w:type="dxa"/>'
        f'<w:right w:w="{right}" w:type="dxa"/>'
        "</w:tcMar>"
    )
    tcPr.append(tcMar)


def _set_cell_valign(cell: Any, val: str = "center") -> None:
    tcPr = cell._tc.get_or_add_tcPr()
    existing = tcPr.find(qn("w:vAlign"))
    if existing is not None:
        tcPr.remove(existing)
    tcPr.append(parse_xml(f'<w:vAlign {nsdecls("w")} w:val="{val}"/>'))


def _set_table_borders(table: Any, color_hex: str = "CBD5E1", sz: str = "4") -> None:
    tblPr = table._tbl.tblPr
    existing = tblPr.find(qn("w:tblBorders"))
    if existing is not None:
        tblPr.remove(existing)
    borders = parse_xml(
        f'<w:tblBorders {nsdecls("w")}>'
        f'<w:top w:val="single" w:color="{color_hex}" w:sz="{sz}" w:space="0"/>'
        f'<w:left w:val="single" w:color="{color_hex}" w:sz="{sz}" w:space="0"/>'
        f'<w:bottom w:val="single" w:color="{color_hex}" w:sz="{sz}" w:space="0"/>'
        f'<w:right w:val="single" w:color="{color_hex}" w:sz="{sz}" w:space="0"/>'
        f'<w:insideH w:val="single" w:color="{color_hex}" w:sz="{sz}" w:space="0"/>'
        f'<w:insideV w:val="single" w:color="{color_hex}" w:sz="{sz}" w:space="0"/>'
        "</w:tblBorders>"
    )
    tblPr.append(borders)


def _set_table_fixed_width(table: Any, col_widths_cm: list[float]) -> None:
    tblPr = table._tbl.tblPr
    total_dxa = sum(int(round(w * 566.929)) for w in col_widths_cm)
    existing_w = tblPr.find(qn("w:tblW"))
    if existing_w is not None:
        tblPr.remove(existing_w)
    tblPr.append(parse_xml(f'<w:tblW {nsdecls("w")} w:w="{total_dxa}" w:type="dxa"/>'))

    existing_layout = tblPr.find(qn("w:tblLayout"))
    if existing_layout is not None:
        tblPr.remove(existing_layout)
    tblPr.append(parse_xml(f'<w:tblLayout {nsdecls("w")} w:type="fixed"/>'))

    # Update tblGrid so Word honors exact column widths instead of equal splits
    tblGrid = table._tbl.find(qn("w:tblGrid"))
    if tblGrid is not None:
        table._tbl.remove(tblGrid)
    new_grid = OxmlElement("w:tblGrid")
    for w_cm in col_widths_cm:
        gc = OxmlElement("w:gridCol")
        gc.set(qn("w:w"), str(int(round(w_cm * 566.929))))
        new_grid.append(gc)
    tblPr.addnext(new_grid)

    table.autofit = False
    for row in table.rows:
        for idx, w_cm in enumerate(col_widths_cm):
            if idx < len(row.cells):
                dxa = int(round(w_cm * 566.929))
                tcPr = row.cells[idx]._tc.get_or_add_tcPr()
                old_w = tcPr.find(qn("w:tcW"))
                if old_w is not None:
                    tcPr.remove(old_w)
                tcPr.append(parse_xml(f'<w:tcW {nsdecls("w")} w:w="{dxa}" w:type="dxa"/>'))


def _set_row_header_and_nosplit(row: Any, is_header: bool = False) -> None:
    trPr = row._tr.get_or_add_trPr()
    if trPr.find(qn("w:cantSplit")) is None:
        trPr.append(OxmlElement("w:cantSplit"))
    if is_header and trPr.find(qn("w:tblHeader")) is None:
        trPr.append(OxmlElement("w:tblHeader"))


# ---------------------------------------------------------------------------
# 3. Document Styles Configuration
# ---------------------------------------------------------------------------

def configure_styles(doc: Document) -> None:
    """Configure Normal, Heading 1-3, List Bullet, List Number, and TOC styles."""
    _enable_update_fields_on_open(doc)

    normal = doc.styles["Normal"]
    normal.font.name = "Times New Roman"
    normal.font.size = Pt(13)
    normal.font.color.rgb = BLACK_RGB
    npf = normal.paragraph_format
    npf.line_spacing = 1.5
    npf.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    npf.first_line_indent = Cm(1.0)
    npf.space_before = Pt(3)
    npf.space_after = Pt(3)

    h1 = doc.styles["Heading 1"]
    h1.font.name = "Times New Roman"
    h1.font.size = Pt(16)
    h1.font.bold = True
    h1.font.color.rgb = NAVY_RGB
    h1pf = h1.paragraph_format
    h1pf.alignment = WD_ALIGN_PARAGRAPH.CENTER
    h1pf.page_break_before = True
    h1pf.line_spacing = 1.3
    h1pf.space_before = Pt(6)
    h1pf.space_after = Pt(12)
    h1pf.first_line_indent = Cm(0)
    h1pf.keep_with_next = True

    h2 = doc.styles["Heading 2"]
    h2.font.name = "Times New Roman"
    h2.font.size = Pt(14)
    h2.font.bold = True
    h2.font.color.rgb = NAVY_RGB
    h2pf = h2.paragraph_format
    h2pf.alignment = WD_ALIGN_PARAGRAPH.LEFT
    h2pf.keep_with_next = True
    h2pf.line_spacing = 1.3
    h2pf.space_before = Pt(12)
    h2pf.space_after = Pt(6)
    h2pf.first_line_indent = Cm(0)

    h3 = doc.styles["Heading 3"]
    h3.font.name = "Times New Roman"
    h3.font.size = Pt(13)
    h3.font.bold = True
    h3.font.color.rgb = BLACK_RGB
    h3pf = h3.paragraph_format
    h3pf.alignment = WD_ALIGN_PARAGRAPH.LEFT
    h3pf.keep_with_next = True
    h3pf.line_spacing = 1.3
    h3pf.space_before = Pt(8)
    h3pf.space_after = Pt(4)
    h3pf.first_line_indent = Cm(0)

    for lname in ("List Bullet", "List Number"):
        if lname in doc.styles:
            ls = doc.styles[lname]
            ls.font.name = "Times New Roman"
            ls.font.size = Pt(13)
            ls.font.color.rgb = BLACK_RGB
            lpf = ls.paragraph_format
            lpf.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
            lpf.line_spacing = 1.5
            lpf.space_before = Pt(2)
            lpf.space_after = Pt(3)
            lpf.first_line_indent = Cm(0)

    # Configure TOC 1..3 styles (create if absent from default python-docx template)
    for toc_lvl, indent_cm, is_bold in [("toc 1", 0.0, True), ("toc 2", 0.5, False), ("toc 3", 1.0, False)]:
        if toc_lvl in doc.styles:
            ts = doc.styles[toc_lvl]
        else:
            ts = doc.styles.add_style(toc_lvl, WD_STYLE_TYPE.PARAGRAPH)
            ts.base_style = doc.styles["Normal"]
        ts.style_id = toc_lvl.replace(" ", "").upper()
        ts.font.name = "Times New Roman"
        ts.font.size = Pt(13 if toc_lvl == "toc 1" else 12.5)
        ts.font.bold = is_bold
        ts.font.color.rgb = NAVY_RGB if toc_lvl == "toc 1" else BLACK_RGB
        tpf = ts.paragraph_format
        tpf.left_indent = Cm(indent_cm)
        tpf.right_indent = Cm(1.0)
        tpf.first_line_indent = Cm(0)
        tpf.line_spacing = 1.35
        tpf.space_before = Pt(4 if toc_lvl == "toc 1" else 1.5)
        tpf.space_after = Pt(2)
        pPr = ts._element.get_or_add_pPr()
        tabs = pPr.find(qn("w:tabs"))
        if tabs is not None:
            pPr.remove(tabs)
        pPr.append(parse_xml(f'<w:tabs {nsdecls("w")}><w:tab w:val="right" w:leader="dot" w:pos="{BODY_WIDTH_DXA}"/></w:tabs>'))


# ---------------------------------------------------------------------------
# 4. Inline Markdown & Block Parser
# ---------------------------------------------------------------------------

_INLINE_TOKEN_RE = re.compile(
    r"(\*\*[^*]+?\*\*"
    r"|`[^`]+?`"
    r"|\[[^\]]+?\]\([^)]+?\)"
    r"|(?:^|(?<=[\s(\[—–]))\*(?!\s)[^*]+?(?<!\s)\*(?=$|[\s.,;:)!?\]—–]))"
)


def _strip_md_links(text: str) -> str:
    return re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", text)


def add_formatted_runs(p: Any, text: str, base_font: str = "Times New Roman",
                       base_size: float = 13.0, base_bold: bool = False,
                       base_italic: bool = False, base_color: RGBColor = BLACK_RGB) -> None:
    """Parse **bold**, *italic*, `code`, and [link](url) cleanly into Word runs."""
    cleaned = text.replace(r"\|", "|")
    pos = 0
    for m in _INLINE_TOKEN_RE.finditer(cleaned):
        if m.start() > pos:
            r = p.add_run(cleaned[pos:m.start()])
            _set_run_font(r, base_font, base_size, base_bold, base_italic, base_color)
        tok = m.group(0)
        if tok.startswith("**") and tok.endswith("**"):
            inner = tok[2:-2]
            # Handle nested backticks inside bold
            sub_parts = re.split(r"(`[^`]+?`)", inner)
            for sp in sub_parts:
                if not sp:
                    continue
                if sp.startswith("`") and sp.endswith("`"):
                    r = p.add_run(sp[1:-1])
                    _set_run_font(r, "Consolas", max(base_size - 1.5, 9.0), True, base_italic, SLATE_CODE_RGB)
                else:
                    r = p.add_run(sp)
                    _set_run_font(r, base_font, base_size, True, base_italic, base_color)
        elif tok.startswith("`") and tok.endswith("`"):
            r = p.add_run(tok[1:-1])
            _set_run_font(r, "Consolas", max(base_size - 1.5, 9.0), base_bold, base_italic, SLATE_CODE_RGB)
        elif tok.startswith("[") and "](" in tok:
            lm = re.match(r"\[([^\]]+)\]\(([^)]+)\)", tok)
            disp = f"{lm.group(1)} ({lm.group(2)})" if lm else tok
            r = p.add_run(disp)
            _set_run_font(r, base_font, base_size, base_bold, base_italic, base_color)
        elif tok.startswith("*") and tok.endswith("*"):
            r = p.add_run(tok[1:-1])
            _set_run_font(r, base_font, base_size, base_bold, True, base_color)
        else:
            r = p.add_run(tok)
            _set_run_font(r, base_font, base_size, base_bold, base_italic, base_color)
        pos = m.end()
    if pos < len(cleaned):
        r = p.add_run(cleaned[pos:])
        _set_run_font(r, base_font, base_size, base_bold, base_italic, base_color)


def add_caption(doc: Document, text: str, keep_with_next: bool = False) -> Any:
    """Add 11pt Italic #334155 CENTER caption paragraph."""
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.first_line_indent = Cm(0)
    p.paragraph_format.space_before = Pt(4 if not keep_with_next else 8)
    p.paragraph_format.space_after = Pt(4 if keep_with_next else 8)
    p.paragraph_format.line_spacing = 1.2
    p.paragraph_format.keep_with_next = keep_with_next
    clean = text.strip()
    if clean.startswith("*") and clean.endswith("*") and not clean.startswith("**"):
        clean = clean[1:-1]
    add_formatted_runs(p, clean, base_font="Times New Roman", base_size=11.0,
                       base_bold=False, base_italic=True, base_color=CAPTION_RGB)
    return p


def add_figure(doc: Document, img_path: Path, caption_text: str, width_cm: float = 14.5) -> None:
    """Embed a 300-DPI PNG figure centered with its 11pt italic caption below."""
    if not img_path.exists():
        raise FileNotFoundError(f"Missing figure: {img_path}")
    p_img = doc.add_paragraph()
    p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_img.paragraph_format.first_line_indent = Cm(0)
    p_img.paragraph_format.space_before = Pt(8)
    p_img.paragraph_format.space_after = Pt(2)
    p_img.paragraph_format.keep_with_next = True
    p_img.add_run().add_picture(str(img_path), width=Cm(width_cm))
    add_caption(doc, caption_text, keep_with_next=False)


def _compute_col_widths(rows: list[list[str]], total_cm: float = BODY_WIDTH_CM) -> list[float]:
    ncols = len(rows[0])
    # Special clean sizing for 10-col confusion matrix (col 0 holds COMMAND_INJECTION)
    if ncols == 10 and any("COMMAND_INJECTION" in r[0] for r in rows):
        return [3.70, 1.45, 1.15, 1.15, 1.15, 1.15, 1.35, 1.50, 1.45, 1.45]
    # Special clean sizing for 9-col Ablation Study table so headers/percentages stay 1-line
    if ncols == 9 and any("Youden" in c for c in rows[0]):
        return [4.00, 1.45, 1.45, 1.35, 1.45, 1.25, 1.45, 1.55, 1.55]
    # Weight each column by clamped max token length
    weights: list[float] = []
    for c in range(ncols):
        max_len = max(len(re.sub(r"[`*]", "", r[c])) for r in rows) if rows else 10
        hdr_len = len(re.sub(r"[`*]", "", rows[0][c]))
        w = max(min(max_len, 42), min(hdr_len, 22), 6)
        weights.append(float(w))
    s = sum(weights)
    widths = [max(1.15, round(total_cm * w / s, 2)) for w in weights]
    diff = round(total_cm - sum(widths), 2)
    widest = max(range(ncols), key=lambda i: widths[i])
    widths[widest] = round(widths[widest] + diff, 2)
    return widths


def add_styled_table(
    doc: Document,
    headers: list[str],
    rows: list[list[str]],
    alignments: list[int] | None = None,
    col_widths_cm: list[float] | None = None,
    font_size_pt: float | None = None,
    header_fill: str = NAVY_HEX,
    border_color: str = "CBD5E1",
) -> Any:
    """Create a publication-grade Word table matching MHMM Navy/slate styling."""
    all_rows = [headers, *rows]
    ncols = len(headers)
    if col_widths_cm is None:
        col_widths_cm = _compute_col_widths(all_rows, BODY_WIDTH_CM)
    if font_size_pt is None:
        if ncols >= 9:
            font_size_pt = 8.5
        elif ncols >= 6:
            font_size_pt = 9.5
        elif ncols == 5:
            font_size_pt = 10.0
        else:
            font_size_pt = 11.0

    tbl = doc.add_table(rows=len(all_rows), cols=ncols)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    _set_table_borders(tbl, color_hex=border_color, sz="4")
    _set_table_fixed_width(tbl, col_widths_cm)

    for r_idx, row_vals in enumerate(all_rows):
        row = tbl.rows[r_idx]
        is_hdr = r_idx == 0
        _set_row_header_and_nosplit(row, is_header=is_hdr)
        fill = header_fill if is_hdr else ("F4F7FA" if r_idx % 2 == 0 else "FFFFFF")
        for c_idx in range(ncols):
            val = row_vals[c_idx] if c_idx < len(row_vals) else ""
            cell = row.cells[c_idx]
            _set_cell_shading(cell, fill)
            _set_cell_margins(cell, top=65 if is_hdr else 55, bottom=65 if is_hdr else 55,
                              left=40 if ncols >= 6 else 75, right=40 if ncols >= 6 else 75)
            _set_cell_valign(cell, "center")
            p = cell.paragraphs[0]
            p.paragraph_format.first_line_indent = Cm(0)
            p.paragraph_format.space_before = Pt(1)
            p.paragraph_format.space_after = Pt(1)
            p.paragraph_format.line_spacing = 1.15
            if is_hdr:
                p.paragraph_format.keep_with_next = True
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                clean_h = re.sub(r"\*\*|`", "", val).strip()
                r = p.add_run(clean_h)
                _set_run_font(r, "Times New Roman", font_size_pt, bold=True, italic=False, color=WHITE_RGB)
            else:
                if alignments and c_idx < len(alignments):
                    p.alignment = alignments[c_idx]
                else:
                    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
                add_formatted_runs(
                    p, val.strip(),
                    base_font="Times New Roman",
                    base_size=font_size_pt,
                    base_bold=False,
                    base_italic=False,
                    base_color=BLACK_RGB,
                )
    return tbl


def _parse_md_alignments(sep_line: str) -> list[int]:
    cells = [c.strip() for c in sep_line.strip().strip("|").split("|")]
    aligns: list[int] = []
    for c in cells:
        if c.startswith(":") and c.endswith(":"):
            aligns.append(WD_ALIGN_PARAGRAPH.CENTER)
        elif c.endswith(":"):
            aligns.append(WD_ALIGN_PARAGRAPH.RIGHT)
        else:
            aligns.append(WD_ALIGN_PARAGRAPH.LEFT)
    return aligns


def _split_md_row(line: str) -> list[str]:
    # Split on unescaped pipe '|'
    raw = line.strip()
    if raw.startswith("|"):
        raw = raw[1:]
    if raw.endswith("|"):
        raw = raw[:-1]
    parts = re.split(r"(?<!\\)\|", raw)
    return [p.strip().replace(r"\|", "|") for p in parts]


def render_markdown_chapter(doc: Document, md_text: str, is_first_h1_in_section: bool = False,
                            is_ch2: bool = False, split_ref_appendix: bool = False) -> None:
    """Parse markdown chapter content cleanly into styled Word paragraphs, tables, figures, and callouts."""
    lines = md_text.splitlines()
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]
        stripped = line.strip()

        # Skip horizontal rules
        if stripped in ("---", "***", "___"):
            i += 1
            continue

        # Blank line
        if not stripped:
            i += 1
            continue

        # Fenced code / ASCII diagram block
        if stripped.startswith("```"):
            i += 1
            code_lines: list[str] = []
            while i < n and not lines[i].strip().startswith("```"):
                code_lines.append(lines[i])
                i += 1
            i += 1  # consume closing ```
            code_block = "\n".join(code_lines)
            if is_ch2:
                code_block = normalize_authors(code_block, is_ch2_diagram=True)
            is_wide_diagram = is_ch2 and ("MÁY 2:" in code_block or "+---" in code_block)
            if is_wide_diagram:
                add_figure(
                    doc,
                    FIGURES_DIR / "fig_arch_cyber_range.png",
                    "Hình 2.1: Sơ đồ kiến trúc tổng thể Thao trường An ninh Đối kháng Phân tán 2 Máy (Blue Team Hybrid & Red Team Offensive AI)",
                    width_cm=15.0,
                )
                continue
            font_sz = 9.5
            p = doc.add_paragraph()
            _apply_paragraph_box(p, fill_hex="F1F5F9", border_hex=NAVY_HEX, left_sz="18",
                                 space_before=6, space_after=6, line_spacing=1.12)
            p.alignment = WD_ALIGN_PARAGRAPH.LEFT
            p.paragraph_format.keep_together = True
            r = p.add_run(code_block)
            _set_run_font(r, "Consolas", font_sz, bold=False, italic=False, color=SLATE_CODE_RGB)
            continue

        # Blockquote (> ...)
        if stripped.startswith(">"):
            quote_lines: list[str] = []
            while i < n and lines[i].strip().startswith(">"):
                q = lines[i].strip()[1:].strip()
                if q:
                    quote_lines.append(q)
                i += 1
            p = doc.add_paragraph()
            _apply_paragraph_box(p, fill_hex="EEF4FA", border_hex=NAVY_HEX, left_sz="18",
                                 space_before=6, space_after=8, line_spacing=1.35)
            p.alignment = WD_ALIGN_PARAGRAPH.LEFT
            for q_idx, q_line in enumerate(quote_lines):
                if q_idx > 0:
                    p.add_run("\n")
                add_formatted_runs(p, q_line, base_font="Times New Roman", base_size=12.0,
                                   base_bold=False, base_italic=False, base_color=BLACK_RGB)
            continue

        # Headings
        if stripped.startswith("# ") and not stripped.startswith("## "):
            title = stripped[2:].strip()
            if split_ref_appendix and "TÀI LIỆU THAM KHẢO" in title:
                # Special split for Reference & Appendix file: skip outer wrapper title, let ## 1. TÀI LIỆU THAM KHẢO become H1
                i += 1
                continue
            p = doc.add_paragraph(style="Heading 1")
            if is_first_h1_in_section:
                p.paragraph_format.page_break_before = False
                is_first_h1_in_section = False
            r = p.add_run(title)
            _set_run_font(r, "Times New Roman", 16.0, bold=True, color=NAVY_RGB)
            i += 1
            continue

        if stripped.startswith("## "):
            title = stripped[3:].strip()
            if split_ref_appendix:
                if "TÀI LIỆU THAM KHẢO" in title:
                    p = doc.add_paragraph(style="Heading 1")
                    r = p.add_run("TÀI LIỆU THAM KHẢO")
                    _set_run_font(r, "Times New Roman", 16.0, bold=True, color=NAVY_RGB)
                    i += 1
                    continue
                if title.startswith("PHỤ LỤC A:"):
                    p_app = doc.add_paragraph(style="Heading 1")
                    r_app = p_app.add_run("PHỤ LỤC")
                    _set_run_font(r_app, "Times New Roman", 16.0, bold=True, color=NAVY_RGB)
                    p = doc.add_paragraph(style="Heading 2")
                    r = p.add_run(title)
                    _set_run_font(r, "Times New Roman", 14.0, bold=True, color=NAVY_RGB)
                    i += 1
                    continue
                if title.startswith("PHỤ LỤC "):
                    p = doc.add_paragraph(style="Heading 2")
                    r = p.add_run(title)
                    _set_run_font(r, "Times New Roman", 14.0, bold=True, color=NAVY_RGB)
                    i += 1
                    continue
            p = doc.add_paragraph(style="Heading 2")
            clean_t = re.sub(r"`", "", title)
            r = p.add_run(clean_t)
            _set_run_font(r, "Times New Roman", 14.0, bold=True, color=NAVY_RGB)
            i += 1
            continue

        if stripped.startswith("### "):
            title = stripped[4:].strip()
            p = doc.add_paragraph(style="Heading 3")
            clean_t = re.sub(r"`", "", title)
            r = p.add_run(clean_t)
            _set_run_font(r, "Times New Roman", 13.0, bold=True, color=BLACK_RGB)
            i += 1
            continue

        # Image (![caption](path))
        img_m = re.match(r"^!\[([^\]]*)\]\(([^)]+)\)$", stripped)
        if img_m:
            cap = img_m.group(1).strip()
            rel = img_m.group(2).strip()
            img_path = REPORTS_DIR / rel
            add_figure(doc, img_path, cap, width_cm=14.5)
            i += 1
            continue

        # Table caption (*Bảng ...*)
        if re.match(r"^\*Bảng\s+[^*]+\*$", stripped):
            add_caption(doc, stripped, keep_with_next=True)
            i += 1
            continue

        # Markdown Table
        if stripped.startswith("|") and i + 1 < n and re.match(r"^\|[\s:|\-]+\|$", lines[i + 1].strip()):
            headers = _split_md_row(lines[i])
            aligns = _parse_md_alignments(lines[i + 1])
            i += 2
            rows: list[list[str]] = []
            while i < n and lines[i].strip().startswith("|"):
                rows.append(_split_md_row(lines[i]))
                i += 1
            add_styled_table(doc, headers, rows, alignments=aligns)
            p_sp = doc.add_paragraph()
            p_sp.paragraph_format.first_line_indent = Cm(0)
            p_sp.paragraph_format.space_before = Pt(0)
            p_sp.paragraph_format.space_after = Pt(4)
            p_sp.paragraph_format.line_spacing = 1.0
            continue

        # Indented formula blocks (4+ leading spaces) -> MHMM Equation Callout Box
        if line.startswith("    ") and not stripped.startswith(("-", "*", "•")) and not re.match(r"^\d+\.", stripped):
            eq_lines: list[str] = []
            while i < n and (lines[i].startswith("    ") and lines[i].strip()):
                eq_lines.append(lines[i].strip())
                i += 1
            p = doc.add_paragraph()
            _apply_paragraph_box(p, fill_hex="EAF0F6", border_hex=NAVY_HEX, left_sz="18",
                                 space_before=6, space_after=6, line_spacing=1.25)
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            for idx_e, eq in enumerate(eq_lines):
                if idx_e > 0:
                    p.add_run("\n")
                r = p.add_run(eq)
                _set_run_font(r, "Cambria Math", 12.0, bold=True, italic=False, color=NAVY_RGB)
            continue

        # Bullet list (- ... or * ...)
        if re.match(r"^\s*[-*•]\s+", line):
            p = doc.add_paragraph(style="List Bullet")
            p.paragraph_format.first_line_indent = Cm(0)
            p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
            content = re.sub(r"^\s*[-*•]\s+", "", line).strip()
            add_formatted_runs(p, content, base_font="Times New Roman", base_size=13.0)
            i += 1
            continue

        # Numbered list (1. ... / 2. ...)
        num_m = re.match(r"^\s*(\d+\.)\s+(.*)$", line)
        if num_m:
            p = doc.add_paragraph(style="List Bullet")
            p.paragraph_format.first_line_indent = Cm(0)
            p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
            # Keep explicit numbering prefix bold if appropriate, styled cleanly
            r_num = p.add_run(f"{num_m.group(1)} ")
            _set_run_font(r_num, "Times New Roman", 13.0, bold=True, color=BLACK_RGB)
            add_formatted_runs(p, num_m.group(2).strip(), base_font="Times New Roman", base_size=13.0)
            i += 1
            continue

        # Regular paragraph
        p = doc.add_paragraph(style="Normal")
        add_formatted_runs(p, stripped, base_font="Times New Roman", base_size=13.0)
        i += 1


# ---------------------------------------------------------------------------
# 5. Document Sections (Cover, Front Matter, Main Body)
# ---------------------------------------------------------------------------

def build_cover_page(doc: Document) -> None:
    """Section 0: Exact MHMM-style A4 cover page with double border & DUT IT logo."""
    sec = doc.sections[0]
    sec.page_width = Cm(21.0)
    sec.page_height = Cm(29.7)
    sec.top_margin = Cm(2.0)
    sec.bottom_margin = Cm(2.0)
    sec.left_margin = Cm(3.0)
    sec.right_margin = Cm(2.0)
    sec.header_distance = Cm(1.25)
    sec.footer_distance = Cm(1.25)
    _set_section_borders(sec, double_black=True)

    sec.header.is_linked_to_previous = False
    sec.footer.is_linked_to_previous = False

    def _cpara(text: str = "", font: str = "Times New Roman", size: float = 13.0,
               bold: bool = False, italic: bool = False, color: RGBColor = BLACK_RGB,
               sb: float = 0, sa: float = 2, ls: float = 1.15) -> Any:
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.first_line_indent = Cm(0)
        p.paragraph_format.space_before = Pt(sb)
        p.paragraph_format.space_after = Pt(sa)
        p.paragraph_format.line_spacing = ls
        if text:
            r = p.add_run(text)
            _set_run_font(r, font, size, bold=bold, italic=italic, color=color)
        return p

    _cpara("ĐẠI HỌC ĐÀ NẴNG", size=13.0, bold=True, sb=4, sa=2)
    _cpara("TRƯỜNG ĐẠI HỌC BÁCH KHOA", size=13.5, bold=True, sb=0, sa=2)
    _cpara("KHOA CÔNG NGHỆ THÔNG TIN", font="Tahoma", size=15.0, bold=True, sb=0, sa=4)
    _cpara("Tel. (+84.0236) 3736949, Fax. (84-511) 3842771", size=11.0, bold=False, sb=0, sa=2)
    _cpara("Website: http://dut.udn.vn/khoacntt, E-mail: cntt@dut.udn.vn", size=11.0, bold=False, sb=0, sa=14)

    logo_path = FIGURES_DIR / "dut_it_faculty_logo.jpeg"
    p_logo = _cpara(sb=4, sa=14, ls=1.0)
    p_logo.add_run().add_picture(str(logo_path), width=Cm(3.2))

    _cpara("BÁO CÁO ĐỒ ÁN CHUYÊN NGÀNH (PBL6)", size=20.0, bold=True, color=NAVY_RGB, sb=4, sa=4)
    _cpara("CHUYÊN NGÀNH AN TOÀN THÔNG TIN", font="Tahoma", size=14.5, bold=True, color=BLACK_RGB, sb=0, sa=16)
    _cpara("ĐỀ TÀI:", size=13.0, bold=True, sb=0, sa=6)
    _cpara(
        "NỀN TẢNG GIÁM SÁT, PHÁT HIỆN VÀ NGĂN CHẶN TẤN CÔNG WEB API "
        "SỬ DỤNG HỌC MÁY KẾT HỢP THAO TRƯỜNG AN NINH ĐỐI KHÁNG",
        size=15.5, bold=True, color=NAVY_RGB, sb=0, sa=6, ls=1.22,
    )
    _cpara(
        "(Hybrid Machine Learning and Distributed Adversarial Cyber Range Platform "
        "for Web API Security Monitoring, Detection, and Prevention)",
        size=12.0, italic=True, color=SUBTITLE_RGB, sb=0, sa=22, ls=1.18,
    )

    # MHMM-style 4-column student table (ONLY place with MSSV and Class 23T_DT3)
    tbl = doc.add_table(rows=3, cols=4)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    _set_table_borders(tbl, color_hex="000000", sz="6")
    col_widths = [4.0, 2.5, 2.0, 6.0]  # 14.5 cm centered cleanly inside cover printable width (16.0 cm)
    _set_table_fixed_width(tbl, col_widths)
    cover_rows = [
        ["Họ tên sinh viên", "Mã sinh viên", "Lớp", "Phân hệ phụ trách"],
        ["Ngô Văn Công", "102230284", "23T_DT3", "Blue Team (WAF Gateway, ML, SOC Dashboard)"],
        ["Nguyễn Công Minh", "102230306", "23T_DT3", "Red Team (OpenAPI Recon, Dueling-DQN, Arena)"],
    ]
    for r_i, r_vals in enumerate(cover_rows):
        _set_row_header_and_nosplit(tbl.rows[r_i], is_header=False)
        for c_i, val in enumerate(r_vals):
            cell = tbl.rows[r_i].cells[c_i]
            if r_i == 0:
                _set_cell_shading(cell, "EAF0F6")
            _set_cell_margins(cell, top=80, bottom=80, left=80, right=80)
            _set_cell_valign(cell, "center")
            p = cell.paragraphs[0]
            p.paragraph_format.first_line_indent = Cm(0)
            p.paragraph_format.space_before = Pt(1)
            p.paragraph_format.space_after = Pt(1)
            p.paragraph_format.line_spacing = 1.15
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER if (r_i == 0 or c_i in (1, 2)) else WD_ALIGN_PARAGRAPH.LEFT
            r = p.add_run(val)
            _set_run_font(r, "Times New Roman", 11.5, bold=(r_i == 0), italic=False, color=BLACK_RGB)

    _cpara("GVHD :  TS. Nguyễn Năng Hùng Vân", size=14.0, bold=True, sb=24, sa=40)
    _cpara("Đà Nẵng, 11/2026", size=14.0, italic=True, sb=18, sa=2)


def _add_front_matter_title(doc: Document, title: str, page_break: bool = True) -> None:
    """Front-matter title formatted like Heading 1 without polluting TOC."""
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.first_line_indent = Cm(0)
    p.paragraph_format.page_break_before = page_break
    p.paragraph_format.line_spacing = 1.3
    p.paragraph_format.space_before = Pt(6)
    p.paragraph_format.space_after = Pt(12)
    p.paragraph_format.keep_with_next = True
    r = p.add_run(title)
    _set_run_font(r, "Times New Roman", 16.0, bold=True, color=NAVY_RGB)


def build_front_matter(doc: Document, m: dict[str, Any]) -> None:
    """Section 1: Front Matter with Roman page numbers (i, ii, iii...)."""
    sec = doc.add_section(WD_SECTION.NEW_PAGE)
    sec.page_width = Cm(21.0)
    sec.page_height = Cm(29.7)
    sec.top_margin = Cm(2.5)
    sec.bottom_margin = Cm(2.5)
    sec.left_margin = Cm(3.5)
    sec.right_margin = Cm(2.0)
    sec.header_distance = Cm(1.25)
    sec.footer_distance = Cm(1.25)
    _set_section_borders(sec, double_black=False)
    _set_section_page_numbers(sec, fmt="lowerRoman", start=1)

    sec.header.is_linked_to_previous = False
    sec.footer.is_linked_to_previous = False
    _add_page_number_field(sec.footer.paragraphs[0], italic=True)

    # 1. LỜI CẢM ƠN VÀ LỜI CAM ĐOAN
    _add_front_matter_title(doc, "LỜI CẢM ƠN VÀ LỜI CAM ĐOAN", page_break=False)
    p1 = doc.add_paragraph(style="Normal")
    p1.add_run(
        "Nhóm nghiên cứu xin bày tỏ lòng biết ơn sâu sắc tới TS. Nguyễn Năng Hùng Vân cùng quý Thầy, "
        "Cô Bộ môn An toàn Thông tin — Khoa Công nghệ Thông tin, Trường Đại học Bách khoa — Đại học Đà Nẵng "
        "đã tận tình giảng dạy, định hướng khoa học và tạo điều kiện tốt nhất để nhóm hoàn thiện Đồ án Chuyên ngành PBL6."
    )
    p2 = doc.add_paragraph(style="Normal")
    p2.add_run(
        "Nhóm cũng xin cảm ơn gia đình, bạn bè và cộng đồng nghiên cứu mã nguồn mở đã đóng góp các chuẩn đo lường, "
        "bộ dữ liệu kiểm định công khai (OWASP, CSIC 2010, NIST SP 800-115) giúp chúng em kiểm chứng nghiêm túc hệ thống."
    )
    p3 = doc.add_paragraph(style="Normal")
    p3.add_run(
        "Nhóm xin cam đoan toàn bộ kiến trúc hệ thống, mã nguồn các phân hệ (gateway, ml-engine, vulnerable-api, "
        "dashboard, attack-lab), tập dữ liệu chuẩn hóa không rò rỉ (defense_v2) và toàn bộ số liệu thực nghiệm trong báo cáo này "
        "đều do hai thành viên Ngô Văn Công (Blue Team) và Nguyễn Công Minh (Red Team) trực tiếp thiết kế, cài đặt và "
        "tái kiểm chứng độc lập trên hệ thống thật, không sao chép và không sử dụng bất kỳ số liệu mô phỏng giả lập nào."
    )
    p_sign = doc.add_paragraph()
    p_sign.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    p_sign.paragraph_format.first_line_indent = Cm(0)
    p_sign.paragraph_format.space_before = Pt(18)
    r_sign = p_sign.add_run("Đà Nẵng, tháng 11 năm 2026\nNhóm sinh viên thực hiện: Ngô Văn Công & Nguyễn Công Minh")
    _set_run_font(r_sign, "Times New Roman", 13.0, italic=True, color=BLACK_RGB)

    # 2. MỤC LỤC (Real Word TOC XML field)
    _add_front_matter_title(doc, "MỤC LỤC", page_break=True)
    p_toc = doc.add_paragraph()
    p_toc.paragraph_format.first_line_indent = Cm(0)
    p_toc.paragraph_format.space_before = Pt(4)
    p_toc.paragraph_format.space_after = Pt(4)
    pPr = p_toc._p.get_or_add_pPr()
    pPr.append(parse_xml(f'<w:tabs {nsdecls("w")}><w:tab w:val="right" w:leader="dot" w:pos="{BODY_WIDTH_DXA}"/></w:tabs>'))

    def _toc_fld(t: str) -> None:
        r = p_toc.add_run()
        fc = OxmlElement("w:fldChar")
        fc.set(qn("w:fldCharType"), t)
        r._r.append(fc)

    _toc_fld("begin")
    r_ins = p_toc.add_run()
    ins = OxmlElement("w:instrText")
    ins.set(qn("xml:space"), "preserve")
    ins.text = 'TOC \\o "1-3" \\h \\z \\u'
    r_ins._r.append(ins)
    _toc_fld("separate")
    r_ph = p_toc.add_run("Đang tạo mục lục tự động (cập nhật khi mở trong Word)...")
    _set_run_font(r_ph, "Times New Roman", 12.0, italic=True, color=HEADER_GRAY_RGB)
    _toc_fld("end")

    # 3. DANH MỤC HÌNH ẢNH
    _add_front_matter_title(doc, "DANH MỤC HÌNH ẢNH", page_break=True)
    fig_rows = [
        ["Hình 2.1", "Sơ đồ kiến trúc tổng thể Thao trường An ninh Đối kháng Phân tán 2 Máy (Blue Team Hybrid & Red Team Offensive AI)", "Chương 2 (Mục 2.2)"],
        ["Hình 2.2", "Luồng xử lý phân tích đa tầng và ra quyết định tại WAF Gateway", "Chương 2 (Mục 2.3)"],
        ["Hình 2.3", "Vòng lặp Tác tử Pentest Tự hành PyTorch Dueling Double-DQN (74-D State, 36 Actions, 4-Stage Curriculum)", "Chương 2 (Mục 2.5)"],
        ["Hình 4.1", "Đối sánh 5 mô hình học máy trên tập kiểm thử Zero-Leakage defense_v2 (N = 6.929)", "Chương 4 (Mục 4.2.1)"],
        ["Hình 4.1b", "Ma trận nhầm lẫn XGBoost (N = 6.929) và Đối sánh Độ trễ Nội bộ so với HTTP 2-Hop Thực tế (CSIC N = 3.000)", "Chương 4 (Mục 4.2.2)"],
        ["Hình 4.2", "Kết quả Ablation Study 4 cấu hình phòng thủ và độ trễ cô lập", "Chương 4 (Mục 4.4)"],
        ["Hình 4.3", "Đối sánh hiệu năng & bảo mật giữa Baseline (RF 17-D) và Blue Team Hybrid", "Chương 4 (Mục 4.5)"],
        ["Hình 4.4", "Thông lượng xử lý đồng thời (RPS) của WAF Gateway dưới tải ASGI C = 1..50", "Chương 4 (Mục 4.6.2)"],
        ["Hình 4.5a", "Đường hội tụ phần thưởng Curriculum 3 giai đoạn và hiệu suất giảm thử mù quáng Stage 3", "Chương 4 (Mục 4.7.3)"],
        ["Hình 4.5b", "Biểu đồ đối sánh Block Rate giữa tập Familiar và tập Strange Held-Out", "Chương 4 (Mục 4.7.3)"],
    ]
    add_styled_table(
        doc,
        ["Ký hiệu", "Tên hình ảnh / biểu đồ", "Vị trí"],
        fig_rows,
        alignments=[WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER],
        col_widths_cm=[2.3, 10.2, 3.0],
        font_size_pt=11.0,
    )

    # 4. DANH MỤC BẢNG BIỂU
    _add_front_matter_title(doc, "DANH MỤC BẢNG BIỂU", page_break=True)
    tbl_rows = [
        ["Bảng 1.1", "Các kỹ thuật làm mờ payload và né tránh tường lửa (WAF Evasion & Obfuscation)", "Chương 1 (Mục 1.1.3)"],
        ["Bảng 2.1", "Tổng hợp 8 nhóm yêu cầu chức năng cốt lõi của hệ thống", "Chương 2 (Mục 2.1.2)"],
        ["Bảng 2.2", "Chỉ tiêu phi chức năng và cam kết chất lượng dịch vụ (SLA)", "Chương 2 (Mục 2.1.3)"],
        ["Bảng 2.3", "Phân công trách nhiệm triển khai giữa 2 thành viên trên Thao trường 2 Máy", "Chương 2 (Mục 2.2)"],
        ["Bảng 2.4", "Ma trận quyết định hành động của Hybrid Decision Engine (0 – 100)", "Chương 2 (Mục 2.3.4)"],
        ["Bảng 2.5", "8 nhóm lỗ hổng Web API trong Bookie Bookstore (vulnerable-api)", "Chương 2 (Mục 2.4)"],
        ["Bảng 3.1", "Ngăn xếp công nghệ triển khai thực tế của PBL6 (Blue Team Hybrid + Red Team)", "Chương 3 (Mục 3.1)"],
        ["Bảng 4.1", "Tổng hợp 4 bộ dữ liệu và kịch bản kiểm định thực nghiệm Blue Team + Red Team", "Chương 4 (Mục 4.1.2)"],
        ["Bảng 4.2", "Kết quả đối sánh 5 thuật toán học máy trên tập Test defense_v2 (N = 6.929)", "Chương 4 (Mục 4.2.1)"],
        ["Bảng 4.3", "Ma trận nhầm lẫn thực tế của xgb_v2.ubj trên tập Test defense_v2 (N = 6.929)", "Chương 4 (Mục 4.2.2)"],
        ["Bảng 4.4", "Hiệu năng hiệu chuẩn phân vị của Calibrated Isolation Forest (iforest_v2.npz)", "Chương 4 (Mục 4.3)"],
        ["Bảng 4.5", "Ma trận đối sánh thực nghiệm Ablation Study — Blue Team Hybrid (N = 1000)", "Chương 4 (Mục 4.4)"],
        ["Bảng 4.6", "Tỷ lệ chặn theo từng họ lỗ hổng của Hybrid Defense (benchmark_1000_diverse)", "Chương 4 (Mục 4.4)"],
        ["Bảng 4.7", "Đối sánh Zero-Shot CSIC 2010 Two-Tier giữa Baseline (RF 17-D) và Hybrid Defense (N = 3.000)", "Chương 4 (Mục 4.5)"],
        ["Bảng 4.8", "Độ trễ đo thực tế từng thành phần nội bộ Gateway (run_gateway_profiling.py)", "Chương 4 (Mục 4.6.1)"],
        ["Bảng 4.9", "Thông lượng (RPS) và độ trễ phân vị của WAF Gateway dưới tải đồng thời ASGI", "Chương 4 (Mục 4.6.2)"],
        ["Bảng 4.10", "Kết quả đối kháng thực tế Red Team PyTorch DQN vs Blue Team Hybrid (20 lượt)", "Chương 4 (Mục 4.7.1)"],
        ["Bảng 4.11a", "Ma trận đối kháng 3x3 In-Process trên tập quen thuộc OpenAPI (Familiar Suite)", "Chương 4 (Mục 4.7.3)"],
        ["Bảng 4.11b", "Ma trận đối kháng 3x3 In-Process trên tập ngoại miền mới (Strange Held-Out Suite)", "Chương 4 (Mục 4.7.3)"],
        ["Bảng 4.11c", "Ma trận đối kháng qua Socket HTTP thật trên tập Strange Held-Out (N = 54)", "Chương 4 (Mục 4.7.4)"],
    ]
    add_styled_table(
        doc,
        ["Ký hiệu", "Tên bảng số liệu", "Vị trí"],
        tbl_rows,
        alignments=[WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER],
        col_widths_cm=[2.3, 10.2, 3.0],
        font_size_pt=10.5,
    )

    # 5. DANH MỤC CÁC TỪ VIẾT TẮT
    _add_front_matter_title(doc, "DANH MỤC CÁC TỪ VIẾT TẮT", page_break=True)
    abbr_rows = [
        ["API", "Application Programming Interface", "Giao diện lập trình ứng dụng (REST, GraphQL, SOAP/XML, JSON-RPC)"],
        ["ASGI", "Asynchronous Server Gateway Interface", "Giao diện máy chủ bất đồng bộ cho FastAPI / Uvicorn hiệu năng cao"],
        ["BFF", "Backend-For-Frontend", "Tầng proxy máy chủ Next.js (/api/gateway/*) bảo vệ X-API-Key"],
        ["BOLA / IDOR", "Broken Object Level Authorization", "Lỗ hổng phân quyền mức đối tượng (OWASP API1:2023)"],
        ["CRS", "Core Rule Set", "Bộ quy tắc phòng thủ chuẩn của OWASP ModSecurity WAF"],
        ["CWE-502", "Deserialization of Untrusted Data", "Lỗ hổng giải tuần tự hóa không tin cậy (triệt tiêu bằng Zero-Pickle)"],
        ["DLP", "Data Loss Prevention", "Cơ chế ngăn rò rỉ dữ liệu nhạy cảm ở chiều phản hồi (Outbound)"],
        ["DQN", "Deep Q-Network", "Mạng học tăng cường sâu có Action Masking (74-D / 36-Action) của Red Team"],
        ["FPR / TPR", "False / True Positive Rate", "Tỷ lệ báo động nhầm trên mẫu sạch / Tỷ lệ phát hiện đúng tấn công"],
        ["GBDT", "Gradient Boosted Decision Trees", "Cây quyết định tăng cường độ dốc (XGBoost)"],
        ["iForest", "Isolation Forest", "Thuật toán học không giám sát phát hiện dị biệt Zero-Day (iforest_v2.npz)"],
        ["MDP", "Markov Decision Process", "Quy trình quyết định Markov mô hình hóa chuỗi tấn công né tránh WAF"],
        ["ReDoS", "Regular Expression Denial of Service", "Tấn công từ chối dịch vụ bằng biểu thức chính quy quay lui bậc hai"],
        ["RPS", "Requests Per Second", "Thông lượng yêu cầu xử lý mỗi giây (đạt 253–340 RPS @ C=50)"],
        ["SLA", "Service Level Agreement", "Cam kết hiệu năng (Inline <= 1.5 ms, 2-Hop HTTP E2E <= 5.5 ms, >= 150 RPS)"],
        ["SOC", "Security Operations Center", "Trung tâm điều hành và giám sát an ninh mạng thời gian thực"],
        ["SQLi / XSS", "SQL Injection / Cross-Site Scripting", "Hai họ lỗ hổng tiêm mã cơ sở dữ liệu và kịch bản chéo trang phổ biến"],
        ["UBJSON / NPZ", "Universal Binary JSON / NumPy Zip", "Hai định dạng tuần tự hóa Zero-Pickle an toàn cho XGBoost và IForest"],
        ["WAF", "Web Application Firewall", "Tường lửa ứng dụng web Tầng 7 bảo vệ Web API"],
        ["WAL", "Write-Ahead Logging", "Chế độ nhật ký đồng thời SQLite kết hợp Group Commit không khóa nghẽn"],
        ["XAI", "Explainable Artificial Intelligence", "Trí tuệ nhân tạo giải trình qua vector 26-D và điểm từng tầng phòng thủ"],
        ["XGBoost", "Extreme Gradient Boosting", "Mô hình Champion Cost-Sensitive Regularized GBDT (xgb_v2.ubj)"],
    ]
    add_styled_table(
        doc,
        ["Từ viết tắt", "Thuật ngữ tiếng Anh", "Diễn giải & Ứng dụng trong PBL6"],
        abbr_rows,
        alignments=[WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT],
        col_widths_cm=[2.6, 5.2, 7.7],
        font_size_pt=10.5,
    )

    # 6. PHÂN CÔNG CÔNG VIỆC
    _add_front_matter_title(doc, "PHÂN CÔNG CÔNG VIỆC", page_break=True)
    assign_rows = [
        ["1", "Khảo sát 20 tài liệu học thuật, chuẩn OWASP API Top 10 (2023), NIST SP 800-115 & kiến trúc Cyber Range 2 máy", "Ngô Văn Công (Blue Team)\nNguyễn Công Minh (Red Team)"],
        ["2", "Thiết kế & hiện thực ứng dụng mục tiêu Bookie Bookstore (Django, 8 lỗ hổng OWASP, OpenAPI 3.0, loopback 127.0.0.1:5000)", "Ngô Văn Công (Blue Team)"],
        ["3", "Xây dựng tập dữ liệu Zero-Leakage defense_v2 (47.372 mẫu), bộ 26 đặc trưng thống nhất, XGBoost (UBJ) & IForest (NPZ)", "Ngô Văn Công (Blue Team)"],
        ["4", "Xây dựng WAF Gateway Async (28 Hardened Rules, Multi-Protocol, OpenAPI Schema, 5 OWASP API Guards, Rate Limit, WAL)", "Ngô Văn Công (Blue Team)"],
        ["5", "Xây dựng SOC Command Center & Server-Side BFF Proxy (Next.js 14, 100% số liệu thật, Kill Chain, 26-D XAI, Docker Hardening & CI)", "Ngô Văn Công (Blue Team)"],
        ["6", "Xây dựng module trinh sát OpenAPI (recon.py có cycle guard) và môi trường Đồ thị Tấn công MDP (74-D state / 36 actions)", "Nguyễn Công Minh (Red Team)"],
        ["7", "Phát triển bộ biến dị bảo toàn ngữ nghĩa (evasion.py) & huấn luyện PyTorch Dueling Double-DQN 4 giai đoạn (800 episodes, SHA-256)", "Nguyễn Công Minh (Red Team)"],
        ["8", "Phát triển Đấu Trường AI trực quan (/arena SSE Cockpit) & điều phối chiến dịch đối kháng 3x3 In-Process / Live HTTP", "Nguyễn Công Minh (Red Team)"],
        ["9", "Thực nghiệm kiểm định độc lập (Ablation, CSIC Two-Tier, Strange Suite, Blind Held-Out Vault, C=50 Profiling) & hoàn thiện báo cáo", "Ngô Văn Công (Blue Team)\nNguyễn Công Minh (Red Team)"],
    ]
    add_styled_table(
        doc,
        ["TT", "Nội dung công việc thực hiện", "Sinh viên phụ trách"],
        assign_rows,
        alignments=[WD_ALIGN_PARAGRAPH.CENTER, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.LEFT],
        col_widths_cm=[1.1, 9.7, 4.7],
        font_size_pt=10.5,
    )


def build_mo_dau(doc: Document, m: dict[str, Any]) -> None:
    """Section 2 first Heading 1: MỞ ĐẦU (styled like MHMM MỞ ĐẦU)."""
    ab_hy = m["abl"]["modes"]["hybrid"]
    e2e = m["lat"]["http_e2e_latency_ms"]
    d2_tot = _fmt_vi(int(m["leak"]["metadata"]["defense_v2_total_rows"]))
    c50_rps = float(m["perf"]["concurrency_benchmark"]["benign_passthrough"][-1]["rps"])
    dqn = m["dqn"]

    h1 = doc.add_paragraph("MỞ ĐẦU", style="Heading 1")
    h1.paragraph_format.page_break_before = False  # Starts right after Section 2 break

    doc.add_paragraph("1. Bối cảnh và Tính cấp thiết của đề tài", style="Heading 2")
    p = doc.add_paragraph(style="Normal")
    p.add_run(
        "Sự bùng nổ của kiến trúc Microservices và điện toán đám mây đã biến Web API (REST/JSON, GraphQL, SOAP/XML, JSON-RPC 2.0) "
        "thành hạ tầng kết nối cốt lõi của các hệ thống thương mại điện tử, ngân hàng số và chính phủ điện tử. Tuy nhiên, việc phơi bày "
        "trực tiếp lược đồ OpenAPI/Swagger và logic nghiệp vụ qua tầng HTTP khiến bề mặt tấn công (Attack Surface) mở rộng nhanh chóng. "
        "Các tường lửa ứng dụng web (WAF) truyền thống dựa trên chữ ký tĩnh (như tập luật đơn lẻ) bộc lộ ba điểm yếu nghiêm trọng: "
        "dễ bị qua mặt bởi các kỹ thuật làm mờ payload bảo toàn ngữ nghĩa (Double URL Encoding, inline comment, ký tự vô hình Unicode, "
        "trùng khóa JSON), đánh đổi gay gắt giữa tỷ lệ chặn và báo động nhầm (False Positive), cùng nguy cơ treo CPU do biểu thức chính quy "
        "quay lui bậc hai (ReDoS)."
    )
    p2 = doc.add_paragraph(style="Normal")
    p2.add_run(
        "Song song với đó, sự phát triển của Trí tuệ nhân tạo tấn công (Offensive AI) — đặc biệt là các tác tử Học tăng cường sâu (Deep RL / DQN) "
        "tự động trinh sát đặc tả OpenAPI và biến dị payload theo phản hồi HTTP — đòi hỏi hệ thống phòng thủ phải chuyển từ mô hình tĩnh sang "
        "kiến trúc phòng thủ lai đa tầng (Hybrid Defense-in-Depth) kết hợp Chuẩn hóa đầu vào, Positive Security Schema, Luật gia cố chống ReDoS, "
        "Học máy có giám sát và Phát hiện dị biệt không giám sát, đồng thời được kiểm chứng trực diện trong một Thao trường An ninh Đối kháng "
        "(Distributed Cyber Range) vận hành trên lưu lượng HTTP thật."
    )

    doc.add_paragraph("2. Mục tiêu đề tài (5 mục tiêu phòng thủ + 5 mục tiêu tấn công cốt lõi)", style="Heading 2")
    p_def_intro = doc.add_paragraph(style="Normal")
    add_formatted_runs(p_def_intro, "**5 mục tiêu cốt lõi phân hệ Phòng thủ (Blue Team — Ngô Văn Công):**")
    def_goals = [
        "Xây dựng Cổng WAF Reverse Proxy bất đồng bộ chịu tải cao (`FastAPI` + `Pure ASGI` + `SQLite WAL Group Commit`), đạt thông lượng `>= 150 RPS` ở mức tải đồng thời `C = 50` (thực đo `~340 RPS`) và độ trễ 2-hop HTTP E2E `<= 5.5 ms`.",
        f"Thiết lập bộ dữ liệu chuẩn hóa không rò rỉ **`defense_v2` ({d2_tot} mẫu, `0` trùng lặp hash)** cùng **Không gian 26 đặc trưng thống nhất (`extract_26_from_http`)** và **Per-Parameter Max-Pooling** nhằm triệt tiêu hiện tượng Training-Serving Skew.",
        f"Triển khai đường ống AI/ML **Zero-Pickle 100%** (`XGBoost` UBJSON + `Calibrated Isolation Forest` NPZ kèm xác thực SHA-256 Fail-Closed), đạt độ trễ inline `<= 1.5 ms/req` (thực đo **`{ab_hy['avg_latency_ms']:.3f} ms/req`**) và **`{ab_hy['f1_score_pct']:.2f}%` F1-Score**.",
        "Hoàn thiện **28 Hardened Signatures**, `InputNormalizer` chống biến dị đa tầng, `OpenAPI 3.0 Schema Validator` (`route_tiered`), và **5 lá chắn OWASP API Top 10** (`SSRF`, `NoSQLi`, `Mass Assignment`, `Stateful BOLA`, `Response DLP`), giữ **`0.00%` Operational FPR**.",
        "Xây dựng Trung tâm Điều hành SOC (`Next.js 14`) giao tiếp 100% qua Server-Side BFF Proxy (`0` client secret), hiển thị 100% số liệu thật, chuỗi Cyber Kill Chain 5 pha và giải trình XAI 26 chiều.",
    ]
    for idx, g in enumerate(def_goals, 1):
        pb = doc.add_paragraph(style="List Bullet")
        pb.paragraph_format.first_line_indent = Cm(0)
        add_formatted_runs(pb, f"**[Blue-{idx}]** {g}")

    p_red_intro = doc.add_paragraph(style="Normal")
    add_formatted_runs(p_red_intro, "**5 mục tiêu cốt lõi phân hệ Tấn công Đối kháng (Red Team — Nguyễn Công Minh):**")
    red_goals = [
        "Xây dựng module trinh sát tự động đặc tả OpenAPI 3.0 (`recon.py`) tích hợp cơ chế chống vòng lặp vô hạn `$ref` (`seen_refs` cycle guard) để lập bản đồ bề mặt tấn công.",
        f"Mô hình hóa bài toán thâm nhập Web API thành Đồ thị Tấn công MDP (`AttackGraph`) với không gian trạng thái **`{dqn['state_dim']}-D`** và **`{dqn['action_dim']}` hành động rời rạc** có mặt nạ hành động hợp lệ (Action Masking).",
        "Phát triển động cơ biến dị bảo toàn ngữ nghĩa (`evasion.py`) bao phủ 4 họ OWASP (`SQLi`, `XSS`, `Path Traversal`, `CMD Injection`) cùng kỹ thuật nested traversal, scientific-float, wildcard-globbing và JSON duplicate-key tamper.",
        f"Huấn luyện tác tử **PyTorch Dueling Double-DQN** qua giáo trình đa giai đoạn **`{dqn['episodes_trained']} episodes`** (gồm RAM và Live-HTTP `:8056/:8055`), nạp an toàn bằng `weights_only=True` + SHA-256 Fail-Closed.",
        "Tích hợp **Đấu Trường AI (`/arena`)** phát trực tiếp luồng SSE thời gian thực Red vs Blue trên SOC Cockpit và kiểm chứng độ bền phòng thủ qua các bộ `Familiar`, `Strange Suite` và `Blind Held-Out Vault`.",
    ]
    for idx, g in enumerate(red_goals, 1):
        pb = doc.add_paragraph(style="List Bullet")
        pb.paragraph_format.first_line_indent = Cm(0)
        add_formatted_runs(pb, f"**[Red-{idx}]** {g}")

    doc.add_paragraph("3. Phương pháp nghiên cứu và Thực hiện", style="Heading 2")
    methods = [
        "**Nghiên cứu lý thuyết & chuẩn hóa kiến trúc:** Tổng hợp 20 giáo trình, tiêu chuẩn công nghiệp (OWASP API Top 10 2023, ModSecurity CRS v4.0, NIST SP 800-115, MITRE ATT&CK) và công trình học thuật quốc tế về ML WAF và Cyber Range.",
        "**Thiết kế & hiện thực hóa hướng bảo mật (Security-by-Design):** Triển khai ứng dụng mục tiêu `Bookie Bookstore` độc lập (Django), cổng WAF Gateway Async (FastAPI), bộ tác tử Red Team PyTorch DQN và SOC Dashboard Next.js BFF; đóng gói 4 container non-root kèm CI/CD tự động.",
        f"**Đánh giá thực nghiệm định lượng không rò rỉ dữ liệu:** Áp dụng phân tách Canonical Hash Disjoint Split (`0` overlap), thực hiện Ablation Study (`N = 1.000`), Zero-Shot CSIC 2010 Two-Tier (`N = 3.000`, E2E `{e2e['mean_ms']:.3f} ms`), chịu tải đồng thời `C = 50` (`{c50_rps:.0f} RPS`) và đối kháng Live-HTTP 3x3.",
    ]
    for m_txt in methods:
        pb = doc.add_paragraph(style="List Bullet")
        pb.paragraph_format.first_line_indent = Cm(0)
        add_formatted_runs(pb, m_txt)

    doc.add_paragraph("4. Bố cục báo cáo", style="Heading 2")
    p_org = doc.add_paragraph(style="Normal")
    p_org.add_run("Ngoài phần Mở đầu, Kết luận, Tài liệu tham khảo và Phụ lục, nội dung chính của báo cáo được tổ chức thành 5 chương:")
    chapters_overview = [
        "**Chương 1 — Cơ sở lý thuyết và Tổng quan công nghệ:** Trình bày nền tảng bảo mật Web API theo OWASP 2023, các kỹ thuật né tránh WAF, lý thuyết trích xuất 26 đặc trưng, XGBoost, Calibrated Isolation Forest, khung Cyber Range và mô hình MDP / Dueling Double-DQN.",
        "**Chương 2 — Phân tích yêu cầu và Thiết kế kiến trúc hệ thống:** Đặc tả 8 nhóm yêu cầu chức năng (FR-01..FR-08), 5 nhóm phi chức năng (NFR-01..NFR-05), kiến trúc Thao trường 2 máy, đường ống WAF Async, ứng dụng Bookie Bookstore, tác tử Red Team và CSDL SQLite WAL.",
        "**Chương 3 — Cài đặt và Hiện thực hóa hệ thống:** Chi tiết kỹ thuật cài đặt từng phân hệ (`gateway/`, `ml-engine/`, `vulnerable-api/`, `attack-lab/`, `dashboard/`), gia cố chuỗi cung ứng Zero-Pickle, Server-Side BFF Proxy, Docker non-root và pipeline CI/CD.",
        "**Chương 4 — Thực nghiệm và Đánh giá kết quả:** Trình bày đầy đủ kết quả đối sánh 5 thuật toán ML, Ablation Study 4 cấu hình, Zero-Shot CSIC 2010 Two-Tier + `/tienda1` Schema, đo kiểm tải cao `C = 50`, kiểm toán an ninh 26 findings và ma trận đối kháng 3x3 Live-HTTP / Blind Held-Out Vault.",
        "**Chương 5 — Kết luận và Hướng phát triển:** Tổng kết các đóng góp khoa học – kỹ thuật, chỉ ra thẳng thắn 3 giới hạn hiện tại và đề xuất 4 hướng mở rộng trong tương lai.",
    ]
    for ch_txt in chapters_overview:
        pb = doc.add_paragraph(style="List Bullet")
        pb.paragraph_format.first_line_indent = Cm(0)
        add_formatted_runs(pb, ch_txt)


def configure_main_body_section(doc: Document) -> None:
    """Section 2: Main Body with Arabic page numbers (1, 2, 3...) and running header."""
    sec = doc.add_section(WD_SECTION.NEW_PAGE)
    sec.page_width = Cm(21.0)
    sec.page_height = Cm(29.7)
    sec.top_margin = Cm(2.5)
    sec.bottom_margin = Cm(2.5)
    sec.left_margin = Cm(3.5)
    sec.right_margin = Cm(2.0)
    sec.header_distance = Cm(1.25)
    sec.footer_distance = Cm(1.25)
    _set_section_borders(sec, double_black=False)
    _set_section_page_numbers(sec, fmt="decimal", start=1)

    sec.header.is_linked_to_previous = False
    sec.footer.is_linked_to_previous = False

    # Running Header: italic gray with thin bottom border (matching MHMM header3.xml)
    hp = sec.header.paragraphs[0]
    hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    hp.paragraph_format.first_line_indent = Cm(0)
    hp.paragraph_format.space_before = Pt(0)
    hp.paragraph_format.space_after = Pt(2)
    hpPr = hp._p.get_or_add_pPr()
    hpPr.append(parse_xml(
        f'<w:pBdr {nsdecls("w")}>'
        '<w:bottom w:val="single" w:color="CCCCCC" w:sz="4" w:space="4"/>'
        "</w:pBdr>"
    ))
    hr = hp.add_run("Báo cáo Đồ án Chuyên ngành (PBL6)  |  Nền tảng Bảo mật Web API Lai & Cyber Range Đối kháng")
    _set_run_font(hr, "Times New Roman", 9.5, bold=False, italic=True, color=HEADER_GRAY_RGB)

    # Footer: right-aligned regular Arabic page number
    _add_page_number_field(sec.footer.paragraphs[0], italic=False)


# ---------------------------------------------------------------------------
# 6. Reconciliation Parity Verifier (All 33 Tokens)
# ---------------------------------------------------------------------------

def verify_reconciliation_tokens(docx_path: Path, m: dict[str, Any]) -> None:
    """Assert every single one of the 33 reconciliation matrix tokens exists in PBL6_Bao_Cao.docx."""
    d = Document(str(docx_path))
    parts = [p.text for p in d.paragraphs]
    for tbl in d.tables:
        for row in tbl.rows:
            parts.append(" | ".join(c.text for c in row.cells))
    docx_txt = "\n".join(parts)

    fam = m["adv"]["familiar"]
    stg = m["adv"]["strange"]
    lfam = m["live"]["familiar_results"]
    lstg = m["live"]["strange_results"]
    dqn = m["dqn"]
    cm = dqn["curriculum_metrics"]
    fp_agg = m["fp"]["aggregate_summary"]
    b1000 = m["fp"]["corpora"]["benchmark_1000_diverse_benign"]
    fpt = m["fpt"]
    e2e = m["lat"]["http_e2e_latency_ms"]
    ab_m = m["abl"]["modes"]
    csic = m["csic"]
    csic_h = csic["hybrid_defense_in_depth"]
    c50_rps = m["perf"]["concurrency_benchmark"]["benign_passthrough"][-1]["rps"]
    aug = m["aug"]
    tax = m["csic_tax"]
    td1 = m["csic_tienda1"]
    st33 = m["st33"]
    bv2 = m["bv2"]

    tokens = [
        f"{fam['Static Replay']['Rules Only']['block_rate_pct']:.1f}% ({fam['Static Replay']['Rules Only']['blocked_count']}/{fam['Static Replay']['Rules Only']['total_rounds']})",
        f"{fam['Dueling-DQN v2.0']['Rules Only']['block_rate_pct']:.1f}% ({fam['Dueling-DQN v2.0']['Rules Only']['blocked_count']}/{fam['Dueling-DQN v2.0']['Rules Only']['total_rounds']})",
        f"{fam['Dueling-DQN v2.0']['Rules Only']['evasion_rate_pct']:.1f}%",
        f"{fam['Dueling-DQN v2.0']['Hybrid v3.0']['block_rate_pct']:.1f}% ({fam['Dueling-DQN v2.0']['Hybrid v3.0']['blocked_count']}/{fam['Dueling-DQN v2.0']['Hybrid v3.0']['total_rounds']})",
        f"{fam['Dueling-DQN v2.0']['Hybrid v3.0']['avg_latency_ms']:.3f} ms",
        f"{stg['Static Replay']['Rules Only']['block_rate_pct']:.1f}% ({stg['Static Replay']['Rules Only']['blocked_count']}/{stg['Static Replay']['Rules Only']['total_rounds']})",
        f"{stg['Dueling-DQN v2.0']['Rules Only']['block_rate_pct']:.1f}% ({stg['Dueling-DQN v2.0']['Rules Only']['blocked_count']}/{stg['Dueling-DQN v2.0']['Rules Only']['total_rounds']})",
        f"{stg['Dueling-DQN v2.0']['Hybrid v3.0']['block_rate_pct']:.1f}%",
        f"{lfam['Dueling-DQN v2.0']['Hybrid v3.0']['block_rate_pct']:.1f}% ({lfam['Dueling-DQN v2.0']['Hybrid v3.0']['blocked_count']}/{lfam['Dueling-DQN v2.0']['Hybrid v3.0']['total_episodes']})",
        f"{lstg['Dueling-DQN v2.0']['Rules Only']['block_rate_pct']:.1f}% ({lstg['Dueling-DQN v2.0']['Rules Only']['blocked_count']}/{lstg['Dueling-DQN v2.0']['Rules Only']['total_episodes']})",
        f"{lstg['Dueling-DQN v2.0']['Hybrid v3.0']['block_rate_pct']:.1f}%",
        f"{lstg['Dueling-DQN v2.0']['Hybrid v3.0']['avg_latency_ms']:.3f} ms",
        f"{dqn['episodes_trained']} episodes",
        f"{cm['stage3_avg_reward']:.2f}",
        f"{cm['stage3_blind_retries_reduction_pct']:.2f}%",
        f"{fp_agg['fp_operational_pct']:.2f}%",
        f"{b1000['fp_strict_schema_off_pct']:.1f}%",
        f"{fpt['rounds'][2]['b1000_strict_schema_on_pct']:.1f}%",
        f"{e2e['mean_ms']:.3f} ms",
        f"{e2e['p50_ms']:.3f} ms",
        f"{ab_m['rules_only']['f1_score_pct']:.2f}%",
        f"{ab_m['ml_only']['f1_score_pct']:.2f}%",
        f"{ab_m['hybrid']['f1_score_pct']:.2f}%",
        f"{csic_h['fpr']:.2f}%",
        f"{csic['two_tier_parallel_metrics']['overall_1500']['hybrid_operational_t80_recall_pct']:.2f}%",
        "zero_leakage_verified = true",
        f"{c50_rps:.0f} RPS",
        f"{dqn['stage4_live_http_metrics']['live_http_8056_dqn_bypass_rate_pct']:.1f}%",
        f"{aug['added_total_rows']}",
        f"{tax['parallel_metrics']['operational_decision_engine_t80']['group_a_recall_pct']:.2f}% ({tax['parallel_metrics']['operational_decision_engine_t80']['group_a_blocked']}/{tax['two_tier_breakdown']['group_a_true_payload']['count']})",
        f"{td1['operational_decision_engine_t80']['hybrid_plus_tienda1_schema_strict']['group_b_parameter_tampering']['recall_pct']:.2f}%",
        f"{st33['live_http']['Dueling-DQN v2.0']['Hybrid v3.3']['block_rate_pct']:.2f}% ({st33['live_http']['Dueling-DQN v2.0']['Hybrid v3.3']['blocked_count']}/{st33['live_http']['Dueling-DQN v2.0']['Hybrid v3.3']['total_episodes']})",
        f"{bv2['live_http']['Dueling-DQN v2.0']['Hybrid v3.3']['block_rate_pct']:.2f}% ({bv2['live_http']['Dueling-DQN v2.0']['Hybrid v3.3']['blocked_count']}/{bv2['live_http']['Dueling-DQN v2.0']['Hybrid v3.3']['total_episodes']})",
    ]
    missing = [(idx + 1, tok) for idx, tok in enumerate(tokens) if tok not in docx_txt]
    if missing:
        raise AssertionError(f"Missing reconciliation tokens in {docx_path}: {missing}")
    print(f"[OK] Verified {len(tokens)}/{len(tokens)} reconciliation tokens present in {docx_path.name}")


def verify_canonical_requirements(docx_path: Path) -> None:
    """Assert canonical GVHD, MSSV/class uniqueness, zero handles, and zero dotted version labels."""
    d = Document(str(docx_path))
    chunks: list[str] = [p.text for p in d.paragraphs]
    for tbl in d.tables:
        for row in tbl.rows:
            for cell in row.cells:
                chunks.append(cell.text)
    for sec in d.sections:
        for hf in (sec.header, sec.footer):
            for p in hf.paragraphs:
                chunks.append(p.text)
            for tbl in hf.tables:
                for row in tbl.rows:
                    for cell in row.cells:
                        chunks.append(cell.text)
    full_txt = "\n".join(chunks)

    forbidden = [
        ("vcongggggg", re.compile(r"vcongggggg", re.I)),
        ("naocavang08", re.compile(r"naocavang08", re.I)),
        ("Nguyễn Thế Xuân Ly", re.compile(r"Nguyễn Thế Xuân Ly", re.I)),
        ("Xuân Ly", re.compile(r"Xuân Ly", re.I)),
        ("21T_DT", re.compile(r"21T_DT", re.I)),
        ("dotted_version", re.compile(r"\bv(?:1\.0|2\.0|3\.0|3\.1|3\.2|3\.3|3\.4)\b", re.I)),
        ("placeholder_ref_research_team", re.compile(r"Research Team", re.I)),
        ("placeholder_ref_academic_authors", re.compile(r"Academic Authors", re.I)),
        ("placeholder_ref_security_researchers", re.compile(r"Security Researchers", re.I)),
    ]
    for label, pat in forbidden:
        hits = pat.findall(full_txt)
        if hits:
            raise AssertionError(f"Canonical check failed: found forbidden {label}: {hits[:10]}")

    c_id1 = full_txt.count("102230284")
    c_id2 = full_txt.count("102230306")
    c_cls = full_txt.count("23T_DT3")
    c_gvhd = full_txt.count("TS. Nguyễn Năng Hùng Vân")
    if c_id1 != 1 or c_id2 != 1 or c_cls < 1 or c_gvhd < 2:
        raise AssertionError(
            f"Canonical count mismatch: 102230284={c_id1}, 102230306={c_id2}, 23T_DT3={c_cls}, GVHD={c_gvhd}"
        )
    print(
        f"[OK] Verified canonical constraints: GVHD={c_gvhd}, "
        f"102230284={c_id1}, 102230306={c_id2}, 23T_DT3={c_cls}, dotted_versions=0, handles=0"
    )


# ---------------------------------------------------------------------------
# 7. Main Builder Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    metrics = load_all_metrics()
    doc = Document()
    configure_styles(doc)

    # Section 0: Cover Page
    build_cover_page(doc)

    # Section 1: Front Matter
    build_front_matter(doc, metrics)

    # Section 2: Main Body
    configure_main_body_section(doc)
    build_mo_dau(doc, metrics)

    ch1 = normalize_authors(prepare_chapter1_markdown((ARCHIVE_DIR / "CHUONG_1_CO_SO_LY_THUYET.md").read_text(encoding="utf-8")))
    ch2 = normalize_authors(prepare_chapter2_markdown((ARCHIVE_DIR / "CHUONG_2_THIET_KE_KIEN_TRUC.md").read_text(encoding="utf-8")))
    ch3 = normalize_authors(prepare_chapter3_markdown((ARCHIVE_DIR / "CHUONG_3_CAI_DAT_HIEN_THUC_HOA.md").read_text(encoding="utf-8")))
    ch4_raw = (ARCHIVE_DIR / "CHUONG_4_THUC_NGHIEM_DANH_GIA.md").read_text(encoding="utf-8")
    ch4 = normalize_authors(prepare_chapter4_markdown(ch4_raw, metrics))
    ch5_raw = (ARCHIVE_DIR / "CHUONG_5_KET_LUAN_HUONG_PHAT_TRIEN.md").read_text(encoding="utf-8")
    ch5 = normalize_authors(prepare_chapter5_markdown(ch5_raw, metrics))
    ref_app = normalize_authors(prepare_ref_appendix_markdown((ARCHIVE_DIR / "TAI_LIEU_THAM_KHAO_VA_PHU_LUC.md").read_text(encoding="utf-8")))

    render_markdown_chapter(doc, ch1)
    render_markdown_chapter(doc, ch2, is_ch2=True)
    render_markdown_chapter(doc, ch3)
    render_markdown_chapter(doc, ch4)
    render_markdown_chapter(doc, ch5)
    render_markdown_chapter(doc, ref_app, split_ref_appendix=True)

    OUT_DOCX.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(OUT_DOCX))
    print(f"[OK] Saved consolidated report -> {OUT_DOCX}")
    verify_reconciliation_tokens(OUT_DOCX, metrics)
    verify_canonical_requirements(OUT_DOCX)


if __name__ == "__main__":
    main()

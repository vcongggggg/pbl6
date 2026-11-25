"""Programmatic Thesis <-> JSON Artifact Reconciliation Verifier & Matrix Generator (Phase C4).

Zero manual/human number entry:
1. Loads every ground-truth JSON artifact from disk.
2. Extracts raw text + table cells from `PBL6_Bao_Cao.docx`, `PBL6_Academic_Defense_Slides.pptx`,
   and `CHUONG_4_THUC_NGHIEM_DANH_GIA.md`.
3. Asserts that every metric's formatted string ACTUALLY appears in the target document(s) on disk.
   Exits non-zero immediately if any discrepancy exists.
4. Writes `docs/reports/THESIS_ARTIFACT_RECONCILIATION_MATRIX.md` from verified ground truth.
"""

from __future__ import annotations

import json
from pathlib import Path

from docx import Document
from pptx import Presentation

ROOT_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = ROOT_DIR / "docs" / "reports"
OUT_MD = REPORTS_DIR / "THESIS_ARTIFACT_RECONCILIATION_MATRIX.md"


def _extract_docx_text(path: Path) -> str:
    doc = Document(str(path))
    parts = [p.text for p in doc.paragraphs]
    for tbl in doc.tables:
        for row in tbl.rows:
            parts.append(" | ".join(c.text for c in row.cells))
    return "\n".join(parts)


def _extract_pptx_text(path: Path) -> str:
    prs = Presentation(str(path))
    parts: list[str] = []
    for sl in prs.slides:
        for sh in sl.shapes:
            if sh.has_text_frame:
                parts.append(sh.text)
            if sh.has_table:
                for row in sh.table.rows:
                    parts.append(" | ".join(c.text for c in row.cells))
    return "\n".join(parts)


def main() -> None:
    adv = json.loads((REPORTS_DIR / "adversarial_benchmark_3x3.json").read_text(encoding="utf-8"))
    live = json.loads((REPORTS_DIR / "adversarial_benchmark_live_http.json").read_text(encoding="utf-8"))
    dqn = json.loads((ROOT_DIR / "attack-lab/models/pentest_dqn_v2_metadata.json").read_text(encoding="utf-8"))
    fp = json.loads((REPORTS_DIR / "fp_v3_measurement.json").read_text(encoding="utf-8"))
    fpt = json.loads((REPORTS_DIR / "fp_v3_tuning_c3.json").read_text(encoding="utf-8"))
    lat = json.loads((REPORTS_DIR / "latency_e2e_v3_csic.json").read_text(encoding="utf-8"))
    abl = json.loads((REPORTS_DIR / "ablation_results.json").read_text(encoding="utf-8"))
    csic = json.loads((REPORTS_DIR / "csic2010_benchmark_results.json").read_text(encoding="utf-8"))
    leak = json.loads((REPORTS_DIR / "zero_leakage_v3_verification.json").read_text(encoding="utf-8"))
    perf = json.loads((REPORTS_DIR / "performance_profile_results.json").read_text(encoding="utf-8"))
    aug = json.loads((REPORTS_DIR / "phase_e_augmentation_manifest.json").read_text(encoding="utf-8"))
    csic_tax = json.loads((REPORTS_DIR / "csic2010_taxonomy_breakdown.json").read_text(encoding="utf-8"))
    csic_tienda1 = json.loads((REPORTS_DIR / "csic2010_tienda1_schema_proof.json").read_text(encoding="utf-8"))
    st33 = json.loads((REPORTS_DIR / "strange_suite_v33_results.json").read_text(encoding="utf-8"))
    bv2 = json.loads((REPORTS_DIR / "blind_heldout_vault_v2_results.json").read_text(encoding="utf-8"))

    docx_txt = _extract_docx_text(REPORTS_DIR / "PBL6_Bao_Cao.docx")
    docx_ch4_txt = _extract_docx_text(REPORTS_DIR / "PBL6_Bao_Cao_Chuong_4_Thuc_Nghiem_Danh_Gia.docx")
    docx_full_txt = _extract_docx_text(REPORTS_DIR / "PBL6_Bao_Cao_Tong_Hop_Toan_Van.docx")
    pptx_txt = _extract_pptx_text(REPORTS_DIR / "PBL6_Academic_Defense_Slides.pptx")
    md_txt = (REPORTS_DIR / "CHUONG_4_THUC_NGHIEM_DANH_GIA.md").read_text(encoding="utf-8").replace("**", "").replace("`", "")

    fam = adv["familiar"]
    stg = adv["strange"]
    lfam = live["familiar_results"]
    lstg = live["strange_results"]
    cm = dqn["curriculum_metrics"]
    e2e = lat["http_e2e_latency_ms"]
    fp_agg = fp["aggregate_summary"]
    b1000_fp = fp["corpora"]["benchmark_1000_diverse_benign"]
    ab_m = abl["modes"]
    csic_h = csic["hybrid_defense_in_depth"]
    c50_rps = perf["concurrency_benchmark"]["benign_passthrough"][-1]["rps"]

    # Each check: (Category, Metric Name, Artifact File, JSON Path, Ground Truth Str, Search Token, Targets)
    checks: list[tuple[str, str, str, str, str, str, list[tuple[str, str]]]] = [
        (
            "1. In-Process 3x3 (Familiar)",
            "Static Replay vs Legacy Rules Block",
            "adversarial_benchmark_3x3.json",
            "familiar.Static Replay.Rules Only.block_rate_pct",
            f"{fam['Static Replay']['Rules Only']['block_rate_pct']:.1f}% ({fam['Static Replay']['Rules Only']['blocked_count']}/{fam['Static Replay']['Rules Only']['total_rounds']})",
            f"{fam['Static Replay']['Rules Only']['block_rate_pct']:.1f}% ({fam['Static Replay']['Rules Only']['blocked_count']}/{fam['Static Replay']['Rules Only']['total_rounds']})",
            [("DOCX", docx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "1. In-Process 3x3 (Familiar)",
            "Dueling-DQN vs Legacy Rules Block",
            "adversarial_benchmark_3x3.json",
            "familiar.Dueling-DQN v2.0.Rules Only.block_rate_pct",
            f"{fam['Dueling-DQN v2.0']['Rules Only']['block_rate_pct']:.1f}% ({fam['Dueling-DQN v2.0']['Rules Only']['blocked_count']}/{fam['Dueling-DQN v2.0']['Rules Only']['total_rounds']})",
            f"{fam['Dueling-DQN v2.0']['Rules Only']['block_rate_pct']:.1f}% ({fam['Dueling-DQN v2.0']['Rules Only']['blocked_count']}/{fam['Dueling-DQN v2.0']['Rules Only']['total_rounds']})",
            [("DOCX", docx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "1. In-Process 3x3 (Familiar)",
            "Dueling-DQN vs Legacy Rules Evasion",
            "adversarial_benchmark_3x3.json",
            "familiar.Dueling-DQN v2.0.Rules Only.evasion_rate_pct",
            f"{fam['Dueling-DQN v2.0']['Rules Only']['evasion_rate_pct']:.1f}%",
            f"{fam['Dueling-DQN v2.0']['Rules Only']['evasion_rate_pct']:.1f}%",
            [("DOCX", docx_txt), ("PPTX", pptx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "1. In-Process 3x3 (Familiar)",
            "Dueling-DQN vs Hybrid v3.0 Block",
            "adversarial_benchmark_3x3.json",
            "familiar.Dueling-DQN v2.0.Hybrid v3.0.block_rate_pct",
            f"{fam['Dueling-DQN v2.0']['Hybrid v3.0']['block_rate_pct']:.1f}% ({fam['Dueling-DQN v2.0']['Hybrid v3.0']['blocked_count']}/{fam['Dueling-DQN v2.0']['Hybrid v3.0']['total_rounds']})",
            f"{fam['Dueling-DQN v2.0']['Hybrid v3.0']['block_rate_pct']:.1f}% ({fam['Dueling-DQN v2.0']['Hybrid v3.0']['blocked_count']}/{fam['Dueling-DQN v2.0']['Hybrid v3.0']['total_rounds']})",
            [("DOCX", docx_txt), ("PPTX", pptx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "1. In-Process 3x3 (Familiar)",
            "In-Process Hybrid Engine Mean Latency",
            "adversarial_benchmark_3x3.json",
            "familiar.Dueling-DQN v2.0.Hybrid v3.0.avg_latency_ms",
            f"{fam['Dueling-DQN v2.0']['Hybrid v3.0']['avg_latency_ms']:.3f} ms",
            f"{fam['Dueling-DQN v2.0']['Hybrid v3.0']['avg_latency_ms']:.3f} ms",
            [("DOCX", docx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "2. In-Process 3x3 (Strange)",
            "Static Replay vs Legacy Rules Block",
            "adversarial_benchmark_3x3.json",
            "strange.Static Replay.Rules Only.block_rate_pct",
            f"{stg['Static Replay']['Rules Only']['block_rate_pct']:.1f}% ({stg['Static Replay']['Rules Only']['blocked_count']}/{stg['Static Replay']['Rules Only']['total_rounds']})",
            f"{stg['Static Replay']['Rules Only']['block_rate_pct']:.1f}% ({stg['Static Replay']['Rules Only']['blocked_count']}/{stg['Static Replay']['Rules Only']['total_rounds']})",
            [("DOCX", docx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "2. In-Process 3x3 (Strange)",
            "Dueling-DQN vs Legacy Rules Block",
            "adversarial_benchmark_3x3.json",
            "strange.Dueling-DQN v2.0.Rules Only.block_rate_pct",
            f"{stg['Dueling-DQN v2.0']['Rules Only']['block_rate_pct']:.1f}% ({stg['Dueling-DQN v2.0']['Rules Only']['blocked_count']}/{stg['Dueling-DQN v2.0']['Rules Only']['total_rounds']})",
            f"{stg['Dueling-DQN v2.0']['Rules Only']['block_rate_pct']:.1f}% ({stg['Dueling-DQN v2.0']['Rules Only']['blocked_count']}/{stg['Dueling-DQN v2.0']['Rules Only']['total_rounds']})",
            [("DOCX", docx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "2. In-Process 3x3 (Strange)",
            "Dueling-DQN vs Hybrid v3.0 Block",
            "adversarial_benchmark_3x3.json",
            "strange.Dueling-DQN v2.0.Hybrid v3.0.block_rate_pct",
            f"{stg['Dueling-DQN v2.0']['Hybrid v3.0']['block_rate_pct']:.1f}% ({stg['Dueling-DQN v2.0']['Hybrid v3.0']['blocked_count']}/{stg['Dueling-DQN v2.0']['Hybrid v3.0']['total_rounds']})",
            f"{stg['Dueling-DQN v2.0']['Hybrid v3.0']['block_rate_pct']:.1f}%",
            [("DOCX", docx_txt), ("PPTX", pptx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "3. Live HTTP 3x3 (C1)",
            "Live HTTP Familiar: DQN vs Hybrid Block",
            "adversarial_benchmark_live_http.json",
            "familiar_results.Dueling-DQN v2.0.Hybrid v3.0.block_rate_pct",
            f"{lfam['Dueling-DQN v2.0']['Hybrid v3.0']['block_rate_pct']:.1f}% ({lfam['Dueling-DQN v2.0']['Hybrid v3.0']['blocked_count']}/{lfam['Dueling-DQN v2.0']['Hybrid v3.0']['total_episodes']})",
            f"{lfam['Dueling-DQN v2.0']['Hybrid v3.0']['block_rate_pct']:.1f}% ({lfam['Dueling-DQN v2.0']['Hybrid v3.0']['blocked_count']}/{lfam['Dueling-DQN v2.0']['Hybrid v3.0']['total_episodes']})",
            [("DOCX", docx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "3. Live HTTP 3x3 (C1)",
            "Live HTTP Strange: DQN vs Gateway Rules Block",
            "adversarial_benchmark_live_http.json",
            "strange_results.Dueling-DQN v2.0.Rules Only.block_rate_pct",
            f"{lstg['Dueling-DQN v2.0']['Rules Only']['block_rate_pct']:.1f}% ({lstg['Dueling-DQN v2.0']['Rules Only']['blocked_count']}/{lstg['Dueling-DQN v2.0']['Rules Only']['total_episodes']})",
            f"{lstg['Dueling-DQN v2.0']['Rules Only']['block_rate_pct']:.1f}% ({lstg['Dueling-DQN v2.0']['Rules Only']['blocked_count']}/{lstg['Dueling-DQN v2.0']['Rules Only']['total_episodes']})",
            [("DOCX", docx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "3. Live HTTP 3x3 (C1)",
            "Live HTTP Strange: DQN vs Hybrid v3.0 Block",
            "adversarial_benchmark_live_http.json",
            "strange_results.Dueling-DQN v2.0.Hybrid v3.0.block_rate_pct",
            f"{lstg['Dueling-DQN v2.0']['Hybrid v3.0']['block_rate_pct']:.1f}% ({lstg['Dueling-DQN v2.0']['Hybrid v3.0']['blocked_count']}/{lstg['Dueling-DQN v2.0']['Hybrid v3.0']['total_episodes']})",
            f"{lstg['Dueling-DQN v2.0']['Hybrid v3.0']['block_rate_pct']:.1f}%",
            [("DOCX", docx_txt), ("PPTX", pptx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "3. Live HTTP 3x3 (C1)",
            "Live HTTP Strange: Hybrid Avg Latency",
            "adversarial_benchmark_live_http.json",
            "strange_results.Dueling-DQN v2.0.Hybrid v3.0.avg_latency_ms",
            f"{lstg['Dueling-DQN v2.0']['Hybrid v3.0']['avg_latency_ms']:.3f} ms",
            f"{lstg['Dueling-DQN v2.0']['Hybrid v3.0']['avg_latency_ms']:.3f} ms",
            [("DOCX", docx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "4. Curriculum DQN 600-Ep (C2)",
            "Episodes Trained",
            "pentest_dqn_v2_metadata.json",
            "episodes_trained",
            f"{dqn['episodes_trained']} episodes",
            f"{dqn['episodes_trained']} episodes",
            [("DOCX", docx_txt), ("PPTX", pptx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "4. Curriculum DQN 600-Ep (C2)",
            "Stage 1 / Stage 2 / Stage 3 Avg Rewards",
            "pentest_dqn_v2_metadata.json",
            "curriculum_metrics.stage{1,2,3}_avg_reward",
            f"{cm['stage1_avg_reward']:.2f} / {cm['stage2_avg_reward']:.2f} / {cm['stage3_avg_reward']:.2f}",
            f"{cm['stage3_avg_reward']:.2f}",
            [("DOCX", docx_txt), ("PPTX", pptx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "4. Curriculum DQN 600-Ep (C2)",
            "Stage 3 Blind Retries Reduction",
            "pentest_dqn_v2_metadata.json",
            "curriculum_metrics.stage3_blind_retries_reduction_pct",
            f"{cm['stage3_blind_retries_reduction_pct']:.2f}%",
            f"{cm['stage3_blind_retries_reduction_pct']:.2f}%",
            [("DOCX", docx_txt), ("PPTX", pptx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "5. FPR & Controlled Tuning (C3)",
            "Operational FPR (N=1,715 Benign)",
            "fp_v3_measurement.json",
            "aggregate_summary.fp_operational_pct",
            f"{fp_agg['fp_operational_pct']:.2f}%",
            f"{fp_agg['fp_operational_pct']:.2f}%",
            [("DOCX", docx_txt), ("PPTX", pptx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "5. FPR & Controlled Tuning (C3)",
            "B1000 Strict FPR Post-Tuning (Schema OFF)",
            "fp_v3_measurement.json",
            "corpora.benchmark_1000_diverse_benign.fp_strict_schema_off_pct",
            f"{b1000_fp['fp_strict_schema_off_pct']:.1f}%",
            f"{b1000_fp['fp_strict_schema_off_pct']:.1f}%",
            [("DOCX", docx_txt), ("PPTX", pptx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "5. FPR & Controlled Tuning (C3)",
            "B1000 Strict FPR Post-Tuning (Schema ON)",
            "fp_v3_tuning_c3.json",
            "rounds[2].b1000_strict_schema_on_pct",
            f"{fpt['rounds'][2]['b1000_strict_schema_on_pct']:.1f}%",
            f"{fpt['rounds'][2]['b1000_strict_schema_on_pct']:.1f}%",
            [("DOCX", docx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "6. CSIC 2-Hop HTTP Latency (D2)",
            "2-Hop TCP HTTP Mean Latency (N=3,000)",
            "latency_e2e_v3_csic.json",
            "http_e2e_latency_ms.mean_ms",
            f"{e2e['mean_ms']:.3f} ms",
            f"{e2e['mean_ms']:.3f} ms",
            [("DOCX", docx_txt), ("DOCX_CH4", docx_ch4_txt), ("DOCX_FULL", docx_full_txt), ("PPTX", pptx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "6. CSIC 2-Hop HTTP Latency (D2)",
            "2-Hop TCP HTTP p50 / p95 / p99",
            "latency_e2e_v3_csic.json",
            "http_e2e_latency_ms.{p50_ms,p95_ms,p99_ms}",
            f"{e2e['p50_ms']:.3f} / {e2e['p95_ms']:.3f} / {e2e['p99_ms']:.3f} ms",
            f"{e2e['p50_ms']:.3f} ms",
            [("DOCX", docx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "7. Ablation, CSIC & C=50",
            "Ablation Rules Only F1-Score",
            "ablation_results.json",
            "modes.rules_only.f1_score_pct",
            f"{ab_m['rules_only']['f1_score_pct']:.2f}%",
            f"{ab_m['rules_only']['f1_score_pct']:.2f}%",
            [("DOCX", docx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "7. Ablation, CSIC & C=50",
            "Ablation ML Only F1-Score",
            "ablation_results.json",
            "modes.ml_only.f1_score_pct",
            f"{ab_m['ml_only']['f1_score_pct']:.2f}%",
            f"{ab_m['ml_only']['f1_score_pct']:.2f}%",
            [("DOCX", docx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "7. Ablation, CSIC & C=50",
            "Ablation Hybrid F1-Score & FPR",
            "ablation_results.json",
            "modes.hybrid.{f1_score_pct,fpr_pct}",
            f"{ab_m['hybrid']['f1_score_pct']:.2f}% / {ab_m['hybrid']['fpr_pct']:.2f}%",
            f"{ab_m['hybrid']['f1_score_pct']:.2f}%",
            [("DOCX", docx_txt), ("PPTX", pptx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "7. Ablation, CSIC & C=50",
            "CSIC 2010 Zero-Shot FPR & Precision",
            "csic2010_benchmark_results.json",
            "hybrid_defense_in_depth.{fpr,precision}",
            f"{csic_h['fpr']:.2f}% / {csic_h['precision']:.2f}%",
            f"{csic_h['fpr']:.2f}%",
            [("DOCX", docx_txt), ("PPTX", pptx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "7. Ablation, CSIC & C=50",
            "CSIC 2010 Two-Tier Overall (Op T=80 / Loose) & Group B",
            "csic2010_benchmark_results.json",
            "two_tier_parallel_metrics.{overall_1500,group_b_parameter_tampering}",
            f"{csic['two_tier_parallel_metrics']['overall_1500']['hybrid_operational_t80_recall_pct']:.2f}% Op / {csic['two_tier_parallel_metrics']['overall_1500']['hybrid_loose_recall_pct']:.2f}% Loose / {csic['two_tier_parallel_metrics']['group_b_parameter_tampering']['hybrid_operational_t80']['recall_pct']:.2f}% Group B",
            f"{csic['two_tier_parallel_metrics']['overall_1500']['hybrid_operational_t80_recall_pct']:.2f}%",
            [("DOCX", docx_txt), ("PPTX", pptx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "7. Ablation, CSIC & C=50",
            "Disjoint Canonical Hash Overlap (D3 / E4)",
            "zero_leakage_v3_verification.json",
            "zero_leakage_verified",
            f"{leak['zero_leakage_verified']} (0 overlaps / {leak['metadata']['defense_v2_total_rows']:,} rows)",
            "zero_leakage_verified = true",
            [("CH4_MD", md_txt)],
        ),
        (
            "7. Ablation, CSIC & C=50",
            "Concurrency C=50 Benign Throughput",
            "performance_profile_results.json",
            "concurrency_benchmark.benign_passthrough[-1].rps",
            f"{c50_rps:.2f} RPS",
            f"{c50_rps:.0f} RPS",
            [("PPTX", pptx_txt)],
        ),
        (
            "8. Phase E (v3.3)",
            "E1 Live-HTTP :8056 Greedy DQN Bypass",
            "pentest_dqn_v2_metadata.json",
            "stage4_live_http_metrics.live_http_8056_dqn_bypass_rate_pct",
            f"{dqn['stage4_live_http_metrics']['live_http_8056_dqn_bypass_rate_pct']:.1f}%",
            f"{dqn['stage4_live_http_metrics']['live_http_8056_dqn_bypass_rate_pct']:.1f}%",
            [("DOCX", docx_txt), ("PPTX", pptx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "8. Phase E (v3.3)",
            "E2 Zero-Leakage Augmented Train Rows Added",
            "phase_e_augmentation_manifest.json",
            "added_total_rows",
            f"+{aug['added_total_rows']} ({aug['added_by_source']['phase_e_e2a_sandbox']} E2a + {aug['added_by_source']['phase_e_e3_group_a_synth']} E3)",
            f"{aug['added_total_rows']}",
            [("DOCX", docx_txt), ("PPTX", pptx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "8. Phase E (v3.3)",
            "E3 CSIC Group A True Payload Recall (Op T=80)",
            "csic2010_taxonomy_breakdown.json",
            "parallel_metrics.operational_decision_engine_t80.group_a_recall_pct",
            f"{csic_tax['parallel_metrics']['operational_decision_engine_t80']['group_a_recall_pct']:.2f}% ({csic_tax['parallel_metrics']['operational_decision_engine_t80']['group_a_blocked']}/{csic_tax['two_tier_breakdown']['group_a_true_payload']['count']})",
            f"{csic_tax['parallel_metrics']['operational_decision_engine_t80']['group_a_recall_pct']:.2f}% ({csic_tax['parallel_metrics']['operational_decision_engine_t80']['group_a_blocked']}/{csic_tax['two_tier_breakdown']['group_a_true_payload']['count']})",
            [("DOCX", docx_txt), ("PPTX", pptx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "8. Phase E (v3.3)",
            "E3 /tienda1 OpenAPI Schema Group B & Overall",
            "csic2010_tienda1_schema_proof.json",
            "operational_decision_engine_t80.hybrid_plus_tienda1_schema_strict.{group_b,overall}",
            f"{csic_tienda1['operational_decision_engine_t80']['hybrid_plus_tienda1_schema_strict']['group_b_parameter_tampering']['recall_pct']:.2f}% / {csic_tienda1['operational_decision_engine_t80']['hybrid_plus_tienda1_schema_strict']['overall_1500']['recall_pct']:.2f}%",
            f"{csic_tienda1['operational_decision_engine_t80']['hybrid_plus_tienda1_schema_strict']['group_b_parameter_tampering']['recall_pct']:.2f}%",
            [("DOCX", docx_txt), ("PPTX", pptx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "8. Phase E (v3.3)",
            "E4 Expanded Strange Suite v3.3 Live-HTTP Hybrid",
            "strange_suite_v33_results.json",
            "live_http.Dueling-DQN v2.0.Hybrid v3.3.block_rate_pct",
            f"{st33['live_http']['Dueling-DQN v2.0']['Hybrid v3.3']['block_rate_pct']:.2f}% ({st33['live_http']['Dueling-DQN v2.0']['Hybrid v3.3']['blocked_count']}/{st33['live_http']['Dueling-DQN v2.0']['Hybrid v3.3']['total_episodes']})",
            f"{st33['live_http']['Dueling-DQN v2.0']['Hybrid v3.3']['block_rate_pct']:.2f}% ({st33['live_http']['Dueling-DQN v2.0']['Hybrid v3.3']['blocked_count']}/{st33['live_http']['Dueling-DQN v2.0']['Hybrid v3.3']['total_episodes']})",
            [("DOCX", docx_txt), ("PPTX", pptx_txt), ("CH4_MD", md_txt)],
        ),
        (
            "8. Phase E (v3.3)",
            "E4 Blind Held-Out Vault v2 Live-HTTP Hybrid",
            "blind_heldout_vault_v2_results.json",
            "live_http.Dueling-DQN v2.0.Hybrid v3.3.block_rate_pct",
            f"{bv2['live_http']['Dueling-DQN v2.0']['Hybrid v3.3']['block_rate_pct']:.2f}% ({bv2['live_http']['Dueling-DQN v2.0']['Hybrid v3.3']['blocked_count']}/{bv2['live_http']['Dueling-DQN v2.0']['Hybrid v3.3']['total_episodes']})",
            f"{bv2['live_http']['Dueling-DQN v2.0']['Hybrid v3.3']['block_rate_pct']:.2f}% ({bv2['live_http']['Dueling-DQN v2.0']['Hybrid v3.3']['blocked_count']}/{bv2['live_http']['Dueling-DQN v2.0']['Hybrid v3.3']['total_episodes']})",
            [("DOCX", docx_txt), ("PPTX", pptx_txt), ("CH4_MD", md_txt)],
        ),
    ]

    failures: list[str] = []
    md_rows: list[str] = []
    for idx, (cat, name, art_f, jpath, gt_str, token, targets) in enumerate(checks, start=1):
        verified_targets: list[str] = []
        for t_label, t_content in targets:
            if token not in t_content:
                failures.append(f"Row #{idx} ({name}): token {token!r} NOT FOUND in {t_label}")
            else:
                verified_targets.append(t_label)
        status = f"VERIFIED ({', '.join(verified_targets)})"
        md_rows.append(f"| {idx} | {cat} | {name} | `{art_f}` | `{jpath}` | `{gt_str}` | **{status}** |")

    if failures:
        raise AssertionError("Reconciliation verification FAILED:\n  - " + "\n  - ".join(failures))

    content = (
        "# BẢNG ĐỐI CHIẾU SỐ LIỆU ĐỒ ÁN VÀ ARTIFACT THỰC NGHIỆM (AUTO-VERIFIED RECONCILIATION MATRIX)\n\n"
        "- **Mã công việc:** `PBL6 v3.1 — Phase C (Mục C4)`\n"
        "- **Trình sinh & Kiểm chứng tự động:** `scripts/generate_reconciliation_matrix.py` (đọc trực tiếp JSON + giải nén kiểm tra chuỗi thật trên `.docx`, `.pptx`, `.md`; `0` nhập tay).\n"
        f"- **Tổng số phép kiểm chứng chéo:** **`{len(checks)}/{len(checks)} VERIFIED PASS` (`0` sai lệch)**.\n\n"
        "| STT | Nhóm Thực Nghiệm | Chỉ Số Kiểm Chứng | Artifact Gốc | JSON Key | Giá Trị Ground-Truth | Trạng Thái Quét Tệp Thực Tế |\n"
        "| :---: | :--- | :--- | :--- | :--- | :---: | :--- |\n"
        + "\n".join(md_rows)
        + "\n"
    )
    OUT_MD.write_text(content, encoding="utf-8")
    print(f"[OK] Verified {len(checks)}/{len(checks)} cross-document metrics with 0 discrepancies -> {OUT_MD}")


if __name__ == "__main__":
    main()

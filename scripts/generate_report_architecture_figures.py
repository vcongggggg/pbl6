"""Generate 4 publication-grade 300-DPI architecture & metric figures for PBL6_Bao_Cao.docx.

All numbers are dynamically loaded from verified live JSON artifacts on disk.
Zero dotted version tags (v1.0..v3.4) are emitted anywhere in titles or labels.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

ROOT_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = ROOT_DIR / "docs" / "reports"
FIGURES_DIR = REPORTS_DIR / "figures"

# Consistent Vietnamese-capable sans-serif font stack
plt.rcParams["font.family"] = "sans-serif"
plt.rcParams["font.sans-serif"] = ["DejaVu Sans", "Arial", "Segoe UI"]
plt.rcParams["axes.unicode_minus"] = False

NAVY = "#0F294A"
BLUE_EDGE = "#1D4ED8"
BLUE_FILL = "#EFF6FF"
TEAL_EDGE = "#0F766E"
TEAL_FILL = "#ECFDF5"
RED_EDGE = "#B91C1C"
RED_FILL = "#FEF2F2"
AMBER_EDGE = "#B45309"
AMBER_FILL = "#FFFBEB"
SLATE_EDGE = "#334155"
SLATE_FILL = "#F1F5F9"
DARK_TEXT = "#0F172A"
MUTED_TEXT = "#334155"


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _draw_box(
    ax: Any,
    x: float,
    y: float,
    w: float,
    h: float,
    title: str,
    lines: list[str],
    edge: str,
    fill: str,
    title_color: str | None = None,
    title_size: float = 10.5,
    body_size: float = 8.4,
    pad: float = 0.012,
    lw: float = 1.8,
) -> None:
    """Draw a rounded bordered box with a centered bold title and body lines."""
    patch = FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle=f"round,pad=0,rounding_size={pad}",
        linewidth=lw,
        edgecolor=edge,
        facecolor=fill,
        zorder=2,
    )
    ax.add_patch(patch)
    t_col = title_color or edge
    if lines:
        n_lines = len(lines)
        title_y = y + h * (0.76 if n_lines <= 2 else 0.80 if n_lines <= 4 else 0.84)
        ax.text(
            x + w / 2,
            title_y,
            title,
            ha="center",
            va="center",
            fontsize=title_size,
            fontweight="bold",
            color=t_col,
            zorder=3,
        )
        body_y = y + h * (0.34 if n_lines <= 2 else 0.37 if n_lines <= 4 else 0.40)
        ax.text(
            x + w / 2,
            body_y,
            "\n".join(lines),
            ha="center",
            va="center",
            fontsize=body_size,
            color=DARK_TEXT,
            linespacing=1.35,
            zorder=3,
        )
    else:
        ax.text(
            x + w / 2,
            y + h / 2,
            title,
            ha="center",
            va="center",
            fontsize=title_size,
            fontweight="bold",
            color=t_col,
            zorder=3,
        )


def _draw_arrow(
    ax: Any,
    start: tuple[float, float],
    end: tuple[float, float],
    color: str = NAVY,
    label: str | None = None,
    label_pos: tuple[float, float] | None = None,
    lw: float = 1.8,
    rad: float = 0.0,
) -> None:
    """Draw a crisp arrow with an optional boxed label badge."""
    arr = FancyArrowPatch(
        start,
        end,
        arrowstyle="-|>,head_length=7,head_width=4.5",
        linewidth=lw,
        color=color,
        connectionstyle=f"arc3,rad={rad}",
        zorder=4,
    )
    ax.add_patch(arr)
    if label:
        lx, ly = label_pos if label_pos else ((start[0] + end[0]) / 2, (start[1] + end[1]) / 2)
        ax.text(
            lx,
            ly,
            label,
            ha="center",
            va="center",
            fontsize=7.8,
            fontweight="bold",
            color=color,
            bbox={
                "boxstyle": "round,pad=0.22",
                "facecolor": "#FFFFFF",
                "edgecolor": color,
                "linewidth": 1.1,
            },
            zorder=5,
        )


def _init_canvas(
    figsize: tuple[float, float], title: str, subtitle: str
) -> tuple[Any, Any]:
    fig, ax = plt.subplots(figsize=figsize, dpi=300)
    fig.patch.set_facecolor("#FFFFFF")
    ax.set_facecolor("#FFFFFF")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    ax.text(
        0.5,
        0.962,
        title,
        ha="center",
        va="center",
        fontsize=14.0,
        fontweight="bold",
        color=NAVY,
    )
    ax.text(
        0.5,
        0.922,
        subtitle,
        ha="center",
        va="center",
        fontsize=9.6,
        color=MUTED_TEXT,
    )
    return fig, ax


def generate_cyber_range_figure(m: dict[str, Any]) -> Path:
    """Generate Fig 2.1: 2-Host Distributed Adversarial Cyber Range Architecture."""
    rules_n = int(m["abl"]["metadata"]["active_rules_count"])
    fig, ax = _init_canvas(
        (13.2, 7.2),
        "KIẾN TRÚC THAO TRƯỜNG AN NINH ĐỐI KHÁNG PHÂN TÁN 2 MÁY",
        "Mạng cục bộ LAN (192.168.1.0/24) | Blue Team Hybrid (Máy 1) vs Autonomous Red Team Dueling-DQN (Máy 2)",
    )

    # Outer Host Containers
    red_outer = FancyBboxPatch(
        (0.015, 0.03),
        0.315,
        0.85,
        boxstyle="round,pad=0,rounding_size=0.018",
        linewidth=2.2,
        edgecolor=RED_EDGE,
        facecolor="#FFF8F8",
        zorder=1,
    )
    ax.add_patch(red_outer)
    ax.text(
        0.1725,
        0.850,
        "MÁY 2: RED TEAM HOST (ATTACKER)",
        ha="center",
        va="center",
        fontsize=10.8,
        fontweight="bold",
        color=RED_EDGE,
    )
    ax.text(
        0.1725,
        0.822,
        "Nguyễn Công Minh  |  attack-lab/",
        ha="center",
        va="center",
        fontsize=8.6,
        color=MUTED_TEXT,
    )

    blue_outer = FancyBboxPatch(
        (0.365, 0.03),
        0.620,
        0.85,
        boxstyle="round,pad=0,rounding_size=0.018",
        linewidth=2.2,
        edgecolor=NAVY,
        facecolor="#F4F8FD",
        zorder=1,
    )
    ax.add_patch(blue_outer)
    ax.text(
        0.675,
        0.850,
        "MÁY 1: BLUE TEAM HOST (DEFENDER & TARGET)",
        ha="center",
        va="center",
        fontsize=10.8,
        fontweight="bold",
        color=NAVY,
    )
    ax.text(
        0.675,
        0.822,
        "Ngô Văn Công  |  Docker Non-Root Hardened Compose (gateway + vulnerable-api + dashboard)",
        ha="center",
        va="center",
        fontsize=8.6,
        color=MUTED_TEXT,
    )

    # Left column: 4 Red Team stages
    red_boxes = [
        (
            0.665,
            0.125,
            "1. OpenAPI Recon Agent",
            ["recon.py ($ref cycle guard)", "Phát hiện bề mặt tấn công"],
        ),
        (
            0.490,
            0.125,
            "2. OpenAPI Test Synthesizer",
            ["synthesizer.py & AttackGraph", "8 họ lỗ hổng OWASP Top 10"],
        ),
        (
            0.295,
            0.145,
            "3. Dueling Double-DQN",
            [
                f"{m['dqn']['state_dim']}-D State | {m['dqn']['action_dim']} Masked Actions",
                f"4-Stage Curriculum ({m['dqn']['episodes_trained']} ep)",
                "pentest_dqn_v2.pt & .npz (SHA-256)",
            ],
        ),
        (
            0.095,
            0.145,
            "4. Semantic Evasion & Runner",
            ["Toán tử biến dị đa hình + HTTPX", "runner.py -> campaign_report.json"],
        ),
    ]
    for idx, (by, bh, bt, bl) in enumerate(red_boxes):
        _draw_box(ax, 0.042, by, 0.261, bh, bt, bl, RED_EDGE, "#FFFFFF", title_size=10.0, body_size=8.2)
        if idx > 0:
            prev_y = red_boxes[idx - 1][0]
            _draw_arrow(ax, (0.1725, prev_y), (0.1725, by + bh), color=RED_EDGE, lw=1.7)

    # Right side: WAF Gateway, Bookie API, SQLite WAL, SOC Dashboard
    _draw_box(
        ax,
        0.382,
        0.380,
        0.332,
        0.405,
        "WAF Reverse Proxy Gateway",
        [
            "FastAPI Async (0.0.0.0:8000) + Thread Offload",
            "Rate Limiter (LRU 50k) & Protocol Sniffer",
            f"InputNormalizer + {rules_n} Hardened Rules (Anti-ReDoS)",
            "OpenAPI Route-Tiered + BOLA + Outbound DLP",
            "Unified 26-D + Max-Pooling (predict_http)",
            "XGBoost (UBJ) + IForest (NPZ) & Hybrid Risk",
        ],
        BLUE_EDGE,
        "#FFFFFF",
        title_size=10.5,
        body_size=7.6,
    )

    _draw_box(
        ax,
        0.748,
        0.585,
        0.222,
        0.200,
        "Bookie Bookstore API",
        [
            "Python Django Target",
            "Cô lập 127.0.0.1:5000",
            "8 Lỗ hổng OWASP API/Web",
            "OpenAPI 3.0 Spec",
        ],
        TEAL_EDGE,
        TEAL_FILL,
        title_size=9.8,
        body_size=7.8,
    )

    _draw_box(
        ax,
        0.748,
        0.380,
        0.222,
        0.180,
        "SQLite WAL Database",
        [
            "Group Commit + busy_timeout",
            "requests | security_events",
            "audit_logs | waf_config",
        ],
        SLATE_EDGE,
        SLATE_FILL,
        title_size=9.8,
        body_size=7.8,
    )

    _draw_box(
        ax,
        0.382,
        0.058,
        0.588,
        0.215,
        "SOC Command Center & Live SSE Pentest Arena (Next.js — Port 3000)",
        [
            "Server-Side BFF Proxy (/api/gateway/* chèn X-API-Key, 0 Secret trong trình duyệt)",
            "/ (SOC Overview): KPI thực tế, Biểu đồ 60s RPS, MITRE Kill Chain, 26-D Evidence & XAI",
            "/arena: Điều phối Red vs Blue trực tiếp qua Server-Sent Events (SSE), Replay & Export D4",
        ],
        NAVY,
        "#FFFFFF",
        title_size=10.0,
        body_size=7.9,
    )

    # Inter-module arrows
    _draw_arrow(
        ax,
        (0.303, 0.175),
        (0.382, 0.555),
        color=RED_EDGE,
        label="HTTP/1.1 LAN\n/api/proxy/*",
        label_pos=(0.343, 0.365),
        lw=2.0,
    )
    _draw_arrow(
        ax,
        (0.714, 0.680),
        (0.748, 0.680),
        color=TEAL_EDGE,
        label="ALLOW\n(Clean)",
        label_pos=(0.731, 0.728),
        lw=1.9,
    )
    _draw_arrow(
        ax,
        (0.714, 0.465),
        (0.748, 0.465),
        color=SLATE_EDGE,
        label="Async\nWAL",
        label_pos=(0.731, 0.514),
        lw=1.9,
    )
    _draw_arrow(
        ax,
        (0.550, 0.380),
        (0.550, 0.273),
        color=BLUE_EDGE,
        label="REST + Live SSE (X-API-Key BFF)",
        label_pos=(0.550, 0.326),
        lw=1.9,
    )

    out_path = FIGURES_DIR / "fig_arch_cyber_range.png"
    fig.savefig(out_path, dpi=300, bbox_inches="tight", pad_inches=0.12)
    plt.close(fig)
    return out_path


def generate_waf_pipeline_figure(m: dict[str, Any]) -> Path:
    """Generate Fig 2.2: Multi-Layer Inspection & Hybrid Decision Pipeline."""
    abl_m = m["abl"]["modes"]
    rules_n = int(m["abl"]["metadata"]["active_rules_count"])
    xgb_acc = float(m["xgb"]["metrics"]["test_accuracy"]) * 100.0
    if_rec = float(m["iforest"]["benchmark_1000_diverse_eval"]["at_60"]["recall"]) * 100.0
    e2e_mean = float(m["lat"]["http_e2e_latency_ms"]["mean_ms"])
    hyb_ms = float(abl_m["hybrid"]["avg_latency_ms"])
    rl_ms = float(abl_m["rules_only"]["avg_latency_ms"])
    ml_ms = float(abl_m["ml_only"]["avg_latency_ms"])
    an_ms = float(abl_m["anomaly_only"]["avg_latency_ms"])

    fig, ax = _init_canvas(
        (13.2, 6.8),
        "LUỒNG XỬ LÝ PHÂN TÍCH ĐA TẦNG & RA QUYẾT ĐỊNH TẠI WAF GATEWAY",
        f"Pure ASGI + anyio.to_thread.run_sync  |  Inline Hybrid {hyb_ms:.3f} ms/req  |  HTTP 2-Hop TCP E2E {e2e_mean:.3f} ms/req",
    )

    # Row 1: Pre-inspection chain
    row1 = [
        (0.025, "1. Pure ASGI & Limit", ["Gán X-Request-ID", "Stream Body <= 1 MB", "(Quá 1 MB -> HTTP 413)"]),
        (0.268, "2. Rate Limiter LRU", ["Sliding Window 50k LRU", "IP Hard Cap (/auth/login)", "Vượt ngưỡng -> HTTP 429"]),
        (0.511, "3. Protocol Sniffer", ["REST / GraphQL / SOAP", "JSON-RPC / Generic", "Bắt XXE & Deep Nesting"]),
        (0.754, "4. OpenAPI Validator", ["Positive Security Spec", "Route-Tiered Validation", "Method / Params / Body"]),
    ]
    r1_w, r1_h, r1_y = 0.215, 0.175, 0.675
    for idx, (rx, rt, rl) in enumerate(row1):
        _draw_box(ax, rx, r1_y, r1_w, r1_h, rt, rl, BLUE_EDGE, BLUE_FILL, title_size=10.2, body_size=8.2)
        if idx > 0:
            prev_x = row1[idx - 1][0]
            _draw_arrow(ax, (prev_x + r1_w, r1_y + r1_h / 2), (rx, r1_y + r1_h / 2), color=NAVY, lw=1.7)

    # Row 2: 3 Defense Layers + BOLA Guard
    r2_w, r2_h, r2_y = 0.215, 0.245, 0.345
    row2 = [
        (
            0.025,
            "Tầng 1: Rule Engine",
            [
                "InputNormalizer (5x URL,",
                "HTML, NFC, Zero-Width)",
                f"{rules_n} Rules (Anti-ReDoS)",
                f"Sliding >16KB | {rl_ms:.3f} ms",
            ],
            SLATE_EDGE,
            SLATE_FILL,
        ),
        (
            0.268,
            "Tầng 2: XGBoost",
            [
                "Unified 26-D + Max-Pooling",
                "xgb_v2.ubj (Zero-Pickle)",
                "SHA-256 Fail-Closed",
                f"Acc {xgb_acc:.2f}% | {ml_ms:.3f} ms",
            ],
            TEAL_EDGE,
            TEAL_FILL,
        ),
        (
            0.511,
            "Tầng 3: Calibrated IForest",
            [
                "iforest_v2.npz (Zero-Pickle)",
                "Hiệu chuẩn phân vị Benign",
                "Bare-root '/' Guard",
                f"Recall@60 {if_rec:.2f}% | {an_ms:.3f} ms",
            ],
            TEAL_EDGE,
            TEAL_FILL,
        ),
        (
            0.754,
            "BOLA & Logic Guard",
            [
                "BOLADetector (60s LRU)",
                ">= 4 IDs khác nhau / IP",
                "ID <= 0 & Mass Assignment",
                "Route-Tiered Integrity",
            ],
            AMBER_EDGE,
            AMBER_FILL,
        ),
    ]
    for rx, rt, rl, re_c, rf_c in row2:
        _draw_box(ax, rx, r2_y, r2_w, r2_h, rt, rl, re_c, rf_c, title_size=10.1, body_size=8.0)

    # Dispatch arrows from Protocol Sniffer (Row 1[2]) and OpenAPI Validator (Row 1[3]) to Row 2
    sniffer_cx = row1[2][0] + r1_w / 2
    val_cx = row1[3][0] + r1_w / 2
    for target_x in [row2[0][0] + r2_w / 2, row2[1][0] + r2_w / 2, row2[2][0] + r2_w / 2]:
        _draw_arrow(ax, (sniffer_cx, r1_y), (target_x, r2_y + r2_h), color=NAVY, lw=1.6)
    _draw_arrow(ax, (val_cx, r1_y), (row2[3][0] + r2_w / 2, r2_y + r2_h), color=NAVY, lw=1.6)

    # Row 3: Decision Engine, Upstream & DLP, Background WAL
    r3_y, r3_h = 0.065, 0.195
    _draw_box(
        ax,
        0.025,
        r3_y,
        0.372,
        r3_h,
        "Hybrid Risk & Decision Engine",
        [
            "Risk = 0.40·S_Rule + 0.35·S_ML + 0.25·S_Anom",
            "Override (Rule>=85 | ML>=90) & Dual-AI Consensus",
            "<30 ALLOW | 30-59 MON | 60-79 429 | >=80 BLOCK 403",
        ],
        AMBER_EDGE,
        AMBER_FILL,
        title_size=10.0,
        body_size=7.4,
    )
    _draw_box(
        ax,
        0.452,
        r3_y,
        0.268,
        r3_h,
        "Upstream & Outbound DLP",
        [
            "Header Sanitize (xóa X-API-Key)",
            "Bookie API (127.0.0.1:5000)",
            "ResponseDLPGuard (<=512 KB JSON)",
            "Che secret -> [REDACTED_BY_WAF_DLP]",
        ],
        TEAL_EDGE,
        TEAL_FILL,
        title_size=9.9,
        body_size=7.7,
    )
    _draw_box(
        ax,
        0.748,
        r3_y,
        0.221,
        r3_h,
        "Background WAL Commit",
        [
            "SQLite WAL Group Commit",
            "Session_ID = HMAC(IP, 15m)",
            "MITRE Kill Chain Stage",
            "Realtime SOC & SSE Arena",
        ],
        SLATE_EDGE,
        SLATE_FILL,
        title_size=9.9,
        body_size=7.8,
    )

    # Row 2 -> Decision Engine arrows
    dec_y = r3_y + r3_h
    _draw_arrow(ax, (row2[0][0] + r2_w / 2, r2_y), (0.145, dec_y), color=NAVY, lw=1.6)
    _draw_arrow(ax, (row2[1][0] + r2_w / 2, r2_y), (0.215, dec_y), color=TEAL_EDGE, lw=1.6)
    _draw_arrow(ax, (row2[2][0] + r2_w / 2, r2_y), (0.285, dec_y), color=TEAL_EDGE, lw=1.6)
    _draw_arrow(ax, (row2[3][0] + r2_w / 2, r2_y), (0.355, dec_y), color=AMBER_EDGE, lw=1.6)

    # Row 3 horizontal flow
    _draw_arrow(
        ax,
        (0.397, r3_y + r3_h / 2),
        (0.452, r3_y + r3_h / 2),
        color=TEAL_EDGE,
        label="ALLOW/\nMON",
        label_pos=(0.424, r3_y + r3_h / 2),
        lw=1.8,
    )
    _draw_arrow(
        ax,
        (0.720, r3_y + r3_h / 2),
        (0.748, r3_y + r3_h / 2),
        color=NAVY,
        lw=1.8,
    )

    out_path = FIGURES_DIR / "fig_arch_waf_pipeline.png"
    fig.savefig(out_path, dpi=300, bbox_inches="tight", pad_inches=0.12)
    plt.close(fig)
    return out_path


def generate_dqn_loop_figure(m: dict[str, Any]) -> Path:
    """Generate Fig 2.3: PyTorch Dueling Double-DQN Autonomous Agent Loop (74-D, 36 Actions)."""
    dqn = m["dqn"]
    cm = dqn["curriculum_metrics"]
    s4 = dqn["stage4_live_http_metrics"]
    sdim = int(dqn["state_dim"])
    adim = int(dqn["action_dim"])
    eps = int(dqn["episodes_trained"])
    e2e_mean = float(m["lat"]["http_e2e_latency_ms"]["mean_ms"])
    fam_hyb = m["adv"]["familiar"]["Dueling-DQN v2.0"]["Hybrid v3.0"]
    st33_hyb = m["st33"]["live_http"]["Dueling-DQN v2.0"]["Hybrid v3.3"]
    bv_pf2 = m["bv2p"]["live_http"]["Dueling-DQN v2.0"]["Hybrid v3.3"]

    fig, ax = _init_canvas(
        (13.2, 6.8),
        "VÒNG LẶP TÁC TỬ PENTEST TỰ HÀNH PYTORCH DUELING DOUBLE-DQN",
        f"{sdim}-D Telemetry State -> Dueling MLP (Value + Advantage) -> {adim} Masked Actions -> 4-Stage Curriculum ({eps} Episodes)",
    )

    # Row 1: 5 Operational Phases
    p1_y, p1_h, p1_w = 0.705, 0.140, 0.172
    phases = [
        (0.025, "Pha 1: OpenAPI Recon", ["recon.py", "($ref cycle guard)"], NAVY, "#F1F5F9"),
        (0.220, "Pha 2: Attack Graph", ["attack_graph.py", "Xếp hạng tham số"], NAVY, "#F1F5F9"),
        (0.415, "Pha 3: Baseline Probe", ["synthesizer.py", "Thăm dò 8 họ OWASP"], NAVY, "#F1F5F9"),
        (0.610, "Pha 4: DQN Evasion", [f"{sdim}-D State + {adim} Actions", "Biến dị hoặc pivot mục tiêu"], RED_EDGE, RED_FILL),
        (0.805, "Pha 5: Verdict & SSE", ["Đo Bypass thực tế", "Cập nhật Q(s,a) & Arena"], RED_EDGE, RED_FILL),
    ]
    for idx, (px, pt, pl, pe, pf) in enumerate(phases):
        _draw_box(ax, px, p1_y, p1_w, p1_h, pt, pl, pe, pf, title_size=8.9, body_size=7.7)
        if idx > 0:
            prev_x = phases[idx - 1][0]
            _draw_arrow(ax, (prev_x + p1_w, p1_y + p1_h / 2), (px, p1_y + p1_h / 2), color=NAVY, lw=1.7)

    # Row 2: State Space -> Dueling Network -> Action Masking
    r2_y, r2_h = 0.365, 0.255
    _draw_box(
        ax,
        0.025,
        r2_y,
        0.275,
        r2_h,
        f"Không Gian Trạng Thái {sdim}-D",
        [
            "• Telemetry HTTP (403/429/200) & Latency",
            "• Điểm rủi ro WAF (X-WAF-Risk-Score)",
            "• Lịch sử hành động & số lần chặn liên tiếp",
            "• Ngữ cảnh endpoint, tham số & chuỗi Pivot",
            "• Đặc trưng thành công/thất bại biến dị trước",
        ],
        NAVY,
        "#FFFFFF",
        title_size=9.7,
        body_size=7.6,
    )
    _draw_box(
        ax,
        0.340,
        r2_y,
        0.320,
        r2_h,
        "Mạng Dueling Double-DQN",
        [
            f"Shared Trunk: Linear({sdim},128)->ReLU->Linear(128,128)",
            "• Value Stream V(s): 128 -> 64 -> 1",
            f"• Advantage Stream A(s,a): 128 -> 64 -> {adim}",
            "Q(s,a) = V(s) + (A(s,a) - mean A)",
            "Dual Inference: .pt (weights_only) / .npz (Zero-Pickle)",
        ],
        BLUE_EDGE,
        BLUE_FILL,
        title_size=9.8,
        body_size=7.5,
    )
    _draw_box(
        ax,
        0.700,
        r2_y,
        0.275,
        r2_h,
        f"Action Masking ({adim} Actions)",
        [
            "Cộng mặt nạ -1e9 lên hành động vô hiệu:",
            "• 0..2: Recon, Prioritize, Tactical Pivot",
            "• 3..10: Baseline Probes (8 họ OWASP)",
            "• 11..35: Biến dị SQLi, XSS, Path, CMD,",
            "  SSRF, NoSQLi, BOLA & Mass Assignment",
        ],
        RED_EDGE,
        RED_FILL,
        title_size=9.7,
        body_size=7.6,
    )

    _draw_arrow(ax, (0.300, r2_y + r2_h / 2), (0.340, r2_y + r2_h / 2), color=NAVY, label="s_t", label_pos=(0.320, r2_y + r2_h / 2), lw=1.8)
    _draw_arrow(ax, (0.660, r2_y + r2_h / 2), (0.700, r2_y + r2_h / 2), color=BLUE_EDGE, label="Q(s,a)", label_pos=(0.680, r2_y + r2_h / 2), lw=1.8)

    # Row 3: 4-Stage Curriculum <-> Live Target Environment
    r3_y, r3_h = 0.065, 0.215
    _draw_box(
        ax,
        0.025,
        r3_y,
        0.452,
        r3_h,
        f"Huấn Luyện 4 Giai Đoạn ({eps} Episodes, Seed={dqn['seed']})",
        [
            f"• Stage 1 (Legacy Static): Reward {cm['stage1_avg_reward']:+.2f} | Bypass {cm['stage1_legacy_static_waf_avg_bypass_rate']*100:.2f}%",
            f"• Stage 2 (Hardened Rules): Reward {cm['stage2_avg_reward']:+.2f} | Bypass {cm['stage2_hardened_rules_avg_bypass_rate']*100:.2f}%",
            f"• Stage 3 (Hybrid In-Proc): Reward {cm['stage3_avg_reward']:+.2f} | Giảm {cm['stage3_blind_retries_reduction_pct']:.2f}% thử mù quáng",
            f"• Stage 4 (Live HTTP {s4['stage4_episodes']} ep): Stealth {s4['stage4_avg_stealth_efficiency']:.4f} | Sandbox bypass: {s4['stage4_sandbox_bypasses_recorded']}",
        ],
        AMBER_EDGE,
        AMBER_FILL,
        title_size=9.4,
        body_size=7.5,
    )
    _draw_box(
        ax,
        0.525,
        r3_y,
        0.450,
        r3_h,
        "Môi Trường Thực Chiến (WAF Gateway Hybrid)",
        [
            "Kiểm định chéo socket HTTP thật qua /api/proxy/*:",
            f"• Tập Familiar (N={fam_hyb['total_episodes']}): Hybrid chặn {fam_hyb['block_rate_pct']:.1f}% ({fam_hyb['blocked_count']}/{fam_hyb['total_episodes']})",
            f"• Tập Strange Suite (N={st33_hyb['total_episodes']}): Hybrid chặn {st33_hyb['block_rate_pct']:.2f}% ({st33_hyb['blocked_count']}/{st33_hyb['total_episodes']})",
            f"• Blind Vault (N={bv_pf2['total_episodes']}): Hybrid chặn {bv_pf2['block_rate_pct']:.2f}% ({bv_pf2['blocked_count']}/{bv_pf2['total_episodes']}) | E2E {e2e_mean:.3f} ms",
        ],
        TEAL_EDGE,
        TEAL_FILL,
        title_size=9.4,
        body_size=7.5,
    )

    _draw_arrow(ax, (0.838, r2_y), (0.838, r3_y + r3_h), color=RED_EDGE, label="a_t (Payload)", label_pos=(0.838, (r2_y + r3_y + r3_h) / 2), lw=1.8)
    _draw_arrow(ax, (0.525, r3_y + r3_h / 2), (0.477, r3_y + r3_h / 2), color=TEAL_EDGE, label="r_t,\ns_{t+1}", label_pos=(0.501, r3_y + r3_h / 2), lw=1.8)
    _draw_arrow(ax, (0.162, r3_y + r3_h), (0.162, r2_y), color=NAVY, label="Cập nhật State", label_pos=(0.162, (r2_y + r3_y + r3_h) / 2), lw=1.8)

    out_path = FIGURES_DIR / "fig_arch_dqn_loop.png"
    fig.savefig(out_path, dpi=300, bbox_inches="tight", pad_inches=0.12)
    plt.close(fig)
    return out_path


def generate_cm_and_latency_figure(m: dict[str, Any]) -> Path:
    """Generate Fig 4.1b: Live XGBoost Confusion Matrix + Inline vs 2-Hop Latency."""
    xgb_m = m["xgb"]["metrics"]
    cm = np.array(xgb_m["confusion_matrix"], dtype=int)
    cm_pct = cm / cm.sum(axis=1, keepdims=True) * 100.0
    n_test = int(cm.sum())
    acc_pct = float(xgb_m["test_accuracy"]) * 100.0
    f1_pct = float(xgb_m["test_f1_macro"]) * 100.0
    labels = ["BENIGN", "CMD", "PATH", "SQLI", "XSS"]

    abl_m = m["abl"]["modes"]
    e2e = m["lat"]["http_e2e_latency_ms"]
    c50_rps = float(m["perf"]["concurrency_benchmark"]["benign_passthrough"][-1]["rps"])
    csic_n = int(m["lat"].get("sample_counts", {}).get("total", 3000))

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13.2, 5.6), dpi=300, gridspec_kw={"width_ratios": [1.05, 1.05]})
    fig.patch.set_facecolor("#FFFFFF")

    # Left subplot: Confusion Matrix
    im = ax1.imshow(cm_pct, interpolation="nearest", cmap="Blues", vmin=0, vmax=100)
    cbar = fig.colorbar(im, ax=ax1, fraction=0.046, pad=0.04)
    cbar.set_label("Tỷ lệ phân loại theo hàng (%)", fontsize=9.0, color=DARK_TEXT)
    ax1.set_xticks(range(len(labels)))
    ax1.set_yticks(range(len(labels)))
    ax1.set_xticklabels(labels, fontsize=9.0, fontweight="bold", color=NAVY)
    ax1.set_yticklabels(labels, fontsize=9.0, fontweight="bold", color=NAVY)
    ax1.set_xlabel("Nhãn Dự Đoán (Predicted Class)", fontsize=10.0, fontweight="bold", color=NAVY, labelpad=8)
    ax1.set_ylabel("Nhãn Thực Tế (True Class)", fontsize=10.0, fontweight="bold", color=NAVY, labelpad=8)
    ax1.set_title(
        f"Ma trận nhầm lẫn XGBoost (Test Set N = {n_test:,})\nAccuracy = {acc_pct:.2f}% | Macro-F1 = {f1_pct:.2f}%".replace(",", "."),
        fontsize=11.0,
        fontweight="bold",
        color=NAVY,
        pad=12,
    )
    for r in range(cm.shape[0]):
        for c in range(cm.shape[1]):
            val = cm[r, c]
            pct = cm_pct[r, c]
            txt_color = "#FFFFFF" if pct >= 55.0 else DARK_TEXT
            ax1.text(
                c,
                r,
                f"{val:,}\n({pct:.1f}%)".replace(",", "."),
                ha="center",
                va="center",
                fontsize=8.3,
                fontweight="bold" if r == c else "normal",
                color=txt_color,
            )

    # Right subplot: Latency Comparison Bar Chart
    bar_labels = [
        "Rules Only\n(Inline)",
        "XGBoost ML\n(Inline)",
        "Hybrid AI\n(Inline)",
        "2-Hop TCP\nMean",
        "2-Hop TCP\nP50",
        "2-Hop TCP\nP95",
        "2-Hop TCP\nP99",
    ]
    bar_vals = [
        float(abl_m["rules_only"]["avg_latency_ms"]),
        float(abl_m["ml_only"]["avg_latency_ms"]),
        float(abl_m["hybrid"]["avg_latency_ms"]),
        float(e2e["mean_ms"]),
        float(e2e["p50_ms"]),
        float(e2e["p95_ms"]),
        float(e2e["p99_ms"]),
    ]
    bar_colors = ["#64748B", TEAL_EDGE, BLUE_EDGE, NAVY, "#1E40AF", "#C2410C", RED_EDGE]
    x = np.arange(len(bar_labels))
    bars = ax2.bar(x, bar_vals, width=0.58, color=bar_colors, edgecolor="#0F172A", linewidth=0.7, zorder=3)
    ax2.axhline(1.5, color=TEAL_EDGE, linestyle="--", linewidth=1.4, label="SLA Inline AI (1.500 ms)", zorder=2)
    ax2.axhline(5.5, color=RED_EDGE, linestyle="-.", linewidth=1.4, label="SLA E2E 2-Hop TCP (5.500 ms)", zorder=2)
    ax2.set_xticks(x)
    ax2.set_xticklabels(bar_labels, fontsize=8.0, color=DARK_TEXT)
    ax2.set_ylabel("Độ trễ xử lý (ms)", fontsize=10.0, fontweight="bold", color=NAVY)
    ax2.set_ylim(0, max(bar_vals) * 1.25)
    ax2.grid(axis="y", linestyle=":", alpha=0.55, zorder=1)
    ax2.set_title(
        f"Độ Trễ Nội Bộ vs HTTP 2-Hop Thực Tế (CSIC N = {csic_n:,})\nTải đồng thời C = 50: {c50_rps:.2f} RPS Benign Passthrough".replace(",", "."),
        fontsize=11.0,
        fontweight="bold",
        color=NAVY,
        pad=12,
    )
    ax2.legend(loc="upper left", fontsize=8.5, frameon=True, facecolor="#FFFFFF", edgecolor="#CBD5E1")
    for bar, val in zip(bars, bar_vals):
        ax2.text(
            bar.get_x() + bar.get_width() / 2,
            val + 0.16,
            f"{val:.3f}\nms",
            ha="center",
            va="bottom",
            fontsize=7.8,
            fontweight="bold",
            color=NAVY,
        )

    fig.tight_layout(w_pad=2.8)
    out_path = FIGURES_DIR / "fig_cm_and_latency.png"
    fig.savefig(out_path, dpi=300, bbox_inches="tight", pad_inches=0.14)
    plt.close(fig)
    return out_path


def main() -> None:
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    metrics = {
        "xgb": _load_json(ROOT_DIR / "ml-engine" / "artifacts" / "xgb_v2_metadata.json"),
        "iforest": _load_json(ROOT_DIR / "ml-engine" / "artifacts" / "iforest_v2_metadata.json"),
        "abl": _load_json(REPORTS_DIR / "ablation_results.json"),
        "lat": _load_json(REPORTS_DIR / "latency_e2e_v3_csic.json"),
        "perf": _load_json(REPORTS_DIR / "performance_profile_results.json"),
        "dqn": _load_json(ROOT_DIR / "attack-lab" / "models" / "pentest_dqn_v2_metadata.json"),
        "adv": _load_json(REPORTS_DIR / "adversarial_benchmark_3x3.json"),
        "st33": _load_json(REPORTS_DIR / "strange_suite_v33_results.json"),
        "bv2p": _load_json(REPORTS_DIR / "blind_heldout_vault_v2_postfix2_results.json"),
    }
    outputs = [
        generate_cyber_range_figure(metrics),
        generate_waf_pipeline_figure(metrics),
        generate_dqn_loop_figure(metrics),
        generate_cm_and_latency_figure(metrics),
    ]
    for p in outputs:
        print(f"[OK] Generated {p} ({p.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()

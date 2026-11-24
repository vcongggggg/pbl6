"""Generate 300 DPI Curriculum Convergence & Stealth Efficiency Figure (Phase C2).

Reads `attack-lab/models/pentest_dqn_v2_convergence.json` (600 episodes) and outputs
`docs/reports/figures/fig6_dqn_600ep_convergence.png`.
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

ROOT_DIR = Path(__file__).resolve().parent.parent
CONV_JSON = ROOT_DIR / "attack-lab" / "models" / "pentest_dqn_v2_convergence.json"
OUT_PNG = ROOT_DIR / "docs" / "reports" / "figures" / "fig6_dqn_600ep_convergence.png"


def _rolling_mean(vals: list[float], window: int = 20) -> np.ndarray:
    arr = np.asarray(vals, dtype=float)
    if len(arr) < window:
        return arr
    kernel = np.ones(window, dtype=float) / float(window)
    padded = np.pad(arr, (window - 1, 0), mode="edge")
    return np.convolve(padded, kernel, mode="valid")


def main() -> None:
    data = json.loads(CONV_JSON.read_text(encoding="utf-8"))
    episodes = data["episodes"]
    rewards = [float(e["reward"]) for e in episodes]

    s3_hyb = [e for e in episodes if e.get("tier") == "hybrid_v3"]
    s3_x = [int(e["episode"]) for e in s3_hyb]
    s3_blind = [int(e.get("blind_retries", 0)) for e in s3_hyb]
    s3_stealth = [float(e.get("stealth_efficiency", 0.0)) * 100.0 for e in s3_hyb]
    s3_hyb_rewards = [float(e["reward"]) for e in s3_hyb]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13.5, 5.2), dpi=300)
    fig.patch.set_facecolor("white")

    # Panel (a): 600-Episode Curriculum Reward Trajectory (separating Hybrid v3.0 encounters in Stage 3)
    s12 = [e for e in episodes if int(e["episode"]) <= 400]
    ax1.plot([int(e["episode"]) for e in s12], [float(e["reward"]) for e in s12], color="#94a3b8", alpha=0.30, linewidth=0.9)
    ax1.plot(
        [int(e["episode"]) for e in s12],
        _rolling_mean([float(e["reward"]) for e in s12], 20),
        color="#1d4ed8",
        linewidth=2.2,
        label="Stage 1-2 Rolling Mean Reward",
    )
    ax1.plot(s3_x, s3_hyb_rewards, color="#fda4af", alpha=0.35, linewidth=0.9)
    ax1.plot(
        s3_x,
        _rolling_mean(s3_hyb_rewards, 15),
        color="#be123c",
        linewidth=2.2,
        label="Stage 3 Hybrid v3.0 Mean (-14.32)",
    )
    ax1.axvline(200, color="#475569", linestyle="--", linewidth=1.1)
    ax1.axvline(400, color="#475569", linestyle="--", linewidth=1.1)
    ax1.axhline(0.0, color="#dc2626", linestyle=":", linewidth=1.0, alpha=0.7)

    ax1.text(100, max(rewards) * 0.90, "Stage 1\nLegacy WAF\n(Ep 1-200)", ha="center", fontsize=8.5, fontweight="bold", color="#0f172a")
    ax1.text(300, max(rewards) * 0.90, "Stage 2\nHardened Rules\n(Ep 201-400)", ha="center", fontsize=8.5, fontweight="bold", color="#0f172a")
    ax1.text(500, max(rewards) * 0.86, "Stage 3\nInterleaved\nHybrid v3.0\n(Ep 401-600)", ha="center", fontsize=8.5, fontweight="bold", color="#0f172a")

    ax1.set_title("(a) 3-Stage Curriculum Reward Convergence (600 Episodes)", fontsize=10.5, fontweight="bold", pad=10)
    ax1.set_xlabel("Training Episode", fontsize=9.5)
    ax1.set_ylabel("Cumulative Episode Reward", fontsize=9.5)
    ax1.grid(True, linestyle="--", alpha=0.3)
    ax1.legend(loc="lower left", fontsize=8.5, frameon=True)

    # Panel (b): Stage 3 Hybrid v3.0 Anti-Reward-Hacking & Stealth Efficiency
    ax2_twin = ax2.twinx()
    l1 = ax2.plot(
        s3_x,
        _rolling_mean([float(v) for v in s3_blind], 15),
        color="#e11d48",
        linewidth=2.1,
        label="Blind Retries After >=2 Blocks (Left)",
    )
    l2 = ax2_twin.plot(
        s3_x,
        _rolling_mean(s3_stealth, 15),
        color="#059669",
        linewidth=2.1,
        linestyle="-.",
        label="Stealth Pivot Efficiency % (Right)",
    )
    ax2.set_title("(b) Stage 3 Hybrid v3.0: Blind Retries Reduction (-8.51%)", fontsize=10.5, fontweight="bold", pad=10)
    ax2.set_xlabel("Training Episode (Hybrid v3.0 Encounters)", fontsize=9.5)
    ax2.set_ylabel("Rolling Mean Blind Retries", fontsize=9.5, color="#e11d48")
    ax2_twin.set_ylabel("Stealth Pivot Efficiency (%)", fontsize=9.5, color="#059669")
    ax2.grid(True, linestyle="--", alpha=0.3)

    lines = l1 + l2
    labels = [ln.get_label() for ln in lines]
    ax2.legend(lines, labels, loc="upper left", fontsize=8.2, frameon=True)

    plt.tight_layout()
    OUT_PNG.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT_PNG, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"[OK] Saved {OUT_PNG} ({OUT_PNG.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()

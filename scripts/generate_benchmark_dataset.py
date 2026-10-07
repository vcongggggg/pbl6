"""Benchmark Dataset Generator for Ablation Study (Master Plan B3).

Reproducibly generates a balanced, diverse 1,000-sample benchmark dataset
from data/processed/defense/test.csv for ablation experiments.
Categories: SQLI (200), XSS (200), PATH (200), CMD (200), BENIGN (200).
"""

from __future__ import annotations

import logging
from pathlib import Path

import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("generate_benchmark")

ROOT_DIR = Path(__file__).resolve().parent.parent
INPUT_CSV = ROOT_DIR / "data" / "processed" / "defense" / "test.csv"
OUTPUT_CSV = ROOT_DIR / "data" / "benchmark_1000_diverse.csv"


def generate_benchmark_dataset(
    input_path: Path = INPUT_CSV,
    output_path: Path = OUTPUT_CSV,
    samples_per_category: int = 200,
    random_state: int = 42,
) -> pd.DataFrame:
    if not input_path.exists():
        raise FileNotFoundError(f"Source dataset not found: {input_path}")

    logger.info("Loading base dataset from %s ...", input_path)
    df = pd.read_csv(input_path)

    categories = ["SQLI", "XSS", "PATH", "CMD", "BENIGN"]
    sampled_dfs: list[pd.DataFrame] = []

    for cat in categories:
        subset = df[df["attack_type"] == cat]
        n_avail = len(subset)
        if n_avail < samples_per_category:
            logger.warning("Category %s has only %d samples, sampling with replacement.", cat, n_avail)
            s = subset.sample(n=samples_per_category, replace=True, random_state=random_state)
        else:
            s = subset.sample(n=samples_per_category, replace=False, random_state=random_state)
        sampled_dfs.append(s)

    b1000 = pd.concat(sampled_dfs).sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    b1000.to_csv(output_path, index=False)

    logger.info("SUCCESS: Saved %d diverse benchmark rows to %s", len(b1000), output_path)
    logger.info("Class distribution:\n%s", b1000["attack_type"].value_counts().to_string())
    return b1000


if __name__ == "__main__":
    generate_benchmark_dataset()

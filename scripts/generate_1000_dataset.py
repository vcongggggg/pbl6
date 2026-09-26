import pandas as pd
from pathlib import Path

ROOT_DIR = Path(r"C:\Study\HocKy6\PBL6")
input_csv = ROOT_DIR / "data" / "processed" / "defense" / "test.csv"
output_csv = ROOT_DIR / "data" / "benchmark_1000_diverse.csv"

print(f"Loading base dataset from {input_csv} ...")
df = pd.read_csv(input_csv)

categories = ['SQLI', 'XSS', 'PATH', 'CMD', 'BENIGN']
sampled_dfs = []

for cat in categories:
    subset = df[df['attack_type'] == cat]
    s = subset.sample(n=200, random_state=42)
    sampled_dfs.append(s)

b1000 = pd.concat(sampled_dfs).sample(frac=1.0, random_state=42).reset_index(drop=True)
b1000.to_csv(output_csv, index=False)

print(f"SUCCESS: Saved {len(b1000)} diverse benchmark rows to {output_csv}")
print("\nAttack Category Distribution:")
print(b1000['attack_type'].value_counts())

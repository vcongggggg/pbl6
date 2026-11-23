"""Execute attack agent notebook and persist outputs into the ipynb."""

import json
import sys
from pathlib import Path
import matplotlib
matplotlib.use("Agg")

# Add attack-lab and ml-engine to sys.path
repo_root = Path.cwd().resolve()
sys.path.insert(0, str(repo_root / "attack-lab"))
sys.path.insert(0, str(repo_root))

nb_path = repo_root / "attack-lab" / "notebooks" / "01_train_attack_agent.ipynb"
with open(nb_path, "r", encoding="utf-8") as f:
    nb = json.load(f)

# Global execution context
global_ctx = {"display": lambda x: print(x)}

print("Starting execution of notebook cells...")
for idx, cell in enumerate(nb["cells"]):
    if cell["cell_type"] == "code":
        code = "".join(cell["source"])
        print(f"Executing cell {idx}...")
        try:
            exec(code, global_ctx)
            print(f"Cell {idx} executed successfully.")
        except Exception as e:
            print(f"Error in cell {idx}: {e}")
            raise e

print("All notebook cells executed successfully!")

import urllib.request
import json
import subprocess
import time

def get_git_token():
    p = subprocess.Popen(
        ['git', 'credential', 'fill'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    out, _ = p.communicate(input="url=https://github.com/vcongggggg/pbl6\n")
    for line in out.splitlines():
        if line.startswith("password="):
            return line.split("=", 1)[1]
    return None

def assign_issue(token, issue_number, assignees):
    url = f"https://api.github.com/repos/vcongggggg/pbl6/issues/{issue_number}/assignees"
    data = {"assignees": assignees}
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "User-Agent": "PBL6-Assignee-Script",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json"
        }
    )
    try:
        with urllib.request.urlopen(req) as resp:
            res = json.loads(resp.read().decode())
            print(f"Assigned #{issue_number} -> {assignees}")
    except Exception as e:
        print(f"Error assigning #{issue_number}: {e}")

ASSIGNMENTS = {
    # Phase 0, 1, 2
    1: ["vcongggggg", "naocavang08"],
    2: ["vcongggggg"],
    3: ["vcongggggg"],

    # Phase 3
    4: ["naocavang08"],
    14: ["naocavang08"],
    15: ["naocavang08"],
    16: ["naocavang08"],
    17: ["naocavang08"],
    18: ["naocavang08"],

    # Phase 4
    5: ["naocavang08"],
    19: ["naocavang08"],
    20: ["naocavang08"],
    21: ["naocavang08"],

    # Phase 5
    6: ["naocavang08"],
    22: ["naocavang08"],
    23: ["naocavang08"],
    24: ["naocavang08"],
    25: ["vcongggggg"],

    # Phase 6
    7: ["naocavang08"],
    26: ["naocavang08"],
    27: ["naocavang08"],
    28: ["naocavang08"],
    29: ["vcongggggg"],

    # Phase 7
    8: ["vcongggggg"],
    30: ["vcongggggg"],
    31: ["vcongggggg"],
    32: ["vcongggggg"],

    # Phase 8
    9: ["vcongggggg"],
    33: ["vcongggggg"],
    34: ["vcongggggg"],

    # Phase 9
    10: ["vcongggggg"],
    35: ["vcongggggg"],
    36: ["vcongggggg"],
    37: ["vcongggggg"],
    38: ["vcongggggg"],

    # Phase 10
    11: ["naocavang08"],
    39: ["naocavang08"],
    40: ["naocavang08"],
    41: ["naocavang08"],
    42: ["vcongggggg", "naocavang08"],

    # Phase 11
    12: ["naocavang08"],
    43: ["naocavang08"],
    44: ["naocavang08"],
    45: ["vcongggggg"],
    46: ["naocavang08"],

    # Phase 12
    13: ["vcongggggg", "naocavang08"],
    47: ["vcongggggg"],
    48: ["vcongggggg"],
    49: ["vcongggggg", "naocavang08"],
    50: ["vcongggggg", "naocavang08"],
}

def main():
    token = get_git_token()
    if not token:
        print("Error: Could not retrieve GitHub token")
        return
    
    print(f"Assigning {len(ASSIGNMENTS)} issues to team members (vcongggggg, naocavang08)...")
    for issue_num, assignees in ASSIGNMENTS.items():
        assign_issue(token, issue_num, assignees)
        time.sleep(0.3)
    print("\nAll issues assigned successfully!")

if __name__ == "__main__":
    main()

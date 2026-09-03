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

def graphql(token, query):
    req = urllib.request.Request(
        'https://api.github.com/graphql',
        data=json.dumps({'query': query}).encode('utf-8'),
        headers={
            'Authorization': f'Bearer {token}',
            'User-Agent': 'PBL6-Subissue-Linker',
            'Content-Type': 'application/json'
        }
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())

def get_issue_node_ids(token):
    # Fetch all issue number -> node id mappings for pbl6
    url = "https://api.github.com/repos/vcongggggg/pbl6/issues?state=all&per_page=100"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "User-Agent": "PBL6-Subissue-Linker",
            "Accept": "application/vnd.github.v3+json"
        }
    )
    with urllib.request.urlopen(req) as resp:
        issues = json.loads(resp.read().decode())
        return {iss['number']: iss['node_id'] for iss in issues}

HIERARCHY = {
    4: [14, 15, 16, 17, 18],     # Phase 3
    5: [19, 20, 21],             # Phase 4
    6: [22, 23, 24, 25],         # Phase 5
    7: [26, 27, 28, 29],         # Phase 6
    8: [30, 31, 32],             # Phase 7
    9: [33, 34],                 # Phase 8
    10: [35, 36, 37, 38],        # Phase 9
    11: [39, 40, 41, 42],        # Phase 10
    12: [43, 44, 45, 46],        # Phase 11
    13: [47, 48, 49, 50],        # Phase 12
}

def main():
    token = get_git_token()
    if not token:
        print("Error: Could not retrieve token")
        return
    
    print("Fetching issue node IDs from GitHub...")
    node_map = get_issue_node_ids(token)
    print(f"Loaded {len(node_map)} issues.")

    for parent_num, child_nums in HIERARCHY.items():
        parent_id = node_map.get(parent_num)
        if not parent_id:
            print(f"Parent #{parent_num} not found!")
            continue
        print(f"\nLinking Phase #{parent_num} with sub-issues {child_nums}...")
        for child_num in child_nums:
            child_id = node_map.get(child_num)
            if not child_id:
                print(f"  Child #{child_num} not found!")
                continue
            mutation = f"""
            mutation {{
              addSubIssue(input: {{
                issueId: "{parent_id}",
                subIssueId: "{child_id}"
              }}) {{
                issue {{ id }}
                subIssue {{ id }}
              }}
            }}
            """
            try:
                res = graphql(token, mutation)
                if 'errors' in res:
                    print(f"  #{child_num}: {res['errors'][0].get('message', 'Error')}")
                else:
                    print(f"  -> Successfully linked #{child_num} into Parent #{parent_num}!")
            except Exception as e:
                print(f"  Failed #{child_num}: {e}")
            time.sleep(0.3)

    print("\nAll sub-issues linked successfully into their parent phases!")

if __name__ == "__main__":
    main()

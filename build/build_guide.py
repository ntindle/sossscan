"""Build public/data/guide.json from the skeleton, the content files and the research data.

  python3 -I build/build_guide.py

Inputs:
  build/skeleton.json        (this repo) structure: tiers, layers, stages, attacks, items (links, cli, templates...)
  build/content/*.json       (this repo) prose per item: short, why, steps, snippets, pitfalls, docs, and for a
                             self-check check, no_result and habit (all optional)
  research data, which is private, in $SOSF_RESEARCH_DIR (default: ../sossscan-research, next to this repo):
    data/changes/{taxonomy,checklist,changes,team_profiles,repo_scan}.json
    data/changes/fix_commits.jsonl
    data/posts_index.json
Output: public/data/guide.json

Action pins ({{pin:owner/repo}}) are looked up on the GitHub API, with GITHUB_TOKEN, GH_TOKEN or `gh auth token`.
"""

import glob
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
RESEARCH = os.path.abspath(
    os.environ.get("SOSF_RESEARCH_DIR")
    or os.path.join(REPO, os.pardir, "sossscan-research")
)
OUT = os.path.join(REPO, "public", "data", "guide.json")
INPUTS = [
    "data/changes/taxonomy.json",
    "data/changes/checklist.json",
    "data/changes/changes.json",
    "data/changes/team_profiles.json",
    "data/changes/repo_scan.json",
    "data/changes/fix_commits.jsonl",
    "data/posts_index.json",
]


def P(*a):
    """A path in the research data."""
    return os.path.join(RESEARCH, *a)


def load(p):
    return json.loads(Path(P(p)).read_text())


_missing = [f for f in INPUTS if not os.path.isfile(P(f))]
if _missing:
    sys.exit(
        f"build_guide.py: no research data at {RESEARCH}\n"
        f"  missing: {', '.join(_missing)}\n"
        "  Set SOSF_RESEARCH_DIR to the folder that holds data/changes/ and data/posts_index.json\n"
        "  (default: ../sossscan-research, next to this repo). That data is private; the site itself only\n"
        "  needs the built public/data/guide.json, which is committed."
    )

skel = json.loads(Path(HERE, "skeleton.json").read_text())
tax = load("data/changes/taxonomy.json")
checklist = {c["id"]: c for c in load("data/changes/checklist.json")}
rows = load("data/changes/changes.json")
profiles = load("data/changes/team_profiles.json")
scan = load("data/changes/repo_scan.json")
posts = load("data/posts_index.json")
CATS = {c["id"]: c["label"] for c in tax["categories"]}
TAX = {i["id"]: i for i in tax["items"]}

content = {}
for f in sorted(glob.glob(os.path.join(HERE, "content", "*.json"))):
    content.update(json.loads(Path(f).read_text()))

# ---------------------------------------------------------------- pinned action refs ({{pin:owner/repo}})
def _github_token():
    """GITHUB_TOKEN, GH_TOKEN, then `gh auth token`, like the scanner CLI. None without one (60 requests an hour)."""
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        if os.environ.get(name, "").strip():
            return os.environ[name].strip()
    try:
        out = subprocess.run(
            ["gh", "auth", "token"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout.strip() or None


_token = _github_token()


def gh_get(path):
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "sosf-guide-build",
    }
    if _token:
        headers["Authorization"] = f"Bearer {_token}"
    req = urllib.request.Request("https://api.github.com" + path, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


_pins = {}


def _semver(t):
    """'v1.2.3' -> (1, 2, 3); 'v1' -> (1, -1, -1) so full versions sort above floating major tags."""
    m = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?$", t)
    return tuple(int(x) if x is not None else -1 for x in m.groups()) if m else None


# The guide tells maintainers to let new releases age before adopting them, so its own pins do the same.
COOLDOWN_DAYS = 7


def _cooled_release(repo):
    """The newest full-version release published at least COOLDOWN_DAYS ago, or None."""
    cutoff = datetime.now(UTC) - timedelta(days=COOLDOWN_DAYS)
    best = None
    for r in gh_get(f"/repos/{repo}/releases?per_page=50"):
        tag = r.get("tag_name") or ""
        v = _semver(tag)
        if r.get("draft") or r.get("prerelease") or not v or -1 in v:
            continue
        if datetime.fromisoformat(r["published_at"].replace("Z", "+00:00")) > cutoff:
            continue
        if best is None or v > _semver(best):
            best = tag
    return best


def pin(action):
    """owner/repo[/sub/path] -> 'owner/repo[/sub/path]@<sha> # <tag>' using the newest release that has aged COOLDOWN_DAYS."""
    if action not in _pins:
        repo = "/".join(action.split("/")[:2])
        tag = None
        try:
            tag = _cooled_release(repo)
            if not tag:  # every release is newer than the cooldown: take the latest one
                rel = gh_get(f"/repos/{repo}/releases/latest")["tag_name"]
                if _semver(rel) and -1 not in _semver(rel):
                    tag = rel
        except (urllib.error.URLError, KeyError, ValueError):
            tag = None  # no usable release; fall back to tags
        try:
            if not tag:
                tags = [
                    t["name"]
                    for t in gh_get(f"/repos/{repo}/tags?per_page=100")
                    if _semver(t["name"])
                ]
                tag = max(tags, key=_semver)
            sha = gh_get(f"/repos/{repo}/commits/{tag}")["sha"]
            _pins[action] = f"{action}@{sha} # {tag}"
        except (urllib.error.URLError, KeyError, ValueError):
            _pins[action] = f"{action}@main # TODO pin to a full commit SHA"
    return _pins[action]


def resolve_pins(text):
    return (
        re.sub(
            r"\{\{pin:([\w.-]+/[\w.-]+(?:/[\w.-]+)*)\}\}",
            lambda m: pin(m.group(1)),
            text,
        )
        if isinstance(text, str)
        else text
    )


# ---------------------------------------------------------------- evidence selection
CLAIM = ("post", "github-recap", "field-artifact")
by_item = defaultdict(list)
for r in rows:
    by_item[r["item_id"]].append(r)


def from_teams(iid, k=6):
    claims = [
        r
        for r in by_item[iid]
        if r["source_type"] in CLAIM and r.get("quote") and not r.get("vague")
    ]
    order = {"did": 0, "recommends": 1, "already-had": 2, "planned": 3}
    claims.sort(key=lambda r: (order.get(r["status"], 9), -len(r["detail"])))
    out, seen = [], set()
    for r in claims:
        key = (tuple(r["teams"]), r["status"])
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "team": " / ".join(r["teams"]),
                "status": r["status"],
                "detail": r["detail"],
                "quote": r["quote"],
                "source_url": r.get("source_url"),
                "source_title": r.get("source_title"),
                "source_type": r["source_type"],
            }
        )
        if len(out) >= k:
            break
    return out


def repo_examples(iid, k=8):
    ev = [
        r
        for r in by_item[iid]
        if r["source_type"] == "repo-scan"
        and r["status"] == "present"
        and r.get("evidence_url")
    ]
    rank = {"during-program": 0, "after-program": 1, "before-program": 2, None: 3}
    ev.sort(
        key=lambda r: (
            rank.get(r.get("timing"), 3),
            -(r.get("source_date") or "0000").__len__(),
        )
    )
    out, seen = [], set()
    for r in ev:
        if r["teams"][0] in seen:
            continue
        seen.add(r["teams"][0])
        out.append(
            {
                "team": r["teams"][0],
                "repo": r.get("source_title"),
                "label": r["detail"],
                "url": r["evidence_url"],
                "timing": r.get("timing"),
                "date": r.get("source_date"),
                "added_commit": r.get("first_added_commit"),
            }
        )
        if len(out) >= k:
            break
    return out


FIX_KEYS = {
    "pull_request_target": "ci-dangerous-triggers",
    "injection": "ci-script-injection",
    "persist-credentials": "ci-persist-credentials",
    "zizmor": "ci-workflow-audit",
    "permissions": "ci-token-permissions",
    "pin": "ci-pin-actions",
    "trusted-publishing": "rel-trusted-publishing",
    "attestation": "rel-provenance",
    "cooldown": "deps-cooldown",
}
FIX_FILTER = {
    "ci-dangerous-triggers": r"(?i)(remov|replac|drop|avoid|no longer|stop using|get rid|split|restrict|harden|secur|safer|isolat|away from|instead of|migrat\w* (off|from))[^\n]{0,80}(pull_request_target|workflow_run|privileged workflow)|(pull_request_target|workflow_run)[^\n]{0,60}(->|→| to | with )`?pull_request\b(?!_target)|(pull_request_target|workflow_run)[^\n]{0,80}(remov|replac|drop|split|restrict|harden|safer|isolat)",
    "ci-script-injection": r"(?i)(template|expression|script|code|shell)[- ]injection[^\n]{0,60}(workflows?\b|github actions?|\bgha\b|\bactions?\b|\bci\b)|(\bci\b|workflows?\b|github actions?|\bgha\b)[^\n]{0,60}injection|injection via template expansion",
    "ci-persist-credentials": r"(?i)(no longer|don'?t|do not|never|stop|without|disabl\w*|drop\w*)[^\n]{0,30}(persist|checkout credential)|persist-credentials:?`?\s*false|set `?persist-credentials|no-persist-credentials|unused checkout credentials",
    "ci-workflow-audit": r"(?i)zizmor",
    "ci-token-permissions": r"(?i)permission",
    "ci-pin-actions": r"(?i)\bpin",
    "rel-trusted-publishing": r"(?i)trusted publish",
    "rel-provenance": r"(?i)attest|provenance",
    "deps-cooldown": r"(?i)cooldown[^\n]{0,60}(dependabot|renovate|dependenc|npm|uv\b|pip|cargo|package|updates?\b|releases?\b)|(dependabot|renovate|dependenc|npm|uv\b|pip|cargo|package|updates?\b)[^\n]{0,60}cooldown|min-?release-?age|minimumReleaseAge|exclude-newer",
}
BOT = re.compile(
    r"(?i)^(merge pull request #\d+ from \S*/(dependabot|renovate)|build\(deps|chore\(deps|bump |update [\w./@-]+ (action|digest) to )"
    r"|^[\w.+/@-]+:\s*[\w.+-]+\s*->\s*[\w.+-]+"
)  # also package-set bumps like "foo: 1.2 -> 1.3"
# commits that undo a protection are not "how teams fixed it"
REVERSAL = re.compile(
    r"(?i)(remov\w*|drop\w*|revert\w*|disabl\w*)\s+`?persist-credentials:\s*false|^revert\b|(remov\w*|revert\w*|disabl\w*)\s+(the\s+)?zizmor\b"
    r"|prompt[- ]injection|remov\w*\s+(the\s+)?cooldown"
)
fix_extra = defaultdict(list)
for line in Path(P("data/changes/fix_commits.jsonl")).read_text().splitlines():
    c = json.loads(line)
    iid = FIX_KEYS.get(c["key"])
    msg = c["msg"].split("\n")[0]
    if (
        iid
        and not BOT.search(msg)
        and re.search(FIX_FILTER[iid], msg)
        and not REVERSAL.search(msg)
    ):
        fix_extra[iid].append(
            {
                "team": c["teams"][0],
                "repo": c["repo"],
                "date": c["date"],
                "msg": msg[:160],
                "url": c["url"],
            }
        )


ADOPTS = re.compile(
    r"(?i)\b(use|uses|using|switch(ed)? to|add(ed)?|migrat\w* to|mov\w* to|enabl\w*)\s+(the\s+)?`?(pull_request_target|workflow_run)\b"
    r"|\b(with|to|into|in)\s+`?pull_request_target\b(?!\s*(->|→))"
)


def fix_commits(iid, k=10):
    items = [
        {
            "team": r["teams"][0],
            "repo": r.get("source_title"),
            "date": r.get("source_date"),
            "msg": r["detail"][:160],
            "url": r["source_url"],
        }
        for r in by_item[iid]
        if r["source_type"] == "repo-commit"
        and not REVERSAL.search(r["detail"])
        and (
            iid not in FIX_FILTER
            or iid in ("ci-token-permissions", "ci-pin-actions")
            or re.search(FIX_FILTER[iid], r["detail"])
        )
    ] + fix_extra.get(iid, [])
    if iid in FIX_FILTER and iid not in ("ci-token-permissions", "ci-pin-actions"):
        items = [c for c in items if re.search(FIX_FILTER[iid], c["msg"])]
    if iid == "ci-dangerous-triggers":
        items = [c for c in items if not ADOPTS.search(c["msg"])]
    items.sort(key=lambda c: c["date"] or "", reverse=True)
    out, seen_url, per_team = [], set(), Counter()
    for c in items:
        key = (c["team"], re.sub(r"\s*\(#\d+\)$", "", c["msg"]).lower())
        if c["url"] in seen_url or key in seen_url or per_team[c["team"]] >= 2:
            continue
        seen_url.update([c["url"], key])
        per_team[c["team"]] += 1
        out.append(c)
        if len(out) >= k:
            break
    return out


# ---------------------------------------------------------------- peer adoption by tier (stars-based for alumni)
TIERS = skel["tiers"]


def stars_tier(stars):
    t = 0
    for x in TIERS:
        if (stars or 0) >= x["stars"] and x["stars"] > 0:
            t = x["id"]
    return t


team_tier = {
    s["team"]: stars_tier(s.get("stars")) for s in scan if s.get("default_branch")
}
present = defaultdict(set)
for r in rows:
    if r["source_type"] == "repo-scan" and r["status"] == "present":
        present[r["item_id"]].add(r["teams"][0])
tier_counts = Counter(team_tier.values())
peer = {}
for iid in skel["items"]:
    if not TAX.get(iid, {}).get("repo_signal"):
        continue
    by_t = {}
    for t, n in sorted(tier_counts.items()):
        have = sum(
            1 for team, tt in team_tier.items() if tt == t and team in present[iid]
        )
        by_t[str(t)] = round(100 * have / n) if n else None
    peer[iid] = {
        "overall": round(100 * len(present[iid]) / max(1, len(team_tier))),
        "by_tier": by_t,
    }

# ---------------------------------------------------------------- items
items = []
for iid, s in skel["items"].items():
    c = content.get(iid, {})
    ck = checklist.get(iid, {})
    tx = TAX.get(iid, {})
    item = {
        "id": iid,
        "category": tx.get("category"),
        "category_label": CATS.get(tx.get("category")),
        "label": tx.get("label"),
        "title": s["title"],
        "tier": s["tier"],
        "effort": s["effort"],
        "impact": s["impact"],
        "layer": s["layer"],
        "stage": s["stage"],
        "attacks": s.get("attacks", []),
        "week": s.get("week"),
        "tags": s.get("tags", []),
        "recurs_months": s.get("recurs_months"),
        "short": c.get("short") or tx.get("label"),
        "why": c.get("why", ""),
        "steps": c.get("steps", []),
        "snippets": [
            {**sn, "code": resolve_pins(sn.get("code", ""))}
            for sn in c.get("snippets", [])
        ],
        "pitfalls": c.get("pitfalls", []),
        "docs": c.get("docs", []),
        "check": c.get("check", ""),
        "no_result": c.get("no_result", ""),
        "habit": c.get("habit", ""),
        "links": s.get("links", []),
        "cli": s.get("cli"),
        "app_fix": s.get("app_fix", []),
        "new_file": {
            **s["new_file"],
            "template": resolve_pins(s["new_file"]["template"]),
        }
        if s.get("new_file")
        else None,
        "stats": {
            "teams_did": len(ck.get("teams_did", [])),
            "teams_planned": len(ck.get("teams_planned", [])),
            "teams_recommend": len(ck.get("teams_recommend", [])),
            "repo_present": len(ck.get("repo_present", [])),
            "repo_total": len(team_tier),
            "repo_added_in_window": len(ck.get("repo_added_during_program", [])),
            "window_commit_teams": len(ck.get("window_commit_teams", [])),
            "repo_risk": len(ck.get("repo_risk", [])),
        },
        "peer_adoption": peer.get(iid),
        "tools": ck.get("tools", [])[:10],
        "from_teams": from_teams(iid),
        "repo_examples": repo_examples(iid),
        "fix_commits": fix_commits(iid),
    }
    items.append(item)

# ---------------------------------------------------------------- teams
post_by_team = defaultdict(list)
for p in posts:
    if p.get("local_file") and p["tier"] in ("primary", "secondary"):
        for t in p["projects"]:
            post_by_team[t].append(
                {
                    "title": p["title"],
                    "url": p["url"],
                    "date": p.get("date"),
                    "tier": p["tier"],
                }
            )
scan_by_team = {s["team"]: s for s in scan if s.get("default_branch")}
teams = []
for name, pr in sorted(profiles.items(), key=lambda kv: kv[0].lower()):
    sc = scan_by_team.get(name, {})
    hl = [
        r["detail"]
        for r in rows
        if name in r["teams"]
        and r["source_type"] in ("post", "github-recap")
        and r["status"] == "did"
    ][:6]
    teams.append(
        {
            "name": name,
            "sessions": pr["sessions"],
            "repo": sc.get("repo"),
            "stars": sc.get("stars"),
            "language": sc.get("language"),
            "tier": team_tier.get(name),
            "scorecard": (sc.get("scorecard") or {}).get("score"),
            "did": pr["claims"]["did"],
            "planned": pr["claims"]["planned"],
            "present": sorted(
                k
                for k, v in ((pr.get("repo") or {}).get("present") or {}).items()
                if v == "present"
            ),
            "posts": post_by_team.get(name, []),
            "highlights": hl,
        }
    )

guide = {
    "version": 1,
    "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "counts": {
        "teams": len(profiles),
        "repos_scanned": len(team_tier),
        "posts": len([p for p in posts if p.get("local_file")]),
        "claims": sum(1 for r in rows if r["source_type"] in CLAIM),
        "window_commits": sum(1 for r in rows if r["source_type"] == "repo-commit"),
    },
    "tiers": skel["tiers"],
    "tier_note": skel["tier_note"],
    "layers": skel["layers"],
    "stages": skel["stages"],
    "attacks": skel["attacks"],
    "sprint": skel["sprint"],
    "app_fixes": skel["app_fixes"],
    "categories": [
        c for c in tax["categories"] if any(i["category"] == c["id"] for i in items)
    ],
    "items": items,
    "teams": teams,
    "pinned_actions": _pins,
}


def scrub(v, key=""):
    """Third-party text (commit messages, quotes, post titles) may contain markup; links must be http(s)."""
    if isinstance(v, str):
        if key in ("url", "source_url", "added_commit"):
            return v if re.match(r"^https?://", v) else None
        return v.replace("<", "‹").replace(">", "›")
    if isinstance(v, list):
        return [scrub(x, key) for x in v]
    if isinstance(v, dict):
        return {k: scrub(x, k) for k, x in v.items()}
    return v


for it in guide["items"]:
    for k in ("fix_commits", "from_teams", "repo_examples"):
        it[k] = scrub(it[k])
for t in guide["teams"]:
    for k in ("highlights", "posts"):
        t[k] = scrub(t[k])
todo_pins = [a for a, p in _pins.items() if "TODO" in p]
if todo_pins:
    print("WARNING: could not pin", todo_pins)
Path(OUT).write_text(json.dumps(guide, ensure_ascii=False, separators=(",", ":")))
print(
    f"wrote {os.path.relpath(OUT, REPO)}: {len(items)} items, {len(teams)} teams, {os.path.getsize(OUT) // 1024} KB; "
    f"content for {sum(1 for i in items if i['why'])} items; pins: {list(_pins)}"
)
print(
    "fix commits per item:",
    {i["id"]: len(i["fix_commits"]) for i in items if i["fix_commits"]},
)

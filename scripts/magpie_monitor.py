#!/usr/bin/env python3
"""magpie ecosystem monitor — daily watchdog for upstream protocol drift.

Watches the two repositories our plugins' protocol layers are aligned with:

  yetone/magpie            the app + its issue tracker, where the protocol
                           forensics (e.g. issue #808, the 9074 device-binding
                           side-by-sides) land first.
  magpie-community/plugins community provider plugins; packages/
                           {trae,qoder,workbuddy,zcode,mimo} mirror our five
                           plugin families (bound-exchange / cosy signing /
                           billing gateways / V4 signing / oauth).

Every run:
  1. reads the cursor (last_checked, UTC) from the state backend
  2. lists new commits / issue activity / releases since the cursor
  3. builds a markdown digest, flagging protocol-relevant items
  4. advances the cursor; when the run is alert-worthy AND posting is on,
     the digest is posted as a comment on the tracking issue

State backends (env MAGPIE_MONITOR_STATE):
  file   JSON file (MAGPIE_MONITOR_STATE_FILE, default: next to script) —
         local/manual runs
  issue  HTML comment on the tracking issue body (env MAGPIE_MONITOR_REPO) —
         CI runs, survives ephemeral runners; needs issues:write token

Env:
  GITHUB_TOKEN              API token (read: public upstream repos; write:
                            tracking issue in the target repo)
  MAGPIE_MONITOR_REPO       target repo for the tracking issue
                            (default mmqz/cpa-multi-plugins)
  MAGPIE_MONITOR_POST       "1" force posting on, "0" force off;
                            default: on iff state=issue
  MAGPIE_MONITOR_STATE_FILE state file path (file mode)
  MAGPIE_MONITOR_REPORT     also write the full report to this path

CLI:
  --since "2026-10-01T00:00:00Z"   cursor override (rewind for a deep digest)
  --lookback-days N                first-run window (default 7)
  --dry-run                        no state persist, nothing posted

Exit codes: 0 ok (quiet / alert / partially degraded), 1 total failure.
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

# --------------------------------------------------------------- config ----

MAGPIE_REPO = "yetone/magpie"
PLUGINS_REPO = "magpie-community/plugins"
TARGET_REPO = os.environ.get("MAGPIE_MONITOR_REPO", "mmqz/cpa-multi-plugins")
TRACKING_TITLE = "magpie ecosystem monitor (daily 06:00 CST)"

TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""

# magpie-community/packages → our plugin + the files whose protocol surface
# mirrors that package (the digest's "diff-check" hints).
WATCHED_PACKAGES = [
    ("packages/trae", "trae",
     ("plugins/trae/upstream/bound_exchange.go", "plugins/trae/upstream/client.go",
      "plugins/trae/auth/device.go", "plugins/trae/upstream/headers.go")),
    ("packages/qoder", "qoder",
     ("plugins/qoder/sign.go", "plugins/qoder/checkin.go", "plugins/qoder/billing.go",
      "plugins/qoder/image_upload.go", "plugins/qoder/oauth.go", "plugins/qoder/campaign.go")),
    ("packages/workbuddy", "workbuddy",
     ("plugins/workbuddy/billing.go", "plugins/workbuddy/checkin.go",
      "plugins/workbuddy/net_dial.go", "plugins/workbuddy/oauth.go",
      "plugins/workbuddy/payload.go")),
    ("packages/zcode", "zcode",
     ("plugins/zcode/signing.go", "plugins/zcode/claim.go", "plugins/zcode/oauth.go",
      "plugins/zcode/quota.go", "plugins/zcode/offpeak.go")),
    ("packages/mimo", "mimo",
     ("plugins/mimo/oauth.go", "plugins/mimo/exchange.go", "plugins/mimo/session.go")),
]

# Protocol-terms: any hit alone is alert-worthy (error codes, check-in,
# device-bound renewal machinery, signing dialects).
KEY_HIGH = [r"\b9074\b", r"\b11128\b", r"\b10605\b", r"\b20403\b",
            r"\bcheck[- ]?ins?\b", r"签到", r"\bproof", r"\bcosy\b",
            r"\bdeviceexchange\b", r"\bexchangetoken\b", r"\bdeviceinfo\b",
            r"\bdeviceproof\b", r"\bcloud-?ide\b", r"\bx-app-type\b",
            r"\bsolo_pc\b", r"\bide_pc\b", r"\bbound exchange\b"]

# Provider names: alone = context; combined with a token/auth/limiting signal
# in an issue = alert.
KEY_PROVIDER = [(r"\btrae\b", "trae"), (r"\bmarscode\b", "trae"),
                (r"\bqoder\b", "qoder"), (r"\bsash\b", "qoder"),
                (r"\bworkbuddy\b", "workbuddy"), (r"\bcodebuddy\b", "workbuddy"),
                (r"copilot\.tencent", "workbuddy"),
                (r"\bzcode\b", "zcode"), (r"\bglm\b", "zcode"),
                (r"\bzhipu\b", "zcode"), (r"智谱", "zcode"),
                (r"\bmimo\b", "mimo"), (r"\bxiaomi\b", "mimo")]

KEY_ISSUE_SIGNAL = [r"\btoken", r"\bauth(?!or)", r"\baccess\b", r"\blogin\b",
                    r"\blog ?in\b", r"\b401\b", r"\b403\b", r"\b429\b",
                    r"\bquota", r"\bcredit", r"\bbilling", r"\brefresh",
                    r"\bexpired", r"额度", r"失效", r"登录", r"风控", r"拦截"]

STATE_RE = re.compile(r"<!--\s*magpie-monitor-state:\s*(\{.*?\})\s*-->", re.S)

ISSUE_BODY = """# 🔔 magpie ecosystem monitor

Daily **06:00 Asia/Shanghai** (22:00 UTC) via [`.github/workflows/magpie-monitor.yml`](../blob/main/.github/workflows/magpie-monitor.yml) — also runnable on demand from *Actions → magpie-monitor → Run workflow* (optional `since` input rewinds the cursor for a deep digest).

**Why:** our plugins' protocol layers are byte-aligned with this ecosystem — trae device-bound renewal ← `magpie-community/packages/trae` `SITES["trae-cn"].deviceExchange`; the 9074 root-cause dossier ← `yetone/magpie` #808; qoder `cosy-*` dialects ← `packages/qoder`. Watching upstream buys early warning for protocol drift and speeds up issue triage here.

**Watched surfaces**

| upstream | what | maps to |
|---|---|---|
| `magpie-community/plugins` | commits in `packages/trae` | `plugins/trae` |
| 〃 | `packages/qoder` | `plugins/qoder` |
| 〃 | `packages/workbuddy` | `plugins/workbuddy` |
| 〃 | `packages/zcode` | `plugins/zcode` |
| 〃 | `packages/mimo` | `plugins/mimo` |
| 〃 | issues + releases | all |
| `yetone/magpie` | protocol-relevant commits, issues, releases | all |
| `mmqz/cpa-multi-plugins` | new issues (morning triage) | — |

**How to read it:** every run bumps *Last checked* below. Alert-worthy runs additionally post a digest comment listing the changes and which of our files to diff-check; quiet runs stay silent by design.

- Last checked: **{checked}** — status: **{status}**
- Runs so far: {runs}
- Cursor: `{cursor}`

<!-- magpie-monitor-state: {state} -->
"""

# -------------------------------------------------------------- helpers ----


def utcnow():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def cst(dt):
    return (dt + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M") + " CST"


def parse_iso(s):
    s = (s or "").strip()
    if not s:
        raise ValueError("empty timestamp")
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class FetchError(Exception):
    pass


def _headers(extra=None):
    h = {"Accept": "application/vnd.github+json",
         "User-Agent": "cpa-magpie-monitor",
         "X-GitHub-Api-Version": "2022-11-28"}
    if TOKEN:
        h["Authorization"] = "Bearer " + TOKEN
    if extra:
        h.update(extra)
    return h


def gh_get(path, params=None):
    url = "https://api.github.com" + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers=_headers())
    last = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code in (403, 429) and attempt < 2:
                time.sleep(5 * (attempt + 1))
                continue
            raise FetchError("GET %s -> HTTP %s" % (path, e.code))
        except Exception as e:  # network / timeout / json
            last = e
            if attempt < 2:
                time.sleep(3)
                continue
    raise FetchError("GET %s -> %s" % (path, last))


def gh_send(method, path, payload):
    req = urllib.request.Request(
        "https://api.github.com" + path,
        data=json.dumps(payload).encode("utf-8"),
        method=method,
        headers=_headers({"Content-Type": "application/json"}))
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        raise FetchError("%s %s -> HTTP %s %s" % (method, path, e.code, detail))


def match_patterns(text, patterns):
    t = (text or "").lower()
    return [p for p in patterns if re.search(p, t)]


def first_line(msg, cap=110):
    s = (msg or "").strip()
    if not s:
        return "(no message)"
    return s.splitlines()[0][:cap]


# ---------------------------------------------------------------- state ----


def fresh_state():
    return {"last_checked": None, "run_count": 0, "last_status": "BASELINE",
            "seen_shas": [], "seen_releases": [], "issue_updates": {},
            "issue_number": None}


def merge_state(st, loaded):
    for k in st:
        if k in loaded:
            st[k] = loaded[k]


def find_tracking_issue():
    try:
        res = gh_get("/search/issues",
                     {"q": 'repo:%s in:title "%s"' % (TARGET_REPO, TRACKING_TITLE),
                      "per_page": 10})
        for it in res.get("items", []):
            if TRACKING_TITLE in (it.get("title") or ""):
                return it
    except FetchError:
        pass
    try:  # fallback: recent-issues scan (search API can be rate-limited/lag)
        for page in (1, 2):
            batch = gh_get("/repos/%s/issues" % TARGET_REPO,
                           {"state": "all", "per_page": 100, "page": page})
            if not isinstance(batch, list):
                break
            for it in batch:
                if "pull_request" in it:
                    continue
                if TRACKING_TITLE in (it.get("title") or ""):
                    return it
            if len(batch) < 100:
                break
    except FetchError:
        pass
    return None


def fetch_issues(repo, since_dt):
    items = []
    for page in (1, 2):
        batch = gh_get("/repos/%s/issues" % repo,
                       {"state": "all", "sort": "updated", "direction": "desc",
                        "per_page": 50, "page": page})
        if not isinstance(batch, list):
            break
        stop = False
        for it in batch:
            if "pull_request" in it:
                continue
            try:
                upd = parse_iso(it["updated_at"])
            except Exception:
                continue
            if upd <= since_dt:
                stop = True
                break
            items.append(it)
        if stop or len(batch) < 50:
            break
    return items


# --------------------------------------------------------------- gather ----


def gather(cursor_dt, st):
    """Returns (alerts, contexts, errors); mutates st's dedupe collections."""
    alerts, contexts, errors = [], [], []
    cursor_iso = iso(cursor_dt)
    seen = set(st["seen_shas"])

    # 1) watched packages in magpie-community/plugins — always alert-worthy
    for pkg_path, plugin, files in WATCHED_PACKAGES:
        try:
            commits = gh_get("/repos/%s/commits" % PLUGINS_REPO,
                             {"path": pkg_path, "since": cursor_iso,
                              "per_page": 30})
        except FetchError as e:
            errors.append("%s: %s" % (pkg_path, e))
            continue
        fresh = [c for c in commits if c.get("sha") and c["sha"] not in seen]
        if not fresh:
            continue
        lines = ["#### `%s/%s` → `plugins/%s`" % (PLUGINS_REPO, pkg_path, plugin)]
        for c in fresh[:12]:
            when = (c["commit"].get("author") or {}).get("date") or ""
            who = (c["commit"].get("author") or {}).get("name") or "?"
            lines.append("- [`%s`](%s) %s — _%s_ (%s)" %
                         (c["sha"][:7], c["html_url"],
                          first_line(c["commit"].get("message")), who, when[:10]))
        if len(fresh) > 12:
            lines.append("- … and %d more" % (len(fresh) - 12))
        lines.append("  ↳ diff-check: `%s`" % "`, `".join(files))
        alerts.append("\n".join(lines))
        st["seen_shas"].extend(c["sha"] for c in fresh)

    # 2) yetone/magpie default-branch commits — keyword triage on the FIRST
    #    LINE only (magpie writes conventional-commit summaries; the long
    #    narrative bodies routinely contain incidental keyword hits)
    try:
        commits = gh_get("/repos/%s/commits" % MAGPIE_REPO,
                         {"since": cursor_iso, "per_page": 60})
    except FetchError as e:
        errors.append("magpie commits: %s" % e)
        commits = []
    hi, lo = [], []
    for c in commits:
        if c.get("sha") in seen:
            continue
        headline = first_line(c["commit"].get("message"), cap=400)
        if match_patterns(headline, KEY_HIGH):
            hi.append(c)
            st["seen_shas"].append(c["sha"])
        elif [p for p, _ in KEY_PROVIDER if re.search(p, headline.lower())]:
            lo.append(c)
    if hi:
        blocks = ["- [`%s`](%s) %s" % (c["sha"][:7], c["html_url"],
                                       first_line(c["commit"].get("message")))
                  for c in hi[:12]]
        if len(hi) > 12:
            blocks.append("- … and %d more" % (len(hi) - 12))
        alerts.append("#### `yetone/magpie` — protocol-flagged commits\n" +
                      "\n".join(blocks))
    if lo:
        contexts.append("`yetone/magpie`: %d provider-touching commits (latest: [`%s`](%s) %s)"
                        % (len(lo), lo[0]["sha"][:7], lo[0]["html_url"],
                           first_line(lo[0]["commit"].get("message"), 60)))

    # 3) issue activity on both upstream repos
    for repo in (MAGPIE_REPO, PLUGINS_REPO):
        try:
            items = fetch_issues(repo, cursor_dt)
        except FetchError as e:
            errors.append("%s issues: %s" % (repo, e))
            continue
        hi_blocks, lo_notes = [], []
        for it in items:
            key = "%s#%s" % (repo, it["number"])
            if st["issue_updates"].get(key) == it["updated_at"]:
                continue  # already reported, unchanged since
            blob = (it.get("title") or "") + "\n" + (it.get("body") or "")
            t = blob.lower()
            highs = match_patterns(blob, KEY_HIGH)
            provs = [(p, pl) for p, pl in KEY_PROVIDER if re.search(p, t)]
            sig = match_patterns(blob, KEY_ISSUE_SIGNAL)
            if highs or (provs and sig):
                matched = ", ".join(sorted(set(highs + [p for p, _ in provs])))
                hi_blocks.append("- [#%s](%s) **%s** _%s_ — matched: `%s` (updated %s)"
                                 % (it["number"], it["html_url"], it.get("state"),
                                    (it.get("title") or "")[:80], matched,
                                    it["updated_at"][:10]))
                if provs:
                    plugins = sorted({pl for _, pl in provs})
                    hi_blocks.append("  ↳ triage: may affect %s"
                                     % ", ".join("`plugins/%s`" % pl for pl in plugins))
            elif provs:
                lo_notes.append("[#%s](%s) _%s_" % (it["number"], it["html_url"],
                                                     (it.get("title") or "")[:60]))
        if hi_blocks:
            alerts.append("#### `%s` — issue activity\n%s"
                          % (repo, "\n".join(hi_blocks[:24])))
        if lo_notes:
            contexts.append("`%s`: %d provider-mentioning issues (e.g. %s)"
                            % (repo, len(lo_notes), "; ".join(lo_notes[:4])))
        for it in items:
            st["issue_updates"]["%s#%s" % (repo, it["number"])] = it["updated_at"]

    # 4) releases on both upstream repos
    for repo in (MAGPIE_REPO, PLUGINS_REPO):
        try:
            rels = gh_get("/repos/%s/releases" % repo, {"per_page": 10})
        except FetchError as e:
            errors.append("%s releases: %s" % (repo, e))
            continue
        for r in rels:
            tag = r.get("tag_name") or ""
            key = "%s@%s" % (repo, tag)
            if not tag or key in st["seen_releases"]:
                continue
            try:
                if parse_iso(r.get("published_at") or "") <= cursor_dt:
                    continue
            except Exception:
                continue
            st["seen_releases"].append(key)
            blob = (r.get("name") or "") + "\n" + (r.get("body") or "")
            if match_patterns(blob, KEY_HIGH) or \
               [p for p, _ in KEY_PROVIDER if re.search(p, blob.lower())]:
                alerts.append("#### `%s` — release [%s](%s) _%s_\n%s"
                              % (repo, tag, r["html_url"], (r.get("name") or "")[:60],
                                 (r.get("body") or "").strip()[:600]))
            else:
                contexts.append("`%s` released [%s](%s) _%s_ (no provider keywords in notes)"
                                % (repo, tag, r["html_url"], (r.get("name") or "")[:60]))

    # 5) new issues in OUR repo — the morning triage list
    try:
        ours = fetch_issues(TARGET_REPO, cursor_dt)
        new_ours = [it for it in ours
                    if parse_iso(it.get("created_at") or "1970-01-01T00:00:00Z") > cursor_dt
                    and str(it["number"]) != str(st.get("issue_number") or -1)]
        for it in ours:
            st["issue_updates"]["%s#%s" % (TARGET_REPO, it["number"])] = it["updated_at"]
        if new_ours:
            blocks = ["- [#%s](%s) **%s** _%s_ by @%s"
                      % (it["number"], it["html_url"], it.get("state"),
                         (it.get("title") or "")[:80], it["user"]["login"])
                      for it in new_ours[:10]]
            alerts.append("#### `%s` — new issues (morning triage)\n%s\n  ↳ correlate with the upstream changes above before replying"
                          % (TARGET_REPO, "\n".join(blocks)))
    except FetchError as e:
        errors.append("own-repo issues: %s" % e)

    return alerts, contexts, errors


# --------------------------------------------------------------- output ----


def build_digest(now, cursor, alerts, contexts):
    b = ["## 🚨 magpie monitor digest — %s" % cst(now), "",
         "**%d protocol-relevant section(s)** since %s." % (len(alerts), cst(cursor)), ""]
    b.append("\n\n".join(alerts))
    if contexts:
        b.append("\n**Context (no immediate action):**")
        b.extend("- %s" % c for c in contexts)
    b.append("\n---\n*Automated by `.github/workflows/magpie-monitor.yml` · daily 06:00 CST · "
             "posts only when protocol-relevant changes are found · quiet runs just bump "
             "Last checked on this issue.*")
    return "\n".join(b)


def build_report(now, cursor, status, post, alerts, contexts, errors):
    b = ["# magpie ecosystem monitor — %s" % cst(now),
         "status=%s post=%s cursor=%s → %s" % (status, post, iso(cursor), iso(now)), ""]
    b.append("## ALERTS (%d)" % len(alerts))
    b.append("\n\n".join(alerts) if alerts else "(none)")
    b.append("")
    b.append("## Context (%d)" % len(contexts))
    b.extend("- %s" % c for c in contexts) if contexts else b.append("(none)")
    b.append("")
    b.append("## Errors (%d)" % len(errors))
    b.extend("- %s" % e for e in errors) if errors else b.append("(none)")
    return "\n".join(b)


# ----------------------------------------------------------------- main ----


def main():
    ap = argparse.ArgumentParser(description="magpie ecosystem monitor")
    ap.add_argument("--since", default="",
                    help="cursor override, ISO 8601 UTC (rewind for a deep digest)")
    ap.add_argument("--lookback-days", type=int, default=7,
                    help="first-run lookback window in days (default 7)")
    ap.add_argument("--dry-run", action="store_true",
                    help="report only: no state persist, nothing posted")
    args = ap.parse_args()
    if not args.since.strip():
        args.since = None

    state_mode = os.environ.get("MAGPIE_MONITOR_STATE", "file").strip().lower()
    if state_mode not in ("file", "issue"):
        state_mode = "file"
    post_env = os.environ.get("MAGPIE_MONITOR_POST", "").strip()
    post = (post_env == "1") or (post_env != "0" and state_mode == "issue")

    now = utcnow()
    st = fresh_state()

    if state_mode == "issue":
        tracking = find_tracking_issue()
        if tracking:
            st["issue_number"] = tracking["number"]
            m = STATE_RE.search(tracking.get("body") or "")
            if m:
                try:
                    merge_state(st, json.loads(m.group(1)))
                except Exception:
                    pass
    else:
        sf = os.environ.get("MAGPIE_MONITOR_STATE_FILE") or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "magpie_monitor_state.json")
        if os.path.exists(sf):
            try:
                with open(sf) as f:
                    merge_state(st, json.load(f))
            except Exception:
                pass

    baseline = not st.get("last_checked")
    if args.since:
        cursor = parse_iso(args.since)
        baseline = False
    elif baseline:
        cursor = now - timedelta(days=max(1, args.lookback_days))
    else:
        cursor = parse_iso(st["last_checked"])

    alerts, contexts, errors = gather(cursor, st)

    status = "ALERT" if alerts else ("BASELINE" if baseline else "QUIET")
    if errors:
        status += " (degraded)"

    report = build_report(now, cursor, status, post, alerts, contexts, errors)
    print(report)
    rp = os.environ.get("MAGPIE_MONITOR_REPORT")
    if rp:
        os.makedirs(os.path.dirname(rp) or ".", exist_ok=True)
        with open(rp, "w") as f:
            f.write(report)

    # trim dedupe collections, advance cursor
    st["seen_shas"] = st["seen_shas"][-250:]
    st["seen_releases"] = st["seen_releases"][-60:]
    st["issue_updates"] = dict(list(st["issue_updates"].items())[-200:])
    st["run_count"] = st.get("run_count", 0) + 1
    st["last_checked"] = iso(now)
    st["last_status"] = status

    if args.dry_run:
        print("\ndry-run: state not persisted, nothing posted")
        return 0

    # ensure the tracking issue exists (needed for posting and/or issue-state)
    if (state_mode == "issue" or (alerts and post)) and not st["issue_number"]:
        try:
            created = gh_send("POST", "/repos/%s/issues" % TARGET_REPO,
                              {"title": TRACKING_TITLE,
                               "body": "bootstrapping — first run in progress…"})
            st["issue_number"] = created["number"]
            print("created tracking issue #%s" % st["issue_number"])
        except FetchError as e:
            print("tracking issue creation failed: %s" % e, file=sys.stderr)

    if alerts and post and st["issue_number"]:
        try:
            gh_send("POST", "/repos/%s/issues/%s/comments" % (TARGET_REPO, st["issue_number"]),
                    {"body": build_digest(now, cursor, alerts, contexts)})
            print("digest posted to %s#%s" % (TARGET_REPO, st["issue_number"]))
        except FetchError as e:
            print("digest post failed: %s" % e, file=sys.stderr)

    if state_mode == "issue":
        if st["issue_number"]:
            try:
                body = ISSUE_BODY.format(
                    checked=cst(now), status=status, runs=st["run_count"],
                    cursor=iso(now),
                    state=json.dumps({k: st[k] for k in
                                      ("last_checked", "run_count", "last_status",
                                       "seen_shas", "seen_releases", "issue_updates",
                                       "issue_number")},
                                     ensure_ascii=False, separators=(",", ":")))
                gh_send("PATCH", "/repos/%s/issues/%s" % (TARGET_REPO, st["issue_number"]),
                        {"body": body})
            except FetchError as e:
                print("state save failed: %s" % e, file=sys.stderr)
                return 1
        else:
            print("no tracking issue available; state not persisted", file=sys.stderr)
            return 1
    else:
        os.makedirs(os.path.dirname(sf) or ".", exist_ok=True)
        with open(sf, "w") as f:
            json.dump(st, f, indent=1)

    return 1 if (errors and not (alerts or contexts)) else 0


if __name__ == "__main__":
    sys.exit(main())

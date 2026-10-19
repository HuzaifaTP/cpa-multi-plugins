#!/usr/bin/env python3
"""trae-usage — per-account Trae quota report.

Reads every trae credential from the CPA auth dir and prints the metered
allocation vs consumption from the official intl pay face.

Endpoints (all POST, body JSON, header Authorization: Cloud-IDE-JWT <token>):
  https://grow-normal.trae.ai/trae/api/v1/pay/ide_user_ent_usage
      -> user_entitlement_pack_list[].entitlement_base_info.quota  (allocation)
      -> user_entitlement_pack_list[].usage                        (consumption)
  https://grow-normal.trae.ai/trae/api/v1/pay/ide_user_pay_status
      -> user_pay_identity_str (Free / Pro / ...)

Metering model (Free plan, verified 2026-10-19):
  basic_usage_limit  = 1.0            fractional meter, 1.0 == exhausted
  basic_usage_amount = 0.15374        consumption so far this period
  advanced_model_request_limit = 1000 request counter (non-premium models)
  premium_model_fast_request_limit  = 10   GPT-6.x fast lane
  premium_model_slow_request_limit  = 50   GPT-6.x slow lane
  solo_agent_parallel_limit         = 2    concurrent sessions

There is NO per-model allocation: models draw from shared pools. A model
outside the lane returns 4001; an exhausted pool returns 1005; a spent
basic_usage_limit returns 4008.

Usage: trae-usage.py [auth_dir]
"""
import json
import os
import sys
import urllib.error
import urllib.request

PAY = "https://grow-normal.trae.ai"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")


def call(path, token, region, device_id):
    h = {
        "Content-Type": "application/json",
        "Accept": "*/*",
        "User-Agent": UA,
        "X-User-Region": region or "US-East",
        "X-Device-Id": device_id or "",
        "Authorization": "Cloud-IDE-JWT " + token,
    }
    body = json.dumps({"require_usage": True, "req_source": 1,
                       "full_data": True, "Request": {}}).encode()
    req = urllib.request.Request(PAY + path, data=body, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=25) as f:
            return json.loads(f.read().decode())
    except urllib.error.HTTPError as e:
        return {"_error": "HTTP %d %s" % (e.code, e.read().decode()[:120])}
    except Exception as e:                       # noqa: BLE001
        return {"_error": str(e)[:120]}


def bar(used, total, width=24):
    if not total:
        return ""
    frac = max(0.0, min(1.0, used / total))
    n = int(frac * width)
    return "[%s%s] %5.1f%%" % ("#" * n, "." * (width - n), frac * 100)


def main():
    auth_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser(
        "~/github/CLIProxyAPI/auths")
    files = sorted(f for f in os.listdir(auth_dir)
                   if f.startswith("trae-") and f.endswith(".json"))
    if not files:
        print("no trae-*.json in", auth_dir)
        return 1

    for fn in files:
        with open(os.path.join(auth_dir, fn), encoding="utf-8") as fh:
            cred = json.load(fh)
        auth = cred.get("auth") or {}
        token = auth.get("accessToken") or ""
        if not token:
            print(f"{fn}: no accessToken"); continue

        name = cred.get("nickname") or cred.get("uid") or fn
        uid = cred.get("uid") or auth.get("uid") or "?"
        ent = call("/trae/api/v1/pay/ide_user_ent_usage", token,
                   auth.get("region"), auth.get("deviceId"))
        ps = call("/trae/api/v1/pay/ide_user_pay_status", token,
                  auth.get("region"), auth.get("deviceId"))

        print("=" * 74)
        print(f"{name}   uid={uid}")
        if "_error" in ent:
            print("  ent_usage error:", ent["_error"]); continue
        identity = ps.get("user_pay_identity_str") or "?"
        print(f"  plan: {identity}")
        for p in ent.get("user_entitlement_pack_list") or []:
            q = (p.get("entitlement_base_info") or {}).get("quota") or {}
            u = p.get("usage") or {}
            used = u.get("basic_usage_amount") or 0
            total = q.get("basic_usage_limit") or 0
            print(f"  pack: {p.get('display_desc')}   {bar(used, total)}")
            print(f"    basic_usage   {used} / {total}"
                  f"   (remaining {round(max(total - used, 0), 5)})")
            print(f"    advanced      {q.get('advanced_model_request_limit')} requests")
            print(f"    premium fast  {q.get('premium_model_fast_request_limit')}")
            print(f"    premium slow  {q.get('premium_model_slow_request_limit')}")
            print(f"    parallel      {q.get('solo_agent_parallel_limit')}")
            if u.get("is_flash_consuming"):
                print("    flash-consuming: yes")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())

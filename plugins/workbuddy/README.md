# workbuddy

A [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) provider plugin for the CodeBuddy / WorkBuddy family. The CN and Global/Intl variants share one plugin and one identifier; accounts are routed by the platform and region recorded in each auth file, and legacy per-platform auth files are adopted on startup.

Built with Go (CGO, c-shared). Release artifacts for all supported platforms are produced by CI from tagged commits — see the repository root README for the version matrix and the disclaimer.

## Credit guardrails (opt-in, #61)

Two scheduler-pick guardrails keep accounts usable instead of drained to zero by routine pool traffic. Both are **default-off**, both are pure consumers of the existing credits cache — guardrails never add a single upstream call.

- **`reserve_credits`** — a credential whose cached remaining credits are `<= N` is simply not offered as a scheduler candidate, keeping the account usable for the official client / for emergencies.
- **`daily_credits_cap`** — a credential whose estimated same-day credit spend reaches the cap is withheld. Spend is estimated as *day-start remaining − current remaining* from the same credits plane (monotone enough for a guardrail; no per-request accounting). Credits granted mid-day (check-in rewards) can make the estimate negative — a negative spend never guards. The metering day is the **UTC+8** calendar day; counters are in-memory only, so a restart mid-day re-snapshots on first sight and errs toward firing later, never earlier.

Global defaults live in the plugin's config block (either form):

```yaml
reserve_credits: 100      # 0 / absent / non-positive = off
daily_credits_cap: 500    # 0 / absent / non-positive = off
```

Per-credential overrides ride the auth document's top level as numbers — a pool usually wants one policy with a few exceptions:

```json
{
  "reserve_credits": 100,
  "daily_credits_cap": 500
}
```

Absent fields inherit the global; `0` explicitly disables that guardrail for this credential (and per-credential overrides work even when the globals are off).

**Scope limitation (by design):** the skip only bites when the plugin is doing the picking (`scheduler_mode: credits`). In host-side pick modes the guardrail cannot intervene — the host never asks the plugin for candidates. When every workbuddy candidate is guarded, the pick defers to the host like any empty-candidate case, with a log line.

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

The code originates from the upstream reference repository and is provided for mirroring purposes only.

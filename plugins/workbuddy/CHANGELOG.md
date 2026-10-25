# Changelog

## 0.9.70

### Per-account machine identity on the billing plane (PR #58, implements #57)

The billing surface sent no device identity at all: N gateway-fronted accounts presented zero device separation on every billing, growth, school and task call — the whole non-chat family shares one header set, so a pool looked like one machine making all the calls. The official non-chat family carries `X-Machine-ID` (OS hardware UUID) / `X-Session-ID` (per-process randomUUID) plus a fresh `X-Request-ID` per call, on both CN and Global realms (workbuddy2api-hub `wb_fingerprint.py` / `wb_accounts.py`, 5.8.4 captures).

- `billingHeaders` now derives `X-Machine-ID` / `X-Session-ID` per account (stable UUIDv4-shaped, same account always the same virtual device, two accounts never share a value — a process-wide value would tie the whole pool to one machine) and mints a fresh bare-32-hex `X-Request-ID` per call, deliberately not uid-derived.
- Derivation lives in `fingerprint.go` next to the other identity constants; sha256-seeded, version/variant nibbles forced to the UUIDv4 shape. The chat plane is deliberately untouched — official chat requests carry none of these headers, and ours never did.
- Deliberately out of scope (per #57): `growthDeriveID`'s bare-hex event-body shape. Aligning it would migrate every existing install's reported growth device id mid-flight; tracked separately.

### Opt-in per-credential in-flight admission control (PR #60)

The host's scheduler picks a credential and calls the executor; what it cannot see is that the plugin holds the upstream call open for the whole streaming response. Two conversations landing on one credential meant two long-lived upstream calls on the same account — and the upstream meters per (account, minute), so parallel big-context calls on one credential were the fastest path to a model-scoped 6004 that then cooled the pair for everyone.

- New `account_max_concurrent` config field (default **0 = off**, byte-for-byte old dispatch when disabled): caps concurrent executor calls per credential. At capacity the executor fails fast with a plain error — no HTTP status, no literal rate-limit wording, same discipline as `model_ratelimit.go` — so the host rotates to another candidate instead of reading it as this credential's quota trouble. No local queueing.
- The slot is held for the whole upstream call, not the handler call: `defer` in the two synchronous executors, the pump goroutine in the async stream path (the upstream call is still in flight after the handler returns — that is the point of async). Release is `sync.Once`-wrapped, safe from both a defer and a wrapped goroutine.
- Empty auth id (hand-built snapshots: tests, pre-persist logins) bypasses admission and records no state.

## 0.9.69

### Per-credential model exclusions survive and apply (issue #56)

Field report (2026-10-24): an education/enterprise account in a shared CN channel advertises the realm's full 54-model catalog but is only authorized for a subset — the rest answer 400 `11136 model not allowed`, so every poll onto the account burns an upstream round trip and marks the credential failed. Channel-level exclusion (config.yaml `oauth-excluded-models`) removes those models from EVERY account on the channel, and the host's documented per-credential list (top-level `excluded_models` in the auth file, merged by the watcher synthesizer into `auth.Attributes` and applied per-auth at model registration) never survived on disk: every plugin-side typed rebuild (lifecycle note churn, check-in status) reconstructed the document without it, and the field wasn't in the `preservePluginDocKeys` whitelist — wiped within seconds of a hand edit.

- `excluded_models` (and the hyphen spelling `excluded-models`) joined the `preservePluginDocKeys` whitelist — typed rebuilds now re-inject the field from the physical document exactly the way `model_cache` has survived since v0.9.38. Restores are logged (`preserved key(s) … re-injected into …`) so field-vanishing reports have an audit trail.
- The serve layer filters each credential's advertised list through its own exclusion (`fetchDynamicModelsFromStorage`, after the alias overlay, covering the pin/cache/discovery/snapshot branches alike). Matching is the host's own semantics — trim, lowercase, `*` wildcard — so the plugin's filter and the host's registry filter can never disagree. An empty/absent list still means "no opinion": channel-level rules keep applying.
- New management endpoints give the per-account narrowing a real UI path instead of hand-edited files: `GET /v0/management/plugins/workbuddy/excluded-models?auth_index=…` reads the current list; `POST` with `{auth_index, models:[…]}` merges it into the physical document through the `hostAuthSaveJSON` funnel (normalize + preserve), and an empty list removes the field entirely.
- The import endpoint no longer bypasses the funnel: `handleImportAuth` ran a raw `host.auth.save` that skipped `preservePluginDocKeys`, so re-importing an existing credential started the document over (wiping `model_cache` and operator fields).

### Request fingerprint rides current client versions (issue #56)

Same report: the plugin's identity strings sat three minors behind the reference implementations' 2026-10-18 captures — `CLI/2.108.1` vs the CLI package's `2.168.2`, desktop `5.5.6`/CLI `2.137.1` vs `5.8.3`/`2.161.0`, `X-IDE-Version: 5.5.6` vs `5.8.3`, and no OpenAI SDK fingerprint at all. Not a wire-correctness bug, but every request reading as a stale client is free risk surface against the 11128 channel-verification family.

- `clientUA` → `CLI/2.168.2 CodeBuddy/2.168.2`; desktop UA (growth event plane) → `WorkBuddy/5.8.3 WorkBuddy/5.8.3 CLI/2.161.0`; `X-IDE-Version` and the growth fingerprint's `ideVersion`/`extVersion` → `5.8.3`. Version constants live in one place (`fingerprint.go`) so the next bump is a single edit.
- CLI-identity chat calls now carry the OpenAI Node SDK fingerprint family the official CLI's bundled SDK sends: `X-Stainless-Lang/Package-Version/OS/Arch/Runtime/Runtime-Version` (6.25.0 shape), with OS/arch mapped from the REAL runtime platform (darwin→macOS, amd64→x64). IDE-identity logins keep their CodeBuddyIDE family untouched — mixing the two would be a new mismatch, not an alignment.

## 0.9.68

### A billing 401 renews once and sends once more (magpie packages/workbuddy 0.1.31)

magpie's workbuddy plugin taught this lesson on 2026-10-23 (0.1.31): "a chat or usage read WorkBuddy answers 401 is renewed once, whatever the token's time, and sent once more." Our keepalive refresh keeps offline sessions alive on a daily schedule, but a session that died between keepalive ticks surfaced as a hard failure on every billing call — check-in, usage read, enterprise meter, payment type — until the next daily cycle came around.

- `billingCall` now recognizes the billing plane's two 401 shapes (the gateway's HTML credential bounce, and the JSON envelope's `code=12153` "Offline user session not found") and attempts ONE token renewal plus ONE resend before giving up.
- A token another process saved since the snapshot is taken first, instead of spending the refresh token again; and exactly one renewal per credential per 30s window — a scheduler tick fans out into several billing calls, and rotation makes concurrent refresh spends destructive.
- The credential is flagged dead only on the upstream's own word: the refresh itself refused with the session-dead family (12153). A 401 that survives a successful renewal surfaces with "re-login required"; every other renewal failure (throttled, snapshot without host identity, no refresh token, transport) leaves the account exactly as it was and keeps the plain 401 shape for the next cycle.
- `storedAuth` carries its host-side auth index (unexported, JSON-invisible) so the heal can renew-and-persist in place; `hostAuthGet`/`hostAuthGetBundle` stamp it, and the persist/mark paths route through the testable seams.

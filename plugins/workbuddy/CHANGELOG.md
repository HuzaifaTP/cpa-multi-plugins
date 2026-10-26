# Changelog

## 0.9.77

### Chat-plane 401 self-heal: renew once and resend once (field report 2026-10-26, Buddycn account)

Field report: an account's every chat request surfaced as HTTP 500 `upstream 401: <html>…401 Authorization Required…openresty…` — the APISIX gateway bouncing the access token with its HTML error page. That page is the documented signature of a dead Keycloak offline session (see keepalive.go): the token is rejected before any business logic runs, and nothing in the plugin can revive the session — only re-login can.

- Root cause: 0.9.68 wired the 401 renew-once on the BILLING plane only (magpie packages/workbuddy 0.1.31 parity — "a chat or usage read WorkBuddy answers 401 is renewed once … and sent once more"), but the CHAT half never landed. A chat 401 got only the host's 30-minute credential cooldown, which retries the SAME dead access token after the window: the user sees 401→500 after 401→500 until a keepalive tick or a billing call happens to renew the credential, and the surfaced error is the raw openresty HTML with no actionable guidance.
- New `chat_401_heal.go`: `healChat401` resolves the credential's host identity (the executor snapshot carries no authIndex; same resolution `reconcileAfterExecutorError` applies) and drives the shared `billing401RenewOnce`. Outcomes: renewed → the caller resends once with the fresh snapshot; refresh refused with the session-dead family (12153) → the credential is already flagged disabled by the shared renewal and the error carries bilingual re-login guidance; throttled/identity-less → the exact pre-0.9.77 raw-401 behavior (the next request retries the heal).
- Wiring: all three chat executor paths (sync `handleExecExecute`, stream sync-collector `collectUpstreamStream`, async `pumpUpstreamStream`). The heal runs BEFORE any failure bookkeeping, so a rescued request is indistinguishable from one that simply worked — no failed-usage entry, no cooldown notes; a resend that still fails becomes the primary failure (a second 401 appends the "renewed once and still refused — re-login" guidance). Only real HTTP 401 round trips are healed; in-stream unauthorized-looking frames keep their status-less path.
- `billing401RenewOnce` concurrency upgrade: callers that arrive while a renewal is in flight now JOIN it and take what it gave (magpie's renewing-map semantics) instead of failing "throttled" — a fan-out of 401s spends the refresh token exactly once, on both planes. The 30s window now only gates starting a NEW renewal when nothing is running.
- New test seam `chatEndpointOverride` (same shape as `refreshEndpointOverride`) drives the full 401→renew→resend chain hermetically; `chat_401_heal_test.go` pins the heal end-to-end on the sync executor and the sync collector, the session-dead disable + guidance, the renewed-but-refused guidance, and the throttled raw-401 passthrough.
## 0.9.76

### oneOf of objects with no type gets type:object — Kimi 400 fix (magpie workbuddy 0.1.33, #378)

Absorbed from magpie-community/plugins `def6a83` (workbuddy 0.1.33, 2026-10-25): kimi-k3.1-pro on workbuddy and workbuddy-ai answers 400 `Invalid request parameters` to a tool whose parameters hold a oneOf with no type — even when every branch is an object, directly or through a chain of local $refs (dsh's REA tools). The same request with `"type": "object"` beside the oneOf gets 200, verified in three real dsh runs with all 198 tools.

- New `payload.go` pipeline step 3.3 (`typeUnionToolSchemas`): walks `tools` in all three shapes (the 0.9.72 compaction discipline — nested `function.parameters`, flat Responses-API `parameters`, MCP-namespace sub-tools) and mends each parameters schema.
- `schemaTypeUnions` / `typeUnionObjectBranch` / `typeUnionLocalRef` are a byte-aligned Go port of magpie's `typeUnions` / `objectBranch` / `localRef`: the union gains `type: "object"` only when EVERY branch is typed object (itself or via local `#/...` $ref chains, cycles broken, ≤16 hops); a union of other or mixed types, an anyOf, and a $ref that is missing, external or circular are left as they came; only schema keywords are walked (SUB_ONE/SUB_LIST/SUB_MAP sets — `examples`/`default` payloads never touched), depth-capped at 64.
- Tests (`typeunion_test.go`) port the issue's literal parameters from magpie's tools.test.mjs: the minimal $ref → oneOf, the nested oneOf all routes refused, the REA $ref-branch shape, the left-alone matrix (typed sibling / mixed / anyOf / missing / external / circular / examples — asserted byte-for-byte unchanged), and the three-shape walker. Full `-race` suite green.

## 0.9.75

### Opt-in 429-triggered outbound-identity lane switch (issue #59)

Implements the design as answered by the maintainer (2026-10-25): the outbound identity family (CLI vs adopted-IDE) is fixed at login time per credential, and on a 429 the plugin cools the (credential, model) pair — this adds the opt-in lane switch that treats the two families' quota lanes as separate lines and flips the credential's family after an account-level 429, so its NEXT requests speak the other lane.

- **`identity_switch_on_429: true`** (default **false**) — the value concentrates in 1–2-account deployments that want to drain every quota lane on the account they have; multi-account pools already have the right ceiling (cool the pair, host rotates).
- **Sticky, credential-level, persisted**: the flip writes `identity_family` into the auth record through the standard persistAuthTokens merge — a restart must not forget which lane is hot; a fresh login resets to the login family. Per-request switching is rejected by design (it would make the effective cooldown key (credential, model, family) and turn debugging into archaeology). Without a host authIndex there is nowhere to persist — no persist means no switch (never a half-switch riding a snapshot).
- **Switch order CLI → IDE → CLI, capped at 4/day per credential** (hub's MAX_PRODUCT_SWITCHES=4 parity, day-scoped on the UTC+8 metering day, same day-key machinery as the #61 guardrails) to bound oscillation.
- **Whole-family switch, atomically**: `backendHeaders` now keys both the X-IDE family selection and the Stainless gate on the effective family — a CLI-login credential flipped to ide speaks the CodeBuddyIDE set and drops X-Stainless-*; an IDE-login credential flipped to cli gains the WorkBuddy trio plus Stainless. The families stay internally coherent, never mixed (the v0.9.69 invariant).
- **Scope: CN-realm credentials only** — both families are field-proven on the CN gateway; Intl owns its header family outright (applyRealmHeaders), and Global's proven working shape is the desktop/CLI family (#43/#44/#45 gates). Field reports decide any widening.
- **Trigger surface**: the account-level 429 family only (the same branch that marks the pair rate-limit-cooled). Model-scoped 6004 rejections never flip the lane — they are keyed (credential, model) and own their precise reset windows.
- **Observability**: every switch logs old → new with today's budget; the cap logs once when reached; the credits panel (single-account row and list rows) now always names the credential's current `identity_family`.
- Hermetic coverage: 10 tests in `identity_switch_test.go` (default-off, CLI→IDE, IDE→CLI, daily cap + day rollover, realm scope, no-authIndex, header coherence both directions, sticky-survives-refresh-merge, 6004 not a trigger, config knob). Full `-race` suite green.

## 0.9.74

### The retry ladder's transient classifier derives from conn-level (single source of truth)

Reproduced the 0.9.66-era CI flake live on 2026-10-26 (`-race` full suite, ~50% of runs): `TestBillingExhaustionTransportKeepsUnreachableWording` failed with the raw one-shot error `Post "http://127.0.0.1:PORT/...": http: server closed idle connection` — no retries, no `unreachable after N attempts` summary, no proxy hint.

- Root cause: two hand-kept transport-classification lists had drifted apart. 0.9.66 added `server closed idle connection` / `unexpected EOF` (and `tls:` broadly) to `isConnLevelBillingErr` — the demotion list — but never to `isTransientBillingErr`, so a pooled keep-alive conn the peer cut broke the retry loop at the transient check *before* the demote branch could run: the exact "escape as an unclassified one-shot error" class 0.9.66's comment promised to close. Same hole for truncated bodies (`unexpected EOF`) and every TLS-class death (cert verification, record-layer errors) — all demote-classified but not ladder-riding.
- Fix: `isTransientBillingErr` now derives from `isConnLevelBillingErr` (transient = 5xx ∪ conn-level ∪ DNS-miss/connection-refused), making "every connection-level death rides the ladder" structural instead of list-synced — the lists cannot drift again. `parse failed:` / `code=` / credential-rejection shapes stay terminal via the existing app-layer exclusion, including `parse failed: unexpected EOF` (server answered with garbage).
- Hermetic evidence: full `-race` suite went from intermittent FAIL to 3× consecutive green; new drift-guard block in `TestBillingErrClassifications` asserts every known conn-level family is also transient, and `TestIsTransientBillingErr_TransportClassified` pins the three field shapes (idle-conn cut, truncated body, x509 failure) as retryable.

## 0.9.73

### Account-restriction quarantine for 403+11140 (field report 2026-10-26)

Field report: a freshly initialized account answered every chat request with HTTP 403 `code=11140` "request illegal" / displayMsg "Your account has been restricted due to unusual activity"（账号存在异常行为）, wrapped as 500 by the host after retries. This is the upstream restricting the ACCOUNT — distinct from the bare-403 WAF shape (no envelope), the 11128 channel risk control (request-shaped), and credit exhaustion (credits can read healthy while chat refuses the account). The restriction itself only WorkBuddy/Tencent support can lift; the field-confirmed trigger family is unusual request patterns — most notably PARALLEL requests (magpie-community/plugins#339: an account restricted after two harnesses fired it concurrently survived on a fresh account once the parallelism stopped).

- New `account_restriction.go`: the 403+11140 classifier (JSON envelope first, substring fallback), an in-memory per-credential quarantine registry with an escalating ladder (first strike 1h → 2h → 4h → 8h cap), and a bilingual fast-fail copy. A healthy answer clears the entry on every executor success path, so a restriction lifted upstream self-heals without operator action.
- Wiring: all four chat executor paths note the restriction on >=400 (sync, stream-sync collector, async pump) and clear on success; both executors fast-fail quarantined credentials (plain error, no StatusCode — the host rotates, never reads it as quota); `handleSchedulerPick` skips quarantined candidates with an all-quarantined WARN defer.
- `translateChatUpstreamErrorFull` gives 11140 its own bilingual, actionable copy (names the code, the known triggers incl. the `account_max_concurrent: 1` advice for parallel-request prevention, the appeal path via the official client, and the auto-quarantine) instead of the bare `upstream 403: {json}`.
- The host-side `statusError{403}` credential cooldown is unchanged — the quarantine adds the longer plugin-side hold on top, the same two-layer shape as the 6004 model-scoped registry.

## 0.9.72

### Tool compaction covers the Responses-API tool shapes (issue #63)

Field report (2026-10-25, Codex Desktop on the Responses API): a session loading the full `mcp__rea` extension (170 functions, 322KB serialized tool definitions) failed 100% of the time with upstream 400 `code=11133` / `extError 400001` ("rejected by the model provider") on `kimi-k3.1-pro`, then tripped the 60s unknown-model cooldown into `503 auth_unavailable`.

- Root cause: `compactToolDescriptions` only understood the chat-completions nesting (`tool.function.description`). Two Responses-API shapes slid through UNCOMPRESSED — flat function tools (`{"type":"function","name":…,"description":…}`) and MCP namespace tools (`{"type":"namespace","name":"mcp__rea","description":…,"tools":[…]}`, which is where the 322KB actually lived). Every one of those tools hit the `continue`; the full payload reached Moonshot and its schema-size validation refused it.
- The cleaner now walks all three shapes recursively: nested, flat, and namespace (including namespace-inside-namespace), stripping only `description` fields once the serialized array crosses the existing 64KB threshold. Identity keys (`type`/`name`/`parameters`/nested `tools`) are untouched; under-limit payloads remain byte-for-byte unchanged.
- Pinned by `payload_compact_test.go`: five cases including the exact field-scale shape (170 flat functions inside one namespace + ordinary tools) asserting the post-compaction payload lands back under the limit.

## 0.9.71

### Opt-in credit guardrails for scheduler pick (PR #64, implements #61)

Two knobs, both default-off, both pure consumers of the existing credits cache (the #56-era standing constraint: guardrails add zero upstream calls):

- **`reserve_credits`** — skip a credential in scheduler pick once its cached remaining credits are <= the reserve, keeping the account usable for the official client / emergencies instead of drained to zero by routine pool traffic.
- **`daily_credits_cap`** — skip once same-day spend reaches the cap; spend = day-start remaining − current remaining from the same credits plane. Day boundary is the UTC+8 calendar day (upstream's 6004 reset copy phrases windows in Beijing time); counters are in-memory — estimative state, so a restart under-count errs toward firing later.
- Placement: the `handleSchedulerPick` skip — a guarded credential is simply not offered as a candidate (invisible to the host, no retry budget consumed), layering with #60's admission control (admission owns concurrency, guardrails own balance). When every candidate is guarded the pick defers to the host with a WARN log. Only effective with `scheduler_mode: credits`; README/config-description documents the limitation.
- Config shape: global defaults plus per-credential overrides (`reserve_credits` / `daily_credits_cap` numbers at the auth document top level; absent = inherit, 0 = disable for that credential). Pointer fields + `omitempty` keep nil vs explicit 0 distinct and preserve panel-set values across token refreshes.

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

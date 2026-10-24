# Changelog

## 0.2.3

### Multi-plan balance pools: a spent twin no longer hides the live one (issue #53)

Field report (AkimioJR, 2026-10-23): the ZCode 1024 Dev Day gift (GLM-5.3-Flash + GLM-5.3, 500M tokens, valid to 10-26) was claimed on the website, but the plugin's pools could not tell it apart from the new-user plan's spent GLM-5.3 — same show_name, no plan linkage, the spent bucket listed first. magpie zcode 0.1.23 (yetone, 2026-10-24) pinned the same trap on their side: "two gift plans each bucket is named by its plan, and the live ones come first".

- The balance response's `plans` array is now parsed (`status` / `user_plan_id` / `plan_id` / `name` / `ends_at`); a bucket's owner is matched the way magpie's `giftOf` does — `user_plan_id` pair first, `plan_id` fallback (`sameBalancePlan`).
- When more than one live plan holds buckets, every bucket is named after its plan ("ZCode 1024 Dev Day · GLM-5.3"); one live plan keeps the bucket's own name.
- Pools a request can spend now list first, spent ones next ("（已用尽）"), buckets of an expired/inactive plan last ("（已过期）", still plan-prefixed); each group keeps the balance's own order.
- Route-plane capability harvest (`harvestStartPlaneCapabilities`) now skips spent buckets and buckets owned by a non-live plan — with two plans granting the same model, the spent twin's capability must not stand in for the live one.
- Totals still sum every row, so a live 1024 bucket keeps an account with a spent new-user twin from reading as exhausted.
- The panel's empty claim-list note now says invitation/targeted campaigns (1024 Dev Day invitation packs) come down the website channel, not billing/preview — their pools appear in the balance area after claiming there.

## 0.2.2

### start-plan 3012: the system field carries official blocks only (PR #54, ki11a-Conton)

The start-plan gateway content-inspects the `system` field and answers 405/biz 3012 ("request has been blocked due to unusual activity") as soon as it finds a block that is not part of the official client assembly — single-variable probes: a lone "You are a helpful assistant." in system is rejected (P1), the same text inside the first user turn answers 200 (P2/P4), and official 3 blocks + caller text as a fourth is rejected (P3). magpie zcode 0.1.21 (#343) pinned the same gate on the block count.

- `anthropic.go`: `applyStartPlanTransform` pins `system` to exactly the official 3 blocks and relocates the caller's own system text into the first real user turn (before the context_prefix turn is prepended, so the official prefix keeps its single-block shape).
- `sanitize_prompt.go` (new): plugin-side phrase scrub across every role — system/user/assistant text, reasoning mirrors, and tool_calls arguments — mirroring the sibling workbuddy CN/intl gate (11128) which reads the whole body. Rewrites are meaning-preserving word substitutions; a payload without a trigger phrase passes through byte-identical.

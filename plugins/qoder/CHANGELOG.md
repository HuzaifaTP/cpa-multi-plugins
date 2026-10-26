# Changelog

## 0.8.69

### A oneOf of objects with no type gets type:object — kmodel 502 fix (magpie qoder 0.2.35, #378)

Absorbed from magpie-community/plugins `ebe3555` (qoder 0.2.35, 2026-10-25): Qoder CN's kmodel (Kimi K3.1 Pro) fails a chat whose tools hold a oneOf with no type — even when every branch is an object, directly or through a chain of local $refs (dsh's REA tools, a 502 here) — and takes the same request with `"type": "object"` beside each such oneOf (200 in a real dsh run). The same rule the workbuddy plugin absorbed from workbuddy 0.1.33.

- New `schema_typeunions.go`: `mendToolSchemasRaw` decodes the client's OpenAI tools payload, gives every untyped all-object oneOf inside each tool's parameters the type "object" (branches resolved through local `#/...` $ref chains, cycles broken, ≤16 hops; only schema keywords walked — SUB_ONE/SUB_LIST/SUB_MAP, depth ≤64), and re-encodes. Unions of other or mixed types, anyOf, and missing/external/circular $refs are left as they came. **Done on a decoded copy** — the caller's raw payload bytes are never touched (magpie's structuredClone discipline).
- Wired at the single tools-forwarding point in `buildQoderBody` (covers both execute and execute_stream paths); null / empty / non-array / nothing-to-mend payloads round-trip byte-for-byte.
- Tests (`schema_typeunions_test.go`): the issue's literal shapes — the minimal $ref → oneOf, the REA $ref-branch chain (with the lone-$ref-stays-untyped pin), the left-alone matrix (typed sibling / mixed / anyOf / missing / external / circular / examples — byte-for-byte round-trip), and the pass-through set. Full qoder suite green under `-race`.

// schema_typeunions.go — a oneOf of objects with no type gets type:object
// (magpie qoder 0.2.35, ebe3555, #378 — the same rule the workbuddy plugin
// absorbed from workbuddy 0.1.33).
//
// Qoder CN's kmodel (Kimi K3.1 Pro) fails a chat whose tools hold a oneOf
// with no type — even when every branch is an object, directly or through a
// chain of local $refs (dsh's REA tools, a 502 here) — and takes the same
// request with "type": "object" beside each such oneOf (200 in a real dsh
// run). Other unions, anyOf, and missing, external or circular $refs are
// left alone. The mending is done on a DECODED COPY of the client's tools
// payload — the caller's schema bytes are never touched.
package main

import (
	"encoding/json"
	"strings"
)

// typeUnionSubOne / typeUnionSubList / typeUnionSubMap are the schema-keyword
// walk sets (magpie SUB_ONE / SUB_LIST / SUB_MAP, byte-aligned): only these
// keys are descended, so examples / default / const payloads are never
// touched.
var typeUnionSubOne = []string{"items", "additionalItems", "unevaluatedItems", "contains", "not", "if", "then", "else", "propertyNames", "additionalProperties", "unevaluatedProperties"}
var typeUnionSubList = []string{"anyOf", "oneOf", "allOf", "prefixItems"}
var typeUnionSubMap = []string{"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"}

// mendToolSchemasRaw decodes the client's OpenAI tools payload, gives every
// untyped all-object oneOf inside each tool's parameters the type "object",
// and re-encodes. Unparseable / empty payloads round-trip byte-for-byte.
func mendToolSchemasRaw(tools json.RawMessage) json.RawMessage {
	if len(tools) == 0 || string(tools) == "null" {
		return tools
	}
	var arr []any
	if err := json.Unmarshal(tools, &arr); err != nil {
		return tools
	}
	changed := false
	for _, t := range arr {
		tool, ok := t.(map[string]any)
		if !ok {
			continue
		}
		fn, ok := tool["function"].(map[string]any)
		if !ok {
			continue
		}
		if ps, ok := fn["parameters"].(map[string]any); ok {
			changed = schemaTypeUnions(ps, ps, 0) || changed
		}
	}
	if !changed {
		return tools
	}
	out, err := json.Marshal(arr)
	if err != nil {
		return tools
	}
	return out
}

// schemaTypeUnions gives a oneOf with no sibling type the type "object" when
// every branch is a typed object, itself or through a chain of local $refs
// (magpie typedUnions). A union of other or mixed types, an anyOf, and a $ref
// that is missing, external or circular are left as they came. Only schema
// keywords are walked, depth-capped at 64. Reports whether anything changed.
func schemaTypeUnions(s, root map[string]any, depth int) bool {
	if s == nil || depth > 64 {
		return false
	}
	changed := false
	if _, hasType := s["type"]; !hasType {
		if oneOf, ok := s["oneOf"].([]any); ok && len(oneOf) > 0 {
			allObject := true
			for _, b := range oneOf {
				if !typeUnionObjectBranch(root, b, nil) {
					allObject = false
					break
				}
			}
			if allObject {
				s["type"] = "object"
				changed = true
			}
		}
	}
	for _, k := range typeUnionSubOne {
		if sub, ok := s[k].(map[string]any); ok {
			changed = schemaTypeUnions(sub, root, depth+1) || changed
		}
	}
	for _, k := range typeUnionSubList {
		if list, ok := s[k].([]any); ok {
			for _, v := range list {
				if sub, ok := v.(map[string]any); ok {
					changed = schemaTypeUnions(sub, root, depth+1) || changed
				}
			}
		}
	}
	for _, k := range typeUnionSubMap {
		m, ok := s[k].(map[string]any)
		if !ok {
			continue
		}
		for _, v := range m {
			if sub, ok := v.(map[string]any); ok {
				changed = schemaTypeUnions(sub, root, depth+1) || changed
			}
		}
	}
	return changed
}

// typeUnionObjectBranch says whether b is a typed object, itself or where its
// local $refs lead (magpie objectBranch): a $ref seen before on the way is a
// cycle, and not; more than 16 hops is not.
func typeUnionObjectBranch(root map[string]any, b any, seen []string) bool {
	branch, ok := b.(map[string]any)
	if !ok {
		return false
	}
	if t, has := branch["type"]; has {
		s, _ := t.(string)
		return s == "object"
	}
	ref, _ := branch["$ref"].(string)
	if ref == "" || len(seen) > 16 {
		return false
	}
	for _, s := range seen {
		if s == ref {
			return false
		}
	}
	target := typeUnionLocalRef(root, ref)
	if target == nil {
		return false
	}
	next := make([]string, len(seen), len(seen)+1)
	copy(next, seen)
	next = append(next, ref)
	return typeUnionObjectBranch(root, target, next)
}

// typeUnionLocalRef resolves a local "#/..." JSON pointer in root (with ~0 / ~1
// unescaping, magpie target()); a non-local ref or a missing target returns nil.
func typeUnionLocalRef(root map[string]any, ref string) map[string]any {
	if !strings.HasPrefix(ref, "#/") {
		return nil
	}
	var at any = root
	for _, seg := range strings.Split(ref[2:], "/") {
		seg = strings.ReplaceAll(seg, "~1", "/")
		seg = strings.ReplaceAll(seg, "~0", "~")
		m, ok := at.(map[string]any)
		if !ok {
			return nil
		}
		next, ok := m[seg]
		if !ok {
			return nil
		}
		at = next
	}
	target, ok := at.(map[string]any)
	if !ok {
		return nil
	}
	return target
}

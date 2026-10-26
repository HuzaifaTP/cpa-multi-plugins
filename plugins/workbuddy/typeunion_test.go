package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

// typeunion_test.go — the magpie workbuddy 0.1.33 absorption (#378):
// kimi-k3.1-pro answers 400 "Invalid request parameters" to a oneOf with no
// type even when every branch is an object; the same body with
// "type": "object" beside the oneOf gets 200 (three real dsh runs, all 198
// tools). The literal parameter shapes below are the issue's own, ported
// from magpie's tools.test.mjs.

// typeUnionAB is the issue's two-object union.
var typeUnionAB = []any{
	map[string]any{"type": "object", "properties": map[string]any{"mode": map[string]any{"type": "string", "const": "a"}}},
	map[string]any{"type": "object", "properties": map[string]any{"mode": map[string]any{"type": "string", "const": "b"}}},
}

func typeUnionMustObj(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

// TestTypeUnionRefTargetOneOfTypedObject — the pipeline mends a tool whose
// parameter holds a $ref whose target is an untyped oneOf of objects, and
// touches nothing else in the schema.
func TestTypeUnionRefTargetOneOfTypedObject(t *testing.T) {
	body := []byte(`{"model":"kimi-k3.1-pro","messages":[{"role":"user","content":"Do not call tools. Reply exactly OK."}],"tools":[{"type":"function","function":{"name":"probe","description":"Diagnostic placeholder.","parameters":{"type":"object","properties":{"x":{"$ref":"#/$defs/X"}},"$defs":{"X":{"oneOf":` + unionABJSON() + `}}}}}]}`)
	out := prepareUpstreamBody(body, body, nil, "kimi-k3.1-pro")
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("unmarshal out: %v", err)
	}
	tools := obj["tools"].([]any)
	fn := tools[0].(map[string]any)["function"].(map[string]any)
	ps := fn["parameters"].(map[string]any)
	defs := ps["$defs"].(map[string]any)
	x := defs["X"].(map[string]any)
	if x["type"] != "object" {
		t.Fatalf("the $ref's oneOf target must gain type:object, got %v", x["type"])
	}
	if _, ok := x["oneOf"]; !ok {
		t.Fatal("the oneOf itself must survive")
	}
	if _, hasType := ps["properties"].(map[string]any)["x"].(map[string]any)["type"]; hasType {
		t.Fatal("the property's $ref must NOT gain a type of its own")
	}
}

// TestTypeUnionNestedOneOfAndRefBranches — a oneOf inside a $ref's target,
// and a oneOf whose branches are themselves $refs to objects (the REA
// dsh-tools shape), both get type:object; a lone $ref outside any oneOf
// stays untyped.
func TestTypeUnionNestedOneOfAndRefBranches(t *testing.T) {
	ps := map[string]any{
		"type":       "object",
		"properties": map[string]any{"x": map[string]any{"$ref": "#/$defs/X"}},
		"$defs": map[string]any{
			"X": map[string]any{"type": "object", "properties": map[string]any{"y": map[string]any{"oneOf": typeUnionAB}}, "required": []any{"y"}},
		},
	}
	root := typeUnionMustObj(t, ps)
	if !schemaTypeUnions(root, root, 0) {
		t.Fatal("the nested oneOf must be mended")
	}
	x := root["$defs"].(map[string]any)["X"].(map[string]any)
	y := x["properties"].(map[string]any)["y"].(map[string]any)
	if y["type"] != "object" {
		t.Fatalf("the oneOf inside the $ref's target must gain type:object, got %v", y["type"])
	}

	refs := typeUnionMustObj(t, map[string]any{
		"type":       "object",
		"properties": map[string]any{"s": map[string]any{"$ref": "#/$defs/__schema0"}},
		"$defs": map[string]any{
			"__schema0": map[string]any{"oneOf": []any{map[string]any{"$ref": "#/$defs/__schema1"}, map[string]any{"$ref": "#/$defs/__schema3"}}},
			"__schema1": map[string]any{"type": "object", "properties": map[string]any{"launch": map[string]any{"type": "boolean"}}},
			"__schema2": map[string]any{"$ref": "#/$defs/__schema1"},
			"__schema3": map[string]any{"$ref": "#/$defs/__schema4"},
			"__schema4": map[string]any{"type": "object", "properties": map[string]any{"connect": map[string]any{"type": "string"}}},
		},
	})
	if !schemaTypeUnions(refs, refs, 0) {
		t.Fatal("the $ref-branch oneOf must be mended")
	}
	defs := refs["$defs"].(map[string]any)
	if defs["__schema0"].(map[string]any)["type"] != "object" {
		t.Fatal("the ref-branch oneOf must gain type:object")
	}
	if _, hasType := defs["__schema2"].(map[string]any)["type"]; hasType {
		t.Fatal("a lone $ref outside any oneOf must stay untyped")
	}
}

// TestTypeUnionLeavesAlone — a typed sibling, a mixed union, an anyOf, a
// missing / external / circular $ref and examples payloads are all left as
// they came (byte-for-byte unchanged, false returned).
func TestTypeUnionLeavesAlone(t *testing.T) {
	ps := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"typed":    map[string]any{"type": "object", "oneOf": typeUnionAB},
			"mixed":    map[string]any{"oneOf": []any{typeUnionAB[0], map[string]any{"type": "string"}}},
			"any":      map[string]any{"anyOf": typeUnionAB},
			"missing":  map[string]any{"oneOf": []any{typeUnionAB[0], map[string]any{"$ref": "#/$defs/Nope"}}},
			"external": map[string]any{"oneOf": []any{typeUnionAB[0], map[string]any{"$ref": "other.json#/X"}}},
			"loop":     map[string]any{"oneOf": []any{typeUnionAB[0], map[string]any{"$ref": "#/$defs/A"}}},
			"examples": map[string]any{"type": "array", "examples": []any{map[string]any{"oneOf": typeUnionAB}}},
		},
		"$defs": map[string]any{
			"A": map[string]any{"$ref": "#/$defs/B"},
			"B": map[string]any{"$ref": "#/$defs/A"},
		},
	}
	before := typeUnionMustObj(t, ps)
	beforeRaw, err := json.Marshal(before)
	if err != nil {
		t.Fatalf("marshal before: %v", err)
	}
	if schemaTypeUnions(before, before, 0) {
		t.Fatal("nothing here may be mended")
	}
	afterRaw, err := json.Marshal(before)
	if err != nil {
		t.Fatalf("marshal after: %v", err)
	}
	if !reflect.DeepEqual(beforeRaw, afterRaw) {
		t.Fatal("the schema must be byte-for-byte unchanged")
	}
}

// TestTypeUnionAllThreeToolShapes — the 0.9.72 compaction discipline: nested
// chat-completions, flat Responses-API and MCP-namespace tools are all
// mended.
func TestTypeUnionAllThreeToolShapes(t *testing.T) {
	nested := map[string]any{"tools": []any{map[string]any{
		"type":     "function",
		"function": map[string]any{"name": "t1", "parameters": map[string]any{"properties": map[string]any{"u": map[string]any{"oneOf": typeUnionAB}}}},
	}}}
	if !typeUnionToolSchemas(typeUnionMustObj(t, nested)) {
		t.Fatal("nested shape must be mended")
	}
	flat := map[string]any{"tools": []any{map[string]any{
		"type": "function", "name": "t2",
		"parameters": map[string]any{"properties": map[string]any{"u": map[string]any{"oneOf": typeUnionAB}}},
	}}}
	if !typeUnionToolSchemas(typeUnionMustObj(t, flat)) {
		t.Fatal("flat Responses-API shape must be mended")
	}
	namespace := map[string]any{"tools": []any{map[string]any{
		"type": "namespace", "name": "mcp__rea",
		"tools": []any{map[string]any{
			"type": "function", "name": "t3",
			"parameters": map[string]any{"properties": map[string]any{"u": map[string]any{"oneOf": typeUnionAB}}},
		}},
	}}}
	if !typeUnionToolSchemas(typeUnionMustObj(t, namespace)) {
		t.Fatal("MCP namespace shape must be mended")
	}
}

// unionABJSON renders the issue's two-object union as raw JSON for the
// pipeline test's literal body.
func unionABJSON() string {
	raw, _ := json.Marshal(typeUnionAB)
	return string(raw)
}

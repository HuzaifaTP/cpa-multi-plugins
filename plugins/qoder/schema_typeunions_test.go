package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

// schema_typeunions_test.go — the magpie qoder 0.2.35 absorption (#378),
// same rule as the workbuddy plugin's 0.9.76: kmodel (Kimi K3.1 Pro) 502s a
// chat whose tools hold a oneOf with no type even when every branch is an
// object (dsh's REA tools); type:object beside each such oneOf gets 200.
// The literal shapes below are the issue's own, ported from magpie's
// schema.test.mjs.

var typeUnionAB = []any{
	map[string]any{"type": "object", "properties": map[string]any{"mode": map[string]any{"type": "string", "const": "a"}}},
	map[string]any{"type": "object", "properties": map[string]any{"mode": map[string]any{"type": "string", "const": "b"}}},
}

// TestMendToolSchemasRawRefTarget — a $ref whose target is an untyped oneOf
// of objects gains type:object; nothing else in the payload moves.
func TestMendToolSchemasRawRefTarget(t *testing.T) {
	tools := json.RawMessage(`[{"type":"function","function":{"name":"probe","parameters":{"type":"object","properties":{"x":{"$ref":"#/$defs/X"}},"$defs":{"X":{"oneOf":[{"type":"object","properties":{"mode":{"type":"string","const":"a"}}},{"type":"object","properties":{"mode":{"type":"string","const":"b"}}}]}}}}}]`)
	out := mendToolSchemasRaw(tools)
	var arr []any
	if err := json.Unmarshal(out, &arr); err != nil {
		t.Fatalf("unmarshal out: %v", err)
	}
	ps := arr[0].(map[string]any)["function"].(map[string]any)["parameters"].(map[string]any)
	x := ps["$defs"].(map[string]any)["X"].(map[string]any)
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

// TestMendToolSchemasRawRefBranches — the REA $ref-branch shape: a oneOf
// whose branches are $refs to objects (through a chain) gains type:object;
// a lone $ref outside any oneOf stays untyped.
func TestMendToolSchemasRawRefBranches(t *testing.T) {
	tools := json.RawMessage(`[{"type":"function","function":{"name":"rea","parameters":{"type":"object","properties":{"s":{"$ref":"#/$defs/__schema0"}},"$defs":{"__schema0":{"oneOf":[{"$ref":"#/$defs/__schema1"},{"$ref":"#/$defs/__schema3"}]},"__schema1":{"type":"object","properties":{"launch":{"type":"boolean"}}},"__schema2":{"$ref":"#/$defs/__schema1"},"__schema3":{"$ref":"#/$defs/__schema4"},"__schema4":{"type":"object","properties":{"connect":{"type":"string"}}}}}}}]`)
	out := mendToolSchemasRaw(tools)
	var arr []any
	if err := json.Unmarshal(out, &arr); err != nil {
		t.Fatalf("unmarshal out: %v", err)
	}
	defs := arr[0].(map[string]any)["function"].(map[string]any)["parameters"].(map[string]any)["$defs"].(map[string]any)
	if defs["__schema0"].(map[string]any)["type"] != "object" {
		t.Fatal("the ref-branch oneOf must gain type:object")
	}
	if _, hasType := defs["__schema2"].(map[string]any)["type"]; hasType {
		t.Fatal("a lone $ref outside any oneOf must stay untyped")
	}
}

// TestMendToolSchemasRawLeavesAlone — typed siblings, mixed unions, anyOf,
// missing / external / circular $refs and examples payloads round-trip
// byte-for-byte unchanged.
func TestMendToolSchemasRawLeavesAlone(t *testing.T) {
	tools := json.RawMessage(`[{"type":"function","function":{"name":"matrix","parameters":{"type":"object","properties":{"typed":{"type":"object","oneOf":[{"type":"object"},{"type":"object"}]},"mixed":{"oneOf":[{"type":"object"},{"type":"string"}]},"any":{"anyOf":[{"type":"object"},{"type":"object"}]},"missing":{"oneOf":[{"type":"object"},{"$ref":"#/$defs/Nope"}]},"external":{"oneOf":[{"type":"object"},{"$ref":"other.json#/X"}]},"loop":{"oneOf":[{"type":"object"},{"$ref":"#/$defs/A"}]},"examples":{"type":"array","examples":[{"oneOf":[{"type":"object"},{"type":"object"}]}]}},"$defs":{"A":{"$ref":"#/$defs/B"},"B":{"$ref":"#/$defs/A"}}}}}]`)
	out := mendToolSchemasRaw(tools)
	if !reflect.DeepEqual([]byte(tools), []byte(out)) {
		t.Fatalf("the left-alone payload must round-trip byte-for-byte:\n in: %s\nout: %s", string(tools), string(out))
	}
}

// TestMendToolSchemasRawPassThrough — null, empty, non-array and
// nothing-to-mend payloads round-trip untouched (same slice).
func TestMendToolSchemasRawPassThrough(t *testing.T) {
	for _, raw := range []json.RawMessage{
		json.RawMessage(`null`),
		json.RawMessage(``),
		json.RawMessage(`{"not":"an array"}`),
		json.RawMessage(`[]`),
		json.RawMessage(`[{"type":"function","function":{"name":"t","parameters":{"type":"object","properties":{"a":{"type":"string"}}}}}]`),
	} {
		out := mendToolSchemasRaw(raw)
		if string(out) != string(raw) {
			t.Fatalf("payload %s must round-trip untouched, got %s", string(raw), string(out))
		}
	}
}

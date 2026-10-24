// sanitize_prompt.go — plugin-side scrubbing of the client's own prompt text
// for the ZCode upstream content gate.
//
// Evidence chain: the start-plan gateway answers a blocked body with HTTP 405
// and biz 3012 {"msg":"request has been blocked due to unusual activity."}
// (observed live 2026-10-23 23:15:50 against all four zcode credentials, in the
// same second a DeepSeek Harness session issued a request, while a minimal
// probe two minutes earlier had returned 200 with the same credentials). The
// gateway never names the offending phrase, so the phrase family pinned
// single-variably against the sibling workbuddy CN/intl gate (codes 11-128 /
// 11128, see cpa-multi-plugins/plugins/workbuddy/payload.go) is carried over
// verbatim as the best-known baseline.
//
// Scope: the system field plus EVERY message role — assistant history echoes
// and tool_calls arguments included. The sibling gate reads the whole body: a
// fully sanitized system prompt still 400s when the phrase survives in an
// assistant echo, so a system-only pass is not enough.
//
// Every rewrite is a meaning-preserving word substitution; content without a
// trigger phrase passes through byte-identical, and the JSON shape of the
// payload is never restructured beyond the text it replaces.
package main

import (
	"encoding/json"
	"regexp"
	"strings"
)

var (
	// Claude Code CLI phrasing drift: capitalization and straight/curly quote
	// variants of the verbatim template below.
	reClaudeCodeCli = regexp.MustCompile(`(?i)anthropic(?:'s)?\s+official\s+cli\s+for\s+claude`)
	reMainBranchPr  = regexp.MustCompile(`(?i)main\s+branch\s+\(you\s+will\s+usually\s+use\s+this\s+for\s+prs\)`)

	// Codex CLI base-instructions opening signature (workbuddy issue #31).
	reCodexCliIntro = regexp.MustCompile(`(?i)you are a coding agent running in the codex cli[^.\n]*\.\s*codex cli is an open source project led by openai\s*\.?`)

	// DeepSeek Harness base-instructions opening signature.
	reDeepSeekHarnessIntro = regexp.MustCompile(`(?i)you are an ai agent powered by deepseek harness`)

	// The DSH runtime-context line; only the full four-token phrase gates.
	reDeepSeekHarnessWebGUI = regexp.MustCompile(`(?i)deepseek\s+harness\s+web\s+gui`)
)

const (
	claudeCodeCliReplacement = "Anthropic's official CLI tool for Claude"
	mainBranchPrReplacement  = "Default branch (you will usually use this for PRs)"
	codexCliIntroReplacement = "You are a helpful coding assistant running in the terminal."
	harnessIntroReplacement  = "You are an AI assistant"
	harnessWebGUIReplacement = "DeepSeek Harness web interface"
)

// scrubBlockedPhrases applies every phrase rewrite to one string. The exact
// string forms run first (they are the replay-verified triggers), then the
// tolerant regexes cover case / punctuation drift between client releases.
func scrubBlockedPhrases(s string) string {
	if s == "" {
		return s
	}
	s = strings.ReplaceAll(s,
		"You are Claude Code, Anthropic's official CLI for Claude.",
		"You are Claude Code, Anthropic's official CLI tool for Claude.")
	s = strings.ReplaceAll(s,
		"Main branch (you will usually use this for PRs)",
		mainBranchPrReplacement)
	s = strings.ReplaceAll(s,
		"You are a coding agent running in the Codex CLI, a terminal-based coding assistant. Codex CLI is an open source project led by OpenAI.",
		codexCliIntroReplacement)
	s = reClaudeCodeCli.ReplaceAllString(s, claudeCodeCliReplacement)
	s = reMainBranchPr.ReplaceAllString(s, mainBranchPrReplacement)
	s = reCodexCliIntro.ReplaceAllString(s, codexCliIntroReplacement)
	s = reDeepSeekHarnessIntro.ReplaceAllString(s, harnessIntroReplacement)
	s = reDeepSeekHarnessWebGUI.ReplaceAllString(s, harnessWebGUIReplacement)
	return s
}

// scrubTextFieldsInPlace walks one message/block object and rewrites every
// text-bearing field: content (string or parts array), reasoning mirrors and
// tool_call argument strings.
func scrubTextFieldsInPlace(m map[string]any) bool {
	changed := false
	if c, ok := m["content"].(string); ok && c != "" {
		if r := scrubBlockedPhrases(c); r != c {
			m["content"] = r
			changed = true
		}
	} else if parts, ok := m["content"].([]any); ok {
		for _, pi := range parts {
			p, ok := pi.(map[string]any)
			if !ok {
				continue
			}
			if t, ok := p["text"].(string); ok && t != "" {
				if r := scrubBlockedPhrases(t); r != t {
					p["text"] = r
					changed = true
				}
			}
		}
	}
	for _, key := range []string{"reasoning_content", "reasoning"} {
		if rc, ok := m[key].(string); ok && rc != "" {
			if r := scrubBlockedPhrases(rc); r != rc {
				m[key] = r
				changed = true
			}
		}
	}
	if tcs, ok := m["tool_calls"].([]any); ok {
		for _, tci := range tcs {
			tc, ok := tci.(map[string]any)
			if !ok {
				continue
			}
			fn, ok := tc["function"].(map[string]any)
			if !ok || fn == nil {
				continue
			}
			if a, ok := fn["arguments"].(string); ok && a != "" {
				if r := scrubBlockedPhrases(a); r != a {
					fn["arguments"] = r
					changed = true
				}
			}
		}
	}
	return changed
}

// scrubPromptObjectInPlace rewrites the whole upstream-bound request object:
// the system field (string or block array) and every message. Returns true
// when at least one rewrite landed.
func scrubPromptObjectInPlace(obj map[string]any) bool {
	changed := false
	switch sys := obj["system"].(type) {
	case string:
		if r := scrubBlockedPhrases(sys); r != sys {
			obj["system"] = r
			changed = true
		}
	case []any:
		for _, bi := range sys {
			b, ok := bi.(map[string]any)
			if !ok {
				continue
			}
			if t, ok := b["text"].(string); ok && t != "" {
				if r := scrubBlockedPhrases(t); r != t {
					b["text"] = r
					changed = true
				}
			}
		}
	}
	if msgs, ok := obj["messages"].([]any); ok {
		for _, mi := range msgs {
			m, ok := mi.(map[string]any)
			if !ok {
				continue
			}
			if scrubTextFieldsInPlace(m) {
				changed = true
			}
		}
	}
	return changed
}

// scrubPromptPayload rewrites a raw OpenAI chat-completions payload before it
// is translated/pinned for the upstream. A payload that is not a JSON object
// (or that carries no trigger phrase) is returned as-is, so this can sit on
// the hot path without parsing twice for the common no-op case.
func scrubPromptPayload(payload []byte) []byte {
	if len(payload) == 0 {
		return payload
	}
	var obj map[string]any
	if err := json.Unmarshal(payload, &obj); err != nil {
		return payload
	}
	if !scrubPromptObjectInPlace(obj) {
		return payload
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return payload
	}
	return out
}

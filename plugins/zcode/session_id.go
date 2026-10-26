// session_id.go — a stable conversation UUID for x-session-id
// (magpie-community/plugins 2b56b3b, #388: BigModel keys its prompt cache on
// the session a request names; a fresh UUID per request never hits — the
// author's numbers: 3/12 turns before, 24/24 after).
//
// ZCode's client names every request's conversation in x-session-id: a bare
// lower-case UUID, the same on each turn. Our host's ExecutorRequest carries
// no session context, so the conversation's identity is its FIRST USER
// MESSAGE: within one conversation the first user message never changes, so
// the derived UUID is the same on every turn; a different conversation gets a
// different one. With no user message (or an unreadable body), a UUID made
// from the device mid — magpie's own fallback ("with no session, a UUID made
// from the device"), stable per account.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// uuidFromHash renders 32 bytes of hash input as a lower-case UUIDv4-shaped
// string (8-4-4-4-12, version 4 / variant bits set — the shape the official
// client's crypto.randomUUID() produces and the gateway expects).
func uuidFromHash(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
	}
	raw := h.Sum(nil)
	raw[6] = (raw[6] & 0x0f) | 0x40 // version 4
	raw[8] = (raw[8] & 0x3f) | 0x80 // variant 10
	hexed := hex.EncodeToString(raw[:16])
	return hexed[0:8] + "-" + hexed[8:12] + "-" + hexed[12:16] + "-" + hexed[16:20] + "-" + hexed[20:32]
}

// conversationSessionID derives the stable conversation UUID for one chat
// payload: the first user message's text when one exists (the same
// conversation keeps the same first user message across turns), else the
// device-derived UUID.
func conversationSessionID(payload []byte, deviceMid string) string {
	if sid, ok := firstUserMessageKey(payload); ok {
		return uuidFromHash("zcode-session", sid)
	}
	return uuidFromHash("zcode-session-device", deviceMid)
}

// firstUserMessageKey extracts the stable key of the payload's first user
// message: its text content (plain string or the concatenated text parts).
func firstUserMessageKey(payload []byte) (string, bool) {
	if len(payload) == 0 {
		return "", false
	}
	var probe struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil || len(probe.Messages) == 0 {
		return "", false
	}
	for _, m := range probe.Messages {
		if m.Role != "user" {
			continue
		}
		if text, ok := textKeyOfContent(m.Content); ok && text != "" {
			return text, true
		}
		// A user message whose text is unreadable still identifies the
		// conversation as well as anything else we have — hash the raw bytes.
		return string(m.Content), true
	}
	return "", false
}

// textKeyOfContent reads a message content's text: a plain string as-is, or
// the concatenation of an OpenAI parts array's text parts.
func textKeyOfContent(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, true
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err == nil {
		out := ""
		for _, p := range parts {
			if p.Type == "text" {
				out += p.Text
			}
		}
		return out, true
	}
	return "", false
}

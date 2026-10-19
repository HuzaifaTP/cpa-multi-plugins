// Package upstream implements Trae Intl Web SOLO remote protocol.
//
// Trae Intl 走 Web SOLO remote agent 协议，与 CN 的 IDE SOLO 协议完全不同：
//
//	CN (trae-api-cn.mchost.guru): POST /api/agent/v3/llm_utils_chat + function=solo_work_lite
//	Intl (core-normal.trae.ai): POST /chat_sessions → GET /chat_sessions/{id}/events SSE
//
// Auth: Cloud-IDE-JWT (RS256, ~14d), obtained via OAuth on api.marscode.com.
//
// Based on OmniRoute/open-sse/executors/trae.ts (MIT, by diegosouzapw).
// Translated from TypeScript to Go.
package upstream

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// Web SOLO remote endpoints
	EpChatSessions = "/chat_sessions"
	EpChatEvents   = "/chat_sessions/%s/events"

	// OAuth endpoints (on api.marscode.com)
	EpLoginGuidance = "/cloudide/api/v3/trae/GetLoginGuidance"
	EpExchange      = "/cloudide/api/v3/trae/oauth/ExchangeToken"
	EpUserInfo      = "/cloudide/api/v3/trae/GetUserInfo"

	// Intl v1 pay endpoints (CN uses v2)
	EpPayStatus = "/trae/api/v1/pay/ide_user_pay_status"
	EpEntUsage  = "/trae/api/v1/pay/ide_user_ent_usage"

	// Models list (GET, returns available models for selection)
	EpModels = "/models"

	// EpChatSessionMessages appends a further user turn to an existing session.
	EpChatSessionMessages = "/chat_sessions/%s/messages"

	// Stream timeout (5 minutes for long reasoning).
	StreamTimeout = 5 * time.Minute

	// Default base URL (Web SOLO remote API)
	DefaultBase = "https://core-normal.trae.ai/api/remote/v1"

	// DefaultWebOrigin is the web client origin sent as Origin/Referer on
	// every chat-session call. Trae's web client moved from solo.trae.ai to
	// work.trae.ai (SOLO now lives under the TraeWork product surface) and
	// the backend validates Origin/Referer against the JWT session's real
	// origin — a stale value yields a clean 401 even with a fresh token
	// (same root cause as OmniRoute #12190, 2026-09 confirmed). Overridable
	// per account via Auth.RefererOrigin for credentials still bound to
	// the legacy host.
	DefaultWebOrigin = "https://work.trae.ai"
)

// Auth holds Trae Intl credentials.
// Compatible with trae-cn Auth shape (same OAuth flow, different host).
type Auth struct {
	AccessToken  string // Cloud-IDE-JWT
	RefreshToken string
	ExpiresAt    int64  // Unix seconds
	APIHost      string // OAuth host (api.marscode.com)
	Domain       string // "trae.ai"
	UID          string
	EnterpriseID string
	Nickname     string

	// Web SOLO remote-specific identity fields (from providerSpecificData).
	WebID        string
	BizUserID    string
	UserUniqueID string
	UserIdentity string // "Free" / "Pro" / etc.
	Scope        string // "marscode-us" / "marscode"
	Tenant       string // "marscode"
	Region       string // "US-East"
	AppLanguage  string // "en"
	AppVersion   string // "1.0.0.1229"

	// RefererOrigin optionally overrides the Origin/Referer web origin
	// (DefaultWebOrigin when empty). Providers mirroring an auth file that
	// was captured against the legacy solo.trae.ai host can pin it here.
	RefererOrigin string

	// Device identity (v0.12.72, issue #29 field report): the OAuth login
	// binds a server-side device (newDeviceID/newMachineID in the login
	// verification URI) but the persisted auth JSON omitted both keys —
	// device_id_set surfaced false and X-Device-Id went empty on the intl
	// pay face. Carried on Auth so refresh re-persists them verbatim.
	DeviceID  string
	MachineID string

	// Device key material (P-256 SPKI/PKCS#8 PEM, devicekey.go) — preserved
	// across refresh so the binding proof stays with the account.
	DevicePublicKey  string
	DevicePrivateKey string

	// Timezone optionally sets the x-trae-user-timezone header (OmniRoute
	// #13255 forwards psd.userTimezone alongside the Referer/Origin refresh
	// — both halves together stopped imported connections failing with 401).
	// Empty = header omitted, matching upstream's conditional send.
	Timezone string
}

// Client is the Trae Intl upstream client.
type Client struct {
	HTTP      *http.Client
	BaseURL   string // https://core-normal.trae.ai/api/remote/v1
	OAuthHost string // https://api.marscode.com
	ClientID  string // ono9krqynydwx5
}

// New creates a default client.
func New() *Client {
	tr := &http.Transport{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: StreamTimeout,
	}
	return &Client{
		HTTP:      &http.Client{Timeout: StreamTimeout, Transport: tr},
		BaseURL:   DefaultBase,
		OAuthHost: "https://api.marscode.com",
		ClientID:  "ono9krqynydwx5",
	}
}

// buildHeaders constructs the Web SOLO remote headers.
//
// v0.12.47: Origin/Referer now default to https://work.trae.ai — the backend
// rejects chat-session calls whose origin does not match the JWT session's
// real origin with a bare 401 (checkin/billing endpoints do not validate
// them, which is why check-in kept working while chat broke).
// v0.12.48: forward x-trae-user-timezone when the auth file carries one —
// OmniRoute #13255 ships the timezone header as the second half of the 401
// fix ("refresh Trae's stale Referer/Origin and forward user timezone").
func buildHeaders(a *Auth) http.Header {
	h := http.Header{}
	h.Set("Authorization", "Cloud-IDE-JWT "+a.AccessToken)
	h.Set("Content-Type", "application/json")
	h.Set("X-Trae-Client-Type", "web")
	h.Set("X-Preferenced-Language", nonEmpty(a.AppLanguage, "en"))
	h.Set("x-user-region", nonEmpty(a.Region, "US"))
	origin := strings.TrimRight(nonEmpty(a.RefererOrigin, DefaultWebOrigin), "/")
	h.Set("Origin", origin)
	h.Set("Referer", origin+"/")
	if tz := strings.TrimSpace(a.Timezone); tz != "" {
		h.Set("x-trae-user-timezone", tz)
	}
	h.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36")
	return h
}

// resolveMode translates model id to SOLO remote mode/strategy/modelName.
//
//	"work" / "auto-work" / "solo-work" → mode=work, strategy=auto, modelName=""
//	"auto" / ""                          → mode=code, strategy=auto, modelName=""
//	other (e.g. "gpt-5.2")              → mode=code, strategy=manual, modelName=model
func resolveMode(model string) (mode, strategy, modelName string) {
	m := strings.ToLower(strings.TrimSpace(model))
	if m == "work" || m == "auto-work" || m == "solo-work" {
		return "work", "auto", ""
	}
	if m == "" || m == "auto" {
		return "code", "auto", ""
	}
	// v0.12.37: strip the client-facing "-intl" namespace suffix
	// (intl_main.go appends it to every advertised id). The upstream session
	// API only knows the bare model name — a suffixed id sent verbatim as
	// model_name creates the session with an unknown model.
	return "code", "manual", strings.TrimSuffix(strings.TrimSpace(model), "-intl")
}

// commonParams builds the common_params JSON string for chat_sessions.
func commonParams(a *Auth, mode string) string {
	cp := map[string]any{
		"language":        "en-us",
		"app_language":    nonEmpty(a.AppLanguage, "en"),
		"quality":         "stable",
		"app_version":     nonEmpty(a.AppVersion, "1.0.0.1229"),
		"web_id":          a.WebID,
		"user_identity":   nonEmpty(a.UserIdentity, "Free"),
		"is_freshman":     "0",
		"biz_user_id":     a.BizUserID,
		"user_unique_id":  a.UserUniqueID,
		"scope":           nonEmpty(a.Scope, "marscode-us"),
		"tenant":          nonEmpty(a.Tenant, "marscode"),
		"region":          nonEmpty(a.Region, "US-East"),
		"aiRegion":        nonEmpty(a.Region, "US-East"),
		"is_privacy_mode": 0,
		"privacy_mode":    "off",
		"solo_chat_mode":  mode,
	}
	raw, _ := json.Marshal(cp)
	return string(raw)
}

// flattenQuery converts OpenAI messages array to Trae's `query` format:
//
//	JSON.stringify([{ type: "text", data: { content: <flattened text> } }])
//
// where <flattened text> joins all messages with role prefixes:
//
//	[System]\n<content>
//	[Assistant]\n<content>
//	<user content>  (no prefix)
func flattenQuery(messages []map[string]any) string {
	var parts []string
	for _, m := range messages {
		role, _ := m["role"].(string)
		content := ""
		switch c := m["content"].(type) {
		case string:
			content = c
		case []any:
			var sb strings.Builder
			for _, p := range c {
				switch v := p.(type) {
				case string:
					sb.WriteString(v)
				case map[string]any:
					if t, ok := v["text"].(string); ok {
						sb.WriteString(t)
					}
				}
			}
			content = sb.String()
		}
		switch role {
		case "system":
			parts = append(parts, "[System]\n"+content)
		case "assistant":
			parts = append(parts, "[Assistant]\n"+content)
		default:
			parts = append(parts, content)
		}
	}
	text := strings.Join(parts, "\n\n")
	// Trae expects query as a JSON-encoded string of typed content blocks.
	blocks := []map[string]any{
		{"type": "text", "data": map[string]any{"content": text}},
	}
	raw, _ := json.Marshal(blocks)
	return string(raw)
}

// PATCH(local): conversation memory.
//
// Every request used to open a brand-new chat_session, so the model started
// from zero each turn — a follow-up question could not see anything said
// before it. Trae keeps a session's turns in context, so we reuse one session
// per conversation and only send the NEW messages each time.
//
// The conversation is identified by its system prompt + first user message,
// which stay stable while the client appends turns. A session that fails is
// dropped immediately; the TTL is only a backstop so a stale fingerprint
// cannot capture an unrelated conversation that opens with the same words.
const (
	intlSessionTTL = 24 * time.Hour
	intlKeyMsgs    = 2
)

type intlSessEntry struct {
	id    string
	turns int // number of source messages already delivered to the session
	seen  time.Time
}

var (
	intlSessMu    sync.Mutex
	intlSessCache = map[string]*intlSessEntry{}
)

// conversationKey identifies a conversation by what never changes inside it:
// the system prompt (if any) plus the FIRST user message. Keying on "the first
// N messages" is wrong — the assistant's reply joins the array on the next
// turn, so the key would shift and every conversation would open a new session
// on turn 2.
func conversationKey(messages []map[string]any) string {
	h := sha256.New()
	firstUser := -1
	for i, m := range messages {
		role, _ := m["role"].(string)
		if role == "system" {
			var body string
			switch c := m["content"].(type) {
			case string:
				body = c
			default:
				raw, _ := json.Marshal(c)
				body = string(raw)
			}
			h.Write([]byte("system"))
			h.Write([]byte{0})
			h.Write([]byte(body))
			h.Write([]byte{0})
		} else if role == "user" && firstUser < 0 {
			firstUser = i
			var body string
			switch c := m["content"].(type) {
			case string:
				body = c
			default:
				raw, _ := json.Marshal(c)
				body = string(raw)
			}
			h.Write([]byte("user"))
			h.Write([]byte{0})
			h.Write([]byte(body))
			h.Write([]byte{0})
		}
	}
	_ = firstUser
	return hex.EncodeToString(h.Sum(nil))
}

func intlSessGet(key string) *intlSessEntry {
	intlSessMu.Lock()
	defer intlSessMu.Unlock()
	e := intlSessCache[key]
	if e == nil {
		return nil
	}
	if time.Since(e.seen) > intlSessionTTL {
		delete(intlSessCache, key)
		return nil
	}
	return e
}

func intlSessPut(key, id string, turns int) {
	intlSessMu.Lock()
	defer intlSessMu.Unlock()
	intlSessCache[key] = &intlSessEntry{id: id, turns: turns, seen: time.Now()}
	// opportunistic sweep
	for k, v := range intlSessCache {
		if time.Since(v.seen) > intlSessionTTL {
			delete(intlSessCache, k)
		}
	}
}

func intlSessDrop(key string) {
	intlSessMu.Lock()
	defer intlSessMu.Unlock()
	delete(intlSessCache, key)
}

// trailingUserText returns the user messages that come AFTER the last
// assistant/system message — i.e. what is genuinely new in this request.
//
// Trae's chat already contains every earlier user turn AND every assistant
// reply, so re-sending the slice messages[e.turns:] is wrong: it repeats the
// previous answer inside the next prompt ("[Assistant] ok... What number?"),
// which both wastes tokens and confuses the model into replying with nothing.
func trailingUserText(messages []map[string]any) string {
	start := 0
	for i, m := range messages {
		role, _ := m["role"].(string)
		if role != "user" {
			start = i + 1
		}
	}
	if start >= len(messages) {
		return ""
	}
	return flattenQuery(messages[start:])
}

// PATCH(local): large-context support via multi-message sessions.
//
// Trae stores every message in the user_history service, which enforces a
// per-message value-size cap. Exceeding it fails with:
//
//   failed to add user message to history: ... ERR value size over limit
//
// Measured on an Intl credential (2026-10-19):
//   ~45k tokens  (~180k chars)  -> accepted
//   ~122k tokens (~490k chars)  -> rejected (value size over limit)
//
// A session itself is NOT capped: POST /chat_sessions/{id}/messages appends
// further turns and the model keeps them in context (verified: a codeword
// placed in turn 1 was recalled in turn 4 of a ~248k-token session, with
// prompt_tokens reaching ~81k). So an oversized conversation is split across
// several messages, which lets callers use the model's full context window
// instead of dying at the single-message cap.
const (
	// intlMaxChunkChars keeps each message well inside the observed safe
	// zone. ~150k chars ≈ 37k tokens for English prose.
	intlMaxChunkChars = 150_000
	// intlMaxChunks bounds the work: 6 × 150k chars ≈ 225k tokens, enough to
	// fill a 272k-context model without unbounded fan-out.
	intlMaxChunks = 6
)

// splitQueryChunks cuts a flattened query string into at most intlMaxChunks
// pieces of roughly intlMaxChunkChars, breaking on whitespace so a word is
// never torn in half. Returns a single-element slice when no split is needed.
func splitQueryChunks(q string) []string {
	if len(q) <= intlMaxChunkChars {
		return []string{q}
	}
	n := (len(q) + intlMaxChunkChars - 1) / intlMaxChunkChars
	if n > intlMaxChunks {
		n = intlMaxChunks
	}
	size := (len(q) + n - 1) / n
	out := make([]string, 0, n)
	for i := 0; i < len(q) && len(out) < n; i += size {
		end := i + size
		if end >= len(q) {
			out = append(out, q[i:])
			break
		}
		// walk back to the previous space so we split on a word boundary
		cut := end
		for cut > i && q[cut] != ' ' {
			cut--
		}
		if cut <= i {
			cut = end
		}
		out = append(out, q[i:cut])
		i = cut - size // loop adds size back
	}
	return out
}

// PATCH(local): a session only accepts the next turn once the previous one
// has been processed. Polling the stored messages is deterministic; blind
// 409-retrying is not (a turn can take minutes, and a *failed* turn pins the
// session until it is abandoned).
//
// Session statuses observed: in_progress / completed / failed / canceled.
const (
	// intlTurnWait bounds how long we wait for one turn to settle.
	intlTurnWait = 5 * time.Minute
	// intlTurnPoll is the polling cadence.
	intlTurnPoll = 3 * time.Second
)

// sessionTurnState returns the status of the newest message in the session.
func (c *Client) sessionTurnState(a *Auth, sessionID string) (string, error) {
	req, err := http.NewRequest(http.MethodGet,
		c.BaseURL+fmt.Sprintf(EpChatSessionMessages, sessionID), nil)
	if err != nil {
		return "", err
	}
	req.Header = buildHeaders(a)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("session state upstream %d", resp.StatusCode)
	}
	var env struct {
		Data struct {
			Items []struct {
				Status string `json:"status"`
				Role   string `json:"role"`
			} `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return "", err
	}
	if len(env.Data.Items) == 0 {
		return "", nil
	}
	last := env.Data.Items[len(env.Data.Items)-1]
	return last.Status, nil
}

// waitForTurnDone blocks until the newest message in the session is no longer
// in progress, or the deadline passes. Returns the final status.
func (c *Client) waitForTurnDone(a *Auth, sessionID string) string {
	deadline := time.Now().Add(intlTurnWait)
	for {
		st, err := c.sessionTurnState(a, sessionID)
		if err == nil {
			switch st {
			case "in_progress", "pending", "":
				// still running (or not yet persisted) — keep waiting
			default:
				return st
			}
		}
		if time.Now().After(deadline) {
			if st == "" {
				st = "timeout"
			}
			log.Printf("trae chat_session %s: turn wait timed out (last state %q)", sessionID, st)
			return "timeout"
		}
		time.Sleep(intlTurnPoll)
	}
}

// appendMessage posts one further user turn to an existing session and returns
// the new message id (the one whose events must be streamed).
func (c *Client) appendMessage(a *Auth, mode, modelName, strategy, sessionID, query string) (string, error) {
	body := map[string]any{
		"chat_session_id":          sessionID,
		"content":                  []any{},
		"query":                    query,
		"model_name":               modelName,
		"agent_type":               "solo_agent_remote",
		"model_selection_strategy": strategy,
		"common_params":            commonParams(a, mode),
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost,
		c.BaseURL+fmt.Sprintf(EpChatSessionMessages, sessionID), bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header = buildHeaders(a)
	// PATCH(local): wait for the previous turn to settle first. A turn that
	// ended "failed" still pins the session, so we abandon the whole request
	// rather than leaving a slot occupied behind us.
	state := c.waitForTurnDone(a, sessionID)
	if state == "failed" || state == "canceled" || state == "timeout" {
		return "", fmt.Errorf("session %s abandoned: previous turn ended %q", sessionID, state)
	}
	var respBody []byte
	status := 0
	deadline := time.Now().Add(2 * time.Minute)
	wait := 3 * time.Second
	for {
		resp, rerr := c.HTTP.Do(req)
		if rerr != nil {
			return "", rerr
		}
		respBody, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		status = resp.StatusCode
		// The session reports "busy" inconsistently: 409/991210 while the
		// previous turn is still running, and sometimes a bare 500/995000.
		// Treat both as retryable.
		busy := status == 409 || status >= 500 ||
			bytes.Contains(respBody, []byte(`"code":991210`)) ||
			bytes.Contains(respBody, []byte(`"code":995000`))
		if !busy {
			break
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("append_message: session still busy after 4m: %s", truncate(string(respBody), 160))
		}
		log.Printf("trae chat_session %s: busy (409), retrying in %s", sessionID, wait)
		time.Sleep(wait)
		if wait < 10*time.Second {
			wait += 2 * time.Second
		}
		// rebuild the request body: http.Request is single-use after Do
		raw2, _ := json.Marshal(body)
		req, rerr = http.NewRequest(http.MethodPost,
			c.BaseURL+fmt.Sprintf(EpChatSessionMessages, sessionID), bytes.NewReader(raw2))
		if rerr != nil {
			return "", rerr
		}
		req.Header = buildHeaders(a)
	}
	var env struct {
		Code int `json:"code"`
		Data struct {
			MessageID string `json:"message_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &env); err != nil {
		return "", fmt.Errorf("append_message parse: %w", err)
	}
	if env.Code != 0 {
		return "", fmt.Errorf("append_message code=%d: %s", env.Code, truncate(string(respBody), 200))
	}
	return env.Data.MessageID, nil
}

// CreateSession calls POST /chat_sessions to start a new chat.
// Returns (sessionId, messageId, error).
func (c *Client) CreateSession(a *Auth, model string, messages []map[string]any) (string, string, error) {
	mode, strategy, modelName := resolveMode(model)

	// PATCH(local): if this conversation already has a live session, append
	// only the new turns instead of starting from scratch.
	convKey := conversationKey(messages)
	if e := intlSessGet(convKey); e != nil && len(messages) > e.turns {
		fresh := trailingUserText(messages)
		if fresh == "" {
			intlSessDrop(convKey)
			fresh = flattenQuery(messages)
		}
		if state := c.waitForTurnDone(a, e.id); state == "completed" || state == "idle" || state == "" {
			msgID := ""
			failed := false
			for _, chunk := range splitQueryChunks(fresh) {
				id, aerr := c.appendMessage(a, mode, modelName, strategy, e.id, chunk)
				if aerr != nil {
					log.Printf("trae chat_session %s: reuse append failed (%v) — starting a new session", e.id, aerr)
					intlSessDrop(convKey)
					failed = true
					break
				}
				msgID = id
			}
			if !failed && msgID != "" {
				intlSessPut(convKey, e.id, len(messages))
				log.Printf("trae chat_session %s: reused for turn %d (context held)", e.id, len(messages))
				return e.id, msgID, nil
			}
		} else {
			log.Printf("trae chat_session %s: previous turn ended %q — starting a new session", e.id, state)
			intlSessDrop(convKey)
		}
	}

	query := flattenQuery(messages)
	// PATCH(local): split BEFORE building the initial message — the first turn
	// must carry only chunk 0, otherwise it still trips the history size cap.
	chunks := splitQueryChunks(query)
	firstChunk := chunks[0]
	body := map[string]any{
		"mode":           mode,
		"environment_id": "default",
		"initial_message": map[string]any{
			"chat_session_id":          "",
			"content":                  []any{},
			"query":                    firstChunk,
			"model_name":               modelName,
			"agent_type":               "solo_agent_remote",
			"model_selection_strategy": strategy,
			"common_params":            commonParams(a, mode),
		},
		"env":                 "remote",
		"auto_create_project": false,
		"origin":              "web",
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+EpChatSessions, bytes.NewReader(raw))
	if err != nil {
		return "", "", err
	}
	req.Header = buildHeaders(a)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", "", fmt.Errorf("create_session upstream %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}
	var env struct {
		Code int `json:"code"`
		Data struct {
			ChatSessionID string `json:"chat_session_id"`
			MessageID     string `json:"message_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &env); err != nil {
		return "", "", fmt.Errorf("create_session parse: %w", err)
	}
	if env.Code != 0 {
		return "", "", fmt.Errorf("create_session code=%d: %s", env.Code, truncate(string(respBody), 200))
	}
	// DEBUG(local): expose the upstream chat_session_id so per-model usage can
	// be pulled from POST /api/v1/commercial/get_session_usage {session_id}.
	log.Printf("trae chat_session created: id=%s model=%s msg=%s",
		env.Data.ChatSessionID, model, env.Data.MessageID)

	// PATCH(local): feed any remaining chunks as further turns so oversized
	// conversations survive the per-message history cap. The LAST chunk is the
	// one carrying the actual question, so its message id is what we stream.
	intlSessPut(convKey, env.Data.ChatSessionID, len(messages))
	if len(chunks) > 1 {
		log.Printf("trae chat_session %s: query split into %d messages (%d chars)",
			env.Data.ChatSessionID, len(chunks), len(query))
		msgID := env.Data.MessageID
		for i := 1; i < len(chunks); i++ {
			id, aerr := c.appendMessage(a, mode, modelName, strategy, env.Data.ChatSessionID, chunks[i])
			if aerr != nil {
				return "", "", fmt.Errorf("chunk %d/%d: %w", i+1, len(chunks), aerr)
			}
			msgID = id
		}
		return env.Data.ChatSessionID, msgID, nil
	}
	return env.Data.ChatSessionID, env.Data.MessageID, nil
}

// StreamEvents calls GET /chat_sessions/{id}/events SSE.
// onEvent is called per SSE frame (event, data). Returns when onEvent returns
// true, when "done"/"error" arrives, or when the stream ends.
func (c *Client) StreamEvents(ctx context.Context, a *Auth, sessionID, messageID string, onEvent func(event string, data map[string]any) bool) error {
	u := c.BaseURL + fmt.Sprintf(EpChatEvents, sessionID) + "?reply_to_message_id=" + url.QueryEscape(messageID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header = buildHeaders(a)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("events stream upstream %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	br := bufio.NewReaderSize(resp.Body, 64*1024)
	var ev string
	for {
		line, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			return err
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case line == "":
			ev = ""
		case strings.HasPrefix(line, "event:"):
			ev = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			var data map[string]any
			if err := json.Unmarshal([]byte(payload), &data); err != nil {
				data = map[string]any{"_raw": payload}
			}
			if onEvent != nil && onEvent(ev, data) {
				return nil
			}
		}
		if err == io.EOF {
			return nil
		}
	}
}

// Execute runs a non-streaming chat completion.
// Drives the SSE to completion, accumulates `plan_item.thought` (cumulative),
// then returns a single chat.completion object.
func (c *Client) Execute(ctx context.Context, a *Auth, model string, messages []map[string]any) (map[string]any, error) {
	sessionID, messageID, err := c.CreateSession(a, model, messages)
	if err != nil {
		return nil, err
	}
	var (
		order       []string
		thoughts    = map[string]string{}
		sent        int
		usage       map[string]any
		errorEvent  map[string]any
		fullContent strings.Builder
		finishText  string
	)
	renderNewText := func(data map[string]any) {
		pid, _ := data["id"].(string)
		if pid == "" {
			return
		}
		if _, ok := thoughts[pid]; !ok {
			order = append(order, pid)
		}
		t, _ := data["thought"].(string)
		if len(t) >= len(thoughts[pid]) {
			thoughts[pid] = t
		}
		var sb strings.Builder
		for _, id := range order {
			sb.WriteString(thoughts[id])
		}
		full := sb.String()
		if len(full) > sent {
			fullContent.WriteString(full[sent:])
		}
		sent = len(full)
	}
	err = c.StreamEvents(ctx, a, sessionID, messageID, func(ev string, data map[string]any) bool {
		switch ev {
		case "error":
			errorEvent = data
			return true
		case "token_usage":
			usage = data
		case "plan_item":
			renderNewText(data)
			if s := finishSummaryFrom(data); s != "" {
				finishText = s
			}
		case "done":
			return true
		}
		return false
	})
	if err != nil {
		return nil, err
	}
	if errorEvent != nil {
		code, _ := errorEvent["code"]
		msg, _ := errorEvent["message"].(string)
		return nil, fmt.Errorf("trae %v: %s", code, msg)
	}
	id := fmt.Sprintf("chatcmpl-trae-%d", time.Now().UnixNano())
	content := fullContent.String()
	if tail := mergeFinishSummary(content, finishText); tail != "" {
		content += tail
	}
	resp := map[string]any{
		"id":      id,
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []any{
			map[string]any{
				"index":         0,
				"message":       map[string]any{"role": "assistant", "content": content},
				"finish_reason": "stop",
			},
		},
	}
	if usage != nil {
		if pt, ok := usage["prompt_tokens"].(float64); ok {
			ct := getFloat(usage, "completion_tokens")
			tt := getFloat(usage, "total_tokens")
			if tt == 0 {
				tt = pt + ct
			}
			resp["usage"] = map[string]any{
				"prompt_tokens":     int64(pt),
				"completion_tokens": int64(ct),
				"total_tokens":      int64(tt),
			}
		}
	}
	return resp, nil
}

// ExecuteStream runs a streaming chat completion.
// Returns a reader that yields OpenAI-compatible SSE chunks.
func (c *Client) ExecuteStream(ctx context.Context, a *Auth, model string, messages []map[string]any) (io.Reader, error) {
	sessionID, messageID, err := c.CreateSession(a, model, messages)
	if err != nil {
		return nil, err
	}
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		emit := func(obj map[string]any) error {
			raw, _ := json.Marshal(obj)
			_, err := io.WriteString(pw, "data: "+string(raw)+"\n\n")
			return err
		}
		id := fmt.Sprintf("chatcmpl-trae-%d", time.Now().UnixNano())
		created := time.Now().Unix()
		// Emit role chunk first.
		if err := emit(map[string]any{
			"id":      id,
			"object":  "chat.completion.chunk",
			"created": created,
			"model":   model,
			"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"role": "assistant"}, "finish_reason": nil}},
		}); err != nil {
			return
		}
		var (
			order        []string
			thoughts     = map[string]string{}
			sent         int
			usage        map[string]any
			errorEvent   map[string]any
			finishText   string
			contentSoFar strings.Builder
		)
		renderNewText := func(data map[string]any) string {
			pid, _ := data["id"].(string)
			if pid == "" {
				return ""
			}
			if _, ok := thoughts[pid]; !ok {
				order = append(order, pid)
			}
			t, _ := data["thought"].(string)
			if len(t) >= len(thoughts[pid]) {
				thoughts[pid] = t
			}
			var sb strings.Builder
			for _, id := range order {
				sb.WriteString(thoughts[id])
			}
			full := sb.String()
			var piece string
			if len(full) > sent {
				piece = full[sent:]
			}
			sent = len(full)
			return piece
		}
		err := c.StreamEvents(ctx, a, sessionID, messageID, func(ev string, data map[string]any) bool {
			switch ev {
			case "error":
				errorEvent = data
				return true
			case "token_usage":
				usage = data
			case "plan_item":
				if s := finishSummaryFrom(data); s != "" {
					finishText = s
				}
				piece := renderNewText(data)
				if piece != "" {
					contentSoFar.WriteString(piece)
					if err := emit(map[string]any{
						"id":      id,
						"object":  "chat.completion.chunk",
						"created": created,
						"model":   model,
						"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": piece}, "finish_reason": nil}},
					}); err != nil {
						return true
					}
				}
			case "done":
				return true
			}
			return false
		})
		if err != nil {
			_ = emit(map[string]any{"error": map[string]any{"message": err.Error(), "type": "api_error"}})
		} else if errorEvent != nil {
			code := errorEvent["code"]
			msg, _ := errorEvent["message"].(string)
			_ = emit(map[string]any{
				"id":      id,
				"object":  "chat.completion.chunk",
				"created": created,
				"model":   model,
				"choices": []any{},
				"error":   map[string]any{"message": fmt.Sprintf("trae %v: %s", code, msg), "type": "api_error"},
			})
		} else {
			// The `finish` tool call carries the real answer; `thought` is
			// usually empty. Emit whatever the stream has not already sent.
			if tail := mergeFinishSummary(contentSoFar.String(), finishText); tail != "" {
				_ = emit(map[string]any{
					"id":      id,
					"object":  "chat.completion.chunk",
					"created": created,
					"model":   model,
					"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": tail}, "finish_reason": nil}},
				})
			}
			_ = emit(map[string]any{
				"id":      id,
				"object":  "chat.completion.chunk",
				"created": created,
				"model":   model,
				"choices": []any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": "stop"}},
			})
			if usage != nil {
				pt := getFloat(usage, "prompt_tokens")
				ct := getFloat(usage, "completion_tokens")
				tt := getFloat(usage, "total_tokens")
				if tt == 0 {
					tt = pt + ct
				}
				_ = emit(map[string]any{
					"id":      id,
					"object":  "chat.completion.chunk",
					"created": created,
					"model":   model,
					"choices": []any{},
					"usage":   map[string]any{"prompt_tokens": int64(pt), "completion_tokens": int64(ct), "total_tokens": int64(tt)},
				})
			}
		}
		_, _ = io.WriteString(pw, "data: [DONE]\n\n")
	}()
	return pr, nil
}

// RefreshToken refreshes the access token via ExchangeToken.
// Multi-origin fallback (cockpit-tools build_api_urls): try the account
// apiHost → OAuthHost → Intl alternates so a single-host outage/404 no
// longer breaks token refresh.
func (c *Client) RefreshToken(a *Auth) error {
	if a.RefreshToken == "" {
		return fmt.Errorf("no refreshToken")
	}
	hosts := exchangeHosts(a.APIHost, c.OAuthHost)
	body := map[string]any{
		"ClientID":     c.ClientID,
		"RefreshToken": a.RefreshToken,
		"ClientSecret": "-",
		"UserID":       "",
	}
	raw, _ := json.Marshal(body)
	var respBody []byte
	var lastErr error
	for _, host := range hosts {
		req, err := http.NewRequest(http.MethodPost, host+EpExchange, bytes.NewReader(raw))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "Trae/3.5.66")
		resp, err := c.HTTP.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		respBody, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			lastErr = fmt.Errorf("refresh upstream %d: %s", resp.StatusCode, truncate(string(respBody), 200))
			continue
		}
		lastErr = nil
		break
	}
	if lastErr != nil {
		return lastErr
	}
	var env struct {
		Result struct {
			Token               string `json:"Token"`
			AccessToken         string `json:"AccessToken"`
			TokenExpireAt       int64  `json:"TokenExpireAt"`
			TokenExpireDuration int64  `json:"TokenExpireDuration"`
			RefreshToken        string `json:"RefreshToken"`
			RefreshExpireAt     int64  `json:"RefreshExpireAt"`
		} `json:"Result"`
	}
	if err := json.Unmarshal(respBody, &env); err != nil {
		return fmt.Errorf("refresh parse: %w", err)
	}
	if env.Result.Token == "" {
		env.Result.Token = env.Result.AccessToken
	}
	if env.Result.Token == "" {
		return fmt.Errorf("refresh_failed: no token in response")
	}
	a.AccessToken = env.Result.Token
	if env.Result.RefreshToken != "" {
		a.RefreshToken = env.Result.RefreshToken
	}
	if env.Result.TokenExpireAt > 0 {
		a.ExpiresAt = normalizeExpiresAt(env.Result.TokenExpireAt)
	}
	return nil
}

// GetUserInfo queries the account info (UID, nickname, enterpriseID).
// Multi-origin fallback (cockpit-tools build_api_urls): account apiHost →
// OAuthHost → Intl alternates.
func (c *Client) GetUserInfo(a *Auth) (uid, nickname, enterpriseID string, err error) {
	body := map[string]any{"ReqSource": "IDE", "IDEVersion": "3.5.66"}
	raw, _ := json.Marshal(body)
	var respBody []byte
	var lastErr error
	for _, host := range exchangeHosts(a.APIHost, c.OAuthHost) {
		req, rerr := http.NewRequest(http.MethodPost, host+EpUserInfo, bytes.NewReader(raw))
		if rerr != nil {
			return "", "", "", rerr
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "Trae/3.5.66")
		req.Header.Set("X-Cloudide-Token", a.AccessToken)
		resp, rerr := c.HTTP.Do(req)
		if rerr != nil {
			lastErr = rerr
			continue
		}
		respBody, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			lastErr = fmt.Errorf("userinfo upstream %d: %s", resp.StatusCode, truncate(string(respBody), 200))
			continue
		}
		lastErr = nil
		break
	}
	if lastErr != nil {
		return "", "", "", lastErr
	}
	var env struct {
		Result struct {
			UserID       string `json:"UserID"`
			ScreenName   string `json:"ScreenName"`
			EnterpriseID string `json:"EnterpriseID"`
		} `json:"Result"`
	}
	if err := json.Unmarshal(respBody, &env); err != nil {
		return "", "", "", fmt.Errorf("userinfo parse: %w", err)
	}
	return env.Result.UserID, env.Result.ScreenName, env.Result.EnterpriseID, nil
}

// FetchModels returns the list of available models for selection.
//
// v0.12.53 hardening: the decoder used to accept ANY 200 response — a
// business-error envelope ({code:1001,...} wrapped in HTTP 200, or a
// shape drift like data:null) silently produced an EMPTY list, and
// intlhandleModelForAuth then advertised just the auto/work virtuals with
// no diagnostic ("模型拉取失效" with nothing in the logs). Business codes
// and empty payloads are now errors, so the caller falls back to the
// static catalog and logs the actual reason.
// ModelMeta is the per-model metadata Trae publishes on /models. The
// reverse-engineered executors only ever kept `name`, which threw away
// everything a client needs to decide how to call the model: the pretty
// name, whether it accepts images, and the context window. Trae ships all
// of it — see the field notes on parseModelList.
type ModelMeta struct {
	Name        string
	DisplayName string
	Multimodal  bool
	ContextDev  int64
	ContextMax  int64
	Reasoning   bool
	Beta        bool
	New         bool
	Default     bool
}

// FetchModelInfos is FetchModels with metadata. Prefer this over FetchModels:
// the names alone cannot express vision support or context limits.
func (c *Client) FetchModelInfos(a *Auth) ([]ModelMeta, error) {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+EpModels, nil)
	if err != nil {
		return nil, err
	}
	req.Header = buildHeaders(a)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("models read: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("models upstream %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	// Trae returns two shapes for /models:
	//   legacy: {"code":0,"data":[{"name":"x"}, ...]}
	//   current: {"code":0,"data":{"list":[{"function":"solo_coder",
	//              "models":[{"name":"gpt-5.4", "display_name":"GPT-5.4",
	//                         "multimodal":true,
	//                         "context_window_tokens":{"dev":272000,"max":272000},
	//                         "features":"{\"reasoning\":{\"enable\":true}}"}]}]}}
	// Parsing only the legacy shape made every intl account fall back to the
	// stale static table (advertising claude-sonnet-4-5, which Trae does not
	// offer, and hiding GPT-5.4, Gemini-3-Flash and MiniMax-M2.7).
	var env struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("models parse: %w", err)
	}
	if env.Code != 0 {
		return nil, fmt.Errorf("models api code %d: %s", env.Code, truncate(strings.TrimSpace(env.Message), 120))
	}
	out := parseModelList(env.Data)
	if len(out) == 0 {
		return nil, fmt.Errorf("models api returned empty list")
	}
	return out, nil
}

// FetchModels keeps the historical []string signature for callers that only
// need ids (tests, catalog diffing). Metadata callers should use
// FetchModelInfos.
func (c *Client) FetchModels(a *Auth) ([]string, error) {
	metas, err := c.FetchModelInfos(a)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(metas))
	for _, m := range metas {
		out = append(out, m.Name)
	}
	return out, nil
}

// traeModelWire is the /models entry as Trae sends it. `features` is a
// JSON-encoded STRING (double-encoded object), not an object, so it needs a
// second unmarshal.
type traeModelWire struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Multimodal  bool   `json:"multimodal"`
	IsDefault   bool   `json:"is_default"`
	IsNew       bool   `json:"is_new"`
	IsBeta      bool   `json:"is_beta"`
	Features    string `json:"features"`
	Context     struct {
		Dev int64 `json:"dev"`
		Max int64 `json:"max"`
	} `json:"context_window_tokens"`
}

// traeFeaturesWire is the decoded `features` payload. Only the flags we
// surface are modelled; the object carries more (cost/access/...) that the
// host has no field for.
type traeFeaturesWire struct {
	Reasoning struct {
		Enable bool `json:"enable"`
	} `json:"reasoning"`
	Multimodal struct {
		Enable bool `json:"enable"`
	} `json:"multimodal"`
}

func decodeTraeFeatures(raw string) traeFeaturesWire {
	var f traeFeaturesWire
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" {
		return f
	}
	_ = json.Unmarshal([]byte(raw), &f)
	return f
}

func modelMetaFromWire(m traeModelWire) ModelMeta {
	f := decodeTraeFeatures(m.Features)
	meta := ModelMeta{
		Name:        m.Name,
		DisplayName: strings.TrimSpace(m.DisplayName),
		// `multimodal` is the authoritative top-level flag; features.multimodal
		// mirrors it. Accept either so a shape drift on one still reports vision.
		Multimodal: m.Multimodal || f.Multimodal.Enable,
		ContextDev: m.Context.Dev,
		ContextMax: m.Context.Max,
		Reasoning:  f.Reasoning.Enable,
		Beta:       m.IsBeta,
		New:        m.IsNew,
		Default:    m.IsDefault,
	}
	if meta.DisplayName == "" {
		meta.DisplayName = meta.Name
	}
	// Older payloads only carry `dev`; the advertised ceiling is what matters.
	if meta.ContextMax == 0 {
		meta.ContextMax = meta.ContextDev
	}
	if meta.ContextDev == 0 {
		meta.ContextDev = meta.ContextMax
	}
	return meta
}

// parseModelList extracts models from either /models data shape.
func parseModelList(raw json.RawMessage) []ModelMeta {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	// Shape A (legacy): data is an array of model objects.
	var flat []traeModelWire
	if err := json.Unmarshal(raw, &flat); err == nil && len(flat) > 0 {
		out := make([]ModelMeta, 0, len(flat))
		seen := map[string]bool{}
		for _, m := range flat {
			if m.Name == "" || seen[m.Name] {
				continue
			}
			seen[m.Name] = true
			out = append(out, modelMetaFromWire(m))
		}
		if len(out) > 0 {
			return out
		}
	}
	// Shape B (current): data is {list:[{function, models:[...]}, ...]}.
	var nested struct {
		List []struct {
			Function string          `json:"function"`
			Models   []traeModelWire `json:"models"`
		} `json:"list"`
	}
	if err := json.Unmarshal(raw, &nested); err != nil {
		return nil
	}
	seen := map[string]bool{}
	out := make([]ModelMeta, 0, len(nested.List))
	for _, grp := range nested.List {
		for _, m := range grp.Models {
			if m.Name == "" || seen[m.Name] {
				continue
			}
			seen[m.Name] = true
			out = append(out, modelMetaFromWire(m))
		}
	}
	return out
}

// modelNamesFromData is the legacy name-only view, kept for tests that lock
// the flattening contract.
func modelNamesFromData(raw json.RawMessage) []string {
	metas := parseModelList(raw)
	out := make([]string, 0, len(metas))
	for _, m := range metas {
		out = append(out, m.Name)
	}
	return out
}

// finishSummaryFrom extracts the assistant's actual reply from a `finish`
// tool call. Trae's intl SOLO protocol delivers the final answer as
// tool_call_info{name:"finish", params:{summary:"..."}}; the plan_item
// `thought` field is normally EMPTY, so reading only `thought` returned an
// empty message for most prompts while still billing the completion tokens.
func finishSummaryFrom(data map[string]any) string {
	tc, ok := data["tool_call_info"].(map[string]any)
	if !ok {
		return ""
	}
	if name, _ := tc["name"].(string); name != "finish" {
		return ""
	}
	params, ok := tc["params"].(map[string]any)
	if !ok {
		return ""
	}
	s, _ := params["summary"].(string)
	return strings.TrimSpace(s)
}

// mergeFinishSummary folds the finish summary into already-accumulated content
// and returns only the text still to be emitted. Three cases observed live:
//
//	accumulated empty            -> send the whole summary
//	accumulated is a prefix      -> send the remainder ("Binary" -> full answer)
//	accumulated already has it   -> send nothing (no duplication)
//	otherwise                    -> append after a blank line
func mergeFinishSummary(accumulated, summary string) string {
	s := strings.TrimSpace(summary)
	if s == "" {
		return ""
	}
	acc := strings.TrimSpace(accumulated)
	if acc == "" {
		return summary
	}
	if strings.HasPrefix(s, acc) {
		return s[len(acc):]
	}
	if strings.Contains(acc, s) {
		return ""
	}
	return "\n\n" + s
}

// Helpers

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) != "" {
		return s
	}
	return fallback
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

func normalizeExpiresAt(v int64) int64 {
	if v > 1e12 {
		return v / 1000
	}
	return v
}

func getFloat(m map[string]any, key string) float64 {
	if v, ok := m[key].(float64); ok {
		return v
	}
	return 0
}

// NeedsRefresh reports whether the token will expire within `within` duration.
func (a *Auth) NeedsRefresh(within time.Duration) bool {
	if a.ExpiresAt <= 0 {
		return true
	}
	return time.Now().Add(within).Unix() >= a.ExpiresAt
}

// RefreshTokenIfNeeded refreshes the token only if it will expire within `within`.
// Returns true if a refresh actually happened.
func (c *Client) RefreshTokenIfNeeded(a *Auth, within time.Duration) (bool, error) {
	// v0.12.49: near-expiry check plus issuance-age check — see issuedRotateMax.
	if !a.NeedsRefresh(within) && !issuedTooLong(a.AccessToken) {
		return false, nil
	}
	if err := c.RefreshToken(a); err != nil {
		return false, err
	}
	return true, nil
}

// tokenIssuedAt parses the `iat` (unix seconds) out of a JWT accessToken
// payload ({data:{...},exp,iat}); ok=false when absent/unparseable — callers
// then fall back to the expiresAt-only rule (legacy behaviour).
func tokenIssuedAt(jwtRaw string) (time.Time, bool) {
	parts := strings.Split(strings.TrimSpace(jwtRaw), ".")
	if len(parts) < 2 || parts[1] == "" {
		return time.Time{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		if raw, err = base64.StdEncoding.DecodeString(parts[1]); err != nil {
			return time.Time{}, false
		}
	}
	var payload struct {
		Iat int64 `json:"iat"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil || payload.Iat <= 0 {
		return time.Time{}, false
	}
	return time.Unix(payload.Iat, 0), true
}

// issuedRotateMax mirrors the CN side (dsh-router-traework 23d06cb): refresh
// proactively once the token is 15 days past issuance — the backend may
// revoke long-lived credentials server-side before expiry, and an unused
// credential never hits the near-expiry window, so a broken refresh chain
// would otherwise surface only as a hard session_dead later.
const issuedRotateMax = 15 * 24 * time.Hour

// issuedTooLong reports whether the token's issuance age exceeds the
// proactive rotation cap.
func issuedTooLong(jwtRaw string) bool {
	iat, ok := tokenIssuedAt(jwtRaw)
	if !ok {
		return false
	}
	return time.Since(iat) >= issuedRotateMax
}

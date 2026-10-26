// chat_401_heal.go — the chat plane's 401 self-heal (0.9.74).
//
// 0.9.68 wired the billing plane's 401 renew-once (magpie packages/workbuddy
// 0.1.31: "a chat or usage read WorkBuddy answers 401 is renewed once ...
// and sent once more") — but only the usage half landed. A chat 401 kept
// surfacing as the raw "upstream 401: <html>401 Authorization Required ...
// openresty ...</html>" error with only the host's 30-minute credential
// cooldown, which retries the SAME dead access token once the window lapses:
// the user sees 401→500 after 401→500 until a keepalive tick or a billing
// call happens to renew the credential (2026-10-26 field report, Buddycn
// account).
//
// That HTML page is the documented signature of a dead Keycloak offline
// session (see keepalive.go's header): the gateway bounces the access token
// before any business logic runs. Two outcomes are possible and both are
// handled here:
//
//   - the refresh succeeds → the executor resends once with the fresh
//     snapshot (a healed request is indistinguishable from one that worked:
//     no failure bookkeeping runs for the rescued attempt);
//   - the refresh is refused with the session-dead family (12153) → the
//     shared renewal already flagged the credential disabled, and the
//     surfaced error says to sign in again instead of dumping openresty HTML.
//
// Throttled / identity-less / otherwise-unverdicted renewals keep the exact
// pre-0.9.74 raw-401 behavior — the next request retries the heal.
//
// Scope note: only real HTTP 401 round trips are healed. In-stream error
// frames that merely LOOK unauthorized (streamFaultStatus's wording probes)
// stay on their existing status-less path — a 200 stream carries no retryable
// round trip to redo.
package main

import (
	"fmt"
	"strings"
)

// chat401HealOutcome is what healChat401 decided.
type chat401HealOutcome int

const (
	// chat401HealNone: no rescue — throttled, unresolvable identity, no
	// refresh token, or a renewal failure that is not a credential verdict.
	chat401HealNone chat401HealOutcome = iota
	// chat401HealResend: renewed — the caller must resend once with the
	// returned fresh snapshot.
	chat401HealResend
	// chat401SessionDead: the refresh was refused with the session-dead
	// family; billing401RenewOnce already flagged the credential disabled.
	chat401SessionDead
)

// healChat401 drives the shared renewal behind a chat-plane 401. authID is
// the executor request's credential id (host pick space); the executor's
// parseStored snapshot carries no authIndex, so the host identity is resolved
// here first (same resolution reconcileAfterExecutorError applies).
func healChat401(authID string, sa *storedAuth) (chat401HealOutcome, *storedAuth) {
	if sa == nil {
		return chat401HealNone, nil
	}
	if strings.TrimSpace(sa.authIndex) == "" {
		idx := chat401ResolveAuthIndex(authID, sa)
		if idx == "" {
			return chat401HealNone, nil
		}
		sa.authIndex = idx
	}
	fresh, rerr := billing401RenewOnce(sa)
	switch {
	case rerr == nil && fresh != nil:
		return chat401HealResend, fresh
	case isBilling401SessionDead(rerr):
		return chat401SessionDead, nil
	default:
		return chat401HealNone, nil
	}
}

// chat401ResolveAuthIndex maps the executor's credential reference to the
// host auth_index the renewal needs: the request's AuthID first (index, file
// id, or account UID — resolveAuthIndexAndID handles all three shapes), the
// snapshot's account UID as fallback.
func chat401ResolveAuthIndex(authID string, sa *storedAuth) string {
	if id := strings.TrimSpace(authID); id != "" {
		if idx, _ := resolveAuthIndexAndID(id); idx != "" {
			return idx
		}
	}
	if sa != nil {
		if uid := strings.TrimSpace(sa.Account.UID); uid != "" {
			if idx, _ := resolveAuthIndexAndID(uid); idx != "" {
				return idx
			}
		}
	}
	return ""
}

// chat401Verdict summarizes the heal outcome for the final error copy. The
// zero value annotates nothing — a raw 401 that earned no verdict keeps the
// exact pre-0.9.74 surface.
type chat401Verdict struct {
	// SessionDead: the refresh was refused with the session-dead family —
	// the credential is already flagged disabled by the shared renewal.
	SessionDead bool
	// RenewedRefused: the renewal succeeded but the resend was STILL a 401 —
	// a fresh token the gateway continues to refuse means re-login.
	RenewedRefused bool
}

// annotate upgrades the final translated chat-401 error with the verdict's
// actionable copy. The raw shape stays first (log parsers and the host's
// message-based heuristics keep working); the verdict's bilingual guidance is
// appended.
func (v chat401Verdict) annotate(err error) error {
	switch {
	case v.SessionDead:
		// %w (not %s): the account-level statusError must survive the wrap —
		// the host reads StatusCode() for its credential cooldown, and the
		// verdict copy must not strip it.
		return fmt.Errorf("%w — %s — %s", err,
			"该账号的登录会话已在上游失效（续期被拒，12153 Offline user session not found）：请重新登录该账号；已自动停用，重新登录后自动恢复",
			"// The account's sign-in session is dead upstream (renewal refused, 12153 Offline user session not found): please sign in to this account again; it has been auto-disabled and re-enters rotation after re-login")
	case v.RenewedRefused:
		return fmt.Errorf("%w — %s — %s", err,
			"已续期一次仍被网关 401 拒绝：请重新登录该账号",
			"// Renewed once and the gateway still answers 401: please sign in to this account again")
	}
	return err
}

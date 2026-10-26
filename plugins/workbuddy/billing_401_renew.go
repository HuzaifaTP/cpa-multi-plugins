// billing_401_renew.go — the billing plane's 401 self-heal (0.9.68).
//
// magpie packages/workbuddy 0.1.31 (yetone, 2026-10-23): "a chat or usage
// read WorkBuddy answers 401 is renewed once, whatever the token's time,
// and sent once more." Our keepalive refresh keeps offline sessions alive
// on a daily schedule, but a session that dies between ticks used to
// surface every billing call as a hard failure until the next keepalive
// ran. This file folds the heal into the failing call itself:
//
//   - a token another process saved since the snapshot is taken first,
//     instead of spending the refresh token again;
//   - exactly one renewal per credential per window (a scheduler tick fans
//     out into several billing calls; rotation makes concurrent refresh
//     spends destructive);
//   - the credential is flagged dead only on the upstream's own word —
//     the refresh refused with the session-dead family (12153). Anything
//     else leaves the account exactly as it is.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// errBilling401SessionDead marks a renewal the upstream refused because the
// offline session is gone — the only 401-heal outcome that is a verdict on
// the credential itself.
var errBilling401SessionDead = errors.New("session dead")

// billing401RenewWindow bounds renewal attempts per credential: concurrent
// billing calls in one scheduler tick must not each spend (and rotate) the
// refresh token.
const billing401RenewWindow = 30 * time.Second

var (
	billing401Mu        sync.Mutex
	billing401LastRenew = map[string]time.Time{}
	// billing401InFlight holds the per-credential renewal join channel
	// (0.9.74). Pre-0.9.74 a caller that arrived while a renewal was
	// running failed "throttled" and kept its raw 401; now it waits for
	// the running renewal and takes what it gave — magpie's renewing map
	// semantics ("those who come while it runs get what it gave").
	billing401InFlight = map[string]chan struct{}{}
)

// billing401Acquire decides this caller's role in the renewal for one
// credential. Returns (join, owner):
//   - join != nil, owner == false: a renewal is running — wait on join, then
//     re-read the credential (the owner persisted whatever it got);
//   - join == nil, owner == true: this caller owns the renewal and must call
//     billing401Release when done;
//   - join == nil, owner == false: throttled — the last attempt started
//     inside the window and nothing is running.
func billing401Acquire(authIndex string) (<-chan struct{}, bool) {
	billing401Mu.Lock()
	defer billing401Mu.Unlock()
	if ch, ok := billing401InFlight[authIndex]; ok {
		return ch, false
	}
	if t, ok := billing401LastRenew[authIndex]; ok && time.Since(t) < billing401RenewWindow {
		return nil, false
	}
	billing401LastRenew[authIndex] = time.Now()
	ch := make(chan struct{})
	billing401InFlight[authIndex] = ch
	return nil, true
}

// billing401Release ends one owned renewal: the join channel is closed so
// waiters wake, and the in-flight entry is dropped.
func billing401Release(authIndex string) {
	billing401Mu.Lock()
	ch := billing401InFlight[authIndex]
	delete(billing401InFlight, authIndex)
	billing401Mu.Unlock()
	if ch != nil {
		close(ch)
	}
}

// isBilling401SessionDead reports whether a renewal failure is the upstream's
// session-dead verdict.
func isBilling401SessionDead(err error) bool {
	return errors.Is(err, errBilling401SessionDead)
}

// is401BillingRejection reports whether err is a billing-plane 401: the
// gateway's credential bounce (growthHTTPError carries the status — the
// nginx/APISIX HTML page) or the JSON envelope's code=12153 "Offline user
// session not found" (billingCallOnce collapses that shape to
// "code=12153 msg=..."). Other 401 flavors stay outside the heal — narrow
// and evidence-based, matching keepalive's sessionDeadMarkers.
func is401BillingRejection(err error) bool {
	if err == nil {
		return false
	}
	if growthErrStatus(err) == http.StatusUnauthorized {
		return true
	}
	return strings.HasPrefix(msgOf(err), "code=12153")
}

// billing401RenewOnce attempts one credential renewal behind a billing 401.
// Returns (fresh, nil) when the caller should resend once with the fresh
// snapshot; (nil, err) when renewal is impossible, throttled or refused —
// the caller's original 401 stays the primary failure either way.
//
// v0.9.74: concurrent callers on the same credential JOIN the in-flight
// renewal instead of failing throttled (see billing401Acquire), so a fan-out
// of 401s spends the refresh token exactly once and every caller resends
// with the token that one renewal produced.
func billing401RenewOnce(sa *storedAuth) (*storedAuth, error) {
	if sa == nil || sa.authIndex == "" {
		return nil, fmt.Errorf("401 renew: credential snapshot carries no host identity")
	}
	if strings.TrimSpace(sa.Auth.RefreshToken) == "" {
		return nil, fmt.Errorf("401 renew: no refresh token")
	}
	// A token another process saved since our snapshot is taken first
	// instead of spending the refresh token again (magpie 0.1.31).
	fresh, err := hostAuthGet(sa.authIndex)
	if err != nil {
		return nil, fmt.Errorf("401 renew: re-read: %w", err)
	}
	if fresh.Auth.AccessToken != "" && fresh.Auth.AccessToken != sa.Auth.AccessToken {
		return fresh, nil
	}
	join, owner := billing401Acquire(sa.authIndex)
	if join != nil {
		// Another in-process renewal is running for this credential: wait
		// for it, then take what it left in storage (a failed renewal
		// leaves nothing new — the caller keeps its original 401).
		<-join
		after, err2 := hostAuthGet(sa.authIndex)
		if err2 == nil && after.Auth.AccessToken != "" && after.Auth.AccessToken != sa.Auth.AccessToken {
			return after, nil
		}
		return nil, fmt.Errorf("401 renew: shared renewal produced no new token")
	}
	if !owner {
		return nil, fmt.Errorf("401 renew: throttled (last attempt inside the %s window)", billing401RenewWindow)
	}
	defer billing401Release(sa.authIndex)

	data, raw, status, rerr := refreshCall(fresh)
	if rerr != nil {
		if status == http.StatusUnauthorized && isSessionDeadError(string(raw)) {
			if derr := markSessionDead(sa.authIndex, fresh.Account.UID, fresh); derr != nil {
				return nil, fmt.Errorf("401 renew: %w; flag failed: %v", errBilling401SessionDead, derr)
			}
			return nil, fmt.Errorf("401 renew: %w (refresh refused)", errBilling401SessionDead)
		}
		return nil, fmt.Errorf("401 renew: %w", rerr)
	}
	var tok tokenData
	if err := json.Unmarshal(data, &tok); err != nil || tok.AccessToken == "" {
		return nil, fmt.Errorf("401 renew: no accessToken in response")
	}
	// Fold + persist (twin of refreshOneAuth's tail in keepalive.go — keep
	// the two in sync).
	fresh.Auth.AccessToken = tok.AccessToken
	if tok.RefreshToken != "" {
		fresh.Auth.RefreshToken = tok.RefreshToken
	}
	if tok.Domain != "" {
		fresh.Auth.Domain = tok.Domain
	}
	fresh.Auth.ExpiresAt = preserveExpiry(
		time.Now().Add(time.Duration(tok.ExpiresIn)*time.Second).Unix(),
		fresh.Auth.ExpiresAt,
	)
	if err := persistAuthTokens(sa.authIndex, fresh); err != nil {
		return nil, fmt.Errorf("401 renew: persist: %w", err)
	}
	return fresh, nil
}

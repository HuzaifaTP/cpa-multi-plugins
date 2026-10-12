//go:build live

// qoder_live_probe_helpers_test.go — small helper mirroring callModelsAPI's
// exact dialect for raw-catalog access (build here to keep the probe file
// focused; production code is untouched).
package main

import (
	"context"
	"net/http"
	"strings"
)

// newModelsProbeRequest builds the GET /algo/api/v2/model/list request with
// the same Cosy signing as production (copy of callModelsAPI's first half).
// The context stays alive for the caller's request lifetime (no premature
// cancel — the 20s budget is enforced by the transport's own dial/response
// timeouts inside sharedHTTPClient).
func newModelsProbeRequest(sa *storedAuth, encodedBody, rawURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, strings.NewReader(encodedBody))
	if err != nil {
		return nil, err
	}
	if err := applyCosyHeaders(req, sa, encodedBody, rawURL, "", false); err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", clientUA)
	return req, nil
}

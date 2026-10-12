//go:build live

// qoder_live_upload_matrix_test.go — issue #37 signature-matrix probe: the
// /algo/api/v2/image/upload endpoint answers 403 "Signature invalid" (code
// 101) for the exact dialect chat + model/list accept. This probe tries the
// plausible signature-input/header variants ONE AT A TIME against the real
// gateway so the accepted combination can be identified empirically.
//
//	QD_TOKEN=... QD_REGION=intl QD_UID=... go test -tags live -run TestLiveUploadMatrix -v ./plugins/qoder
package main

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type uploadVariant struct {
	name       string
	sigBodyFn  func(body []byte) string // what goes into the md5 as "body"
	queryFn    func() string            // query string appended to the path
	method     string
	extraHdr   map[string]string
	buildBody  func() ([]byte, string) // body bytes + content-type
	noCosyDate bool
}

func TestLiveUploadMatrix(t *testing.T) {
	sa := liveImageAuth(t)
	uri := redPNG64
	mime, data, ok := parseDataURI(uri)
	if !ok {
		t.Fatalf("parseDataURI")
	}
	_ = mime

	sess, err := cosySessionFor(sa)
	if err != nil {
		t.Fatalf("cosy session: %v", err)
	}

	buildMultipart := func() ([]byte, string, string) {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", `form-data; name="file"; filename="image.png"`)
		h.Set("Content-Type", "image/png")
		part, _ := w.CreatePart(h)
		part.Write(data)
		w.Close()
		return buf.Bytes(), w.FormDataContentType(), w.Boundary()
	}

	sign := func(sigBody, rawURL string) map[string]string {
		u, _ := url.Parse(rawURL)
		pathSig := u.Path
		if strings.HasPrefix(pathSig, "/algo") {
			pathSig = pathSig[len("/algo"):]
		}
		payload := map[string]string{
			"cosyVersion": "0.1.43",
			"ideVersion":  "",
			"info":        sess.Info,
			"requestId":   uuid.NewString(),
			"version":     "v1",
		}
		pb, _ := json.Marshal(payload)
		payloadB64 := base64.StdEncoding.EncodeToString(pb)
		date := fmt.Sprintf("%d", time.Now().Unix())
		sum := md5.Sum([]byte(payloadB64 + "\n" + sess.CosyKey + "\n" + date + "\n" + sigBody + "\n" + pathSig))
		sig := hex.EncodeToString(sum[:])
		return map[string]string{
			"cosy-data-policy":  "AGREE",
			"cosy-machinetype":  sess.MachineType,
			"cosy-clienttype":   "5",
			"cosy-date":         date,
			"cosy-user":         sa.Account.UID,
			"cosy-key":          sess.CosyKey,
			"accept":            "application/json",
			"cosy-clientip":     "169.254.198.161",
			"authorization":     "Bearer COSY." + payloadB64 + "." + sig,
			"accept-encoding":   "identity",
			"cosy-version":      "0.1.43",
			"cosy-machineid":    sess.MachineID,
			"cosy-machinetoken": sess.MachineToken,
			"login-version":     "v2",
			"user-agent":        "Go-http-client/2.0",
			"x-request-id":      uuid.NewString(),
		}
	}

	base := imageUploadBaseFor(sa)

	run := func(name, method, rawURL string, body []byte, contentType string, hdr map[string]string) {
		req, err := http.NewRequest(method, rawURL, bytes.NewReader(body))
		if err != nil {
			t.Fatalf("%s: build: %v", name, err)
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("AI-CLIENT-TIMESTAMP", strconv.FormatInt(time.Now().Unix(), 10))
		resp, err := imageUploadHTTPClient().Do(req)
		if err != nil {
			t.Logf("[%-22s] transport: %v", name, err)
			return
		}
		defer resp.Body.Close()
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		t.Logf("[%-22s] http %d: %s", name, resp.StatusCode, strings.TrimSpace(string(rb)))
	}

	mpBody, mpCT, _ := buildMultipart()
	reqID := "?request_id=" + uuid.NewString()

	// V1 baseline: current production dialect (raw multipart bytes signed).
	h := sign(string(mpBody), base+"/algo/api/v2/image/upload"+reqID)
	h["cosy-bodyhash"] = fmt.Sprintf("%x", md5.Sum(mpBody))
	h["cosy-bodylength"] = strconv.Itoa(len(mpBody))
	run("V1-raw-bytes", "PUT", base+"/algo/api/v2/image/upload"+reqID, mpBody, mpCT, h)

	// V2: signature over UTF-8 lossy reinterpretation of the bytes.
	lossy := strings.ToValidUTF8(string(mpBody), string([]byte{0xEF, 0xBF, 0xBD}))
	h = sign(lossy, base+"/algo/api/v2/image/upload"+reqID)
	run("V2-utf8-lossy", "PUT", base+"/algo/api/v2/image/upload"+reqID, mpBody, mpCT, h)

	// V3: signature over empty body.
	h = sign("", base+"/algo/api/v2/image/upload"+reqID)
	run("V3-empty-sig-body", "PUT", base+"/algo/api/v2/image/upload"+reqID, mpBody, mpCT, h)

	// V4: no request_id query.
	h = sign(string(mpBody), base+"/algo/api/v2/image/upload")
	run("V4-no-query", "PUT", base+"/algo/api/v2/image/upload", mpBody, mpCT, h)

	// V5: POST instead of PUT.
	h = sign(string(mpBody), base+"/algo/api/v2/image/upload"+reqID)
	run("V5-post", "POST", base+"/algo/api/v2/image/upload"+reqID, mpBody, mpCT, h)

	// V6: query included in sigPath.
	u6 := base + "/algo/api/v2/image/upload" + reqID
	h = sign(string(mpBody), u6)
	// (path with query: emulate by signing the full path+query as "path")
	{
		payload := map[string]string{"cosyVersion": "0.1.43", "ideVersion": "", "info": sess.Info, "requestId": uuid.NewString(), "version": "v1"}
		pb, _ := json.Marshal(payload)
		payloadB64 := base64.StdEncoding.EncodeToString(pb)
		date := fmt.Sprintf("%d", time.Now().Unix())
		pathQ := "/api/v2/image/upload" + reqID
		sum := md5.Sum([]byte(payloadB64 + "\n" + sess.CosyKey + "\n" + date + "\n" + string(mpBody) + "\n" + pathQ))
		h["authorization"] = "Bearer COSY." + payloadB64 + "." + hex.EncodeToString(sum[:])
		h["cosy-date"] = date
	}
	run("V6-path-with-query", "PUT", u6, mpBody, mpCT, h)

	// V7: magpie-style header values (ClientType 10, ClientIp=machine, token=machine, disagree, business/scene).
	h = sign(string(mpBody), base+"/algo/api/v2/image/upload"+reqID)
	h["cosy-clienttype"] = "10"
	h["cosy-clientip"] = sess.MachineID
	h["cosy-machinetoken"] = sess.MachineID
	h["cosy-data-policy"] = "disagree"
	h["cosy-business-product"] = "app"
	h["cosy-business-type"] = "agent"
	h["cosy-scene"] = "app"
	run("V7-magpie-hdrs", "PUT", base+"/algo/api/v2/image/upload"+reqID, mpBody, mpCT, h)

	// V8: body qoderEncoded + signed as encoded string, sent as encoded text.
	enc := qoderEncode(mpBody)
	h = sign(enc, base+"/algo/api/v2/image/upload"+reqID)
	run("V8-qoder-encoded", "PUT", base+"/algo/api/v2/image/upload"+reqID, []byte(enc), "application/json", h)

	// V9: encoded multipart + Encode=1 query (gateway decodes for the handler).
	encM := qoderEncode(mpBody)
	h = sign(encM, base+"/algo/api/v2/image/upload"+reqID+"&Encode=1")
	run("V9-enc+Encode=1", "PUT", base+"/algo/api/v2/image/upload"+reqID+"&Encode=1", []byte(encM), mpCT, h)

	// V10: encoded multipart, no Encode=1, content-type multipart.
	h = sign(encM, base+"/algo/api/v2/image/upload"+reqID)
	run("V10-enc-no-flag", "PUT", base+"/algo/api/v2/image/upload"+reqID, []byte(encM), mpCT, h)

	// V11: JSON body with base64 field guesses, encoded + Encode=1.
	b64 := base64.StdEncoding.EncodeToString(data)
	for _, shape := range []map[string]any{
		{"image": b64},
		{"file": b64},
		{"data": b64},
		{"fileName": "image.png", "image": b64},
	} {
		jb, _ := json.Marshal(shape)
		encJ := qoderEncode(jb)
		h = sign(encJ, base+"/algo/api/v2/image/upload"+reqID+"&Encode=1")
		run("V11-json-"+fmt.Sprint(len(shape))+"keys", "PUT", base+"/algo/api/v2/image/upload"+reqID+"&Encode=1", []byte(encJ), "application/json", h)
	}

	// V12: encoded multipart + Encode=1 with cosy-version 1.1.49 in payload+header.
	{
		payload := map[string]string{"cosyVersion": "1.1.49", "ideVersion": "", "info": sess.Info, "requestId": uuid.NewString(), "version": "v1"}
		pb, _ := json.Marshal(payload)
		payloadB64 := base64.StdEncoding.EncodeToString(pb)
		date := fmt.Sprintf("%d", time.Now().Unix())
		u12, _ := url.Parse(base + "/algo/api/v2/image/upload" + reqID + "&Encode=1")
		pathSig := strings.TrimPrefix(u12.Path, "/algo")
		sum := md5.Sum([]byte(payloadB64 + "\n" + sess.CosyKey + "\n" + date + "\n" + encM + "\n" + pathSig))
		hh := map[string]string{
			"cosy-data-policy": "AGREE", "cosy-machinetype": sess.MachineType, "cosy-clienttype": "5",
			"cosy-date": date, "cosy-user": sa.Account.UID, "cosy-key": sess.CosyKey,
			"accept": "application/json", "cosy-clientip": "169.254.198.161",
			"authorization":   "Bearer COSY." + payloadB64 + "." + hex.EncodeToString(sum[:]),
			"accept-encoding": "identity", "cosy-version": "1.1.49",
			"cosy-machineid": sess.MachineID, "cosy-machinetoken": sess.MachineToken,
			"login-version": "v2", "user-agent": "Go-http-client/2.0", "x-request-id": uuid.NewString(),
		}
		run("V12-enc+v1.1.49", "PUT", base+"/algo/api/v2/image/upload"+reqID+"&Encode=1", []byte(encM), mpCT, hh)
	}

	// V13: wire = qoderEncode(multipart), sig over the RAW multipart bytes
	// (hypothesis: multipart CT filter hashes the decoded form).
	h = sign(string(mpBody), base+"/algo/api/v2/image/upload"+reqID)
	run("V13-encwire-rawsig", "PUT", base+"/algo/api/v2/image/upload"+reqID, []byte(encM), mpCT, h)

	// V14: wire = raw multipart, sig over the FILE DATA bytes only
	// (hypothesis: filter hashes the parsed file part).
	h = sign(string(data), base+"/algo/api/v2/image/upload"+reqID)
	run("V14-filedata-sig", "PUT", base+"/algo/api/v2/image/upload"+reqID, mpBody, mpCT, h)

	// V15: wire = qoderEncode(multipart), sig over the FILE DATA bytes.
	h = sign(string(data), base+"/algo/api/v2/image/upload"+reqID)
	run("V15-encwire-datasig", "PUT", base+"/algo/api/v2/image/upload"+reqID, []byte(encM), mpCT, h)

	// V16 family: CT application/json + PLAIN JSON wire + sig over wire.
	// The json-CT filter hashes the raw wire bytes (V8 proved sig passes for
	// that path), so a plain-JSON API body with the right field shape may
	// reach the handler intact. Field-name sweep:
	b64data := base64.StdEncoding.EncodeToString(data)
	shapes := []struct {
		name string
		body string
	}{
		{"image", `{"image":"` + b64data + `"}`},
		{"file", `{"file":"` + b64data + `"}`},
		{"data", `{"data":"` + b64data + `"}`},
		{"imageBase64", `{"imageBase64":"` + b64data + `"}`},
		{"base64", `{"base64":"` + b64data + `"}`},
		{"content", `{"content":"` + b64data + `"}`},
		{"fileName+image", `{"fileName":"image.png","image":"` + b64data + `"}`},
		{"name+type+data", `{"name":"image.png","type":"image/png","data":"` + b64data + `"}`},
		{"file+contentType", `{"file":"` + b64data + `","contentType":"image/png"}`},
		{"fileName+contentType+data", `{"fileName":"image.png","contentType":"image/png","data":"` + b64data + `"}`},
	}
	for _, sh := range shapes {
		h = sign(sh.body, base+"/algo/api/v2/image/upload"+reqID)
		run("V16-"+sh.name, "PUT", base+"/algo/api/v2/image/upload"+reqID, []byte(sh.body), "application/json", h)
	}

	// V17: OFFICIAL dialect from the qodercli bundle (1.1.68): the image
	// upload goes to the CENTER endpoint (center.qoder.sh, no /algo prefix),
	// request_id is a dashless uuid, signature is the "auth" scheme (Bearer
	// device token — wasm-signed in the CLI; simplest hypothesis first).
	{
		nodash := strings.ReplaceAll(uuid.NewString(), "-", "")
		cURL := "https://center.qoder.sh/api/v2/image/upload?request_id=" + nodash
		hdr := map[string]string{
			"Authorization":       "Bearer " + sa.Auth.AccessToken,
			"Accept":              "application/json",
			"X-Request-Id":        nodash,
			"AI-CLIENT-TIMESTAMP": strconv.FormatInt(time.Now().Unix(), 10),
			"user-agent":          "Go-http-client/2.0",
		}
		run("V17-center-bearer", "PUT", cURL, mpBody, mpCT, hdr)
	}

	// V18: center with /algo prefix (in case the gateway expects it).
	{
		nodash := strings.ReplaceAll(uuid.NewString(), "-", "")
		cURL := "https://center.qoder.sh/algo/api/v2/image/upload?request_id=" + nodash
		hdr := map[string]string{
			"Authorization":       "Bearer " + sa.Auth.AccessToken,
			"Accept":              "application/json",
			"X-Request-Id":        nodash,
			"AI-CLIENT-TIMESTAMP": strconv.FormatInt(time.Now().Unix(), 10),
		}
		run("V18-center-algo", "PUT", cURL, mpBody, mpCT, hdr)
	}

	// V19: OFFICIAL dialect, reconstructed: center + /algo path, COSY bearer
	// from our session, but the wasm "auth" scheme never receives binary
	// bodies (prepareRequest only takes strings) — so the md5 body component
	// is EMPTY. Machine headers ride along (V18 proved the filter exists).
	centerSign := func(sigBody, sigPath string) map[string]string {
		payload := map[string]string{"cosyVersion": "0.1.43", "ideVersion": "", "info": sess.Info, "requestId": uuid.NewString(), "version": "v1"}
		pb, _ := json.Marshal(payload)
		payloadB64 := base64.StdEncoding.EncodeToString(pb)
		date := fmt.Sprintf("%d", time.Now().Unix())
		sum := md5.Sum([]byte(payloadB64 + "\n" + sess.CosyKey + "\n" + date + "\n" + sigBody + "\n" + sigPath))
		return map[string]string{
			"cosy-data-policy": "AGREE", "cosy-machinetype": sess.MachineType, "cosy-clienttype": "5",
			"cosy-date": date, "cosy-user": sa.Account.UID, "cosy-key": sess.CosyKey,
			"accept": "application/json", "cosy-clientip": "169.254.198.161",
			"authorization":   "Bearer COSY." + payloadB64 + "." + hex.EncodeToString(sum[:]),
			"accept-encoding": "identity", "cosy-version": "0.1.43",
			"cosy-machineid": sess.MachineID, "cosy-machinetoken": sess.MachineToken,
			"login-version": "v2", "user-agent": "Go-http-client/2.0",
			"x-request-id":        uuid.NewString(),
			"AI-CLIENT-TIMESTAMP": strconv.FormatInt(time.Now().Unix(), 10),
		}
	}
	{
		nodash := strings.ReplaceAll(uuid.NewString(), "-", "")
		cURL := "https://center.qoder.sh/algo/api/v2/image/upload?request_id=" + nodash
		h = centerSign("", "/api/v2/image/upload")
		run("V19-center-empty-body", "PUT", cURL, mpBody, mpCT, h)
	}
	{
		nodash := strings.ReplaceAll(uuid.NewString(), "-", "")
		cURL := "https://center.qoder.sh/algo/api/v2/image/upload?request_id=" + nodash
		h = centerSign("", "/api/v2/image/upload?request_id="+nodash)
		run("V19b-path-with-query", "PUT", cURL, mpBody, mpCT, h)
	}
	{
		nodash := strings.ReplaceAll(uuid.NewString(), "-", "")
		cURL := "https://center.qoder.sh/algo/api/v2/image/upload?request_id=" + nodash
		h = centerSign(string(mpBody), "/api/v2/image/upload")
		run("V19c-raw-body-sig", "PUT", cURL, mpBody, mpCT, h)
	}

	// V20: does api2 (the CLI 1.1.68 prod inference base) skip the 10605
	// datacenter queue that api3 enqueues? One minimal text chat tells.
	{
		nodash := strings.ReplaceAll(uuid.NewString(), "-", "")
		cURL := "https://api2.qoder.sh/algo/api/v2/image/upload?request_id=" + nodash
		h = centerSign("", "/api/v2/image/upload")
		run("V20-api2-empty-body", "PUT", cURL, mpBody, mpCT, h)
	}
}

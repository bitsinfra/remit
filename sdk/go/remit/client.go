package remit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Client submits remits as one identity.
type Client struct {
	Identity *Identity
	HTTP     *http.Client
}

// NewClient returns a client with a default HTTP client.
func NewClient(id *Identity) *Client {
	return &Client{Identity: id, HTTP: &http.Client{Timeout: 60 * time.Second}}
}

// SignRequest adds an RFC 9421 HTTP message signature (and Content-Digest).
func SignRequest(req *http.Request, body []byte, id *Identity, now time.Time) {
	d := sha256.Sum256(body)
	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(d[:]) + ":"
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	comps := [][2]string{{"@method", req.Method}, {"@authority", strings.ToLower(req.URL.Host)}, {"@path", path}, {"content-digest", digest}}
	if req.URL.RawQuery != "" {
		comps = append(comps, [2]string{"@query", "?" + req.URL.RawQuery})
	}
	var names, lines []string
	for _, c := range comps {
		names = append(names, `"`+c[0]+`"`)
		lines = append(lines, `"`+c[0]+`": `+c[1])
	}
	var nonce [12]byte
	_, _ = rand.Read(nonce[:])
	params := fmt.Sprintf(`(%s);created=%d;expires=%d;nonce="%x";alg="ed25519";keyid="%s";tag="remit"`, strings.Join(names, " "), now.Unix(), now.Unix()+60, nonce, id.KeyID)
	lines = append(lines, `"@signature-params": `+params)
	sig := ed25519.Sign(id.key, []byte(strings.Join(lines, "\n")))
	req.Header.Set("Content-Digest", digest)
	req.Header.Set("Signature-Input", "sig1="+params)
	req.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")
}

// Holder is a verified Holder catalog.
type Holder struct {
	c       *Client
	URL     string
	ID      string
	Catalog map[string]any
	Key     ed25519.PublicKey
}

// Diagnostic is a structured admission diagnostic.
type Diagnostic struct {
	Code    string   `json:"code"`
	Path    string   `json:"path"`
	Span    []uint64 `json:"span,omitempty"`
	Message string   `json:"message"`
	Hint    string   `json:"hint,omitempty"`
	Fix     []any    `json:"fix,omitempty"`
}

// Error is returned when a remit is not admitted or does not succeed.
type Error struct {
	Decision    string
	Status      string
	Diagnostics []Diagnostic
}

func (e *Error) Error() string {
	var parts []string
	for _, d := range e.Diagnostics {
		parts = append(parts, d.Code+" "+d.Path+": "+d.Message)
	}
	return fmt.Sprintf("remit %s/%s: %s", e.Decision, e.Status, strings.Join(parts, "; "))
}

// Result is a verified typed result.
type Result struct {
	Value      json.RawMessage
	Status     string
	Labels     []string
	Terms      map[string]any
	Receipt    map[string]any
	Envelope   Envelope
	Cached     bool
	ResultBits uint64
}

var sigRe = regexp.MustCompile(`sig="([^"]+)"`)

// Holder fetches and verifies a catalog. pin, if set, is the expected did:key.
func (c *Client) Holder(ctx context.Context, url, pin string) (*Holder, error) {
	url = strings.TrimRight(url, "/")
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url+"/.well-known/remit", nil)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var cat map[string]any
	if err := json.Unmarshal(body, &cat); err != nil {
		return nil, err
	}
	keys, _ := cat["keys"].([]any)
	if len(keys) == 0 {
		return nil, errors.New("catalog has no keys")
	}
	dk, _ := keys[0].(map[string]any)["did_key"].(string)
	if pin != "" && pin != dk {
		return nil, errors.New("catalog key does not match pinned key")
	}
	pk, err := PublicKeyFromDIDKey(dk)
	if err != nil {
		return nil, err
	}
	m := sigRe.FindStringSubmatch(resp.Header.Get("Remit-Signature"))
	if m == nil {
		return nil, errors.New("catalog is unsigned")
	}
	sig, _ := base64.StdEncoding.DecodeString(m[1])
	canon, err := Canonicalize(body)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pk, PAE(CatalogType, canon), sig) {
		return nil, errors.New("catalog signature does not verify")
	}
	id, _ := cat["holder"].(string)
	return &Holder{c: c, URL: url, ID: id, Catalog: cat, Key: pk}, nil
}

func (h *Holder) post(ctx context.Context, action string, env Envelope) (map[string]any, error) {
	b, _ := json.Marshal(env)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, h.URL+"/remit/v1/"+action, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/vnd.remit.envelope+json")
	SignRequest(req, b, h.c.Identity, time.Now())
	resp, err := h.c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	d := json.NewDecoder(resp.Body)
	d.UseNumber()
	return out, d.Decode(&out)
}

// Check runs admission only.
func (h *Holder) Check(ctx context.Context, m Manifest) (map[string]any, error) {
	m = h.bind(m)
	env, err := SignManifest(m, h.c.Identity)
	if err != nil {
		return nil, err
	}
	return h.post(ctx, "check", env)
}

func (h *Holder) bind(m Manifest) Manifest {
	m = Bind(m, h.c.Identity, 5*time.Minute)
	if m["holder"] == nil {
		m["holder"] = h.ID
	}
	return m
}

// Run signs, submits and verifies the receipt.
func (h *Holder) Run(ctx context.Context, m Manifest) (*Result, error) {
	if params, ok := m["params"].(map[string]any); ok || m["params"] == nil {
		if _, err := Capacity(m["returns"], params); err != nil {
			return nil, &Error{Decision: "rejected_locally", Diagnostics: []Diagnostic{{Code: "RMT-E0101", Path: "/returns", Message: err.Error()}}}
		}
	}
	m = h.bind(m)
	env, err := SignManifest(m, h.c.Identity)
	if err != nil {
		return nil, err
	}
	resp, err := h.post(ctx, "run", env)
	if err != nil {
		return nil, err
	}
	if d, _ := resp["decision"].(string); d != "" && d != "admitted" {
		raw, _ := json.Marshal(resp["diagnostics"])
		var ds []Diagnostic
		_ = json.Unmarshal(raw, &ds)
		return nil, &Error{Decision: d, Diagnostics: ds}
	}
	rawEnv, _ := json.Marshal(resp["receipt"])
	var renv Envelope
	if err := json.Unmarshal(rawEnv, &renv); err != nil {
		return nil, err
	}
	body, err := renv.Open(ReceiptType, h.Key)
	if err != nil {
		return nil, fmt.Errorf("receipt: %w", err)
	}
	var rc map[string]any
	if err := json.Unmarshal(body, &rc); err != nil {
		return nil, err
	}
	status, _ := resp["status"].(string)
	if status != "ok" {
		return nil, &Error{Decision: "admitted", Status: status}
	}
	if rc["status"] != "ok" || rc["decision"] != "admitted" {
		return nil, errors.New("receipt does not record a successful run")
	}
	want, _ := RemitID(m)
	wantP, _ := ParamsSHA256(m)
	if rc["remit_id"] != want || rc["params_sha256"] != wantP {
		return nil, errors.New("receipt does not match the submitted remit")
	}
	if rc["holder"] != h.ID || rc["sender"] != h.c.Identity.ID {
		return nil, errors.New("receipt names different parties")
	}
	canon, err := CanonicalizeValue(resp["result"])
	if err != nil || rc["result_sha256"] != "sha256:"+sha256Hex(canon) {
		return nil, errors.New("result does not match the signed receipt")
	}
	params, _ := m["params"].(map[string]any)
	if err := Validate(m["returns"], params, resp["result"]); err != nil {
		return nil, fmt.Errorf("result type: %w", err)
	}
	val, _ := json.Marshal(resp["result"])
	r := &Result{Value: val, Status: status, Receipt: rc, Envelope: renv}
	if ls, ok := rc["labels"].([]any); ok {
		for _, l := range ls {
			r.Labels = append(r.Labels, fmt.Sprint(l))
		}
	}
	r.Terms, _ = rc["terms"].(map[string]any)
	r.Cached, _ = resp["cached"].(bool)
	if n, ok := rc["result_bits_max"].(float64); ok {
		r.ResultBits = uint64(n)
	}
	return r, nil
}

// Query builds and runs a query-mode remit.
func (h *Holder) Query(ctx context.Context, sql string, returns any, params map[string]any, purpose string) (*Result, error) {
	ptypes := map[string]any{}
	for _, m := range regexp.MustCompile(`\$([A-Za-z_]\w*)`).FindAllStringSubmatch(sql, -1) {
		ptypes[m[1]] = inferType(params[m[1]])
	}
	read := map[string]any{"sql": sql, "max_rows": 1000}
	if len(ptypes) > 0 {
		read["params"] = ptypes
	}
	if params == nil {
		params = map[string]any{}
	}
	return h.Run(ctx, Manifest{"mode": "query", "purpose": purpose, "reads": map[string]any{"q": read}, "params": params, "returns": returns})
}

// Kernel builds and runs a kernel-mode remit.
func (h *Holder) Kernel(ctx context.Context, reads map[string]any, source string, returns any, params map[string]any, purpose string) (*Result, error) {
	return h.Run(ctx, Manifest{"mode": "kernel", "purpose": purpose, "reads": reads, "code": map[string]any{"source": source}, "params": params, "returns": returns})
}

var tsRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}`)

func inferType(v any) string {
	switch x := v.(type) {
	case bool:
		return "bool"
	case int, int64:
		return "int"
	case float64:
		if x == float64(int64(x)) {
			return "int"
		}
		return "float"
	case string:
		if tsRe.MatchString(x) {
			return "timestamp"
		}
	case time.Time:
		return "timestamp"
	}
	return "string"
}

// Package remit is the Go Sender SDK: JCS canonicalization, did:key
// identities, DSSE envelopes, Remit Type capacity, manifests and a client
// that verifies catalogs and receipts.
package remit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// ------------------------------------------------------------------ JCS

// Canonicalize returns the RFC 8785 canonical form of a JSON document.
func Canonicalize(doc []byte) ([]byte, error) {
	d := json.NewDecoder(bytes.NewReader(doc))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, errors.New("trailing JSON input")
	}
	var b bytes.Buffer
	if err := writeJCS(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// CanonicalizeValue canonicalizes any JSON-marshalable Go value.
func CanonicalizeValue(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return Canonicalize(raw)
}

func writeJCS(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case json.Number:
		s, err := esNumber(string(x))
		if err != nil {
			return err
		}
		b.WriteString(s)
	case string:
		writeString(b, x)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeJCS(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			if err := writeJCS(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("jcs: unsupported %T", v)
	}
	return nil
}

func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// esNumber formats a JSON number like ECMAScript Number.prototype.toString.
func esNumber(lit string) (string, error) {
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return "", fmt.Errorf("jcs: bad number %q", lit)
	}
	if f == 0 {
		return "0", nil
	}
	neg := f < 0
	if neg {
		f = -f
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // d.ddddde±XX
	mant, expS, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	exp, _ := strconv.Atoi(expS)
	n := exp + 1
	var s string
	switch {
	case n >= len(digits) && n <= 21:
		s = digits + strings.Repeat("0", n-len(digits))
	case n > 0 && n <= 21:
		s = digits[:n] + "." + digits[n:]
	case n <= 0 && n > -6:
		s = "0." + strings.Repeat("0", -n) + digits
	default:
		sign := "+"
		if n-1 < 0 {
			sign = "-"
		}
		m := digits[:1]
		if len(digits) > 1 {
			m += "." + digits[1:]
		}
		s = m + "e" + sign + strconv.Itoa(abs(n-1))
	}
	if neg {
		s = "-" + s
	}
	return s, nil
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ------------------------------------------------------------- identity

const b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58(b []byte) string {
	n := new(big.Int).SetBytes(b)
	var out []byte
	mod := new(big.Int)
	for n.Sign() > 0 {
		n.DivMod(n, big.NewInt(58), mod)
		out = append([]byte{b58[mod.Int64()]}, out...)
	}
	for _, c := range b {
		if c != 0 {
			break
		}
		out = append([]byte{'1'}, out...)
	}
	return string(out)
}

func unbase58(s string) ([]byte, error) {
	n := new(big.Int)
	for _, c := range s {
		i := strings.IndexRune(b58, c)
		if i < 0 {
			return nil, errors.New("bad base58")
		}
		n.Mul(n, big.NewInt(58)).Add(n, big.NewInt(int64(i)))
	}
	out := n.Bytes()
	for _, c := range s {
		if c != '1' {
			break
		}
		out = append([]byte{0}, out...)
	}
	return out, nil
}

// DIDKey returns the did:key for an Ed25519 public key.
func DIDKey(pk ed25519.PublicKey) string {
	return "did:key:z" + base58(append([]byte{0xed, 0x01}, pk...))
}

// PublicKeyFromDIDKey extracts the Ed25519 key from a did:key (optionally #fragment).
func PublicKeyFromDIDKey(id string) (ed25519.PublicKey, error) {
	base, _, _ := strings.Cut(id, "#")
	if !strings.HasPrefix(base, "did:key:z") {
		return nil, errors.New("not a did:key")
	}
	b, err := unbase58(base[len("did:key:z"):])
	if err != nil || len(b) != 34 || b[0] != 0xed || b[1] != 0x01 {
		return nil, errors.New("not an Ed25519 did:key")
	}
	return ed25519.PublicKey(b[2:]), nil
}

// Identity is a DID plus an Ed25519 key (file format of `remit keygen`).
type Identity struct {
	ID    string
	KeyID string
	key   ed25519.PrivateKey
}

func identityFromSeed(seed []byte, id string) *Identity {
	k := ed25519.NewKeyFromSeed(seed)
	dk := DIDKey(k.Public().(ed25519.PublicKey))
	if id == "" {
		id = dk
	}
	kid := id
	if !strings.HasPrefix(id, "did:key:") {
		kid = id + "#" + strings.TrimPrefix(dk, "did:key:")
	}
	return &Identity{ID: id, KeyID: kid, key: k}
}

// GenerateIdentity creates a fresh identity (did:key when id is empty).
func GenerateIdentity(id string) (*Identity, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return identityFromSeed(seed, id), nil
}

// LoadIdentity reads a `remit keygen` identity file.
func LoadIdentity(path string) (*Identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f struct {
		ID        string `json:"id"`
		SecretKey string `json:"secret_key"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(f.SecretKey)
	if err != nil || len(seed) != 32 {
		return nil, errors.New("identity secret_key must be 32 base64 bytes")
	}
	return identityFromSeed(seed, f.ID), nil
}

// PublicKey returns the identity's public key.
func (i *Identity) PublicKey() ed25519.PublicKey { return i.key.Public().(ed25519.PublicKey) }

// DIDKey returns the identity's did:key.
func (i *Identity) DIDKey() string { return DIDKey(i.PublicKey()) }

// ------------------------------------------------------------- DSSE

const (
	ManifestType = "application/vnd.remit.manifest+json"
	ReceiptType  = "application/vnd.remit.receipt+json"
	CatalogType  = "application/vnd.remit.catalog+json"
)

type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// PAE is the DSSE pre-authentication encoding.
func PAE(typ string, body []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(typ), typ, len(body), body))
}

// Sign wraps body in a DSSE envelope.
func (i *Identity) Sign(typ string, body []byte) Envelope {
	sig := ed25519.Sign(i.key, PAE(typ, body))
	return Envelope{PayloadType: typ, Payload: base64.StdEncoding.EncodeToString(body), Signatures: []Signature{{KeyID: i.KeyID, Sig: base64.StdEncoding.EncodeToString(sig)}}}
}

// Open verifies an envelope against key and returns its payload.
func (e Envelope) Open(typ string, key ed25519.PublicKey) ([]byte, error) {
	if e.PayloadType != typ {
		return nil, fmt.Errorf("payloadType must be %s", typ)
	}
	body, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return nil, err
	}
	for _, s := range e.Signatures {
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err == nil && ed25519.Verify(key, PAE(typ, body), sig) {
			return body, nil
		}
	}
	return nil, errors.New("envelope signature does not verify")
}

// ------------------------------------------------------------- manifest

// Manifest is the remit manifest (spec/manifest.md). Types are plain JSON.
type Manifest map[string]any

// RemitID is sha256 over JCS({remit, mode, purpose, reads, code', limits, returns}).
func RemitID(m Manifest) (string, error) {
	var code any
	if c, ok := m["code"].(map[string]any); ok {
		entry := "main"
		if e, ok := c["entry"].(string); ok {
			entry = e
		}
		h := strings.ToLower(strings.TrimPrefix(fmt.Sprint(c["source_sha256"]), "sha256:"))
		code = map[string]any{"lang": c["lang"], "entry": entry, "source_sha256": h}
	}
	reads := map[string]any{}
	if rs, ok := m["reads"].(map[string]any); ok {
		for k, r := range rs {
			rm, _ := r.(map[string]any)
			calls := rm["max_calls"]
			if calls == nil {
				calls = 1
			}
			out := map[string]any{"sql": rm["sql"], "max_rows": rm["max_rows"], "max_calls": calls}
			if p, ok := rm["params"].(map[string]any); ok && len(p) > 0 {
				out["params"] = p
			}
			reads[k] = out
		}
	}
	limits := m["limits"]
	if limits == nil {
		limits = map[string]any{}
	}
	b, err := CanonicalizeValue(map[string]any{"remit": m["remit"], "mode": m["mode"], "purpose": m["purpose"], "reads": reads, "code": code, "limits": limits, "returns": m["returns"]})
	if err != nil {
		return "", err
	}
	return "sha256:" + sha256Hex(b), nil
}

// ParamsSHA256 hashes the manifest params (empty object for templates).
func ParamsSHA256(m Manifest) (string, error) {
	p := m["params"]
	if p == nil {
		p = map[string]any{}
	}
	b, err := CanonicalizeValue(p)
	if err != nil {
		return "", err
	}
	return "sha256:" + sha256Hex(b), nil
}

func cloneValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, item := range x {
			out[k] = cloneValue(item)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = cloneValue(item)
		}
		return out
	default:
		return v
	}
}

// Bind fills sender, timestamps and nonce.
func Bind(m Manifest, id *Identity, ttl time.Duration) Manifest {
	out := Manifest{}
	for k, v := range m {
		out[k] = cloneValue(v)
	}
	if out["remit"] == nil {
		out["remit"] = "0.1"
	}
	now := time.Now().UTC().Truncate(time.Second)
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	out["sender"] = id.ID
	out["issued_at"] = now.Format(time.RFC3339)
	out["expires_at"] = now.Add(ttl).Format(time.RFC3339)
	out["nonce"] = hex.EncodeToString(nonce)
	if out["limits"] == nil {
		out["limits"] = map[string]any{}
	}
	if rs, ok := out["reads"].(map[string]any); ok {
		for _, r := range rs {
			if rm, ok := r.(map[string]any); ok && rm["max_calls"] == nil {
				rm["max_calls"] = 1
			}
		}
	}
	if c, ok := out["code"].(map[string]any); ok {
		if src, ok := c["source"].(string); ok {
			c["source_sha256"] = sha256Hex([]byte(src))
		}
		if c["lang"] == nil {
			c["lang"] = "js/es2023"
		}
		if c["entry"] == nil {
			c["entry"] = "main"
		}
	}
	return out
}

// SignManifest JCS-canonicalizes and signs a manifest.
func SignManifest(m Manifest, id *Identity) (Envelope, error) {
	b, err := CanonicalizeValue(m)
	if err != nil {
		return Envelope{}, err
	}
	return id.Sign(ManifestType, b), nil
}

// ------------------------------------------------------------- capacity

var charsets = map[string]float64{"digits": 10, "hex": 22, "alpha": 52, "alnum": 62, "base64": 67, "ascii": 95, "unicode": 1_112_064}

// StatusBits is ⌈log2 |status set|⌉.
const StatusBits = 3

// TypeError is an unbounded or invalid type.
type TypeError struct{ Code, Path, Msg string }

func (e *TypeError) Error() string { return e.Code + " at " + e.Path + ": " + e.Msg }

var durRe = regexp.MustCompile(`(\d+(?:\.\d+)?)(ms|s|min|m|h|d|w)`)

func duration(v any) (float64, error) {
	if n, ok := num(v); ok {
		return n, nil
	}
	switch x := v.(type) {
	case float64:
		return x, nil
	case json.Number:
		return x.Float64()
	case string:
		ms := map[string]float64{"ms": 1, "s": 1e3, "m": 6e4, "min": 6e4, "h": 36e5, "d": 864e5, "w": 6048e5}
		total, pos := 0.0, 0
		for _, m := range durRe.FindAllStringSubmatchIndex(x, -1) {
			if m[0] != pos {
				return 0, errors.New("bad duration")
			}
			f, _ := strconv.ParseFloat(x[m[2]:m[3]], 64)
			total += f * ms[x[m[4]:m[5]]]
			pos = m[1]
		}
		if pos != len(x) || pos == 0 {
			return 0, errors.New("bad duration")
		}
		return math.Round(total), nil
	}
	return 0, errors.New("bad duration")
}

func num(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int8:
		return float64(x), true
	case int16:
		return float64(x), true
	case int32:
		return float64(x), true
	case int64:
		return float64(x), true
	case uint:
		return float64(x), true
	case uint8:
		return float64(x), true
	case uint16:
		return float64(x), true
	case uint32:
		return float64(x), true
	case uint64:
		return float64(x), true
	case float32:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	}
	return 0, false
}

func tsMillis(v any) (float64, bool) {
	if s, ok := v.(string); ok {
		t, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			if d, err2 := time.Parse("2006-01-02", s); err2 == nil {
				return float64(d.UnixMilli()), true
			}
			return 0, false
		}
		return float64(t.UnixMilli()), true
	}
	return num(v)
}

func log2c(n float64) float64 {
	if n <= 1 {
		return 0
	}
	return math.Log2(n)
}

// Capacity returns the capacity in bits of a Remit Type bound with params.
func Capacity(rt any, params map[string]any) (float64, error) {
	normalized, err := jsonValue(rt)
	if err != nil {
		return 0, err
	}
	return capacity(normalized, params, "")
}

func jsonValue(value any) (any, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var out any
	err = decoder.Decode(&out)
	return out, err
}

const (
	maxTimeMS = 8_640_000_000_000_000
	maxLen    = 1 << 24
)

// strict rejects what the Rust implementation rejects, before any arithmetic.
func strict(k string, body any, p, path string, get func(string) (any, error)) error {
	b, isObj := body.(map[string]any)
	bad := func(code, f, msg string) error {
		if f != "" {
			f = "/" + f
		}
		return &TypeError{code, p + f, msg}
	}
	number := func(f string, integer bool) (float64, error) {
		v, err := get(f)
		if err != nil {
			return 0, err
		}
		x, ok := num(v)
		if !ok || math.IsNaN(x) || math.IsInf(x, 0) || (integer && x != math.Trunc(x)) {
			return 0, bad("RMT-E0103", f, "must be a finite number")
		}
		return x, nil
	}
	length := func(f string) error {
		x, err := number(f, true)
		if err != nil {
			return err
		}
		if x < 0 {
			return bad("RMT-E0103", f, "must be non-negative")
		}
		if x > maxLen {
			return bad("RMT-E0106", f, "too large")
		}
		return nil
	}
	span := func(lo, hi float64) error {
		if lo > hi {
			return &TypeError{"RMT-E0105", path + "/", "empty range"}
		}
		return nil
	}
	moment := func(f string) (float64, error) {
		v, err := get(f)
		if err != nil {
			return 0, err
		}
		t, ok := tsMillis(v)
		if !ok || t != math.Trunc(t) || math.Abs(t) > maxTimeMS {
			return 0, bad("RMT-E0103", f, "must be an RFC 3339 timestamp or epoch ms")
		}
		return t, nil
	}
	dur := func(f string) (float64, error) {
		v, err := get(f)
		if err != nil {
			return 0, err
		}
		d, err := duration(v)
		if err != nil || d <= 0 || d > maxTimeMS || d != math.Trunc(d) {
			return 0, bad("RMT-E0107", f, "must be a positive duration")
		}
		return d, nil
	}
	switch k {
	case "int", "float", "decimal", "string", "timestamp", "date", "bytes", "list", "table", "struct":
		if !isObj {
			return bad("RMT-E0103", "", "`"+k+"` expects an object of constraints")
		}
	}
	switch k {
	case "int", "float", "decimal":
		if k == "decimal" {
			if sc, ok := num(b["scale"]); !ok || sc != math.Trunc(sc) || sc < 0 || sc > 18 {
				return bad("RMT-E0101", "scale", "`scale` (0..=18) is required")
			}
		}
		lo, err := number("min", k == "int")
		if err != nil {
			return err
		}
		hi, err := number("max", k == "int")
		if err != nil {
			return err
		}
		if err := span(lo, hi); err != nil {
			return err
		}
		if k == "float" && b["precision"] != nil {
			if pr, err := number("precision", false); err != nil {
				return err
			} else if pr <= 0 {
				return bad("RMT-E0103", "precision", "must be > 0")
			}
		}
	case "enum":
		vals, ok := body.([]any)
		if !ok && isObj {
			vals, ok = b["values"].([]any)
		}
		if !ok {
			return bad("RMT-E0101", "", "`enum` needs a list of values")
		}
		seen := map[string]bool{}
		for _, v := range vals {
			s, ok := v.(string)
			if !ok || seen[s] {
				return bad("RMT-E0103", "", "enum values must be distinct strings")
			}
			seen[s] = true
		}
		if len(vals) < 1 || len(vals) > 65536 {
			return bad("RMT-E0106", "", "enum must have 1..=65536 values")
		}
	case "string":
		if c, present := b["charset"]; present {
			s, ok := c.(string)
			if _, known := charsets[s]; !ok || !known {
				return bad("RMT-E0103", "charset", "unknown charset")
			}
		}
		return length("max_len")
	case "bytes":
		return length("max_len")
	case "timestamp", "date":
		lo, err := moment("min")
		if err != nil {
			return err
		}
		hi, err := moment("max")
		if err != nil {
			return err
		}
		if err := span(lo, hi); err != nil {
			return err
		}
		if k == "timestamp" || b["granularity"] != nil {
			d, err := dur("granularity")
			if err != nil {
				return err
			}
			if k == "date" && math.Mod(d, 86_400_000) != 0 {
				return bad("RMT-E0107", "granularity", "date granularity must be whole days")
			}
		}
	case "list", "table":
		of, ok := b["of"]
		if !ok {
			return bad("RMT-E0101", "of", "`"+k+"` needs `of`")
		}
		if k == "table" {
			if m, ok := of.(map[string]any); !ok || m["struct"] == nil {
				return bad("RMT-E0103", "of", "`table` rows must be a struct")
			}
			return length("max_rows")
		}
		return length("max")
	case "struct":
		for f := range b {
			if len(f) < 1 || len(f) > 128 {
				return bad("RMT-E0103", "", "struct field names must be 1..=128 bytes")
			}
		}
	}
	return nil
}

func capacity(rt any, params map[string]any, path string) (float64, error) {
	if s, ok := rt.(string); ok {
		if s == "bool" {
			return 1, nil
		}
		return 0, &TypeError{"RMT-E0101", "/", "type `" + s + "` needs constraints"}
	}
	o, ok := rt.(map[string]any)
	if !ok || len(o) != 1 {
		return 0, &TypeError{"RMT-E0102", path + "/", "a type is \"bool\" or a single-key object"}
	}
	var k string
	var body any
	for kk, vv := range o {
		k, body = kk, vv
	}
	p := path + "/" + k
	b, _ := body.(map[string]any)
	get := func(f string) (any, error) {
		v, ok := b[f]
		if !ok || v == nil {
			return nil, &TypeError{"RMT-E0101", p + "/" + f, "`" + f + "` is required: every Remit Type must be bounded"}
		}
		if s, ok := v.(string); ok && strings.HasPrefix(s, "$") {
			pv, ok := params[s[1:]]
			if !ok {
				return nil, &TypeError{"RMT-E0104", p + "/" + f, "bound references param `" + s + "`, which is not provided"}
			}
			return pv, nil
		}
		return v, nil
	}
	nf := func(f string) (float64, error) {
		v, err := get(f)
		if err != nil {
			return 0, err
		}
		x, ok := num(v)
		if !ok {
			return 0, &TypeError{"RMT-E0103", p + "/" + f, "must be a number"}
		}
		return x, nil
	}
	if err := strict(k, body, p, path, get); err != nil {
		return 0, err
	}
	switch k {
	case "bool":
		return 1, nil
	case "int":
		lo, err := nf("min")
		if err != nil {
			return 0, err
		}
		hi, err := nf("max")
		if err != nil {
			return 0, err
		}
		if lo > hi {
			return 0, &TypeError{"RMT-E0105", path + "/", "empty range"}
		}
		return log2c(hi - lo + 1), nil
	case "float":
		lo, err := nf("min")
		if err != nil {
			return 0, err
		}
		hi, err := nf("max")
		if err != nil {
			return 0, err
		}
		if b["precision"] == nil {
			return 64, nil
		}
		pr, err := nf("precision")
		if err != nil {
			return 0, err
		}
		return log2c(math.Floor((hi-lo)/pr+1e-9) + 1), nil
	case "decimal":
		lo, err := nf("min")
		if err != nil {
			return 0, err
		}
		hi, err := nf("max")
		if err != nil {
			return 0, err
		}
		sc, _ := num(b["scale"])
		return log2c(math.Round((hi-lo)*math.Pow(10, sc)) + 1), nil
	case "enum":
		if a, ok := body.([]any); ok {
			return log2c(float64(len(a))), nil
		}
		a, _ := b["values"].([]any)
		return log2c(float64(len(a))), nil
	case "string":
		l, err := nf("max_len")
		if err != nil {
			return 0, err
		}
		cs := "unicode"
		if c, ok := b["charset"].(string); ok {
			cs = c
		}
		return l*math.Log2(charsets[cs]) + math.Log2(l+1), nil
	case "timestamp", "date":
		lv, err := get("min")
		if err != nil {
			return 0, err
		}
		hv, err := get("max")
		if err != nil {
			return 0, err
		}
		lo, _ := tsMillis(lv)
		hi, _ := tsMillis(hv)
		g := 864e5
		if k == "timestamp" || b["granularity"] != nil {
			gv, err := get("granularity")
			if err != nil {
				return 0, err
			}
			if g, err = duration(gv); err != nil {
				return 0, &TypeError{"RMT-E0107", p + "/granularity", err.Error()}
			}
		}
		return log2c(math.Trunc((hi-lo)/g) + 1), nil
	case "bytes":
		l, err := nf("max_len")
		if err != nil {
			return 0, err
		}
		return 8*l + math.Log2(l+1), nil
	case "list", "table":
		f := "max"
		if k == "table" {
			f = "max_rows"
		}
		m, err := nf(f)
		if err != nil {
			return 0, err
		}
		of, ok := b["of"]
		if !ok {
			return 0, &TypeError{"RMT-E0101", p + "/of", "needs `of`"}
		}
		c, err := capacity(of, params, p+"/of")
		if err != nil {
			return 0, err
		}
		return math.Log2(m+1) + m*c, nil
	case "struct":
		sum := 0.0
		for f, ft := range b {
			c, err := capacity(ft, params, p+"/"+f)
			if err != nil {
				return 0, err
			}
			sum += c
		}
		return sum, nil
	case "optional":
		c, err := capacity(body, params, p)
		if err != nil {
			return 0, err
		}
		return c + math.Log2(1+math.Pow(2, -c)), nil
	}
	return 0, &TypeError{"RMT-E0102", path + "/", "unknown type `" + k + "`"}
}

// CapacityCeil rounds capacity up to whole bits.
func CapacityCeil(bits float64) uint64 {
	c := math.Ceil(bits - 1e-9)
	if c < 0 {
		return 0
	}
	return uint64(c)
}

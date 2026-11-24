package remit

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func vectors(t *testing.T, name string) []byte {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "conformance", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestJCSVectors(t *testing.T) {
	var cases []struct {
		Input     json.RawMessage `json:"input"`
		Canonical string          `json:"canonical"`
	}
	if err := json.Unmarshal(vectors(t, "jcs.json"), &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		got, err := Canonicalize(c.Input)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != c.Canonical {
			t.Errorf("got %s want %s", got, c.Canonical)
		}
	}
}

func TestCapacityVectors(t *testing.T) {
	var v struct {
		Valid []struct {
			Name     string         `json:"name"`
			Returns  any            `json:"returns"`
			Params   map[string]any `json:"params"`
			Bits     float64        `json:"bits"`
			BitsCeil uint64         `json:"bits_ceil"`
		} `json:"valid"`
		Invalid []struct {
			Name    string `json:"name"`
			Returns any    `json:"returns"`
			Code    string `json:"code"`
		} `json:"invalid"`
	}
	if err := json.Unmarshal(vectors(t, "capacity.json"), &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Valid {
		b, err := Capacity(c.Returns, c.Params)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if math.Abs(b-c.Bits) > 1e-6 || CapacityCeil(b) != c.BitsCeil {
			t.Errorf("%s: got %v (%d) want %v (%d)", c.Name, b, CapacityCeil(b), c.Bits, c.BitsCeil)
		}
	}
	for _, c := range v.Invalid {
		_, err := Capacity(c.Returns, map[string]any{})
		te, ok := err.(*TypeError)
		if !ok || te.Code != c.Code {
			t.Errorf("%s: got %v want %s", c.Name, err, c.Code)
		}
	}
}

func TestRemitIDVectors(t *testing.T) {
	var cases []struct {
		Manifest     Manifest `json:"manifest"`
		RemitID      string   `json:"remit_id"`
		ParamsSHA256 string   `json:"params_sha256"`
	}
	if err := json.Unmarshal(vectors(t, "remit_id.json"), &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		id, err := RemitID(c.Manifest)
		if err != nil || id != c.RemitID {
			t.Errorf("remit_id: got %s want %s (%v)", id, c.RemitID, err)
		}
		p, _ := ParamsSHA256(c.Manifest)
		if p != c.ParamsSHA256 {
			t.Errorf("params: got %s want %s", p, c.ParamsSHA256)
		}
	}
}

func TestIdentityInterop(t *testing.T) {
	id, err := LoadIdentity(filepath.Join("..", "..", "..", "examples", "personal-vault", "keys", "travel-agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]string
	b, _ := os.ReadFile(filepath.Join("..", "..", "..", "examples", "personal-vault", "keys", "travel-agent.json"))
	_ = json.Unmarshal(b, &f)
	if id.DIDKey() != f["public_key"] {
		t.Fatalf("did:key mismatch %s vs %s", id.DIDKey(), f["public_key"])
	}
	env := id.Sign(ManifestType, []byte("{}"))
	if _, err := env.Open(ManifestType, id.PublicKey()); err != nil {
		t.Fatal(err)
	}
}

// Live test against the personal-vault example (REMIT_TEST_HOLDER=http://127.0.0.1:8443).
func TestLiveQuery(t *testing.T) {
	url := os.Getenv("REMIT_TEST_HOLDER")
	if url == "" {
		t.Skip("REMIT_TEST_HOLDER not set")
	}
	id, err := LoadIdentity(filepath.Join("..", "..", "..", "examples", "personal-vault", "keys", "travel-agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	h, err := NewClient(id).Holder(ctx, url, "")
	if err != nil {
		t.Fatal(err)
	}
	r, err := h.Query(ctx, "SELECT COUNT(*) AS n FROM calendar.events WHERE start_at < $until AND end_at > $from AND status <> 'cancelled'",
		map[string]any{"int": map[string]any{"min": 0, "max": 64}},
		map[string]any{"from": "2026-11-24T00:00:00Z", "until": "2026-11-26T00:00:00Z"}, "scheduling")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("value=%s bits≤%d labels=%v", r.Value, r.ResultBits, r.Labels)
	_, err = h.Query(ctx, "SELECT title FROM calendar.events", map[string]any{"list": map[string]any{"max": 3, "of": map[string]any{"struct": map[string]any{"title": map[string]any{"string": map[string]any{"max_len": 10}}}}}}, nil, "scheduling")
	if e, ok := err.(*Error); !ok || e.Decision != "rejected" {
		t.Fatalf("expected rejection, got %v", err)
	}
}

func TestNativeTypesAndJSONBoundaries(t *testing.T) {
	for _, rt := range []any{
		map[string]any{"enum": []string{"a", "b"}},
		map[string]any{"int": map[string]any{"min": int64(0), "max": int64(10)}},
		map[string]any{"timestamp": map[string]any{"min": 0, "max": 10000, "granularity": 1000}},
	} {
		if _, err := Capacity(rt, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Canonicalize([]byte("1 2")); err == nil {
		t.Fatal("accepted trailing document")
	}
	identity, _ := GenerateIdentity("")
	read := map[string]any{"sql": "SELECT 1", "max_rows": 1}
	manifest := Manifest{"reads": map[string]any{"q": read}}
	Bind(manifest, identity, time.Minute)
	if _, present := read["max_calls"]; present {
		t.Fatal("template changed")
	}
}

func TestResultValidation(t *testing.T) {
	rt := map[string]any{"struct": map[string]any{
		"count":  map[string]any{"int": map[string]any{"min": 0, "max": 10}},
		"region": map[string]any{"enum": []string{"EMEA", "AMER"}},
	}}
	if err := Validate(rt, nil, map[string]any{"count": 3, "region": "EMEA"}); err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{
		map[string]any{"count": 11, "region": "EMEA"},
		map[string]any{"count": 3, "region": "unknown"},
		map[string]any{"count": 3, "region": "EMEA", "extra": true},
	} {
		if err := Validate(rt, nil, value); err == nil {
			t.Fatalf("accepted %v", value)
		}
	}
}

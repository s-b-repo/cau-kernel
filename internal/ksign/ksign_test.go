package ksign

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

type doc struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

func TestWrapOpenUnsigned(t *testing.T) {
	env, err := Wrap(doc{"x", 1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if env.Signature != "" {
		t.Error("unsigned wrap has a signature")
	}
	var got doc
	if err := env.Open(&got, nil); err != nil || got.Name != "x" || got.Value != 1 {
		t.Errorf("open: %v %+v", err, got)
	}
}

func TestSignedRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	env, err := Wrap(doc{"y", 2}, priv)
	if err != nil {
		t.Fatal(err)
	}
	if env.Signature == "" {
		t.Fatal("signed wrap has no signature")
	}
	var got doc
	if err := env.Open(&got, pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Name != "y" {
		t.Errorf("payload: %+v", got)
	}
}

func TestTamperedPayloadFailsSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	env, _ := Wrap(doc{"y", 2}, priv)
	env.Payload = append(env.Payload, ' ') // tamper after signing
	var got doc
	if err := env.Open(&got, pub); !errors.Is(err, ErrBadSignature) {
		t.Errorf("tampered payload verified: %v", err)
	}
}

func TestWrongKeyAndRequiredButUnsigned(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	env, _ := Wrap(doc{"y", 2}, priv)
	var got doc
	if err := env.Open(&got, other); !errors.Is(err, ErrBadSignature) {
		t.Errorf("wrong key accepted: %v", err)
	}
	unsigned, _ := Wrap(doc{"z", 3}, nil)
	if err := unsigned.Open(&got, pub); !errors.Is(err, ErrBadSignature) {
		t.Errorf("required-but-unsigned: %v", err)
	}
}

// TestSignedSurvivesMarshalRoundTrip guards the subtle failure where indented
// serialization re-serializes the signed RawMessage payload and breaks the
// signature. Persisting via Marshal/Unmarshal must preserve verification.
func TestSignedSurvivesMarshalRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	env, err := Wrap(doc{"persisted", 7}, priv)
	if err != nil {
		t.Fatal(err)
	}
	data, err := Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}
	var got doc
	if err := back.Open(&got, pub); err != nil {
		t.Fatalf("signature broke across Marshal/Unmarshal: %v", err)
	}
	if got.Name != "persisted" || got.Value != 7 {
		t.Errorf("payload wrong after round-trip: %+v", got)
	}
}

func TestParseKeys(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := ParsePublicKey([]byte(hx(pub))); err != nil {
		t.Errorf("pub: %v", err)
	}
	if _, err := ParsePrivateKey([]byte(hx(priv.Seed()))); err != nil {
		t.Errorf("priv seed: %v", err)
	}
	if _, err := ParsePublicKey([]byte("zz")); err == nil {
		t.Error("bad pub accepted")
	}
}

func hx(b []byte) string {
	const h = "0123456789abcdef"
	o := make([]byte, len(b)*2)
	for i, c := range b {
		o[i*2] = h[c>>4]
		o[i*2+1] = h[c&0x0f]
	}
	return string(o)
}

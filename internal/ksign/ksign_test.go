package ksign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/s-b-repo/cau-kernel/internal/kstate"
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

// A signed baseline whose signature cannot be checked is refused, not read.
//
// The caller that cannot check the signature is the one who cannot tell a
// genuine baseline from one an attacker rewrote: an attacker with write access
// to the baseline file rewrites the payload too, and a run that then reports
// "no drift" is reporting what the attacker wanted it to report.
func TestASignedBaselineWithoutAKeyIsRefused(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	env, _ := Wrap(doc{"y", 2}, priv)
	var got doc
	if err := env.Open(&got, nil); !errors.Is(err, ErrBadSignature) {
		t.Errorf("a signed baseline was read without its key: %v", err)
	}
	// An unsigned baseline is still readable without a key: there is
	// nothing to check.
	unsigned, _ := Wrap(doc{"z", 3}, nil)
	if err := unsigned.Open(&got, nil); err != nil {
		t.Errorf("an unsigned baseline was refused: %v", err)
	}
}

// A key of the wrong length is an error, not a panic: ed25519.Sign panics on
// one, and Wrap is exported.
func TestWrapRefusesAMalformedPrivateKey(t *testing.T) {
	if _, err := Wrap(doc{"y", 2}, ed25519.PrivateKey("too short")); err == nil {
		t.Fatal("a malformed private key was accepted")
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
	if _, err := ParsePrivateKey([]byte(hx(priv))); err != nil {
		t.Errorf("priv full (consistent halves): %v", err)
	}
	if _, err := ParsePublicKey([]byte("zz")); err == nil {
		t.Error("bad pub accepted")
	}
}

// TestDomainSeparatesDocumentKinds is the regression test for the swap attack:
// both kinds of baseline are signed with the same key, so an attacker without
// the key could move a signed drift baseline (a Snapshot) over the attest
// baseline file. Unmarshaling a Snapshot's JSON into a Measured yields zeroes,
// so without domain separation `attest verify` reports a false clean. The
// domain check must reject the swap with NO key at all.
func TestDomainSeparatesDocumentKinds(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	snap := kstate.Snapshot{Modules: []kstate.Module{{Name: "nf_tables", State: "Live"}}}
	env, err := Wrap(snap, priv)
	if err != nil {
		t.Fatal(err)
	}
	if env.Domain != "cau-kernel/kstate.Snapshot" {
		t.Fatalf("snapshot domain = %q, want cau-kernel/kstate.Snapshot", env.Domain)
	}

	// Why domain separation is the only defense for this attack: the Snapshot
	// payload unmarshals into a Measured as all-zeroes (nil PCRs, IMACount 0,
	// CrashKernelLoaded false) — a DiffMeasured no-op, i.e. a false "clean".
	var zero kstate.Measured
	if err := json.Unmarshal(env.Payload, &zero); err != nil {
		t.Fatal(err)
	}
	if zero.PCRs != nil || zero.IMACount != 0 || zero.IMAViolations != 0 || zero.Kdump.CrashKernelLoaded {
		t.Errorf("snapshot payload did not unmarshal into a Measured as zeroes: %+v", zero)
	}

	// The swap must fail without a key AND with the correct key.
	var gotM kstate.Measured
	err = env.Open(&gotM, nil)
	if err == nil || !strings.Contains(err.Error(), "kstate.Measured") {
		t.Errorf("snapshot opened as measured without a key: %v", err)
	}
	if err := env.Open(&gotM, pub); err == nil {
		t.Error("snapshot opened as measured even with the matching key")
	}

	// ...and the reverse direction: a Measured baseline must not open as a Snapshot.
	menv, err := Wrap(kstate.Measured{PCRBank: "sha256", PCRs: map[string]string{"0": "aabb"}}, priv)
	if err != nil {
		t.Fatal(err)
	}
	if menv.Domain != "cau-kernel/kstate.Measured" {
		t.Fatalf("measured domain = %q, want cau-kernel/kstate.Measured", menv.Domain)
	}
	var gotS kstate.Snapshot
	if err := menv.Open(&gotS, pub); err == nil {
		t.Error("measured opened as snapshot")
	}
}

// TestMeasuredRoundTripAndPointerDomain pins the happy path the attest command
// depends on: a Measured baseline signed with the key verifies with it, and a
// pointer value (Wrap(&Measured{})) shares its element's domain (Open(&m)).
func TestMeasuredRoundTripAndPointerDomain(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := kstate.Measured{
		PCRBank:      "sha256",
		PCRs:         map[string]string{"0": "aabb", "7": "ccdd"},
		IMACount:     3,
		Kdump:        kstate.KdumpState{CrashKernelLoaded: true, CrashSizeBytes: 1 << 20},
		IMALogSHA256: "deadbeef",
	}
	env, err := Wrap(&m, priv) // pointer form must agree with Open(&m)'s domain
	if err != nil {
		t.Fatal(err)
	}
	if env.Domain != "cau-kernel/kstate.Measured" {
		t.Fatalf("domain = %q", env.Domain)
	}
	var got kstate.Measured
	if err := env.Open(&got, pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.PCRs["0"] != "aabb" || got.IMACount != 3 || got.IMALogSHA256 != "deadbeef" || !got.Kdump.CrashKernelLoaded {
		t.Errorf("payload wrong after round-trip: %+v", got)
	}
}

// TestTamperedDomainFailsSignature: rewriting the envelope's domain to another
// kind without the key must not produce a verifiable signature — signing
// covered the domain, so a forged domain is a bad signature, not a new kind.
func TestTamperedDomainFailsSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	env, _ := Wrap(kstate.Snapshot{Modules: []kstate.Module{{Name: "x", State: "Live"}}}, priv)
	env.Domain = "cau-kernel/kstate.Measured" // forge the kind, no key
	// Opening as a Snapshot: the domain check rejects it.
	var s kstate.Snapshot
	if err := env.Open(&s, pub); err == nil {
		t.Error("forged domain accepted (snapshot)")
	}
	// Opening as a Measured (so the domain matches): the signature must fail,
	// because the signature covered the original domain.
	var m kstate.Measured
	if err := env.Open(&m, pub); !errors.Is(err, ErrBadSignature) {
		t.Errorf("forged domain verified: %v", err)
	}
}

// TestParsePrivateKeyMismatchedPublicHalfRejected guards BUG 2: a 64-byte key
// whose stored public half contradicts its seed signs with a garbage public
// key, so nothing can verify it — a permanent false "baseline tampered".
func TestParsePrivateKeyMismatchedPublicHalfRejected(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	// 64 bytes: a correct seed with someone else's public half.
	bad := append(append([]byte{}, priv[:ed25519.SeedSize]...), other[ed25519.SeedSize:]...)
	if len(bad) != ed25519.PrivateKeySize {
		t.Fatalf("bad key is %d bytes", len(bad))
	}
	if _, err := ParsePrivateKey([]byte(hx(bad))); err == nil {
		t.Error("64-byte key with a public half contradicting its seed was accepted")
	}
	// The consistent 64-byte form and the 32-byte seed stay accepted, and the
	// reconstructed 64-byte key equals the generated one.
	got, err := ParsePrivateKey([]byte(hx(priv)))
	if err != nil {
		t.Fatalf("consistent 64-byte key rejected: %v", err)
	}
	if !bytes.Equal(got, priv) {
		t.Error("reconstructed 64-byte key differs from the generated key")
	}
	if _, err := ParsePrivateKey([]byte(hx(priv.Seed()))); err != nil {
		t.Errorf("32-byte seed rejected: %v", err)
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

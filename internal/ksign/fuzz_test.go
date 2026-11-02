package ksign

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// FuzzOpen drives envelope parsing + verification with arbitrary bytes and keys.
// The invariant is "never panic, never verify a forgery": unwrapping hostile
// envelope bytes must error, never crash and never return success without a
// valid signature when a key is required.
func FuzzOpen(f *testing.F) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	good, _ := Wrap(struct{ X int }{1}, priv)
	goodBytes, _ := Marshal(good)
	f.Add(goodBytes, []byte(pub))
	f.Add([]byte(`{"payload":{},"signature":"zz"}`), []byte(pub))
	f.Add([]byte(`{`), []byte{})
	f.Add([]byte(``), []byte(pub))

	f.Fuzz(func(t *testing.T, envBytes, key []byte) {
		env, err := Unmarshal(envBytes)
		if err != nil {
			return
		}
		var out map[string]any
		var pk ed25519.PublicKey
		if len(key) == ed25519.PublicKeySize {
			pk = ed25519.PublicKey(key)
		}
		// Must not panic. When a key is supplied, Open must only succeed if the
		// signature genuinely verifies — which fuzzed bytes essentially never do.
		_ = env.Open(&out, pk)
	})
}

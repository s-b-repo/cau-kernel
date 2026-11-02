// Package ksign signs and verifies a recorded kernel-state baseline with
// Ed25519, so drift detection cannot be defeated by an attacker who also
// rewrites the baseline file: without the private key (kept off the host) they
// cannot forge the signature, and verification fails closed.
package ksign

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ErrBadSignature is returned when a signed document does not verify.
var ErrBadSignature = errors.New("ksign: signature does not verify")

// Envelope wraps a payload with an optional detached signature over the exact
// payload bytes. The payload is stored verbatim so re-marshaling can never
// change the signed bytes.
type Envelope struct {
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature,omitempty"` // hex Ed25519 over Payload
}

// Wrap marshals v into an envelope, signing it when priv is non-nil.
func Wrap(v any, priv ed25519.PrivateKey) (Envelope, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return Envelope{}, fmt.Errorf("ksign: marshal payload: %w", err)
	}
	e := Envelope{Payload: raw}
	if priv != nil {
		e.Signature = hex.EncodeToString(ed25519.Sign(priv, raw))
	}
	return e, nil
}

// Open verifies the envelope's signature when pub is non-nil (required then),
// and unmarshals the payload into v. With pub nil the payload is read without
// verifying (drift detection still works, but is not tamper-resistant).
func (e Envelope) Open(v any, pub ed25519.PublicKey) error {
	if pub != nil {
		if e.Signature == "" {
			return fmt.Errorf("%w: baseline is unsigned but a key was required", ErrBadSignature)
		}
		sig, err := hex.DecodeString(e.Signature)
		if err != nil {
			return ErrBadSignature
		}
		if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, e.Payload, sig) {
			return ErrBadSignature
		}
	}
	return json.Unmarshal(e.Payload, v)
}

// Marshal serializes an envelope to bytes. It is intentionally compact:
// indenting would re-serialize the signed RawMessage payload and invalidate the
// signature, so callers must persist envelopes through Marshal, never
// json.MarshalIndent.
func Marshal(e Envelope) ([]byte, error) {
	data, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("ksign: marshal envelope: %w", err)
	}
	return data, nil
}

// Unmarshal parses an envelope produced by Marshal.
func Unmarshal(data []byte) (Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return Envelope{}, fmt.Errorf("ksign: parse envelope: %w", err)
	}
	return e, nil
}

// ParsePublicKey reads a hex Ed25519 public key.
func ParsePublicKey(data []byte) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("ksign: decode public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ksign: public key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// ParsePrivateKey reads a hex Ed25519 private key (seed or full form).
func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("ksign: decode private key: %w", err)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	}
	return nil, fmt.Errorf("ksign: private key is %d bytes, want %d or %d", len(raw), ed25519.SeedSize, ed25519.PrivateKeySize)
}

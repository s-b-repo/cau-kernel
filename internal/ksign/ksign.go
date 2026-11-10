// Package ksign signs and verifies a recorded kernel-state baseline with
// Ed25519, so drift detection cannot be defeated by an attacker who also
// rewrites the baseline file: without the private key (kept off the host) they
// cannot forge the signature, and verification fails closed.
//
// Baselines are domain-separated by document kind: the signature covers the
// envelope's Domain (derived from the signed value's Go type), so a baseline
// recorded as one kind — a kstate.Snapshot for drift — cannot be replayed as
// another kind — a kstate.Measured for attest — even under the same key.
package ksign

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// ErrBadSignature is returned when a signed document does not verify.
var ErrBadSignature = errors.New("ksign: signature does not verify")

// Envelope wraps a payload with an optional detached signature. The signature
// covers Domain + "\x00" + Payload, where Domain names the document kind (the
// base type of the signed value). Domain separation keeps one kind of baseline
// from being replayed as another when both are signed with the same key. The
// payload is stored verbatim so re-marshaling can never change the signed bytes.
type Envelope struct {
	Domain    string          `json:"domain"`
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature,omitempty"` // hex Ed25519 over Domain+"\x00"+Payload
}

// domainOf derives a value's document-kind domain: the name of its base
// (pointer-stripped) type, e.g. "cau-kernel/kstate.Snapshot". Wrap(v) and
// Open(&v) must agree, so pointers and their elements share one domain.
func domainOf(v any) string {
	t := reflect.TypeOf(v)
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil {
		return ""
	}
	return "cau-kernel/" + t.String()
}

// signedBytes is exactly what Wrap signs and Open verifies: the domain, a NUL
// separator (a Go type name cannot contain NUL, so the split is unambiguous),
// then the payload bytes.
func (e Envelope) signedBytes() []byte {
	msg := make([]byte, 0, len(e.Domain)+1+len(e.Payload))
	msg = append(msg, e.Domain...)
	msg = append(msg, 0)
	msg = append(msg, e.Payload...)
	return msg
}

// Wrap marshals v into an envelope, signing it when priv is non-nil. The
// signature's domain comes from v's type, so opening must use the same type.
func Wrap(v any, priv ed25519.PrivateKey) (Envelope, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return Envelope{}, fmt.Errorf("ksign: marshal payload: %w", err)
	}
	e := Envelope{Domain: domainOf(v), Payload: raw}
	if priv != nil {
		e.Signature = hex.EncodeToString(ed25519.Sign(priv, e.signedBytes()))
	}
	return e, nil
}

// Open verifies the envelope and unmarshals the payload into v. The caller's
// destination type fixes the expected document kind; a mismatch fails closed
// before any signature work, so a baseline of one kind can never be replayed as
// another kind — even by a caller that supplies no key. With pub non-nil the
// signature is required and must verify over Domain+"\x00"+Payload; with pub
// nil the payload is read without verifying (drift detection still works, but
// is not tamper-resistant).
func (e Envelope) Open(v any, pub ed25519.PublicKey) error {
	want := domainOf(v)
	if e.Domain != want {
		return fmt.Errorf("ksign: baseline is a %q document but a %q was expected", e.Domain, want)
	}
	if pub != nil {
		if e.Signature == "" {
			return fmt.Errorf("%w: baseline is unsigned but a key was required", ErrBadSignature)
		}
		sig, err := hex.DecodeString(e.Signature)
		if err != nil {
			return ErrBadSignature
		}
		if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, e.signedBytes(), sig) {
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

// ParsePrivateKey reads a hex Ed25519 private key (seed or full form). The full
// 64-byte form carries the public key in its second half, and ed25519.Sign uses
// that half as the signing public key: a stored public half that contradicts
// the seed would produce signatures verifiable only against garbage, a
// permanent false "baseline tampered". Require the halves to agree.
func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("ksign: decode private key: %w", err)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		recon := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
		if !bytes.Equal(recon[ed25519.SeedSize:], raw[ed25519.SeedSize:]) {
			return nil, errors.New("ksign: private key's public half does not match its seed")
		}
		return recon, nil
	}
	return nil, fmt.Errorf("ksign: private key is %d bytes, want %d or %d", len(raw), ed25519.SeedSize, ed25519.PrivateKeySize)
}

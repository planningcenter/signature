// Package signature is used to generate ECDSA signatures for messages.
package signature

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

func hashMessage(ec ECurve, message []byte) ([]byte, error) {
	switch ec {
	case ECurve256:
		hash := sha256.Sum256(message)
		return hash[:], nil
	default:
		return nil, ErrInvalidKeySize
	}
}

// CreateSignature creates a new signature for the given message
func CreateSignature(key *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	hash, err := hashMessage(ECurveForSize(key.Params().BitSize), message)
	if err != nil {
		return nil, err
	}

	r, s, err := ecdsa.Sign(rand.Reader, key, hash)
	if err != nil {
		return nil, err
	}

	buffer := bytes.Buffer{}
	buffer.Write(r.Bytes())
	buffer.Write(s.Bytes())

	return buffer.Bytes(), nil
}

// VerifySignature performs the verification of a signature
func VerifySignature(key *ecdsa.PublicKey, message, signature []byte) error {
	hash, err := hashMessage(ECurveForSize(key.Params().BitSize), message)
	if err != nil {
		return err
	}

	r := big.NewInt(0).SetBytes(signature[:len(signature)/2])
	s := big.NewInt(0).SetBytes(signature[len(signature)/2:])

	if ecdsa.Verify(key, hash, r, s) {
		return nil
	}

	return ErrInvalidSignature
}

package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
)

// ECurve is the type of elliptic curve to use for creating key pairs
type ECurve int

const (
	_ ECurve = iota

	// ECurveInvalid is the ECurve for an unsupported elliptic curve size
	ECurveInvalid

	// ECurve256 a 256-bit elliptic curve
	ECurve256
)

func (e ECurve) curve() elliptic.Curve {
	switch e {
	case ECurve256:
		return elliptic.P256()
	default:
		panic(fmt.Errorf("the elliptic curve is not supported %d", e))
	}
}

// ECurveForSize returns the elliptic curve's type for a given size
func ECurveForSize(size int) ECurve {
	switch size {
	case 256:
		return ECurve256
	default:
		return ECurveInvalid
	}
}

var (
	// ErrInvalidKeySize is returned when the key size is not supported by the function
	ErrInvalidKeySize = errors.New("the key is not a supported size")

	// ErrInvalidSignature is returned when the signature does not match the the expected signature for the public key
	ErrInvalidSignature = errors.New("the signature is not valid for the message")
)

// GenerateKeyOutput contains the keys returned by a GenerateKey call
type GenerateKeyOutput struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

// GenerateKey creates a new key pair with the passed type
func GenerateKey(ec ECurve) (*GenerateKeyOutput, error) {
	pubCurve := ec.curve()

	privKey := new(ecdsa.PrivateKey)
	privKey, err := ecdsa.GenerateKey(pubCurve, rand.Reader)

	if err != nil {
		return nil, err
	}

	pubKey := privKey.PublicKey

	return &GenerateKeyOutput{
		PrivateKey: privKey,
		PublicKey:  &(pubKey),
	}, nil
}

package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

// CurveP256 implements a prime256v1 curve
var CurveP256 = elliptic.P256()

// CurveP521 implements a secp521r1 curve
var CurveP521 = elliptic.P521()

// GeneratePrivateECKey creates a new private key with the specified curve
func GeneratePrivateECKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(curve, rand.Reader)
}

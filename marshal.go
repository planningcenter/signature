package signature

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// KeyFormat defines the supported key formats for a EC Key
type KeyFormat string

const (
	// KeyFormatASN1 converts the key into PKCS#8, ASN.1 DER format
	KeyFormatASN1 KeyFormat = "ASN.1_DER"
)

var (
	// ErrInvalidKeyFormat is returned when a key format that is not supported is requested
	ErrInvalidKeyFormat = errors.New("the specified key format is not supported")
)

// MarshalPrivateKeyPem converts a private key into a file with the specified format
func MarshalPrivateKeyPem(key *ecdsa.PrivateKey, format KeyFormat) ([]byte, error) {
	switch format {
	case KeyFormatASN1:
		x509Private, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Private}), nil
	default:
		return nil, ErrInvalidKeyFormat
	}
}

// MarshalPublicKeyPem converts a public key into a file with the specified format
func MarshalPublicKeyPem(key *ecdsa.PublicKey, format KeyFormat) ([]byte, error) {
	switch format {
	case KeyFormatASN1:
		x509Public, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509Public}), nil
	default:
		return nil, ErrInvalidKeyFormat
	}
}

// UnmarshalPrivateKeyPem converts an encoded private key into a usable private key
func UnmarshalPrivateKeyPem(in []byte, format KeyFormat) (*ecdsa.PrivateKey, error) {
	switch format {
	case KeyFormatASN1:
		block, _ := pem.Decode(in)
		if block == nil {
			return nil, errors.New("failed to find a PEM file in input")
		}

		pKeyMaybe, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		pKey, ok := pKeyMaybe.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("the encoded public key is not an ECDSA key")
		}

		return pKey, nil
	default:
		return nil, ErrInvalidKeyFormat
	}
}

// UnmarshalPublicKeyPem converts an encoded public key into a usable public key
func UnmarshalPublicKeyPem(in []byte, format KeyFormat) (*ecdsa.PublicKey, error) {
	switch format {
	case KeyFormatASN1:
		block, _ := pem.Decode(in)
		if block == nil {
			return nil, errors.New("failed to find a PEM file in input")
		}

		pKeyMaybe, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		pKey, ok := pKeyMaybe.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("the encoded public key is not an ECDSA key")
		}

		return pKey, nil
	default:
		return nil, ErrInvalidKeyFormat
	}
}

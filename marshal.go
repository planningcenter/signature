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
	// KeyFormatPKCS8 converts the key into PKCS#8, ASN.1 DER format
	KeyFormatPKCS8 KeyFormat = "PKCS8-ASN.1_DER"

	// KeyFormatSEC1 converts the key into SEC 1, ASN.1 DER format
	KeyFormatSEC1 KeyFormat = "SEC1-ASN.1_DER"
)

var (
	// ErrInvalidKeyFormat is returned when a key format that is not supported is requested
	ErrInvalidKeyFormat = errors.New("the specified key format is not supported")
)

// MarshalPrivateKeyPem converts a private key into a file with the specified format
func MarshalPrivateKeyPem(key *ecdsa.PrivateKey, format KeyFormat) ([]byte, error) {
	switch format {
	case KeyFormatPKCS8:
		x509Private, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Private}), nil
	case KeyFormatSEC1:
		x508Private, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: x508Private}), nil
	default:
		return nil, ErrInvalidKeyFormat
	}
}

// MarshalPublicKeyPem converts a public key into a file with the specified format
func MarshalPublicKeyPem(key *ecdsa.PublicKey, format KeyFormat) ([]byte, error) {
	switch format {
	case KeyFormatPKCS8:
		x509Public, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509Public}), nil
	case KeyFormatSEC1:
		return nil, errors.New("SEC 1, ASN.1 DER does not support public keys")
	default:
		return nil, ErrInvalidKeyFormat
	}
}

// UnmarshalPrivateKeyPemWithBestGuessFormat attempts to unmarshal a private making a best guess for the format given the block type value.
func UnmarshalPrivateKeyPemWithBestGuessFormat(in []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(in)
	switch block.Type {
	case "EC PRIVATE KEY":
		return UnmarshalPrivateKeyPem(in, KeyFormatSEC1)
	default:
		return UnmarshalPrivateKeyPem(in, KeyFormatPKCS8)
	}
}

// UnmarshalPrivateKeyPem converts an encoded private key into a usable private key
func UnmarshalPrivateKeyPem(in []byte, format KeyFormat) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(in)
	if block == nil {
		return nil, errors.New("filed to fine a block in input")
	}

	var err error
	var untypedPrivateKey interface{}

	switch format {
	case KeyFormatPKCS8:
		untypedPrivateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case KeyFormatSEC1:
		untypedPrivateKey, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, ErrInvalidKeyFormat
	}

	if err != nil {
		return nil, err
	}

	pKey, ok := untypedPrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("the encoded public key is not an ECDSA key")
	}

	return pKey, nil
}

// UnmarshalPublicKeyPem converts an encoded public key into a usable public key
func UnmarshalPublicKeyPem(in []byte, format KeyFormat) (*ecdsa.PublicKey, error) {
	switch format {
	case KeyFormatPKCS8:
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
	case KeyFormatSEC1:
		return nil, errors.New("SEC 1, ASN.1 DER does not support public keys")
	default:
		return nil, ErrInvalidKeyFormat
	}
}

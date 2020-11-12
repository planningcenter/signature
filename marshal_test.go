package signature

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarshalPrivateKey(t *testing.T) {
	t.Run("given a valid private key", func(t *testing.T) {
		key, err := GeneratePrivateECKey(CurveP256)

		require.NoError(t, err)

		t.Run("PKCS8", func(t *testing.T) {
			_, err = MarshalPrivateKeyPem(key, KeyFormatPKCS8)
			assert.NoError(t, err)
		})

		t.Run("SEC1", func(t *testing.T) {
			_, err = MarshalPrivateKeyPem(key, KeyFormatSEC1)
			assert.NoError(t, err)
		})
	})
}

func TestMarshalPublicKey(t *testing.T) {
	t.Run("given a valid public key", func(t *testing.T) {
		key, err := GeneratePrivateECKey(CurveP256)

		require.NoError(t, err)

		t.Run("PKCS8", func(t *testing.T) {
			_, err = MarshalPublicKeyPem(&key.PublicKey, KeyFormatPKCS8)
			assert.NoError(t, err)
		})

		t.Run("SEC1", func(t *testing.T) {
			_, err = MarshalPublicKeyPem(&key.PublicKey, KeyFormatSEC1)
			assert.Error(t, err)
		})
	})
}

func TestUnmarshalPrivateKey(t *testing.T) {
	t.Run("PKCS8", func(t *testing.T) {
		_, err := UnmarshalPrivateKeyPem(keyP256PKCS8, KeyFormatPKCS8)

		assert.NoError(t, err)
	})

	t.Run("SEC1", func(t *testing.T) {
		data := []byte("-----BEGIN EC PRIVATE KEY-----\nMIHbAgEBBEEOE/RRHQ2popOIUI+9hhgIPIuGY8Ikd5QRpgW8+AuPwnMGz4Uaa9bC\nHDBh2MjzcrmnWWRCGNzsQRZT2BToNV8bFaAHBgUrgQQAI6GBiQOBhgAEAOP2sC1Y\nkKMAf1N3orZreUwHOvXPlwZQKomO7R5zW3CrKgFGdmn2sCrxK0NhT9w4+Dxwg6zU\n+Jsll/K+6vBxlQ/EAYgMvUey708AHl6x+xw11bEzTuSk9QpBtzt0DC2gV/MPO5+H\nVlceA50g39hF1Bqrh9CbUQ8NBGhrESiMMzjHLMng\n-----END EC PRIVATE KEY-----")

		_, err := UnmarshalPrivateKeyPem(data, KeyFormatSEC1)

		assert.NoError(t, err)
	})
}

func TestUnmarshalPublicKey(t *testing.T) {
	key, err := GeneratePrivateECKey(CurveP256)

	require.NoError(t, err)

	t.Run("given a valid public key", func(t *testing.T) {
		pem, err := MarshalPublicKeyPem(&key.PublicKey, KeyFormatPKCS8)
		require.NoError(t, err)

		_, err = UnmarshalPublicKeyPem(pem, KeyFormatPKCS8)

		assert.NoError(t, err)
	})
}

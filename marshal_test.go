package signature

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarshalPrivateKey(t *testing.T) {
	t.Run("given a valid private key", func(t *testing.T) {
		out, err := GenerateKey(ECurve256)

		require.NoError(t, err)

		_, err = MarshalPrivateKeyPem(out.PrivateKey, KeyFormatASN1)
		assert.NoError(t, err)
	})
}

func TestMarshalPublicKey(t *testing.T) {
	t.Run("given a valid public key", func(t *testing.T) {
		out, err := GenerateKey(ECurve256)

		require.NoError(t, err)

		_, err = MarshalPublicKeyPem(out.PublicKey, KeyFormatASN1)
		assert.NoError(t, err)
	})
}

func TestUnmarshalPrivateKey(t *testing.T) {
	t.Run("given a valid private key", func(t *testing.T) {
		_, err := UnmarshalPrivateKeyPem(privateKeyPem, KeyFormatASN1)

		assert.NoError(t, err)
	})
}

func TestUnmarshalPublicKey(t *testing.T) {
	t.Run("given a valid public key", func(t *testing.T) {
		_, err := UnmarshalPublicKeyPem(publicKeyPem, KeyFormatASN1)

		assert.NoError(t, err)
	})
}

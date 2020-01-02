package signature

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	privateKeyPem = []byte("-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgs1BgKh9zsUq5GHIf\nXshJyxzLKiBJgs+/wAuxRXnFzYahRANCAAQ24F7EnSwfJ75UAWi9bpe9H0LYynq0\nXH5ZTj2J4/ULQmC8DQ/Ph4FsFFQtcqk1sPuYfhNwMHtIjRPihvshwF2E\n-----END PRIVATE KEY-----")
	publicKeyPem  = []byte("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENuBexJ0sHye+VAFovW6XvR9C2Mp6\ntFx+WU49ieP1C0JgvA0Pz4eBbBRULXKpNbD7mH4TcDB7SI0T4ob7IcBdhA==\n-----END PUBLIC KEY-----")
)

func TestCreateSignature(t *testing.T) {
	key, err := UnmarshalPrivateKeyPem(privateKeyPem, KeyFormatASN1)
	require.NoError(t, err)

	_, err = CreateSignature(key, []byte("This is a secure message that can only have come from me"))

	assert.NoError(t, err)
}

func TestVerifySignature(t *testing.T) {
	sig, err := base64.StdEncoding.DecodeString("2vy+splMDIrZwju7tqNH4A6dYWXJPPLFM7telpO+sgRxSh5FppHvrFoncLHWFwbpOAJMtzZPbNvfcodzzP4IjA==")
	require.NoError(t, err)

	key, err := UnmarshalPublicKeyPem(publicKeyPem, KeyFormatASN1)
	require.NoError(t, err)

	err = VerifySignature(key, []byte("This is a secure message that can only have come from me"), sig)

	assert.NoError(t, err)
}

package signature

import (
	"crypto/ecdsa"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

var keyP256PKCS8 = []byte("-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSaaEG6gmtYDn6Yby\nicO4tu+hNmzWcyX1wrA/QW5ZkV+hRANCAAQdsL+2Er6yTeu/bxO8UNLeTieDHTY4\nIGh0CZqv2G3UWy6gXnvCEQyyMdOChyFb4L6Z0dOw7OaXU0E2Hm6FgNo1\n-----END PRIVATE KEY-----")
var keyP521PKCS8 = []byte("-----BEGIN PRIVATE KEY-----\nMIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAQYkyepXIo6lL94FZ\nAl0ygSNOG/4BfjxABtwZGCmadJDO0fVup+RhDN0IKZ+mMvdryPfjEJEHgzffi9iL\ng6f1zEChgYkDgYYABAAkTj4zHqKbxde1cIto0NTitq3kzOUIYfKcs9TJnAIBo+Vo\n2MwDx9YG9YIlAssD2rSxmI+AyH9GMMUieBLR29wdpwHIy+xQMwG/JfzgjYHFPwLT\nqn61cqlfJM+7J2654nw2Q0qouWfljxLKLNr3tzCCA5bLcMa5dX8/muKoGbjTcaFf\nVA==\n-----END PRIVATE KEY-----")

var (
	keyP256 = func() *ecdsa.PrivateKey {
		key, err := UnmarshalPrivateKeyPem(keyP256PKCS8, KeyFormatPKCS8)
		if err != nil {
			panic(err)
		}
		return key
	}()

	keyP521 = func() *ecdsa.PrivateKey {
		key, err := UnmarshalPrivateKeyPem(keyP521PKCS8, KeyFormatPKCS8)
		if err != nil {
			panic(err)
		}
		return key
	}()

	message = []byte("This is a secure message that can only have come from me")
)

func TestCreateECSignature(t *testing.T) {
	t.Run("P-256", func(t *testing.T) {
		_, err := CreateECSignature(keyP256, message)

		assert.NoError(t, err)
	})

	t.Run("P-521", func(t *testing.T) {
		_, err := CreateECSignature(keyP521, message)

		assert.NoError(t, err)
	})
}

func TestVerifyECSignature(t *testing.T) {
	t.Run("P-256", func(t *testing.T) {
		sig, _ := base64.StdEncoding.DecodeString(`LXxsNghx4yJcUtfHgyTdOIQYE/H9baDXunqgaIQ206EBlb4fen2d4A7Z7DnjGChZh5o4ucoRXY1YWp+8Pwar4w==`)

		err := VerifyECSignature(&(keyP256.PublicKey), message, sig)

		assert.NoError(t, err)
	})

	t.Run("P-521", func(t *testing.T) {
		sig, _ := base64.StdEncoding.DecodeString(`eaDiPwwoD/nPUYDwC4yBnMce7boeVrNjoCHglx2dNCp8Zz/aAaip30KtM0yT/mTvpFGYSYBy8AxzdApDeiITReg02RhSzxO5vw7Cj/GJ2pT8JkTJ9pHeCJN2BBUYgNo1iS5Jx5jQ3Tjv3/gduucAX72Se5c2N7aCOLvKygLbs8itAA==`)

		err := VerifyECSignature(&(keyP521.PublicKey), message, sig)

		assert.NoError(t, err)
	})
}

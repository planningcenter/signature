package signature_test

import (
	"encoding/base64"
	"fmt"

	signature "github.com/planningcenter/signature"
)

var (
	privateKeyPem = []byte("-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgs1BgKh9zsUq5GHIf\nXshJyxzLKiBJgs+/wAuxRXnFzYahRANCAAQ24F7EnSwfJ75UAWi9bpe9H0LYynq0\nXH5ZTj2J4/ULQmC8DQ/Ph4FsFFQtcqk1sPuYfhNwMHtIjRPihvshwF2E\n-----END PRIVATE KEY-----")
	publicKeyPem  = []byte("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENuBexJ0sHye+VAFovW6XvR9C2Mp6\ntFx+WU49ieP1C0JgvA0Pz4eBbBRULXKpNbD7mH4TcDB7SI0T4ob7IcBdhA==\n-----END PUBLIC KEY-----")
)

func Example_signAndVerify() {
	private, err := signature.UnmarshalPrivateKeyPem(privateKeyPem, signature.KeyFormatASN1)
	if err != nil {
		panic(err)
	}

	message := []byte("This is a secure message")

	sig, err := signature.CreateSignature(private, message)
	if err != nil {
		panic(err)
	}

	public, err := signature.UnmarshalPublicKeyPem(publicKeyPem, signature.KeyFormatASN1)
	if err != nil {
		panic(err)
	}

	err = signature.VerifySignature(public, message, sig)
	if err != nil {
		panic(err)
	}

	fmt.Println("Valid")

	// Output: Valid
}

func ExampleGenerateKey_pem() {
	key, err := signature.GenerateKey(signature.ECurve256)
	if err != nil {
		panic(err)
	}

	private, err := signature.MarshalPrivateKeyPem(key.PrivateKey, signature.KeyFormatASN1)
	if err != nil {
		panic(err)
	}

	public, err := signature.MarshalPublicKeyPem(key.PublicKey, signature.KeyFormatASN1)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(private))
	fmt.Println(string(public))
}

func ExampleCreateSignature() {
	key, err := signature.GenerateKey(signature.ECurve256)
	if err != nil {
		panic(err)
	}

	signature, err := signature.CreateSignature(key.PrivateKey, []byte("This is the message to sign"))
	if err != nil {
		panic(err)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(signature))
}

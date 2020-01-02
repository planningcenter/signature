package main

import (
	"fmt"
	"log"

	"github.com/planningcenter/signature"
)

func main() {
	key, err := signature.GenerateKey(signature.ECurve256)
	if err != nil {
		log.Fatal(err)
	}

	private, err := signature.MarshalPrivateKeyPem(key.PrivateKey, signature.KeyFormatASN1)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(private))

	public, err := signature.MarshalPublicKeyPem(key.PublicKey, signature.KeyFormatASN1)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(public))
}

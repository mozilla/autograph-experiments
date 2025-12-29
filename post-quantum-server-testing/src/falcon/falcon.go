package falcon

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

const (
	sigName        = "Falcon-512"
	PublicKeySize  = 897
	PrivateKeySize = 1281
)

// Public key struct
type PublicKey struct {
	Pk []byte
}

// Private key struct
type PrivateKey struct {
	PublicKey
	Sk []byte
}

// This is a struct for the response
type response struct {
	Signature string `json:"signature"`
	PublicKey string `json:"publicKey"`
}

// This function generates a pivate/public key pair
func GenerateKey() (*PrivateKey, error) {
	signer := oqs.Signature{}

	if err := signer.Init(sigName, nil); err != nil {
		log.Fatal(err)
	}

	pk, err := signer.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	privateKey := new(PrivateKey)
	sk := signer.ExportSecretKey()

	privateKey.PublicKey.Pk = pk
	privateKey.Sk = sk

	return privateKey, err
}

// This function takes a private key, signs a message and returns a signature
func (priv *PrivateKey) SignPQC(msg []byte) (sig []byte, err error) {
	signer := oqs.Signature{}

	if err := signer.Init(sigName, priv.Sk); err != nil {
		return nil, fmt.Errorf("failed to init signer: %w", err)
	}

	// hash with sha256
	h := sha256.New()
	h.Write(msg)
	hash := h.Sum(nil)

	sign, err := signer.Sign(hash)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}
	return sign, nil
}

func SignData(input string, privKey *PrivateKey) response {

	// Decode the base64 input
	message, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		log.Fatalf("error decoding base64 input %v", err)
	}

	// Generate signature with Falcon signer
	signature, err := privKey.SignPQC(message)
	if err != nil {
		log.Fatalf("error signing message: %v", err)
	}

	// Get the public key
	pubKey := privKey.PublicKey.Pk

	resp := response{
		Signature: base64.StdEncoding.EncodeToString(signature),
		PublicKey: base64.StdEncoding.EncodeToString(pubKey[:]),
	}

	return resp

}

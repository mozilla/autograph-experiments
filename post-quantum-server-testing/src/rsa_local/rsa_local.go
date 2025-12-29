package rsa_local

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
)

const (
	KeySize = 4096
)

// Public key struct
type PublicKey struct {
	Pk *rsa.PublicKey
}

// Private key struct
type PrivateKey struct {
	PublicKey
	Sk *rsa.PrivateKey
}

// Response struct
type response struct {
	Signature string `json:"signature"`
	PublicKey string `json:"publicKey"`
}

// GenerateKey generates a new RSA-4096 key pair
func GenerateKey() (*PrivateKey, error) {
	sk, err := rsa.GenerateKey(rand.Reader, KeySize)
	if err != nil {
		return nil, err
	}
	pk := &sk.PublicKey

	privateKey := &PrivateKey{
		PublicKey: PublicKey{Pk: pk},
		Sk:        sk,
	}
	return privateKey, nil
}

// SignPQC signs a message using the private key
func (priv *PrivateKey) signPQC(msg []byte) ([]byte, error) {
	hash := sha256.Sum256(msg)
	sign, err := rsa.SignPSS(rand.Reader, priv.Sk, crypto.SHA256, hash[:], nil)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %v", err)
	}
	return sign, nil
}

// SignData signs input and returns a response with signature and public key
func SignData(input string, privKey *PrivateKey) response {

	message, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		log.Fatalf("error decoding base64 input %v", err)
	}

	signature, err := privKey.signPQC(message)
	if err != nil {
		log.Fatalf("error signing message: %v", err)
	}

	pubKey := x509.MarshalPKCS1PublicKey(privKey.PublicKey.Pk)
	resp := response{
		Signature: base64.StdEncoding.EncodeToString(signature),
		PublicKey: base64.StdEncoding.EncodeToString(pubKey),
	}

	return resp
}

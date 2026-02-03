package ecdsa_local

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"sync"
)

// Public key struct
type PublicKey struct {
	Pk *ecdsa.PublicKey
}

// Private key struct
type PrivateKey struct {
	PublicKey
	Sk *ecdsa.PrivateKey
}

// Response struct
type response struct {
	Signature string `json:"signature"`
	PublicKey string `json:"publicKey"`
}

// GenerateKey generates a new ECDSA P-384 key pair
func GenerateKey() (*PrivateKey, error) {
	sk, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
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

// signPQC signs a message using the private key
func (priv *PrivateKey) signPQC(msg []byte) ([]byte, error) {
	hash := sha512.Sum384(msg)
	sign, err := ecdsa.SignASN1(rand.Reader, priv.Sk, hash[:])
	if err != nil {
		return nil, fmt.Errorf("signing failed: %v", err)
	}
	return sign, nil
}

// SignData signs input and returns a response with signature and public key
func SignData(input string, privKey *PrivateKey, wg *sync.WaitGroup) response {
	defer wg.Done()

	message, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		log.Fatalf("error decoding base64 input %v", err)
	}

	signature, err := privKey.signPQC(message)
	if err != nil {
		log.Fatalf("error signing message: %v", err)
	}

	pubKey, err := x509.MarshalPKIXPublicKey(privKey.PublicKey.Pk)
	if err != nil {
		log.Fatalf("error marshaling public key: %v", err)
	}
	resp := response{
		Signature: base64.StdEncoding.EncodeToString(signature),
		PublicKey: base64.StdEncoding.EncodeToString(pubKey),
	}

	return resp
}

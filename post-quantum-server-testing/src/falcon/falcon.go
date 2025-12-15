package falcon

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
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

// This is a struct for the request message
type request struct {
	Input string `json:"input"`
	KeyID string `json:"keyid"`
	Auth  string `json:"auth"`
}

// This is a struct for the output signature
type response struct {
	Signature string `json:"signature"`
	PublicKey string `json:"publicKey"`
}

// This function processes the request struct and returns a struct of the data
func parseInput(req request) ([]byte, string, error) {
	if req.Input == "" {
		return nil, "", fmt.Errorf("missing the json data input")
	}
	if req.KeyID == "" {
		return nil, "", fmt.Errorf("missing the json keyid")
	}
	if req.Auth == "" {
		return nil, "", fmt.Errorf("missing the json auth")
	}

	dcd, err := base64.StdEncoding.DecodeString(req.Input)
	if err != nil {
		return nil, "", fmt.Errorf("error decoding base64 input %v", err)
	}

	// This returns the json []byte
	return dcd, req.KeyID, nil
}

// This function generates a pivate/public key pair
func GenerateKey() (*PrivateKey, error) {
	signer := oqs.Signature{}
	//defer signer.Clean() // clean up even in case of panic

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
	//defer signer.Clean()

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

func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return priv.SignPQC(digest)
}

func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

// This function verifies the signature with the public key
func Verify(pubkey *PublicKey, msg, signature []byte) bool {
	var verifier = oqs.Signature{}
	//defer verifier.Clean()

	if err := verifier.Init(sigName, nil); err != nil {
		log.Fatal(err)
	}

	isValid, err := verifier.Verify(msg, signature, pubkey.Pk)
	if err != nil {
		log.Fatal(err)
	}

	return isValid
}

func SignData(input string, key string, auth string) response {
	var reqData request

	//hard coded the request data
	reqData.Auth = auth
	reqData.Input = input
	reqData.KeyID = key

	// Process the input from the request data
	message, _, err := parseInput(reqData)
	if err != nil {
		log.Fatalf("Error parsing the input request data %v", err)
	}

	// auth := reqData.Auth

	// Generate a private key
	privKey, err := GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate a private key: %v", err)
	}

	// Do the signing with the falcon signer
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

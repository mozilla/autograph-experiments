package mldsa

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"log"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// This is a struct for the request message
type request struct {
	Input string `json:"input"`
	KeyID string `json:"keyid"`
}

// This is a struct for the output signature
type response struct {
	Signature string `json:"signature"`
	PublicKey string `json:"publicKey"`
}

// This function processes the request struct and returns a struct of the data
func parseInput(req request) ([]byte, error) {
	if req.Input == "" {
		return nil, fmt.Errorf("missing the json data input")
	}
	if req.KeyID == "" {
		return nil, fmt.Errorf("missing the json keyid")
	}

	message, err := base64.StdEncoding.DecodeString(req.Input)
	if err != nil {
		return nil, fmt.Errorf("error decoding base64 input %v", err)
	}

	// This returns the json []byte
	return message, nil
}

// getPublicKey retrieves the public key from an asymmetric key pair on Cloud KMS
func getPublicKey(name string) ([]byte, error) {
	// Create the client
	ctx := context.Background()
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		log.Fatalf("failed to setup client: %v", err)
	}
	defer client.Close()

	// Build the request
	req := &kmspb.GetPublicKeyRequest{
		Name:            name,
		PublicKeyFormat: kmspb.PublicKey_NIST_PQC,
	}

	// Call the API
	result, err := client.GetPublicKey(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Can add integrity checks

	return result.PublicKey.Data, nil
}

// signAsymmetric will sign a plaintext message using a saved asymmetric private
// key stored in Cloud KMS.
func signAsymmetric(name string, message []byte) ([]byte, error) {
	// Create the client.
	ctx := context.Background()
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		log.Fatalf("failed to setup client: %v", err)
	}
	defer client.Close()

	// hash the message with sha256
	h := sha256.New()
	h.Write(message)
	bs := h.Sum(nil)

	plaintext := bs[:]

	// Compute data CRC32C.
	crc32c := func(data []byte) uint32 {
		t := crc32.MakeTable(crc32.Castagnoli)
		return crc32.Checksum(data, t)

	}

	checksum := crc32c(plaintext)

	// Build the signing request.
	req := &kmspb.AsymmetricSignRequest{
		Name:       name,
		Data:       plaintext,
		DataCrc32C: wrapperspb.Int64(int64(checksum)),
	}

	// Call the API.
	result, err := client.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to sign digest: %w", err)
	}

	// Perform integrity verification on result.
	if result.Name != req.Name {
		return nil, fmt.Errorf("AsymmetricSign: request corrupted in-transit")
	}
	if int64(crc32c(result.Signature)) != result.SignatureCrc32C.Value {
		return nil, fmt.Errorf("AsymmetricSign: response corrupted in-transit")
	}

	//fmt.Fprintf(w, "Signed digest: %s", result.Signature)
	return result.Signature, nil
}

func SignData(input string, key string, keyName string) response {
	var reqData request

	// Input request data to be parsed
	reqData.Input = input
	reqData.KeyID = key

	// Process the input from the request data
	message, err := parseInput(reqData)
	if err != nil {
		log.Fatalf("Error parsing the input request data %v", err)
	}

	// Do the asymmetric signing
	signature, err := signAsymmetric(keyName, message)
	if err != nil {
		log.Fatalf("Error signing the message: %v", err)
	}

	// Get the public key
	pubKey, err := getPublicKey(keyName)
	if err != nil {
		log.Fatalf("error when getting public key: %v", err)
	}

	resp := response{
		Signature: base64.StdEncoding.EncodeToString(signature),
		PublicKey: base64.StdEncoding.EncodeToString(pubKey),
	}

	return resp
}

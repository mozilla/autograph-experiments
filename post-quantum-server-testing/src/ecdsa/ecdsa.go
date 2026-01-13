package ecdsa

import (
	"context"
	"crypto/sha512"
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

// signAsymmetric will sign a plaintext message using a saved asymmetric private
// key stored in Cloud KMS.
func signAsymmetric(name string, message []byte) ([]byte, error) {
	// Create the client.
	ctx := context.Background()
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create kms client: %w", err)
	}
	defer client.Close()

	// ciphertexts are always byte arrays.
	plaintext := message

	// Calculate the digest of the message.
	digest := sha512.New384()
	if _, err := digest.Write(plaintext); err != nil {
		return nil, fmt.Errorf("failed to create digest: %w", err)
	}

	// Compute digest's CRC32C.
	crc32c := func(data []byte) uint32 {
		t := crc32.MakeTable(crc32.Castagnoli)
		return crc32.Checksum(data, t)

	}
	digestCRC32C := crc32c(digest.Sum(nil))

	// Build the signing request.
	req := &kmspb.AsymmetricSignRequest{
		Name: name,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha384{
				Sha384: digest.Sum(nil),
			},
		},
		DigestCrc32C: wrapperspb.Int64(int64(digestCRC32C)),
	}

	// Call the API.
	result, err := client.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to sign digest: %w", err)
	}

	// Perform integrity verification on result.
	if !result.VerifiedDigestCrc32C {
		return nil, fmt.Errorf("AsymmetricSign: request corrupted in-transit")
	}
	if result.Name != req.Name {
		return nil, fmt.Errorf("AsymmetricSign: request corrupted in-transit")
	}
	if int64(crc32c(result.Signature)) != result.SignatureCrc32C.Value {
		return nil, fmt.Errorf("AsymmetricSign: response corrupted in-transit")
	}

	return result.Signature, nil
}

// This function signs the data and and returns the signature as a base64 string
func SignData(input string, key string, keyName string) string {
	var reqData request

	//hard coded the request data
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

	return base64.StdEncoding.EncodeToString(signature)
}

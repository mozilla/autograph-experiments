package rsa

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"log"
	"os"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/joho/godotenv"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

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

// use godot package to load/read the .env file and
// return the value of the key
func GoDotEnvVariable(key string) string {
	// Load .env file
	err := godotenv.Load("../.env")
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	return os.Getenv(key)
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

// getPublicKey retrieves the public key from an asymmetric key paird on Cloud KMS
func getPublicKey(name string) ([]byte, error) {
	// Create the client.
	ctx := context.Background()
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create kms client: %w", err)
	}
	defer client.Close()

	// Build the request.
	req := &kmspb.GetPublicKeyRequest{
		Name: name,
	}

	// Call the API.
	result, err := client.GetPublicKey(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// The 'Pem' field is the raw string representation of the public key.
	// Convert 'Pem' into bytes for further processing.
	key := []byte(result.Pem)

	// Perform integrity verification on result.
	crc32c := func(data []byte) uint32 {
		t := crc32.MakeTable(crc32.Castagnoli)
		return crc32.Checksum(data, t)
	}
	if int64(crc32c(key)) != result.PemCrc32C.Value {
		return nil, fmt.Errorf("getPublicKey: response corrupted in-transit")
	}

	return key, nil
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
	digest := sha256.New()
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
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest.Sum(nil),
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

func signData(input string, key string, auth string) response {
	var reqData request

	location := GoDotEnvVariable("LOCATION")
	keyID := GoDotEnvVariable("KEY_VERSION")
	keyRing := GoDotEnvVariable("KEYRING")
	projectID := GoDotEnvVariable("PROJECT_ID")

	//hard coded the request data
	reqData.Auth = auth
	reqData.Input = input
	reqData.KeyID = key

	// Process the input from the request data
	message, keyId, err := parseInput(reqData)
	if err != nil {
		log.Fatalf("Error parsing the input request data %v", err)
	}

	// auth := reqData.Auth

	// Create the name with relevant data
	keyName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s", projectID, location, keyRing, keyId, keyID)

	// Get the time pre-signing
	start := time.Now()

	// Do the asymmetric signing
	signature, err := signAsymmetric(keyName, message)
	if err != nil {
		log.Fatalf("Error signing the message: %v", err)
	}

	// Get the time post-signing
	elapsed := time.Since(start)

	fmt.Printf("Signing time is: %.3f ms\n", elapsed.Seconds()*1000)

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

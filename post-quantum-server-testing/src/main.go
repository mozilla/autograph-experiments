package main

import (
	"fmt"
	"log"
	"os"
	"server-testing/ecdsa"
	"server-testing/falcon"
	"server-testing/mldsa"
	"server-testing/rsa"
	"server-testing/rsa_local"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

const (
	smallInput = "aGkK" // "hi" (<1MB)
)

var (
	mediumInput = strings.Repeat("aGkK", 1024*512) // "hi" repeatedly (1-2MB)
)

// use godot package to load/read the .env file and
// return the value of the key
func goDotEnvVariable(key string) string {
	// Load .env file
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	return os.Getenv(key)
}

func testMldsaSmallPayload(iterations int, location string, keyRing string, projectID string) {

	fmt.Printf("Testing Small Payload ML-DSA-65:\n")
	keyName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/mldsa/cryptoKeyVersions/1", projectID, location, keyRing)
	// Get the time pre-signing
	start := time.Now()
	for range iterations {
		_ = mldsa.SignData(smallInput, "mldsa", keyName)
	}
	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Signing time is: %.3f ms\n", elapsed.Seconds()*1000)

	//fmt.Printf("Completed")
}

func testMldsaMediumPayload(iterations int, location string, keyRing string, projectID string) {

	fmt.Printf("Testing Medium Payload ML-DSA-65:\n")
	keyName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/mldsa/cryptoKeyVersions/1", projectID, location, keyRing)
	// Get the time pre-signing
	start := time.Now()
	for range iterations {
		_ = mldsa.SignData(mediumInput, "mldsa", keyName)
	}
	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Signing time is: %.3f ms\n", elapsed.Seconds()*1000)

	//fmt.Printf("Completed")
}

func testFalconSmallPayload(iterations int) {

	fmt.Printf("Testing Small Payload Falcon-512:\n")

	// Generate a private key
	privKey, err := falcon.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate a private key: %v", err)
	}

	// Get the time pre-signing
	start := time.Now()
	for range iterations {
		_ = falcon.SignData(smallInput, privKey)
	}
	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Signing time is: %.3f ms\n", elapsed.Seconds()*1000)

	//fmt.Printf("Completed")
}

func testEcdsaSmallPayload(iterations int, location string, keyRing string, projectID string) {

	fmt.Printf("Testing Small Payload ECDSA-384:\n")
	keyName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/ecdsa/cryptoKeyVersions/1", projectID, location, keyRing)
	// Get the time pre-signing
	start := time.Now()
	for range iterations {
		_ = ecdsa.SignData(smallInput, "ecdsa", keyName)
	}
	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Signing time is: %.3f ms\n", elapsed.Seconds()*1000)

	//fmt.Printf("Completed")
}

func testEcdsaMediumPayload(iterations int, location string, keyRing string, projectID string) {

	fmt.Printf("Testing Medium Payload ECDSA-384:\n")
	keyName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/ecdsa/cryptoKeyVersions/1", projectID, location, keyRing)
	// Get the time pre-signing
	start := time.Now()
	for range iterations {
		_ = ecdsa.SignData(mediumInput, "ecdsa", keyName)
	}
	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Signing time is: %.3f ms\n", elapsed.Seconds()*1000)

	//fmt.Printf("Completed")
}

func testRsaSmallPayload(iterations int, location string, keyRing string, projectID string) {

	fmt.Printf("Testing Small Payload RSA-4096:\n")
	keyName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/rsa/cryptoKeyVersions/1", projectID, location, keyRing)
	// Get the time pre-signing
	start := time.Now()
	for range iterations {
		_ = rsa.SignData(smallInput, "rsa", "null", keyName)
	}
	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Signing time is: %.3f ms\n", elapsed.Seconds()*1000)

	//fmt.Printf("Completed")
}

func testRsaLocalSmallPayload(iterations int) {

	fmt.Printf("Testing Small Payload RSA-4096:\n")

	// Generate a private key
	privKey, err := rsa_local.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate a private key: %v", err)
	}

	// Get the time pre-signing
	start := time.Now()
	for range iterations {
		_ = rsa_local.SignData(smallInput, privKey)
	}

	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Signing time is: %.3f ms\n", elapsed.Seconds()*1000)

	//fmt.Printf("Completed")
}

func main() {
	iterations := 100
	location := goDotEnvVariable("LOCATION")
	keyRing := goDotEnvVariable("KEYRING")
	projectID := goDotEnvVariable("PROJECT_ID")

	testFalconSmallPayload(iterations)
	testRsaLocalSmallPayload(iterations)
	testMldsaSmallPayload(iterations, location, keyRing, projectID)
	testEcdsaSmallPayload(iterations, location, keyRing, projectID)
}

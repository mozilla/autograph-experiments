package main

import (
	"fmt"
	"log"
	"os"
	"server-testing/ecdsa"
	"server-testing/falcon"
	"server-testing/mldsa"
	"server-testing/rsa_local"
	"strings"
	"sync"
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
	// Ignored error for gcp cloud run
	_ = godotenv.Load(".env")

	return os.Getenv(key)
}

func testMldsaSmallPayload(iterations int, location string, keyRing string, projectID string, wg *sync.WaitGroup) {
	defer wg.Done()

	keyName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/mldsa/cryptoKeyVersions/1", projectID, location, keyRing)
	// Get the time pre-signing
	start := time.Now()
	for range iterations {
		_ = mldsa.SignData(smallInput, "mldsa", keyName)
	}
	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Small Payload ML-DSA-65: %.3f ms\n", (elapsed.Seconds()*1000)/float64(iterations))

	//fmt.Printf("Completed")
}

func testMldsaMediumPayload(iterations int, location string, keyRing string, projectID string, wg *sync.WaitGroup) {
	defer wg.Done()

	keyName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/mldsa/cryptoKeyVersions/1", projectID, location, keyRing)
	// Get the time pre-signing
	start := time.Now()
	for range iterations {
		_ = mldsa.SignData(mediumInput, "mldsa", keyName)
	}
	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Medium Payload ML-DSA-65: %.3f ms\n", (elapsed.Seconds()*1000)/float64(iterations))

	//fmt.Printf("Completed")
}

func testFalconSmallPayload(iterations int, wg *sync.WaitGroup) {
	defer wg.Done()

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
	fmt.Printf("Small Payload Falcon-512: %.3f ms\n", (elapsed.Seconds()*1000)/float64(iterations))

	//fmt.Printf("Completed")
}

func testFalconMediumPayload(iterations int, wg *sync.WaitGroup) {
	defer wg.Done()

	// Generate a private key
	privKey, err := falcon.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate a private key: %v", err)
	}

	// Get the time pre-signing
	start := time.Now()
	for range iterations {
		_ = falcon.SignData(mediumInput, privKey)
	}
	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Medium Payload Falcon-512: %.3f ms\n", (elapsed.Seconds()*1000)/float64(iterations))

	//fmt.Printf("Completed")
}

func testEcdsaSmallPayload(iterations int, location string, keyRing string, projectID string, wg *sync.WaitGroup) {
	defer wg.Done()

	keyName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/ecdsa/cryptoKeyVersions/1", projectID, location, keyRing)
	// Get the time pre-signing
	start := time.Now()
	for range iterations {
		_ = ecdsa.SignData(smallInput, "ecdsa", keyName)
	}
	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Small Payload ECDSA-384: %.3f ms\n", (elapsed.Seconds()*1000)/float64(iterations))

	//fmt.Printf("Completed")
}

func testEcdsaMediumPayload(iterations int, location string, keyRing string, projectID string, wg *sync.WaitGroup) {
	defer wg.Done()

	keyName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/ecdsa/cryptoKeyVersions/1", projectID, location, keyRing)
	// Get the time pre-signing
	start := time.Now()
	for range iterations {
		_ = ecdsa.SignData(mediumInput, "ecdsa", keyName)
	}
	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Medium Payload ECDSA-384: %.3f ms\n", (elapsed.Seconds()*1000)/float64(iterations))

	//fmt.Printf("Completed")
}

func testRsaSmallPayload(iterations int, wg *sync.WaitGroup) {
	defer wg.Done()

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
	fmt.Printf("Small Payload RSA-4096: %.3f ms\n", (elapsed.Seconds()*1000)/float64(iterations))

	//fmt.Printf("Completed")
}

func testRsaMediumPayload(iterations int, wg *sync.WaitGroup) {
	defer wg.Done()

	// Generate a private key
	privKey, err := rsa_local.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate a private key: %v", err)
	}

	// Get the time pre-signing
	start := time.Now()
	for range iterations {
		_ = rsa_local.SignData(mediumInput, privKey)
	}

	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Medium Payload RSA-4096: %.3f ms\n", (elapsed.Seconds()*1000)/float64(iterations))

	//fmt.Printf("Completed")
}

func main() {
	iterations := 100
	location := goDotEnvVariable("LOCATION")
	keyRing := goDotEnvVariable("KEYRING")
	projectID := goDotEnvVariable("PROJECT_ID")
	var wg sync.WaitGroup

	fmt.Printf("---Running Tests: Avg time per signature---\n\n")
	wg.Add(8)
	// Run the small payload tests
	go testFalconSmallPayload(iterations, &wg)
	go testRsaSmallPayload(iterations, &wg)
	go testMldsaSmallPayload(iterations, location, keyRing, projectID, &wg)
	go testEcdsaSmallPayload(iterations, location, keyRing, projectID, &wg)

	//wg.Wait()
	//fmt.Printf("\n---Running Medium Payload Tests---\n\n")
	//wg.Add(4)

	// Run the medium payload tests
	go testFalconMediumPayload(iterations, &wg)
	go testRsaMediumPayload(iterations, &wg)
	go testMldsaMediumPayload(iterations, location, keyRing, projectID, &wg)
	go testEcdsaMediumPayload(iterations, location, keyRing, projectID, &wg)
	wg.Wait()

}

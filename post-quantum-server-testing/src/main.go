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

func testMldsaSmallPayload(iterations int, location string, keyRing string, projectID string) {
	keyName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/mldsa/cryptoKeyVersions/1", projectID, location, keyRing)
	// Get the time pre-signing
	start := time.Now()

	// Create a waitgroup
	var wg sync.WaitGroup
	wg.Add(iterations)

	for i := 0; i < iterations; i++ {
		go func(j int) {
			_ = mldsa.SignData(smallInput, "mldsa", keyName, &wg)
		}(i)
	}
	wg.Wait()

	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Small Payload ML-DSA-65: %.3f ms\n", (elapsed.Seconds()*1000)/float64(iterations))
}

func testMldsaMediumPayload(iterations int, location string, keyRing string, projectID string) {
	keyName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/mldsa/cryptoKeyVersions/1", projectID, location, keyRing)

	// Get the time pre-signing
	start := time.Now()

	// Create a waitgroup
	var wg sync.WaitGroup
	wg.Add(iterations)

	for i := 0; i < iterations; i++ {
		go func(j int) {
			_ = mldsa.SignData(mediumInput, "mldsa", keyName, &wg)
		}(i)
	}
	wg.Wait()
	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Medium Payload ML-DSA-65: %.3f ms\n", (elapsed.Seconds()*1000)/float64(iterations))
}

func testFalconSmallPayload(iterations int) {
	// Generate a private key
	privKey, err := falcon.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate a private key: %v", err)
	}

	// Get the time pre-signing
	start := time.Now()

	// Create a waitgroup
	var wg sync.WaitGroup
	wg.Add(iterations)

	for i := 0; i < iterations; i++ {
		go func(j int) {
			_ = falcon.SignData(smallInput, privKey, &wg)
		}(i)
	}
	wg.Wait()
	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Small Payload Falcon-512: %.3f ms\n", (elapsed.Seconds()*1000)/float64(iterations))
}

func testFalconMediumPayload(iterations int) {
	// Generate a private key
	privKey, err := falcon.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate a private key: %v", err)
	}

	// Get the time pre-signing
	start := time.Now()
	// Create a waitgroup
	var wg sync.WaitGroup
	wg.Add(iterations)

	for i := 0; i < iterations; i++ {
		go func(j int) {
			_ = falcon.SignData(mediumInput, privKey, &wg)
		}(i)
	}
	wg.Wait()
	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Medium Payload Falcon-512: %.3f ms\n", (elapsed.Seconds()*1000)/float64(iterations))
}

func testEcdsaSmallPayload(iterations int, location string, keyRing string, projectID string) {
	keyName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/ecdsa/cryptoKeyVersions/1", projectID, location, keyRing)
	// Get the time pre-signing
	start := time.Now()

	// Create a waitgroup
	var wg sync.WaitGroup
	wg.Add(iterations)

	for i := 0; i < iterations; i++ {
		go func(j int) {
			_ = ecdsa.SignData(smallInput, "ecdsa", keyName, &wg)
		}(i)
	}
	wg.Wait()

	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Small Payload ECDSA-384: %.3f ms\n", (elapsed.Seconds()*1000)/float64(iterations))
}

func testEcdsaMediumPayload(iterations int, location string, keyRing string, projectID string) {
	keyName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/ecdsa/cryptoKeyVersions/1", projectID, location, keyRing)
	// Get the time pre-signing
	start := time.Now()

	// Create a waitgroup
	var wg sync.WaitGroup
	wg.Add(iterations)

	for i := 0; i < iterations; i++ {
		go func(j int) {
			_ = ecdsa.SignData(mediumInput, "ecdsa", keyName, &wg)
		}(i)
	}
	wg.Wait()

	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Medium Payload ECDSA-384: %.3f ms\n", (elapsed.Seconds()*1000)/float64(iterations))
}

func testRsaSmallPayload(iterations int) {
	// Generate a private key
	privKey, err := rsa_local.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate a private key: %v", err)
	}

	// Get the time pre-signing
	start := time.Now()

	// Create a waitgroup
	var wg sync.WaitGroup
	wg.Add(iterations)

	for i := 0; i < iterations; i++ {
		go func(j int) {
			_ = rsa_local.SignData(smallInput, privKey, &wg)
		}(i)
	}
	wg.Wait()

	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Small Payload RSA-4096: %.3f ms\n", (elapsed.Seconds()*1000)/float64(iterations))
}

func testRsaMediumPayload(iterations int) {
	// Generate a private key
	privKey, err := rsa_local.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate a private key: %v", err)
	}

	// Get the time pre-signing
	start := time.Now()

	// Create a waitgroup
	var wg sync.WaitGroup
	wg.Add(iterations)

	for i := 0; i < iterations; i++ {
		go func(j int) {
			_ = rsa_local.SignData(mediumInput, privKey, &wg)
		}(i)
	}
	wg.Wait()

	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Medium Payload RSA-4096: %.3f ms\n", (elapsed.Seconds()*1000)/float64(iterations))
}

func main() {
	iterations := 100
	location := goDotEnvVariable("LOCATION")
	keyRing := goDotEnvVariable("KEYRING")
	projectID := goDotEnvVariable("PROJECT_ID")

	fmt.Printf("---Running Tests: Avg time per signature---\n\n")

	// Run the small payload tests
	testFalconSmallPayload(iterations)
	testRsaSmallPayload(iterations)
	testMldsaSmallPayload(iterations, location, keyRing, projectID)
	testEcdsaSmallPayload(iterations, location, keyRing, projectID)

	// Run the medium payload tests
	testFalconMediumPayload(iterations)
	testRsaMediumPayload(iterations)
	testMldsaMediumPayload(iterations, location, keyRing, projectID)
	testEcdsaMediumPayload(iterations, location, keyRing, projectID)

}

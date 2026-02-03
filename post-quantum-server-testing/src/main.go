package main

import (
	"fmt"
	"log"
	"os"
	"server-testing/ecdsa_local"
	"server-testing/falcon"
	"server-testing/mldsa"
	"server-testing/rsa"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
)

const (
	SMALLINPUT = "aGkK" // "hi" (<1MB)
)

var (
	MEDIUMINPUT = strings.Repeat("aGkK", 1024*512) // "hi" repeatedly (1-2MB)
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
			_ = mldsa.SignData(SMALLINPUT, "mldsa", keyName, &wg)
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
			_ = mldsa.SignData(MEDIUMINPUT, "mldsa", keyName, &wg)
		}(i)
	}
	wg.Wait()
	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Medium Payload ML-DSA-65: %.3f ms\n", (elapsed.Seconds()*1000)/float64(iterations))
}

func testFalconSmallPayload(iterations int, privKey *falcon.PrivateKey) {
	// Get the time pre-signing
	start := time.Now()

	// Create a waitgroup
	var wg sync.WaitGroup
	wg.Add(iterations)

	for i := 0; i < iterations; i++ {
		go func(j int) {
			_ = falcon.SignData(SMALLINPUT, privKey, &wg)
		}(i)
	}
	wg.Wait()
	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Small Payload Falcon-512: %.3f ms\n", (elapsed.Seconds()*1000)/float64(iterations))
}

func testFalconMediumPayload(iterations int, privKey *falcon.PrivateKey) {
	// Get the time pre-signing
	start := time.Now()

	// Create a waitgroup
	var wg sync.WaitGroup
	wg.Add(iterations)

	for i := 0; i < iterations; i++ {
		go func(j int) {
			_ = falcon.SignData(MEDIUMINPUT, privKey, &wg)
		}(i)
	}
	wg.Wait()
	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Medium Payload Falcon-512: %.3f ms\n", (elapsed.Seconds()*1000)/float64(iterations))
}

func testEcdsaSmallPayload(iterations int, privKey *ecdsa_local.PrivateKey) {
	// Get the time pre-signing
	start := time.Now()

	// Create a waitgroup
	var wg sync.WaitGroup
	wg.Add(iterations)

	for i := 0; i < iterations; i++ {
		go func(j int) {
			_ = ecdsa_local.SignData(SMALLINPUT, privKey, &wg)
		}(i)
	}
	wg.Wait()

	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Small Payload ECDSA-384: %.3f ms\n", (elapsed.Seconds()*1000)/float64(iterations))
}

func testEcdsaMediumPayload(iterations int, privKey *ecdsa_local.PrivateKey) {
	// Get the time pre-signing
	start := time.Now()

	// Create a waitgroup
	var wg sync.WaitGroup
	wg.Add(iterations)

	for i := 0; i < iterations; i++ {
		go func(j int) {
			_ = ecdsa_local.SignData(MEDIUMINPUT, privKey, &wg)
		}(i)
	}
	wg.Wait()

	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Medium Payload ECDSA-384: %.3f ms\n", (elapsed.Seconds()*1000)/float64(iterations))
}

func testRsaSmallPayload(iterations int, location string, keyRing string, projectID string) {
	keyName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/rsa/cryptoKeyVersions/1", projectID, location, keyRing)
	// Get the time pre-signing
	start := time.Now()

	// Create a waitgroup
	var wg sync.WaitGroup
	wg.Add(iterations)

	for i := 0; i < iterations; i++ {
		go func(j int) {
			_ = rsa.SignData(SMALLINPUT, "rsa", keyName, &wg)
		}(i)
	}
	wg.Wait()

	// Get the time post-signing
	elapsed := time.Since(start)
	fmt.Printf("Small Payload RSA-4096: %.3f ms\n", (elapsed.Seconds()*1000)/float64(iterations))
}

func testRsaMediumPayload(iterations int, location string, keyRing string, projectID string) {
	keyName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/rsa/cryptoKeyVersions/1", projectID, location, keyRing)
	// Get the time pre-signing
	start := time.Now()

	// Create a waitgroup
	var wg sync.WaitGroup
	wg.Add(iterations)

	for i := 0; i < iterations; i++ {
		go func(j int) {
			_ = rsa.SignData(MEDIUMINPUT, "rsa", keyName, &wg)
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

	// Generate a falcon private key
	privKeyFalcon, err := falcon.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate a private key: %v", err)
	}

	// Generate an ecdsa private key
	privKeyEcdsa, err := ecdsa_local.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate a private key: %v", err)
	}

	fmt.Printf("---Running Tests: Avg time per signature---\n\n")

	// Run the small payload tests
	testFalconSmallPayload(iterations, privKeyFalcon)
	testEcdsaSmallPayload(iterations, privKeyEcdsa)
	testRsaSmallPayload(iterations, location, keyRing, projectID)
	testMldsaSmallPayload(iterations, location, keyRing, projectID)

	// Run the medium payload tests
	testFalconMediumPayload(iterations, privKeyFalcon)
	testEcdsaMediumPayload(iterations, privKeyEcdsa)
	testRsaMediumPayload(iterations, location, keyRing, projectID)
	testMldsaMediumPayload(iterations, location, keyRing, projectID)

}

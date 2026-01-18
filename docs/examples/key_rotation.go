package main

import (
	"fmt"
	"log"
	"time"

	"github.com/poly-workshop/identra/internal/infrastructure/security"
)

// This example demonstrates the key rotation workflow for JWKS.
// In production, these steps would be automated or executed via CLI/API.
func main() {
	fmt.Println("=== JWKS Key Rotation Example ===")
	fmt.Println()

	// Step 1: Initialize KeyManager with first key
	km := security.GetKeyManager()
	if err := km.GenerateKeyPair(); err != nil {
		log.Fatalf("Failed to generate initial key: %v", err)
	}
	
	initialKeyID := km.GetKeyID()
	fmt.Printf("Step 1: Generated initial ACTIVE key: %s\n", initialKeyID)
	printKeyStatus(km)

	// Step 2: Add new key in PASSIVE state
	fmt.Println("\nStep 2: Adding new key in PASSIVE state...")
	newKeyID, err := km.AddKeyPassive()
	if err != nil {
		log.Fatalf("Failed to add passive key: %v", err)
	}
	fmt.Printf("Added new PASSIVE key: %s\n", newKeyID)
	printKeyStatus(km)

	// Step 3: Wait for JWKS cache propagation (simulated)
	fmt.Println("\nStep 3: Waiting for JWKS cache propagation (1 hour in production)...")
	fmt.Println("(Skipping wait in this example)")
	
	// Step 4: Promote new key to ACTIVE
	fmt.Println("\nStep 4: Promoting new key to ACTIVE...")
	if err := km.PromoteKey(newKeyID); err != nil {
		log.Fatalf("Failed to promote key: %v", err)
	}
	fmt.Printf("Promoted key %s to ACTIVE\n", newKeyID)
	fmt.Printf("Previous key %s automatically demoted to PASSIVE\n", initialKeyID)
	printKeyStatus(km)

	// Step 5: Wait for old tokens to expire (simulated)
	fmt.Println("\nStep 5: Waiting for old tokens to expire (30 minutes in production)...")
	fmt.Println("(Skipping wait in this example)")

	// Step 6: Retire old key
	fmt.Println("\nStep 6: Retiring old key...")
	if err := km.RetireKey(initialKeyID); err != nil {
		log.Fatalf("Failed to retire key: %v", err)
	}
	fmt.Printf("Retired key %s\n", initialKeyID)
	printKeyStatus(km)

	fmt.Println("\n=== Key Rotation Complete ===")
	
	// Demonstrate token signing and verification
	fmt.Println("\n=== Token Operations ===")
	demonstrateTokenOperations(km)
}

func printKeyStatus(km *security.KeyManager) {
	keys := km.ListKeys()
	fmt.Printf("\nCurrent key status (%d keys):\n", len(keys))
	for _, key := range keys {
		status := ""
		if km.GetKeyID() == key.KeyID {
			status = " (current signing key)"
		}
		fmt.Printf("  - %s: %s%s\n", key.KeyID, key.State, status)
	}
	
	// Show JWKS content
	jwks := km.GetJWKS()
	fmt.Printf("\nKeys published in JWKS: %d\n", len(jwks.Keys))
	for _, jwk := range jwks.Keys {
		fmt.Printf("  - %s (%s, %s)\n", jwk.Kid, jwk.Kty, jwk.Alg)
	}
}

func demonstrateTokenOperations(km *security.KeyManager) {
	// Create token configuration
	config := security.TokenConfig{
		PrivateKey:             km.GetPrivateKey(),
		PublicKey:              km.GetPublicKey(),
		KeyID:                  km.GetKeyID(),
		Issuer:                 "identra-example",
		AccessTokenExpiration:  15 * time.Minute,
		RefreshTokenExpiration: 7 * 24 * time.Hour,
	}

	// Generate token pair
	userID := "user-12345"
	tokenPair, err := security.NewTokenPair(userID, config)
	if err != nil {
		log.Fatalf("Failed to create token pair: %v", err)
	}

	fmt.Printf("\nGenerated token pair for user: %s\n", userID)
	fmt.Printf("Access token expires at: %v\n", time.Unix(tokenPair.AccessToken.ExpiresAt, 0))
	fmt.Printf("Refresh token expires at: %v\n", time.Unix(tokenPair.RefreshToken.ExpiresAt, 0))

	// Validate access token
	claims, err := security.ValidateAccessToken(tokenPair.AccessToken.Token, config.PublicKey)
	if err != nil {
		log.Fatalf("Failed to validate access token: %v", err)
	}

	fmt.Printf("\nValidated access token:\n")
	fmt.Printf("  User ID: %s\n", claims.UserID)
	fmt.Printf("  Token Type: %s\n", claims.TokenType)
	fmt.Printf("  Token ID: %s\n", claims.TokenID)
	fmt.Printf("  Issuer: %s\n", claims.Issuer)
}

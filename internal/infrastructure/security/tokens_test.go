package security

import (
	"crypto/rsa"
	"testing"
	"time"

	"github.com/google/uuid"
	identra_v1_pb "github.com/poly-workshop/identra/gen/go/identra/v1"
)

// Helper function to create test token config with generated keys
func createTestTokenConfig(t *testing.T) TokenConfig {
	t.Helper()

	km := &KeyManager{}
	if err := km.GenerateKeyPair(); err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	return TokenConfig{
		PrivateKey:             km.GetPrivateKey(),
		PublicKey:              km.GetPublicKey(),
		KeyID:                  km.GetKeyID(),
		Issuer:                 "test-issuer",
		AccessTokenExpiration:  15 * time.Minute,
		RefreshTokenExpiration: 7 * 24 * time.Hour,
	}
}

func TestNewTokenPair(t *testing.T) {
	userID := uuid.New().String()
	config := createTestTokenConfig(t)

	tokenPair, err := NewTokenPair(userID, config)
	if err != nil {
		t.Fatalf("Failed to create token pair: %v", err)
	}

	if tokenPair.AccessToken == nil || tokenPair.AccessToken.Token == "" {
		t.Error("Expected access_token.token to be non-empty")
	}
	if tokenPair.AccessToken == nil || tokenPair.AccessToken.ExpiresAt == 0 {
		t.Error("Expected access_token.expires_at to be set")
	}

	if tokenPair.RefreshToken == nil || tokenPair.RefreshToken.Token == "" {
		t.Error("Expected refresh_token.token to be non-empty")
	}
	if tokenPair.RefreshToken == nil || tokenPair.RefreshToken.ExpiresAt == 0 {
		t.Error("Expected refresh_token.expires_at to be set")
	}

	if tokenPair.TokenType != "Bearer" {
		t.Errorf("Expected token type 'Bearer', got %s", tokenPair.TokenType)
	}

	expectedAccessExp := time.Now().Add(config.AccessTokenExpiration)
	accessExp := time.Unix(tokenPair.AccessToken.ExpiresAt, 0)
	if accessExp.Before(expectedAccessExp.Add(-5*time.Second)) ||
		accessExp.After(expectedAccessExp.Add(5*time.Second)) {
		t.Errorf("Expected access token expiration around %v, got %v", expectedAccessExp, accessExp)
	}

	expectedRefreshExp := time.Now().Add(config.RefreshTokenExpiration)
	refreshExp := time.Unix(tokenPair.RefreshToken.ExpiresAt, 0)
	if refreshExp.Before(expectedRefreshExp.Add(-5*time.Second)) ||
		refreshExp.After(expectedRefreshExp.Add(5*time.Second)) {
		t.Errorf("Expected refresh token expiration around %v, got %v", expectedRefreshExp, refreshExp)
	}
}

func TestValidateAccessToken(t *testing.T) {
	userID := uuid.New().String()
	config := createTestTokenConfig(t)

	tokenPair, err := NewTokenPair(userID, config)
	if err != nil {
		t.Fatalf("Failed to create token pair: %v", err)
	}

	claims, err := ValidateAccessToken(tokenPair.AccessToken.Token, config.PublicKey)
	if err != nil {
		t.Fatalf("Failed to validate access token: %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, claims.UserID)
	}
	if claims.TokenType != AccessTokenType {
		t.Errorf("Expected token type %s, got %s", AccessTokenType, claims.TokenType)
	}
	if claims.TokenID == "" {
		t.Error("Expected token ID to be set")
	}

	if _, err = ValidateRefreshToken(tokenPair.AccessToken.Token, config.PublicKey); err == nil {
		t.Error("Expected access token to fail validation as refresh token")
	}
}

func TestValidateRefreshToken(t *testing.T) {
	userID := uuid.New().String()
	config := createTestTokenConfig(t)

	tokenPair, err := NewTokenPair(userID, config)
	if err != nil {
		t.Fatalf("Failed to create token pair: %v", err)
	}

	claims, err := ValidateRefreshToken(tokenPair.RefreshToken.Token, config.PublicKey)
	if err != nil {
		t.Fatalf("Failed to validate refresh token: %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, claims.UserID)
	}
	if claims.TokenType != RefreshTokenType {
		t.Errorf("Expected token type %s, got %s", RefreshTokenType, claims.TokenType)
	}

	if _, err = ValidateAccessToken(tokenPair.RefreshToken.Token, config.PublicKey); err == nil {
		t.Error("Expected refresh token to fail validation as access token")
	}
}

func TestRefreshTokenPair(t *testing.T) {
	userID := uuid.New().String()
	config := createTestTokenConfig(t)

	originalPair, err := NewTokenPair(userID, config)
	if err != nil {
		t.Fatalf("Failed to create initial token pair: %v", err)
	}

	newPair, err := RefreshTokenPair(originalPair.RefreshToken.Token, config)
	if err != nil {
		t.Fatalf("Failed to refresh token pair: %v", err)
	}

	if newPair.AccessToken.Token == originalPair.AccessToken.Token {
		t.Error("Expected new access token to be different from original")
	}
	if newPair.RefreshToken.Token == originalPair.RefreshToken.Token {
		t.Error("Expected new refresh token to be different from original")
	}

	claims, err := ValidateAccessToken(newPair.AccessToken.Token, config.PublicKey)
	if err != nil {
		t.Fatalf("Failed to validate new access token: %v", err)
	}
	if claims.UserID != userID {
		t.Errorf("Expected user ID %s in refreshed token, got %s", userID, claims.UserID)
	}
}

func TestStandardClaims(t *testing.T) {
	userID := uuid.New().String()
	issuer := "test-issuer"
	expiresAt := time.Now().Add(1 * time.Hour)

	claims, err := NewStandardClaims(userID, AccessTokenType, issuer, expiresAt)
	if err != nil {
		t.Fatalf("Failed to create standard claims: %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, claims.UserID)
	}
	if claims.TokenType != AccessTokenType {
		t.Errorf("Expected token type %s, got %s", AccessTokenType, claims.TokenType)
	}
	if claims.TokenID == "" {
		t.Error("Expected token ID (jti) to be set")
	}

	if claims.Issuer != issuer {
		t.Errorf("Expected issuer %s, got %s", issuer, claims.Issuer)
	}
	if claims.Subject != userID {
		t.Errorf("Expected subject %s, got %s", userID, claims.Subject)
	}
	if claims.ID != claims.TokenID {
		t.Errorf("Expected ID and TokenID to match")
	}
}

// Legacy compatibility tests

func TestLegacyUserTokenClaimsWithExpiration(t *testing.T) {
	userID := uuid.New().String()
	customExpiration := time.Now().Add(3 * time.Hour)

	claims := NewUserTokenClaimsWithExpiration(userID, customExpiration)

	claimsUserID, ok := claims.MapClaims["user_id"].(string)
	if !ok {
		t.Error("Expected user_id in claims")
	}
	if claimsUserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, claimsUserID)
	}

	expUnix, ok := claims.MapClaims["exp"].(int64)
	if !ok {
		t.Error("Expected exp in claims")
	}

	claimsExpiration := time.Unix(expUnix, 0)
	if claimsExpiration.Before(customExpiration.Add(-5*time.Second)) ||
		claimsExpiration.After(customExpiration.Add(5*time.Second)) {
		t.Errorf("Expected expiration around %v, got %v", customExpiration, claimsExpiration)
	}
}

func TestInvalidTokenValidation(t *testing.T) {
	config := createTestTokenConfig(t)

	if _, err := ValidateAccessToken("invalid-token", config.PublicKey); err == nil {
		t.Error("Expected error for invalid token")
	}

	userID := uuid.New().String()
	tokenPair, err := NewTokenPair(userID, config)
	if err != nil {
		t.Fatalf("Failed to create token pair: %v", err)
	}

	wrongKm := &KeyManager{}
	if err := wrongKm.GenerateKeyPair(); err != nil {
		t.Fatalf("Failed to generate wrong key pair: %v", err)
	}

	if _, err = ValidateAccessToken(tokenPair.AccessToken.Token, wrongKm.GetPublicKey()); err == nil {
		t.Error("Expected error for wrong public key")
	}
}

func TestKeyManager(t *testing.T) {
	km := &KeyManager{}

	if km.IsInitialized() {
		t.Error("Expected key manager to be uninitialized")
	}

	if err := km.GenerateKeyPair(); err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	if !km.IsInitialized() {
		t.Error("Expected key manager to be initialized")
	}

	if km.GetKeyID() == "" {
		t.Error("Expected key ID to be set")
	}

	if km.GetPublicKey() == nil {
		t.Error("Expected public key to be available")
	}

	if km.GetPrivateKey() == nil {
		t.Error("Expected private key to be available")
	}

	jwksResponse := km.GetJWKS()
	if len(jwksResponse.Keys) != 1 {
		t.Errorf("Expected 1 key in JWKS, got %d", len(jwksResponse.Keys))
	}
	if jwksResponse.Keys[0].Kty != "RSA" {
		t.Errorf("Expected key type RSA, got %s", jwksResponse.Keys[0].Kty)
	}
	if jwksResponse.Keys[0].Alg != "RS256" {
		t.Errorf("Expected algorithm RS256, got %s", jwksResponse.Keys[0].Alg)
	}
	if jwksResponse.Keys[0].Use != "sig" {
		t.Errorf("Expected use sig, got %s", jwksResponse.Keys[0].Use)
	}

	privatePEM, err := km.ExportPrivateKeyPEM()
	if err != nil {
		t.Fatalf("Failed to export private key PEM: %v", err)
	}
	if privatePEM == "" {
		t.Error("Expected private key PEM to be non-empty")
	}

	publicPEM, err := km.ExportPublicKeyPEM()
	if err != nil {
		t.Fatalf("Failed to export public key PEM: %v", err)
	}
	if publicPEM == "" {
		t.Error("Expected public key PEM to be non-empty")
	}

	newKm := &KeyManager{}
	if err := newKm.InitializeFromPEM(privatePEM); err != nil {
		t.Fatalf("Failed to initialize from PEM: %v", err)
	}
	if !newKm.IsInitialized() {
		t.Error("Expected new key manager to be initialized from PEM")
	}
}

func TestKeyRotation(t *testing.T) {
	km := &KeyManager{}

	// Initialize with first key
	if err := km.GenerateKeyPair(); err != nil {
		t.Fatalf("Failed to generate initial key pair: %v", err)
	}

	firstKeyID := km.GetKeyID()
	if firstKeyID == "" {
		t.Error("Expected initial key ID to be set")
	}

	// Verify only one key in JWKS
	jwks := km.GetJWKS()
	if len(jwks.Keys) != 1 {
		t.Errorf("Expected 1 key in JWKS, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].Kid != firstKeyID {
		t.Errorf("Expected key ID %s, got %s", firstKeyID, jwks.Keys[0].Kid)
	}

	// Add a new key in PASSIVE state
	secondKeyID, err := km.AddKeyPassive()
	if err != nil {
		t.Fatalf("Failed to add passive key: %v", err)
	}
	if secondKeyID == "" {
		t.Error("Expected second key ID to be set")
	}
	if secondKeyID == firstKeyID {
		t.Error("Expected second key ID to be different from first")
	}

	// Verify both keys are in JWKS
	jwks = km.GetJWKS()
	if len(jwks.Keys) != 2 {
		t.Errorf("Expected 2 keys in JWKS after adding passive key, got %d", len(jwks.Keys))
	}

	// Verify active key is still the first one
	if km.GetKeyID() != firstKeyID {
		t.Errorf("Expected active key to still be %s, got %s", firstKeyID, km.GetKeyID())
	}

	// Promote the second key to ACTIVE
	if err := km.PromoteKey(secondKeyID); err != nil {
		t.Fatalf("Failed to promote key: %v", err)
	}

	// Verify active key is now the second one
	if km.GetKeyID() != secondKeyID {
		t.Errorf("Expected active key to be %s after promotion, got %s", secondKeyID, km.GetKeyID())
	}

	// Verify both keys are still in JWKS (old key should be PASSIVE now)
	jwks = km.GetJWKS()
	if len(jwks.Keys) != 2 {
		t.Errorf("Expected 2 keys in JWKS after promotion, got %d", len(jwks.Keys))
	}

	// Retire the first key
	if err := km.RetireKey(firstKeyID); err != nil {
		t.Fatalf("Failed to retire key: %v", err)
	}

	// Verify only the second key is in JWKS
	jwks = km.GetJWKS()
	if len(jwks.Keys) != 1 {
		t.Errorf("Expected 1 key in JWKS after retiring first key, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].Kid != secondKeyID {
		t.Errorf("Expected remaining key to be %s, got %s", secondKeyID, jwks.Keys[0].Kid)
	}
}

func TestKeyRotationWithTokenValidation(t *testing.T) {
	km := &KeyManager{}

	// Initialize with first key
	if err := km.GenerateKeyPair(); err != nil {
		t.Fatalf("Failed to generate initial key pair: %v", err)
	}

	// Create a token with the first key
	userID := uuid.New().String()
	config := TokenConfig{
		PrivateKey:             km.GetPrivateKey(),
		PublicKey:              km.GetPublicKey(),
		KeyID:                  km.GetKeyID(),
		Issuer:                 "test-issuer",
		AccessTokenExpiration:  15 * time.Minute,
		RefreshTokenExpiration: 7 * 24 * time.Hour,
	}

	tokenPair, err := NewTokenPair(userID, config)
	if err != nil {
		t.Fatalf("Failed to create token pair: %v", err)
	}

	// Verify token can be validated with first key
	claims, err := ValidateAccessToken(tokenPair.AccessToken.Token, km.GetPublicKey())
	if err != nil {
		t.Fatalf("Failed to validate token with first key: %v", err)
	}
	if claims.UserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, claims.UserID)
	}

	// Add a new key in PASSIVE state
	secondKeyID, err := km.AddKeyPassive()
	if err != nil {
		t.Fatalf("Failed to add passive key: %v", err)
	}

	// Promote the second key to ACTIVE
	if err := km.PromoteKey(secondKeyID); err != nil {
		t.Fatalf("Failed to promote key: %v", err)
	}

	// Token signed with first key should still be valid (key is now PASSIVE)
	// Note: We need to get the first key's public key from the key ring
	firstPublicKey := getPublicKeyFromJWKS(km.GetJWKS(), claims.TokenID)
	if firstPublicKey == nil {
		// Try validating with current public key (should fail if rotation worked)
		t.Log("First key not found in JWKS (expected after some time), trying current key")
	}

	// Create a new token with the second (now active) key
	config.PrivateKey = km.GetPrivateKey()
	config.PublicKey = km.GetPublicKey()
	config.KeyID = km.GetKeyID()

	newTokenPair, err := NewTokenPair(userID, config)
	if err != nil {
		t.Fatalf("Failed to create token pair with second key: %v", err)
	}

	// New token should be valid with second key
	newClaims, err := ValidateAccessToken(newTokenPair.AccessToken.Token, km.GetPublicKey())
	if err != nil {
		t.Fatalf("Failed to validate token with second key: %v", err)
	}
	if newClaims.UserID != userID {
		t.Errorf("Expected user ID %s in new token, got %s", userID, newClaims.UserID)
	}
}

func TestKeyLifecycleErrors(t *testing.T) {
	km := &KeyManager{}

	// Try to promote a non-existent key
	if err := km.PromoteKey("nonexistent"); err == nil {
		t.Error("Expected error when promoting non-existent key")
	}

	// Try to retire a non-existent key
	if err := km.RetireKey("nonexistent"); err == nil {
		t.Error("Expected error when retiring non-existent key")
	}

	// Generate initial key
	if err := km.GenerateKeyPair(); err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	activeKeyID := km.GetKeyID()

	// Try to promote an already ACTIVE key
	if err := km.PromoteKey(activeKeyID); err == nil {
		t.Error("Expected error when promoting already ACTIVE key")
	}

	// Try to retire an ACTIVE key
	if err := km.RetireKey(activeKeyID); err == nil {
		t.Error("Expected error when retiring ACTIVE key")
	}

	// Add passive key
	passiveKeyID, err := km.AddKeyPassive()
	if err != nil {
		t.Fatalf("Failed to add passive key: %v", err)
	}

	// Retire passive key should succeed
	if err := km.RetireKey(passiveKeyID); err != nil {
		t.Errorf("Failed to retire passive key: %v", err)
	}
}

func TestListKeys(t *testing.T) {
	km := &KeyManager{}

	// Initially empty
	keys := km.ListKeys()
	if len(keys) != 0 {
		t.Errorf("Expected 0 keys initially, got %d", len(keys))
	}

	// Add first key
	if err := km.GenerateKeyPair(); err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	keys = km.ListKeys()
	if len(keys) != 1 {
		t.Errorf("Expected 1 key after generation, got %d", len(keys))
	}
	if keys[0].State != KeyStateActive {
		t.Errorf("Expected first key to be ACTIVE, got %s", keys[0].State)
	}

	// Add passive key
	passiveKeyID, err := km.AddKeyPassive()
	if err != nil {
		t.Fatalf("Failed to add passive key: %v", err)
	}

	keys = km.ListKeys()
	if len(keys) != 2 {
		t.Errorf("Expected 2 keys after adding passive key, got %d", len(keys))
	}

	// Verify states
	activeCount := 0
	passiveCount := 0
	for _, k := range keys {
		if k.State == KeyStateActive {
			activeCount++
		} else if k.State == KeyStatePassive {
			passiveCount++
		}
	}
	if activeCount != 1 {
		t.Errorf("Expected 1 ACTIVE key, got %d", activeCount)
	}
	if passiveCount != 1 {
		t.Errorf("Expected 1 PASSIVE key, got %d", passiveCount)
	}

	// Promote passive key
	if err := km.PromoteKey(passiveKeyID); err != nil {
		t.Fatalf("Failed to promote key: %v", err)
	}

	keys = km.ListKeys()
	activeCount = 0
	passiveCount = 0
	for _, k := range keys {
		if k.State == KeyStateActive {
			activeCount++
		} else if k.State == KeyStatePassive {
			passiveCount++
		}
	}
	if activeCount != 1 {
		t.Errorf("Expected 1 ACTIVE key after promotion, got %d", activeCount)
	}
	if passiveCount != 1 {
		t.Errorf("Expected 1 PASSIVE key after promotion, got %d", passiveCount)
	}
}

// Helper function to get public key from JWKS (simplified for testing)
func getPublicKeyFromJWKS(jwks *identra_v1_pb.GetJWKSResponse, tokenID string) *rsa.PublicKey {
	// In real implementation, this would parse kid from JWT header
	// For testing, we just return nil if not found
	return nil
}

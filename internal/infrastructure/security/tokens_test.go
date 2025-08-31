package security

import (
	"testing"
	"time"

	"github.com/google/uuid"
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

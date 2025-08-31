package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"

	identra_v1_pb "github.com/poly-workshop/identra/gen/go/identra/v1"
)

const (
	// RSAKeySize is the size of RSA keys in bits
	RSAKeySize = 2048
	// KeyAlgorithm is the algorithm used for signing
	KeyAlgorithm = "RS256"
	// KeyUsage indicates the key is used for signing
	KeyUsage = "sig"
)

// KeyManager manages RSA key pairs for JWT signing and verification
// and can expose them as a JWKS document.
type KeyManager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
	mu         sync.RWMutex
}

var (
	globalKeyManager *KeyManager
	keyManagerOnce   sync.Once
)

// GetKeyManager returns the global KeyManager instance.
func GetKeyManager() *KeyManager {
	keyManagerOnce.Do(func() {
		globalKeyManager = &KeyManager{}
	})
	return globalKeyManager
}

// InitializeFromPEM initializes the key manager from a PEM-encoded private key.
func (km *KeyManager) InitializeFromPEM(privateKeyPEM string) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	var privateKey *rsa.PrivateKey
	var err error

	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return fmt.Errorf("failed to parse PKCS8 private key: %w", parseErr)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("private key is not RSA")
		}
	default:
		return fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}

	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	km.privateKey = privateKey
	km.publicKey = &privateKey.PublicKey
	km.keyID = km.generateKeyID()

	return nil
}

// GenerateKeyPair generates a new RSA key pair.
func (km *KeyManager) GenerateKeyPair() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	privateKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	km.privateKey = privateKey
	km.publicKey = &privateKey.PublicKey
	km.keyID = km.generateKeyID()

	return nil
}

// generateKeyID creates a unique key ID based on the public key.
func (km *KeyManager) generateKeyID() string {
	if km.publicKey == nil {
		return ""
	}

	hash := sha256.Sum256(km.publicKey.N.Bytes())
	return base64.RawURLEncoding.EncodeToString(hash[:8])
}

// GetPrivateKey returns the RSA private key for signing.
func (km *KeyManager) GetPrivateKey() *rsa.PrivateKey {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.privateKey
}

// GetPublicKey returns the RSA public key for verification.
func (km *KeyManager) GetPublicKey() *rsa.PublicKey {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.publicKey
}

// GetKeyID returns the key ID.
func (km *KeyManager) GetKeyID() string {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.keyID
}

// IsInitialized checks if the key manager has been initialized.
func (km *KeyManager) IsInitialized() bool {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.privateKey != nil
}

// GetJWKS returns the JSON Web Key Set containing the public key.
func (km *KeyManager) GetJWKS() *identra_v1_pb.GetJWKSResponse {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.publicKey == nil {
		return &identra_v1_pb.GetJWKSResponse{
			Keys: []*identra_v1_pb.JSONWebKey{},
		}
	}

	n := base64.RawURLEncoding.EncodeToString(km.publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(km.publicKey.E)).Bytes())

	return &identra_v1_pb.GetJWKSResponse{
		Keys: []*identra_v1_pb.JSONWebKey{
			{
				Kty: "RSA",
				Alg: KeyAlgorithm,
				Use: KeyUsage,
				Kid: km.keyID,
				N:   &n,
				E:   &e,
			},
		},
	}
}

// ExportPrivateKeyPEM exports the private key in PEM format.
func (km *KeyManager) ExportPrivateKeyPEM() (string, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.privateKey == nil {
		return "", fmt.Errorf("no private key available")
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(km.privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return string(privateKeyPEM), nil
}

// ExportPublicKeyPEM exports the public key in PEM format.
func (km *KeyManager) ExportPublicKeyPEM() (string, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.publicKey == nil {
		return "", fmt.Errorf("no public key available")
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(km.publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(publicKeyPEM), nil
}

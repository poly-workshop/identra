# JWKS Key Rotation Guide

## Overview

Identra's JWT signing key infrastructure supports robust key rotation to enable secure, zero-downtime key updates. This guide explains how key rotation works and provides recommended procedures for operators.

## Key Lifecycle States

Keys in the Identra KeyManager can be in one of three states:

- **ACTIVE**: The key currently used for signing new JWT tokens. Only one key can be ACTIVE at a time.
- **PASSIVE**: Keys published in the JWKS endpoint for token verification but not used for signing. Multiple keys can be PASSIVE simultaneously.
- **RETIRED**: Keys removed from the system entirely. They are no longer published in JWKS and cannot verify tokens.

## Key Rotation Strategy

Identra implements **Option 1: Short-lived JWT with Key Rotation** from the JWKS rotation strategy:

- Access tokens are short-lived (typically 5-15 minutes)
- Refresh tokens are long-lived (typically 7 days)
- Both token types include a `kid` (key ID) in the JWT header
- The JWKS endpoint exposes all ACTIVE and PASSIVE keys
- During rotation, both old and new keys are published simultaneously to ensure continuous token validity

## Rotation Procedure

### Recommended Timeline

For access tokens with a 15-minute lifetime:

1. **T+0**: Add new key in PASSIVE state
2. **T+1 hour**: Promote new key to ACTIVE (old key becomes PASSIVE)
3. **T+2 hours**: Retire old key (after all tokens signed with it have expired)

The 1-hour delay before promotion allows JWKS caches to refresh and clients to discover the new key before it's used for signing.

### Step-by-Step Process

#### 1. Add New Key (PASSIVE)

```go
km := security.GetKeyManager()
newKeyID, err := km.AddKeyPassive()
if err != nil {
    log.Fatalf("Failed to add passive key: %v", err)
}
log.Printf("Added new passive key: %s", newKeyID)
```

At this point:
- New key is published in JWKS but not used for signing
- Existing ACTIVE key continues signing tokens
- All previously issued tokens remain valid

#### 2. Wait for Cache Propagation

**Recommended wait time**: 1 hour (longer than the JWKS cache max-age)

This ensures:
- All clients have refreshed their cached JWKS
- The new key is known to all relying parties
- No verification failures when the key becomes ACTIVE

#### 3. Promote New Key to ACTIVE

```go
km := security.GetKeyManager()
err := km.PromoteKey(newKeyID)
if err != nil {
    log.Fatalf("Failed to promote key: %v", err)
}
log.Printf("Promoted key %s to ACTIVE", newKeyID)
```

At this point:
- New key is now used for signing all new tokens
- Old key is automatically demoted to PASSIVE
- Both keys remain in JWKS for verification
- Tokens signed with either key are valid

#### 4. Wait for Old Tokens to Expire

**Recommended wait time**: 2x access token lifetime (e.g., 30 minutes for 15-minute tokens)

This ensures:
- All tokens signed with the old key have expired
- No valid tokens depend on the old key for verification

#### 5. Retire Old Key

```go
km := security.GetKeyManager()
err := km.RetireKey(oldKeyID)
if err != nil {
    log.Fatalf("Failed to retire key: %v", err)
}
log.Printf("Retired key %s", oldKeyID)
```

At this point:
- Old key is completely removed from the system
- Only the new ACTIVE key appears in JWKS
- System is back to single-key state

## Key Management API

### List All Keys

```go
km := security.GetKeyManager()
keys := km.ListKeys()
for _, key := range keys {
    fmt.Printf("Key ID: %s, State: %s\n", key.KeyID, key.State)
}
```

### Add Key in PASSIVE State

```go
km := security.GetKeyManager()
keyID, err := km.AddKeyPassive()
```

### Promote PASSIVE Key to ACTIVE

```go
km := security.GetKeyManager()
err := km.PromoteKey(keyID)
```

### Demote ACTIVE Key to PASSIVE

```go
km := security.GetKeyManager()
err := km.DemoteKey(keyID)
```

### Retire PASSIVE Key

```go
km := security.GetKeyManager()
err := km.RetireKey(keyID)
```

Note: You cannot retire an ACTIVE key directly. Demote it first.

## HTTP Cache Headers

The JWKS endpoint includes the following cache headers:

- `Cache-Control: public, max-age=3600` (1 hour cache)
- `ETag: "..."` (content-based hash for efficient cache validation)

Clients should:
1. Cache the JWKS response for up to 1 hour
2. Use `If-None-Match` with the ETag for cache revalidation
3. Implement a fallback to re-fetch if verification fails

## Emergency Key Rotation

If a key is compromised:

1. **Immediately** add a new PASSIVE key
2. **Immediately** promote it to ACTIVE (skip the propagation wait)
3. Monitor for verification failures and investigate
4. Consider revoking all active sessions (out of scope for current implementation)
5. After investigation, retire the compromised key

The 1-hour propagation delay is optional in emergencies, but expect some verification failures until caches refresh.

## Monitoring

Monitor the following metrics:

- Number of keys in each state (should normally be 1 ACTIVE, 0-1 PASSIVE)
- JWKS cache hit/miss rates
- Token verification success/failure rates
- Key age (rotate keys periodically, e.g., every 90 days)

## Best Practices

1. **Schedule rotations during low-traffic periods** to minimize impact
2. **Automate the rotation process** to reduce human error
3. **Keep rotation windows generous** (at least 2x token lifetime)
4. **Test rotation in staging** before production
5. **Document each rotation** with timestamps and key IDs
6. **Never skip the PASSIVE phase** unless it's an emergency

## Troubleshooting

### "Token verification failed" after rotation

- Check that both keys are in JWKS
- Verify the token's `kid` matches a published key
- Check client's JWKS cache TTL
- Ensure promotion happened after cache refresh

### "Cannot retire ACTIVE key"

- Call `DemoteKey(keyID)` first
- Then call `RetireKey(keyID)`

### "Key not found" error

- Verify key ID with `ListKeys()`
- Check for typos in the key ID
- Ensure key hasn't already been retired

## Future Enhancements

Potential improvements (out of scope for current implementation):

- CLI tool for key rotation operations
- Admin API endpoints for key management
- Automated periodic rotation
- Key rotation audit log
- Metrics and alerting integration
- Support for multiple key algorithms (ES256, EdDSA)

## References

- RFC 7517: JSON Web Key (JWK)
- RFC 7519: JSON Web Token (JWT)
- [JWKS Best Practices](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets)

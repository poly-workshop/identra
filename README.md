# Identra

Identra is an out-of-the-box authentication and user management service designed to simplify the user
authentication process for applications.

## Features

- 🔐 **Multiple Authentication Methods**: GitHub OAuth, email code, and password-based authentication
- 🔑 **JWT + JWKS**: RS256-signed tokens with a JWKS endpoint for downstream verification
- 🔄 **Token Refresh**: Short-lived access tokens and long-lived refresh tokens
- 🔗 **Account Linking**: Link multiple authentication methods to a single user account
- 🗄️ **Flexible Storage**: SQLite, PostgreSQL, MySQL, or MongoDB persistence
- 📧 **Email Integration**: Configurable SMTP delivery for email-code authentication
- 🚀 **Production Ready**: Docker images, key rotation support, and configurable token settings

## Quick Start

### Running Identra

The repository builds two services:

- `identra-grpc` exposes the gRPC API on port `50051`
- `identra-gateway` exposes the HTTP/JSON API on port `8080`

The easiest way to run Identra is with the published Docker images:

```bash
# Run the gRPC service
docker run --rm -p 50051:50051 \
  -v "$(pwd)/configs:/app/configs" \
  -v "$(pwd)/data:/app/data" \
  ghcr.io/poly-workshop/identra-grpc:latest

# Run the HTTP gateway (in another terminal)
docker run --rm -p 8080:8080 \
  -v "$(pwd)/configs:/app/configs" \
  ghcr.io/poly-workshop/identra-gateway:latest
```

Or run both services from source:

```bash
go mod download

# Run the gRPC service
go run ./cmd/identra-grpc

# Run the HTTP gateway (in another terminal)
go run ./cmd/identra-gateway
```

### Configuration

Identra reads TOML config from `configs/grpc/default.toml` and `configs/gateway/default.toml`. Environment
variables can override the same keys by replacing `.` with `_` (for example `AUTH_GITHUB_CLIENT_ID`).

Minimal gRPC configuration:

```toml
grpc_port = 50051

[auth]
oauth_state_expiration = "10m"
access_token_expiration = "15m"
refresh_token_expiration = "168h"
token_issuer = "identra"
# Optional: if omitted, Identra generates an RSA key pair at startup.
# rsa_private_key = """
# -----BEGIN RSA PRIVATE KEY-----
# ...
# -----END RSA PRIVATE KEY-----
# """

[auth.oauth]
fetch_email_if_missing = true

[auth.github]
client_id = "your-github-client-id"
client_secret = "your-github-client-secret"

[redis]
urls = ["localhost:6379"]

[persistence]
type = "gorm" # or "mongo"

[persistence.gorm]
driver = "sqlite" # or "postgres", "mysql"
dbname = "data/users.db"
sslmode = "disable"

[smtp_mailer]
host = "" # If empty, email-code delivery is disabled
port = 587
username = "your-email@example.com"
password = "your-password"
from_email = "noreply@example.com"
from_name = "Identra"
```

Minimal gateway configuration:

```toml
http_port = 8080
```

For MongoDB persistence, set `persistence.type = "mongo"` and configure `persistence.mongo.uri` and
`persistence.mongo.database`.

## Integrating Identra with Your Service

Identra provides both HTTP and gRPC interfaces.

### Integration Options

#### Option 1: HTTP REST API

Use the HTTP gateway for browser and backend integrations. Use the `/api/` prefix to stay compatible with
setups that also serve frontend assets. When no frontend assets are present, the same routes may also be
reachable without `/api`.

**Base URL**: `http://localhost:8080/api`

#### Option 2: gRPC

Use the gRPC service directly for internal services and high-performance integrations.

**Endpoint**: `localhost:50051`

### Authentication Flow Examples

#### 1. OAuth Authentication (GitHub)

```javascript
const baseUrl = 'http://localhost:8080/api';
const redirectUrl = 'http://localhost:3000/oauth/callback';

// Optional: discover which providers are enabled
const providers = await fetch(`${baseUrl}/oauth/providers`).then(r => r.json());

// Step 1: Get the authorization URL
const response = await fetch(
  `${baseUrl}/oauth/url?provider=github&redirect_url=${encodeURIComponent(redirectUrl)}`
);
const { url, state } = await response.json();

// Step 2: Redirect the user to GitHub
window.location.href = url;

// Step 3: After your callback receives code + state, exchange them for tokens
const loginResponse = await fetch(`${baseUrl}/oauth/login`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ code, state })
});

const { token } = await loginResponse.json();
// token contains: { access_token, refresh_token, token_type }
```

#### 2. Email Code Authentication

```python
import requests

base_url = 'http://localhost:8080/api'

# Step 1: Send a login code to the user's email
requests.post(f'{base_url}/email/code', json={
    'email': 'user@example.com',
    'use_html': True,
})

# Step 2: Exchange the code for tokens
login_response = requests.post(f'{base_url}/email/login', json={
    'email': 'user@example.com',
    'code': '123456',
})

tokens = login_response.json()['token']
access_token = tokens['access_token']['token']
```

#### 3. Password Authentication

```go
package main

import (
    "bytes"
    "encoding/json"
    "net/http"
)

func login(email, password string) (string, error) {
    body, _ := json.Marshal(map[string]string{
        "email":    email,
        "password": password,
    })

    resp, err := http.Post(
        "http://localhost:8080/api/password/login",
        "application/json",
        bytes.NewBuffer(body),
    )
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    var result struct {
        Token struct {
            AccessToken struct {
                Token string `json:"token"`
            } `json:"access_token"`
        } `json:"token"`
    }

    json.NewDecoder(resp.Body).Decode(&result)
    return result.Token.AccessToken.Token, nil
}
```

### Token Validation

Identra issues RS256 JWTs that your services can validate with the JWKS endpoint.

#### Step 1: Fetch the JWKS

```bash
curl http://localhost:8080/api/.well-known/jwks.json
```

Response:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "kid": "key-id-123",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

#### Step 2: Validate JWTs using the public key

Node.js example:

```javascript
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const client = jwksClient({
  jwksUri: 'http://localhost:8080/api/.well-known/jwks.json',
  cache: true,
  cacheMaxAge: 3600000,
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

function verifyToken(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, getKey, {
      algorithms: ['RS256'],
      issuer: 'identra',
    }, (err, decoded) => {
      if (err) reject(err);
      else resolve(decoded);
    });
  });
}
```

Python example:

```python
from jose import jwt
import requests

jwks_url = 'http://localhost:8080/api/.well-known/jwks.json'
jwks = requests.get(jwks_url).json()

def verify_token(token):
    unverified_header = jwt.get_unverified_header(token)

    rsa_key = {}
    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = key
            break

    if not rsa_key:
        raise Exception('Public key not found')

    return jwt.decode(
        token,
        rsa_key,
        algorithms=['RS256'],
        issuer='identra',
    )
```

Go example:

```go
package main

import (
    "context"
    "fmt"

    "github.com/golang-jwt/jwt/v5"
    "github.com/lestrrat-go/jwx/jwk"
)

func validateToken(tokenString string) (*jwt.Token, error) {
    set, err := jwk.Fetch(context.Background(),
        "http://localhost:8080/api/.well-known/jwks.json")
    if err != nil {
        return nil, err
    }

    return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        kid, ok := token.Header["kid"].(string)
        if !ok {
            return nil, fmt.Errorf("kid not found")
        }

        key, ok := set.LookupKeyID(kid)
        if !ok {
            return nil, fmt.Errorf("key not found")
        }

        var pubkey interface{}
        if err := key.Raw(&pubkey); err != nil {
            return nil, err
        }
        return pubkey, nil
    })
}
```

### Token Refresh

```javascript
async function refreshAccessToken(refreshToken) {
  const response = await fetch('http://localhost:8080/api/token/refresh', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: refreshToken })
  });

  const { token } = await response.json();
  return token.access_token.token;
}
```

### Getting User Information

Identra currently expects the access token in the JSON body for its own authenticated endpoints such as
`/me/login-info` and `/oauth/bind`.

```bash
curl -X POST http://localhost:8080/api/me/login-info \
  -H "Content-Type: application/json" \
  -d '{"access_token": "your-access-token"}'
```

Response:

```json
{
  "user_id": "uuid-here",
  "email": "user@example.com",
  "password_enabled": true,
  "github_id": "123456",
  "oauth_connections": [
    {
      "provider": "github",
      "provider_user_id": "123456"
    }
  ]
}
```

### Account Linking

```javascript
const baseUrl = 'http://localhost:8080/api';
const redirectUrl = 'http://localhost:3000/oauth/callback';
const accessToken = 'current-access-token';

const { url, state } = await fetch(
  `${baseUrl}/oauth/url?provider=github&redirect_url=${encodeURIComponent(redirectUrl)}`
).then(r => r.json());

window.location.href = url;

// After the OAuth callback returns code + state:
await fetch(`${baseUrl}/oauth/bind`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    access_token: accessToken,
    code: oauthCode,
    state,
  })
});
```

## API Reference

The service interface is defined in `proto/identra/v1/identra_service.proto` and exported as OpenAPI in
`gen/openapi/identra.swagger.json`.

### Main Endpoints

- `GET /api/.well-known/jwks.json` - Get the JSON Web Key Set for token validation
- `GET /api/oauth/providers` - List supported OAuth providers and whether each one is enabled
- `GET /api/oauth/url` - Get an OAuth authorization URL (`provider` and `redirect_url` are required)
- `POST /api/oauth/login` - Exchange an OAuth code and state for a token pair
- `POST /api/oauth/bind` - Bind an OAuth account to an existing user
- `POST /api/email/code` - Send a login code via email
- `POST /api/email/login` - Login with an email code
- `POST /api/password/login` - Login with email and password
- `POST /api/token/refresh` - Refresh an access token
- `POST /api/me/login-info` - Get the current user's linked login methods

## Advanced Topics

### Key Rotation

For production deployments, Identra supports JWT signing key rotation. See
[`docs/KEY_ROTATION.md`](./docs/KEY_ROTATION.md).

### Database Setup

Example PostgreSQL configuration:

```toml
[persistence]
type = "gorm"

[persistence.gorm]
driver = "postgres"
host = "localhost"
port = 5432
dbname = "identra"
username = "identra_user"
password = "secure_password"
sslmode = "require"
```

### Production Deployment

1. Use environment variables for sensitive configuration
2. Enable HTTPS for all public endpoints
3. Configure CORS for your frontend domains
4. Set up monitoring for authentication and token validation failures
5. Implement rate limiting on authentication endpoints
6. Rotate signing keys regularly
7. Use Redis and durable persistence in multi-instance deployments

## Contributing

Please refer to [CONTRIBUTING.md](./CONTRIBUTING.md) for contribution guidelines, or check the documentation
in the [docs](./docs) directory for more details on project design.

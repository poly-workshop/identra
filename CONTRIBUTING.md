# Contributing to Identra

Thank you for considering contributing to Identra!
We welcome contributions from the community to help improve and expand the project.

## Development Setup

### Local Verification

Run the same core checks locally before opening a pull request:

```sh
make verify
```

Useful focused targets:

```sh
make test            # run Go tests
make lint            # run Go and protobuf lint checks
make generate        # regenerate protobuf, gRPC gateway, and OpenAPI outputs
make generate-check  # regenerate code and fail if gen/ changed
```

### Generating Protobuf Code

```sh
# Install Buf if you haven't already
brew install bufbuild/buf/buf

make generate
```

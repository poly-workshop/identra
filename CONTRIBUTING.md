# Contributing to Identra

Thank you for considering contributing to Identra!
We welcome contributions from the community to help improve and expand the project.

## Development Setup

### Generating Protobuf Code

```sh
# Install Buf if you haven't already
brew install bufbuild/buf/buf

buf dep update
buf generate --clean
```

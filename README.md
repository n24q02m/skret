# Skret

**Cloud-provider secret manager CLI wrapper with Doppler/Infisical-grade developer experience. Zero Lock-in. Zero Server.**

<!-- Badge Row 1: Status -->
[![CI](https://github.com/n24q02m/skret/actions/workflows/ci.yml/badge.svg)](https://github.com/n24q02m/skret/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/n24q02m/skret/graph/badge.svg)](https://codecov.io/gh/n24q02m/skret)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](#)
[![semantic-release](https://img.shields.io/badge/semantic--release-e10079?logo=semantic-release&logoColor=white)](https://github.com/python-semantic-release/python-semantic-release)
[![License: MIT](https://img.shields.io/github/license/n24q02m/skret)](LICENSE)

## Features

- **Zero-Server Architecture**: Direct cloud IAM integration (AWS SSM). BYOC logic without vendor lock-in.
- **Automatic Cross-Reference Expansion**: Use `${SERVICE_KEY}` to transparently link paths to complex systems. 
- **Built-in History & Rollback**: Auto-archive prior secrets and seamlessly rewind when regressions occur.

## Getting Started

Refer to the [Documentation](docs/) for complete guides.

```bash
# Setup
mise run setup

# Install
go install github.com/n24q02m/skret/...@latest
```

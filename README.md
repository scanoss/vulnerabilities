# SCANOSS Platform 2.0 Vulnerabilities

Welcome to the vulnerabilities server for SCANOSS Platform 2.0. The aim of this project is to provide access to vulnerabilities mined at SCANOSS Knowledge Base.


## Service Description

The SCANOSS Vulnerabilities Service provides comprehensive vulnerability information for software components through both gRPC and REST APIs. The service enables developers and security teams to:

- Query vulnerabilities for software components using PURLs (Package URLs)
- Retrieve CPE (Common Platform Enumeration) identifiers
- Access detailed vulnerability data including CVE information and CVSS scores
- Process single components or batch requests
- Integrate vulnerability scanning into CI/CD pipelines

## Repository Structure

This repository is made up of the following components:
- **cmd/server** - Main server application entry point
- **cmd/cli** - Command-line interface tool
- **pkg/service** - gRPC service implementations
- **pkg/protocol** - REST and gRPC protocol handlers
- **pkg/usecase** - Business logic and use cases
- **pkg/models** - Database models and data structures
- **pkg/adapters** - Data transformation adapters
- **config** - Configuration files for different environments

## Configuration

Environmental variables are configured in this order:
.env → env.json → Actual Environment Variable

Key configuration options:
```
APP_NAME="SCANOSS Vulnerability Server"
APP_PORT=50052
APP_MODE=dev
APP_DEBUG=false

DB_DRIVER=postgres
DB_HOST=localhost
DB_USER=scanoss
DB_PASSWD=
DB_SCHEMA=vulnerabilities
DB_SSL_MODE=disable

# Vulnerability data sources
OSV_ENABLED=true                    # Enable/disable OSV (Open Source Vulnerabilities) database
OSV_API_BASE_URL=https://api.osv.dev/v1
OSV_VULNERABILITY_INFO_BASE_URL=https://osv.dev/vulnerability

SCANOSS_ENABLED=true                # Enable/disable SCANOSS vulnerability database
```

## Docker Environment

The vulnerability server can be deployed as a Docker container.

### How to Build
Build the Docker image:
```
make docker-build
```

### How to Run
Run the Docker image, exposing necessary ports and configuration:
```
docker run -it -v "$(pwd)":"$(pwd)" -p 50052:50052 ghcr.io/scanoss/vulnerabilities -json-config $(pwd)/config/app-config-docker-local-dev.json -debug
```

## Development

Run locally:
```
go run cmd/server/main.go -json-config config/app-config-dev.json -debug
```

After changing versions:
```
go mod tidy -compat=1.24
```

## Bugs/Features

To request features or report bugs, please use the project's GitHub Issues.

## Changelog

Details of major changes can be found in CHANGELOG.md. 

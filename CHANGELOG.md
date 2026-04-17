# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
- Upcoming changes...

### Changed
- Updated dependencies to the latest versions

## [0.11.0] - 2026/03/02
### Added
- Added `lint_docker_fix` Makefile target for auto-fixing linting issues via Docker
- Added new `go-component-helper` dependency for shared component handling logic
### Changed
- Extracted `SanitizeComponents` and `GetComponentsVersion` to external `go-component-helper` library, removing local `pkg/helpers/component_helper.go`
- Replaced `dtos.ComponentDTO` and `entities.Component` with `compHelper.ComponentDTO` and `compHelper.Component` across adapters, service, and use cases
- Improved component status classification in vulnerability use case using exhaustive switch with explicit handling for `ComponentNotFound`, `VersionNotFound`, `InvalidPurl`, `ComponentWithoutInfo`, and `InvalidSemver`
- Components with `ComponentNotFound`/`VersionNotFound` status now fall back to requirement as version when no semver operator is present
- Upgraded `scanoss/go-grpc-helper` to `v0.13.0`
- Upgraded `scanoss/go-models` to `v0.5.1`
- Upgraded `scanoss/papi` to `v0.30.0`

## [0.10.0] - 2026/02/23
### Added
- Included component status (`error_code`, `error_message`) in vulnerability and CPE responses
- Added `Component` entity with `Status` field for tracking component processing state
- Added `SanitizeComponents` and `GetComponentsVersion` shared helpers for reuse across vulnerability and CPE use cases
- Added `HasSemverOperator` utility to detect invalid semver operators in PURL versions

### Changed
- Refactored component sanitization: invalid PURLs are no longer filtered out but returned with an appropriate status code (`invalid_purl`, `component_without_info`)
- Moved component version resolution logic from `vulnerability_use_case.go` to shared `helpers/component_helper.go`
- Updated OSV and local vulnerability use cases to accept `entities.Component` instead of `dtos.ComponentDTO`
- Simplified adapter functions by removing the valid/invalid component split
- Upgraded `scanoss/go-grpc-helper` to `v0.12.0`

## [0.9.0] - 2026/02/02
### Changed
- Added support for GitHub PURLs in OSV use case by mapping them to GIT ecosystem with Git URLs
- Refactored component version resolution in vulnerability use case to use concurrent worker pool
- Upgraded `/scanoss/go-models` to `v0.3.0` 

## [0.8.0] - 2026/01/07
### Added
- Included Exploit Prediction Scoring System (EPSS) to vulnerability response
- Added configurable worker pool for local vulnerability processing (`VULN_SCANOSS_WORKERS`)
### Changed
- Refactored OSV use case
- Refactored local vulnerability use case with multithreading support and context cancellation handling
- Upgraded `scanoss/papi` to v0.28.0

## [0.7.0] - 2025/11/13
### Changed
- Optimized query performance for retrieving vulnerabilities by PURL version using CTE (Common Table Expression) approach in `pkg/models/vulns_purl.go:111`

## [0.6.2] - 2025/10/17
### Added
- Added version bump workflow for automated tag management

### Changed
- Updated CI workflow to use actions/checkout@v4 and actions/setup-go@v5
- Updated Go version to 1.24.x in CI workflows

## [0.6.1] - 2025/09/29
### Changed
- Updated default ports: REST `40052`, gRPC `50052`, and logging `66052`

## [0.6.0] - 2025/08/29
### Changed
- Replaced REST endpoint GET `/api/v2/vulnerabilities/cpes/component` by `/v2/vulnerabilities/cpes/component`
- Replaced REST endpoint POST `/api/v2/vulnerabilities/cpes/components` by `/v2/vulnerabilities/cpes/components`
- Replaced REST endpoint GET `/api/v2/vulnerabilities/component` by `/v2/vulnerabilities/component`
- Replaced REST endpoint POST `/api/v2/vulnerabilities/components` by `/v2/vulnerabilities/components`
- Replaced REST endpoint POST `/api/v2/vulnerabilities/echo` by `/v2/vulnerabilities/echo`
- Updated `github.com/scanoss/papi` to v0.17.0

## [0.5.0] - 2025/08/28
### Added
- Added new vulnerability PAPI definitions
- Added semver support for requests
- Added new adapters to map requests to ComponentDTO
- Added gRPC `GetComponentCpes` and REST endpoint GET `/api/v2/vulnerabilities/cpes/component`
- Added gRPC `GetComponentsCpes` and REST endpoint POST `/api/v2/vulnerabilities/cpes/components`
- Added gRPC `GetComponentVulnerabilities` and REST endpoint GET `/api/v2/vulnerabilities/component`
- Added gRPC `GetComponentsVulnerabilities` and REST endpoint POST `/api/v2/vulnerabilities/components`

### Changed
- Integrated the scanoss [go-model module](https://github.com/scanoss/go-models)
- Refactored request and output adapters
- Refactored CPE and Vulnerability use cases to accept the new ComponentDTO struct
- Refactored vulnerability service to maintain both legacy and new vulnerability and CPE handlers
- Updated direct dependencies

## [0.4.0] - 2025/01/24
### Added
- Add OSV integration
- Add version on vulnerability response

## [0.3.0] - 2024/09/06
### Added
- Add REST transport 

## [0.2.0] - 2023/12/22
### Added
- Add queries pointing to curated t_short_cpe_exported
- Add query to map version range

## [0.1.0] - 2023/12/04
### Added
- Increase test coverage
- Add ranges of cpes Initial structure completed
- Add installation and config files
- Rename 
### Fixed
- Fixed vulnerability service unit tests

[0.1.0]: https://github.com/scanoss/vulnerabilities/compare/v0.0.0...v0.1.0
[0.2.0]: https://github.com/scanoss/vulnerabilities/compare/v0.1.0...v0.2.0
[0.3.0]: https://github.com/scanoss/vulnerabilities/compare/v0.2.0...v0.3.0
[0.4.0]: https://github.com/scanoss/vulnerabilities/compare/v0.3.0...v0.4.0
[0.5.0]: https://github.com/scanoss/vulnerabilities/compare/v0.4.0...v0.5.0
[0.6.0]: https://github.com/scanoss/vulnerabilities/compare/v0.5.0...v0.6.0
[0.6.1]: https://github.com/scanoss/vulnerabilities/compare/v0.6.0...v0.6.1
[0.6.2]: https://github.com/scanoss/vulnerabilities/compare/v0.6.1...v0.6.2
[0.7.0]: https://github.com/scanoss/vulnerabilities/compare/v0.6.2...v0.7.0
[0.8.0]: https://github.com/scanoss/vulnerabilities/compare/v0.7.0...v0.8.0
[0.9.0]: https://github.com/scanoss/vulnerabilities/compare/v0.8.0...v0.9.0
[0.10.0]: https://github.com/scanoss/vulnerabilities/compare/v0.9.0...v0.10.0
[0.11.0]: https://github.com/scanoss/vulnerabilities/compare/v0.10.0...v0.11.0
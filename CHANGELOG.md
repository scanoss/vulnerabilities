# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Upcoming changes...

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
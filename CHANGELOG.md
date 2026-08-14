# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
- Upcoming changes...

## [0.15.0] - 2026-08-14
### Changed
- OSV vulnerabilities are read from the `osv` and `osv_severity` tables instead of the `api.osv.dev` HTTP API. The response is unchanged: same fields, same `source`, same URL construction, and the `cvss` array still carries every vector
- Removed the OSV HTTP client along with `getRepoURL` and the GIT-ecosystem fallback. The table stores `pkg:github` purls directly, so a component is looked up by its purl with no translation to a repository URL and no retry
- `packageurl-go` is no longer a direct dependency
- A failed OSV lookup is now reported as `Failed to query OSV data` rather than `No vulnerabilities found`, so a broken query is no longer indistinguishable from a component with no vulnerabilities
- OSV use case tests no longer reach the network; they run on SQLite against a fixture covering both version-matching mechanisms, multi-vector CVSS and non-CVSS scores

### Added
- `pkg/models/osv.go`, reading OSV data with one portable query per engine and collapsing the table's per-range rows into one entry per vulnerability
- `pkg/models/osv_array.go`, parsing the PostgreSQL array literal form of the list columns. 1,082 production rows have a quoted element and some contain a comma, so splitting on commas alone would invent versions
- `TestOSVParity`, comparing the model against the live OSV API. Skipped unless `PG_DSN` and `OSV_PARITY` are set

### Removed
- `VULN_OSV_API_BASE_URL`. It is no longer read, and the config no longer rejects an empty value, which used to prevent startup for a setting that did nothing

### Fixed
- README documented `OSV_ENABLED`, `OSV_API_BASE_URL` and `OSV_VULNERABILITY_INFO_BASE_URL`, none of which match the environment variables the service actually reads

### Deployment
- Requires the `osv` and `osv_severity` tables. `osv` must carry every OSV `affected` entry, including those whose ranges are of type `ECOSYSTEM` (93% of them); a load that keeps only `SEMVER` ranges silently drops vulnerabilities
- Known limitation: OSV marks retracted entries with `withdrawn` and the table has no such column, so 43,739 retracted vulnerabilities across 192,159 rows are reported as live. Adding the column is pending

## [0.14.0] - 2026-08-11
### Added
- SQLite support alongside PostgreSQL: set `DB_DRIVER=sqlite` and `DB_DSN` to a database file
- `sql.Scanner` and `driver.Valuer` on `utils.OnlyDate`, so a date reads from a `TEXT` column (SQLite) or a `date` column (PostgreSQL)
- `pkg/models/test_schema.go` holding the production schema the tests build their database from
- `pkg/models/tests/vulns_scenario.sql`, a deterministic fixture whose match criteria cover every version-bound combination
- `pkg/models/pg_parity_test.go`, comparing the rewritten queries against the ones they replace on a real PostgreSQL database. Skipped unless `PG_DSN` is set

### Changed
- Rewrote both vulnerability queries as portable SQL, valid on PostgreSQL and SQLite
- Moved version range matching out of SQL into `pkg/models/version_range.go`, porting the `natural_sort_order` PostgreSQL function so both engines agree on which vulnerabilities apply to a version
- Test fixtures under `pkg/models/tests/` now carry data only. They used to define their own tables, describing a schema that does not exist, which is what let queries referencing non-existent columns pass CI
- Unified the test driver on `modernc.org/sqlite`, the one the server uses; `mattn/go-sqlite3` is no longer a direct dependency and CGO is not required

### Fixed
- `GetVulnsByPurlName` joined `cpes.id` and `nvd_match_criteria_ids.cpe_ids`, matching numeric CPE ids against a UUID. It returned no vulnerabilities at all on PostgreSQL and could not run on SQLite
- `GetVulnsByPurlVersion` relied on `array_agg`, the `&&` array overlap operator and the custom `natural_sort_order` function, none available in SQLite
- `saveLicense` inserted `is_sanitized`, which is not a column in the `licenses` table
- `saveVersion` passed four arguments to an insert with two placeholders

### Deployment
- Requires an `epss_data` table (`cve`, `epss`, `percentile`) plus an index on `cve`. Without it the EPSS lookup fails on every request and every vulnerability is returned with `epss.probability` and `epss.percentile` reading `0`, indistinguishable from a genuine zero

## [0.13.0] - 2026-06-22
### Added
- `/health` liveness endpoint (GET) on the REST gateway
### Changed
- Upgraded `scanoss/go-grpc-helper` to `v0.16.0`

## [0.12.0] - 2026/04/17
### Changed
- Updated dependencies to the latest versions
- Replace `error_message/error_code` by `info_message/info_code`
- Updated `linter` to `v2.10.1`

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
[0.12.0]: https://github.com/scanoss/vulnerabilities/compare/v0.11.0...v0.12.0
[0.13.0]: https://github.com/scanoss/vulnerabilities/compare/v0.12.0...v0.13.0
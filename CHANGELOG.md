# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.16.0] - 2026-10-27

### Security
- **Hardened against an unimplemented method killing the server.** The service embedded the papi `VulnerabilitiesServer` *interface* rather than the generated `UnimplementedVulnerabilitiesServer`. The interface value is nil, so any method the service does not implement would dereference it and panic, taking the whole process down. Every method of the current papi interface is implemented, so nothing reaches it today - but the first method papi adds would, silently, as a remotely reachable crash. scanoss/components shipped exactly that: `GetComponentStatistics` arrived in papi v0.42.0, was never implemented, and one unauthenticated request killed the server
- Upgraded `google.golang.org/grpc` to v1.83.1, `golang.org/x/net` to v0.57.0 and the OpenTelemetry modules (`otel`, `otel/sdk`, `otlptrace`, `otlptracegrpc`) to v1.45.0 to fix open Dependabot security advisories
- `go-grpc-helper` v0.16.0 → v0.17.0. A failed REST call no longer answers `200` with an empty, unparseable body when the handler set no `x-http-code` trailer: the gateway now falls back to the standard grpc-gateway error response, and gRPC status codes map to their HTTP equivalent, so `Unimplemented` is `501` rather than `500`

### Changed
- **The service now reads the serving knowledge base instead of the mining database.** The mining path is gone; there is no configuration that selects it. Endpoint routes and response shapes are unchanged
- CPE lookups read `cpe ⋈ short_cpe_purl` by purl string. The serving schema denormalises the version onto the `cpe` row, so the hops through `purls` and `versions` the mining query needed are gone
- NVD lookups join `short_cpe_purl → nvd_match_criteria → cve_match_criteria → cve`. The last hop used to be `LIKE '%' || match_criteria_id || '%'` against the delimited `cves.match_criteria_ids` list; `cve_match_criteria` normalises that list, so the join is now an exact, indexed equality rather than an unindexed substring test that could match one criterion id inside another
- EPSS reads `epss` (was `epss_data`)
- Component and version resolution no longer goes through `go-component-helper`, which resolves against `all_urls`, `mines` and `versions` - none of which exist in the serving schema. It is replaced by `pkg/resolver`, which resolves `component.purl → purl_id` and reads the version set from `component_version`
- Version selection is unchanged in behaviour: an exact version must be published by the component, a semver range selects the highest version satisfying it, and a bare purl still resolves to the highest published version
- Binaries are built with `CGO_ENABLED=1`. The DuckDB driver is a cgo binding, so a pure-Go build can no longer be produced
- The runtime image moved to `debian:bookworm-slim` with `libstdc++6`, which the cgo binary links against. `debian:buster` has been end-of-life since 2024
- **Chainguard, Wolfi and MinimOS advisories are excluded unless the purl is an apk package.** The export also files them under the upstream repository's purl (344k rows under `pkg:github`), where they fix at apk releases and carry vendor ids with no CVE alias: `pkg:github/openssl/openssl@3.0.0` drew 573 of them on top of 92 upstream advisories
- A source link that points back at the component itself (11.4 of 13.9 million) is no longer followed. It cost an unindexed full scan of `component`, about 2.5 s of CPU, for a fallback that could only repeat the lookup

### Added
- **DuckDB support**, the intended production backend for the serving knowledge base. Set `DB_DRIVER=duckdb` and `DB_PATH` to the serving file, which is opened read-only
- **Source-purl fallback.** A component that has no data under its own purl is looked up again under the purl its `component.source_purl_id` points at - the repository it was built from. Recovered results carry `info_code: WARNING` and an `info_message` naming the source purl, matching how the current decoration service reports the same thing. This is always on: the papi `vulnerabilitiesv2` contract has no request field to opt in with. It matters because vulnerability data is keyed by purl string, so a package sharing its code with an upstream repository has no rows of its own - `pkg:npm/browser-mjml-table` carries no CPEs while `pkg:github/mjmlio/mjml` carries 34
- `pkg/db`, opening the serving database for any of duckdb, sqlite or postgres. The embedded drivers get a smaller connection pool, since a connection there is a cursor over a local file rather than a socket to a server
- `pkg/resolver`, the serving component resolution and the shared source-purl fallback
- An availability check at the start of each request. Without it an unreachable database would surface as every component reporting `NO_INFO`, which reads as "this component is clean" - the one answer a broken database must never give. The pooled-connection checkout this replaces used to provide the same guarantee as a side effect

### Removed
- `pkg/models/licenses.go`, `mines.go`, `projects.go` and `versions.go`, along with the unused `versionMod` field. They queried mining tables and nothing reached them
- `DB_HOST`, `DB_USER`, `DB_PASSWD`, `DB_SCHEMA` and `DB_SSL_MODE` are only read when `DB_DRIVER=postgres`

### Deployment
- **Breaking:** requires a serving knowledge base. Point `DB_PATH` at the `.duckdb` file and set `DB_DRIVER=duckdb`
- Verified against the production serving file (72.6 GiB): both endpoints, batch and single, with the source-purl fallback. Point lookups run in 2-35 ms
- **Re-checked against the updated export.** Every table this service reads - `short_cpe_purl`, `nvd_match_criteria`, `cve_match_criteria`, `cve`, `osv`, `osv_severity`, `epss`, `component`, `component_version` - is column-for-column what it was, and the queries return data unchanged. The update adds a `short_cpe` table (200,459 rows), which this service does not need: `short_cpe_purl` already carries the `short_cpe` string. `osv` still has no `withdrawn` column, so the retracted-vulnerability limitation above stands
- CVE parity with the mining queries checked over a random sample of 100 purls: 525 `(purl, CVE)` pairs on both sides, none lost, none gained
- The DuckDB Go driver embeds engine v1.4.1 and reads a file written by the v1.5.5 CLI, because the file is stored at `storage_compatibility_version = v0.10.2`
- `make build_arm` now cross-compiles with cgo and needs an `aarch64` toolchain (set `CC`); the amd64 build is unaffected

### Fixed
- **Scoped npm packages, and other purls the export stores encoded or with qualifiers, resolve again.** `component.purl` keeps scoped npm and jsr names percent-encoded (`pkg:npm/%40angular/core`), qualifiers on generic, conda and cran keys, and a raw `+` in some rpm and deb names. The resolver decoded the purl and rebuilt the key, so 1.96 million components (6%) - plus 1.6 million qualified ones - answered `COMPONENT_NOT_FOUND` however they were spelled. It now tries the caller's spelling, the canonical rendering and the decoded form in one indexed lookup
- **Scoped purls match in the OSV and CPE lookups.** `PurlRemoveFromVersionComponent` cut at the first `@`, reducing `pkg:npm/@scope/name` to `pkg:npm/`; and `osv` always encodes the scope while `short_cpe_purl` holds it both ways. Both spellings are now matched
- An empty or malformed request answers HTTP 400 instead of 500 "internal server error"

## [0.15.0] - 2026-08-17
### Changed
- OSV vulnerabilities are read from the `osv` and `osv_severity` tables instead of the `api.osv.dev` HTTP API. The response is unchanged: same fields, same `source`, same URL construction, and the `cvss` array still carries every vector
- Removed the OSV HTTP client along with `getRepoURL` and the GIT-ecosystem fallback. The table stores `pkg:github` purls directly, so a component is looked up by its purl with no translation to a repository URL and no retry
- `packageurl-go` is no longer a direct dependency
- A failed OSV lookup is now reported as `Failed to query OSV data` rather than `No vulnerabilities found`, so a broken query is no longer indistinguishable from a component with no vulnerabilities
- OSV use case tests no longer reach the network; they run on SQLite against a fixture covering both version-matching mechanisms, multi-vector CVSS and non-CVSS scores
- Advisories published under repackager ecosystems (`TuxCare:Maven`, `Echo:npm` and the like) are excluded. They share the purl of the upstream package, so a lookup by purl alone picked them up while the OSV API, which filters by ecosystem, does not return them. Their fixed versions are unreachable from the upstream registry, they carry no CVE aliases, and their `introduced_version` is `0`, so they attached to every version of every affected component. This brought `pkg:maven/org.apache.logging.log4j/log4j-core@2.0.0` from 18 advisories back to the 8 the API returns. Note the filter is by vendor prefix, not by "ecosystem contains a colon": legitimate distro ecosystems are versioned that way (`Ubuntu:22.04:LTS`, `Debian:12`) and cover 69% of the table

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
[0.16.0]: https://github.com/scanoss/vulnerabilities/compare/v0.15.0...v0.16.0

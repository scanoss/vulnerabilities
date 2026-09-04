# Migrating a legacy decoration service to the serving knowledge base

This is the write-up from the pilot migration of `scanoss/vulnerabilities`. It is
meant to be enough to migrate `cryptography`, `components`, `licenses` and
`geoprovenance` without rediscovering any of it.

The reference implementation throughout is `scanoss/scanoss.api`, which already
serves every one of these domains from the serving schema.

## What "serving" is

One DuckDB file (production: `d4:/data/QUIQUE/full.duckdb`, 55.7 GiB, 34 tables)
holding a normalised, singular-named schema. It replaces the mining PostgreSQL
database (`psql service=m00`, database `components`), whose tables are plural and
heavily denormalised through surrogate id columns.

Read-only by design. The service never writes to it.

## The three things every service needs

### 1. The DuckDB driver

`pkg/db` in this repo is the whole of it: `Open(Config{Driver, Path, DSN})`
registering `github.com/marcboeker/go-duckdb/v2`, `sqlx.BindDriver("duckdb",
sqlx.QUESTION)`, and the file opened with `?access_mode=read_only`. Copy it.

It replaces `go-grpc-helper`'s `OpenDBConnection`, which builds a
`driver://user:pass@host/schema` DSN that means nothing to a file-based engine.

The driver is cgo, so `CGO_ENABLED=1` everywhere and a runtime image carrying
`libstdc++6`. There is no pure-Go build any more.

### 2. Component resolution

**This is the part that is easy to miss and blocks everything else.** The legacy
services do not resolve components themselves. They call
`compHelper.GetComponentsVersion`, which goes
`go-component-helper → go-models → all_urls ⋈ mines ⋈ versions ⋈ licenses`.

None of those tables exist in serving. Passing a serving handle to
`GetComponentsVersion` does not fail loudly - every component simply comes back
`COMPONENT_NOT_FOUND`.

`pkg/resolver` in this repo replaces it, resolving `component.purl → purl_id` and
reading the version set from `component_version`. It returns
`compHelper.Component` values, so nothing downstream of the call site changes.
Copy it; the only per-service work is the call site.

Two details worth keeping:

- **`CAST(purl_id AS VARCHAR)` is mandatory.** `component.purl_id` and
  `source_purl_id` are native DuckDB `uuid`. Selected without the cast, the driver
  hands back the raw 16 bytes and the Go string field fills with binary.
- **Version selection reproduces `pickOneUrl`.** A bare purl resolves to the
  highest published version, not to "no version". The serving reference leaves it
  empty; the legacy services do not, and their callers depend on the old answer.

### 3. Source-purl fallback

`component.source_purl_id` links a package to the repository it was built from.
When a purl has no data of its own, the lookup is retried there. `pkg/resolver`
carries the generic (`WithSourceFallback`, `RecoverFromSource`); a service
supplies its own lookup closure.

Recovered results are marked `info_code: WARNING` with an `info_message` naming
the source purl. `domain.StatusCode` has no such constant, but the adapters
forward any non-`SUCCESS` status verbatim, so it reaches the response intact and
matches what the current decoration service emits.

Use `RecoverFromSource` rather than `WithSourceFallback` when the caller already
knows its lookup came back empty - it skips re-running it. That matters: most
components in a scan are clean, so the empty path is the common one.

The papi contracts have no `show_related_results` field, so the fallback is
always on. If a contract later gains search criteria, gate it there.

## Schema mapping

The pattern is the same everywhere: mining reaches a value through a surrogate id
into a lookup table; serving denormalises it onto the row, or normalises a
delimited list into a bridge table.

| Concern | Mining | Serving |
|---|---|---|
| Component identity | `all_urls ⋈ mines ⋈ versions` | `component (purl, purl_id, source_purl_id)` |
| Versions | `versions (id, version_name, semver)` | `component_version (purl_id, version, …)` |
| Source link | `projects.source_purl_name` | `component.source_purl_id` |
| CPEs | `cpes ⋈ short_cpe_purl ⋈ purls ⋈ versions` | `cpe ⋈ short_cpe_purl` (version denormalised) |
| Purl key | `purls.id` → `short_cpe_purl.purl_id` | `short_cpe_purl.purl`, the string itself |
| NVD criteria | `nvd_match_criteria_ids` | `nvd_match_criteria` |
| CVE ↔ criteria | `LIKE '%'‖id‖'%'` on `cves.match_criteria_ids` | `cve_match_criteria (cve_id, match_criteria_id)` |
| CVEs | `cves` | `cve` (gains a surrogate `id`) |
| EPSS | `epss_data` | `epss` |
| OSV | `osv`, `osv_severity` | unchanged |
| Licenses | `licenses`, `purl_licenses` | `license`, `component_version_license` |
| SPDX | `spdx_license_data` | `"SPDX_license_data"` |
| OSADL | `osadl` | `"OSADL"`, `"OSADL_compat"`, `"OSADL_incompat"`, `"OSADL_depending"` |
| Crypto | `component_crypto`, `crypto_libraries` | `component_version_crypto`, `component_version_crypto_library`, `crypto_algorithm`, `crypto_library` |
| Geo | `vendors`, `vendor_locations`, `github_contributors`, `countries` | `vendor_location`, `contribution`, `country` |
| Component status | `projects.status` | `component_status`, `component_version_status` |
| URLs | `all_urls` | `component_version_url` |

Mixed-case serving tables (`SPDX_license_data`, `OSADL*`, `SPDX_crypto_algorithm`)
must be double-quoted in SQL.

Placeholders: serving queries use `?` and go through `db.Rebind(...)`. The legacy
queries mix `$1` and `?`; normalise them all to `?`, or the same SQL will not run
on all three backends.

## Per-service notes

Read the matching `scanoss.api` package first - it is the finished version of the
queries you are about to write.

| Service | Reference | Mining tables to replace |
|---|---|---|
| `cryptography` | `pkg/crypto` | `component_crypto`, `crypto_libraries`, `all_urls`, `mines`, `versions` |
| `components` | `pkg/components` | `all_urls`, `mines`, `projects` |
| `licenses` | `pkg/license` | `licenses`, `purl_licenses`, `osadl`, `spdx_license_data`, `ldb_component_licenses` |
| `geoprovenance` | `pkg/geo` | `vendors`, `vendor_locations`, `github_contributors`, `countries`, `versions` |

`licenses` also reads the LDB for evidence, which is a separate store and not
affected by this migration.

## Testing

Tests run on SQLite against `pkg/models/test_schema.go`, a transcription of the
serving schema taken from the production file with
`SELECT sql FROM duckdb_tables()`. DuckDB `UUID` and `DATE` become `TEXT`, which
the queries already tolerate: they cast the UUIDs, and `OnlyDate` scans a date
string as readily as a `time.Time`.

One trap worth knowing. An in-memory SQLite database is **per connection**, so the
tests cap the pool at one. Nothing may then check a connection out and hold it -
the model's own queries would wait for it forever. Load fixtures through the pool
(`LoadTestSQLData(db, ctx, nil)`), never through a checked-out `*sqlx.Conn`. The
mining-era tests did the opposite, and did not deadlock only because the model
shared the very connection they held.

## Verifying against production

Worth doing before merging, and cheap:

```bash
scp ./service d4:/tmp/ && ssh d4 '/tmp/service --json-config /tmp/serving.json'
```

with `{"Database": {"Driver": "duckdb", "Path": "/data/QUIQUE/full.duckdb"}}`.
The pilot was checked this way on both endpoints, single and batch, including the
fallback.

Measured there: point lookups run in 2-35 ms against the 55.7 GiB file. The Go
driver embeds DuckDB v1.4.1 and reads a file written by the v1.5.5 CLI, because
the file is stored at `storage_compatibility_version = v0.10.2`.

## Things that are deliberately not carried over

- **`on_version_not_found` strategies.** `scanoss.api` has them; the papi contracts
  the legacy services implement have no field to select one, so there is nothing to
  drive them.
- **The mining path.** The migration is a clean cut, with no configuration that
  selects the old behaviour.

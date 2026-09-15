# Migrating a legacy decoration service to the serving knowledge base

This is the write-up from migrating all five legacy decoration services:
`scanoss/vulnerabilities` (the pilot), `cryptography`, `components`, `licenses`
and `geoprovenance`. It records what the serving schema maps onto, what it does
not carry, and the measurement traps that produced two false alarms along the way.

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
- **An exact version matches with or without a leading `v`.** The mining lookup
  ran `version_name = $3 OR version_name = $4` with the second spelling from
  `SemverTogglePrefix`, so a caller asking for `5.4.7` found `v5.4.7`. The
  resolver answers with the spelling the component publishes. Cryptography has a
  test that fails without this.
- **The logger is optional.** Handlers are constructed before any request
  context exists, so `resolver.New(nil, db)` is allowed; the resolver only logs
  errors it also returns.

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

**Check the papi interface embed while you are in there.** Every legacy service
embeds the papi server *interface* rather than the generated
`Unimplemented*Server` struct. The interface value is nil, so any method the
service does not implement panics and takes the process down. It was reachable in
`components` (`GetComponentStatistics`) and `licenses` (`Echo`,
`GetObligations`), and latent in the other two. All four are fixed with a test
pinning the embed; check `geoprovenance` the same way - compare the papi
interface's method set against what the service implements.

**Some services already have a fallback.** Cryptography did, driven by
`go-component-helper` v0.7.0, which populates `Component.SourcePurl` from the
mining `projects` table's source-mine columns. There the work is not to add a
fallback but to re-point it: the resolver fills the same `SourcePurl` field from
`component.source_purl_id`, and the endpoint code is untouched. Check the
helper version in `go.mod` before assuming which case you are in - v0.6.0 has no
`SourcePurl` field at all, v0.7.0 does and also embeds `PurlInfo`.

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
| Crypto | `component_has_crypto`, `crypto_algorithm`, `crypto_libraries` | `component_version_crypto`, `component_version_crypto_library`, `crypto_algorithm`, `crypto_library` |
| Geo | `vendors`, `vendor_locations`, `github_contributors`, `countries` | `vendor_location`, `contribution`, `country` |
| Contributor country | `timezone_based_country` (ISO code) | `country.name` via `country_id` (full name) |
| Declared location | `vendor_locations.declared_location` | none |
| Component status | `projects.status` | `component_status`, `component_version_status` |
| Popularity / ranking | `projects.git_stars`, `git_forks`, … | `component_metrics` |
| Purl type filter | `mines.purl_type = ?` | `purl LIKE 'pkg:<type>/%'` |
| Licence is SPDX | `licenses.is_spdx` flag | membership in `"SPDX_license_data"` |
| DB version | `db_version.created_at` | `db_version.db_release` (no `created_at`) |
| Licences per release | `purl_licenses` (by purl string) | `component_version_license` (by `purl_id`) |
| OSADL lists | array columns on `osadl` | `"OSADL_compat"` / `"OSADL_incompat"` / `"OSADL_depending"` |
| URLs | `all_urls` | `component_version_url` |

Mixed-case serving tables (`SPDX_license_data`, `OSADL*`, `SPDX_crypto_algorithm`)
must be double-quoted in SQL.

Placeholders: serving queries use `?` and go through `db.Rebind(...)`. The legacy
queries mix `$1` and `?`; normalise them all to `?`, or the same SQL will not run
on all three backends.

## Per-service notes

Read the matching `scanoss.api` package first - it is the finished version of the
queries you are about to write.

| Service | Reference | Mining tables to replace | State |
|---|---|---|---|
| `vulnerabilities` | `pkg/vuln` | `cpes`, `purls`, `versions`, `nvd_match_criteria_ids`, `cves`, `epss_data` | done |
| `cryptography` | `pkg/crypto` | `component_crypto`, `crypto_libraries`, `all_urls`, `mines`, `versions` | done |
| `components` | `pkg/components` | `all_urls`, `mines`, `projects` | done |
| `licenses` | `pkg/license` | `licenses`, `purl_licenses`, `osadl`, `spdx_license_data`, `ldb_component_licenses` | done |
| `geoprovenance` | `pkg/geo` | `vendors`, `vendor_locations`, `github_contributors`, `countries`, `versions` | done, blocked on the export (see below) |

`licenses` also reads the LDB for evidence, which is a separate store and not
affected by this migration.

### What geoprovenance cost, and what it found

Four mining tables collapse into three serving ones, and the lookup keys on
`purl_id`. `contribution` covers 99.9% of `github_contributors` and the curated
country coverage is complete (256,731 serving rows against 256,410 mining vendors
with one; `curated_countries_ids` never held more than one country, so collapsing
it to a single `country_id` loses nothing).

What the schema does not carry is the interesting part:

- **`declared_location` and the vendor type**, so `declared_locations` is always
  empty. 1.8M vendors have a declared location in mining.
- **`timezone_based_country`**, which is what `origin` was computed from. Serving
  has only the curated country. They agree on 99.1% of the vendors that have
  both, so the answers are consistent - but mining had a timezone country for
  2.3M vendors and a curated one for 256k, so **14 of 21 sampled components stop
  resolving to an origin at all**. Coverage, not correctness.
- **`too_many_contributors`**, so that status disappears.

Watch the value format, not just the column: mining's `timezone_based_country`
holds ISO codes (`DE`), while `country.name` holds full names (`Germany`). The
same endpoint changes its output format without any query looking wrong.

### What licenses cost, and what it found

The mapping is mechanical - `purl_licenses` to `component_version_license` by
`purl_id`, the SPDX registry renamed, `is_spdx` derived from registry membership
- with one structural change: OSADL's three compatibility lists were array
columns and are now three tables, so they are read separately and reassembled.

Three things to expect:

- **Serving carries the declared licence only**, by design: the detected licences
  mining kept under sources 3/5/31/33/34 are out of scope, so
  `component_version_license.source` is `0` on all 205M rows and the priority
  resolution settles there. The filtering was kept as written rather than
  removed, so nothing has to be reintroduced if that changes.
- **go-models reaches for mining tables here too**, in two places: the licence
  catalogue (`licenses`) and the SPDX registry (`spdx_license_data`). Reuse its
  result types and swap only where they read from, and the SPDX cache needs no
  changes beyond its constructor.
- **`pq.StringArray` fallbacks must be `'{}'`, not `''`.** `see_also` is a
  Postgres array literal in a text column, which the array scanners parse - but
  they cannot parse the empty string, so `COALESCE(col, '')` turns a NULL into a
  scan error.
- **Two tables can hold the same domain at different grains.** The export has
  both `component_version_license` (per release, 22.8M components) and
  `component_license` (per component, all 31.8M). Reading only the first leaves
  8.9M components - 28% - answered as having no licence when one is on record.
  The lookups fall to the second only when no release has a licence, and its rows
  carry an empty version, because stamping the requested version onto a licence
  the database does not attribute to a release invents an attribution. Count
  `DISTINCT purl_id` on every table in a domain, not just the obvious one.

**Never compare the two schemas by joining on the version string.** This cost a
false alarm here: a first pass joined mining and serving on `(purl, version)` and
reported 22 of 40 releases as having lost their licences. They had not. Serving
normalises version strings - mining's `v0.1.1` is `0.1.1`, and tag-shaped
versions (`datahub-0.2.188`, `node-http2-0.0.6`, `OpenSSL_1_1_1a`) are rewritten
entirely - so the join missed rows that were plainly there. Re-measured per
component, 36 of 40 had at least as many licensed versions in serving as mining
declared, 2 had one fewer, and 2 had none (both `pkg:apk/*`, which carry no
`component_version` rows at all).

Compare per component, or per version only after normalising both sides. The same
trap applies to any domain keyed by version: crypto, components and licences all
have it. It bit the crypto measurement too - an openssl comparison pinned to one
version string read 82 against 41 - though that measurement was wrong for a
second reason as well; see the cryptography section.

### What components cost, and what it found

The three concerns map cleanly - search to `component` + `component_metrics`,
versions to `component_version`, status to `component_status` /
`component_version_status` - and the reference's `pkg/components/serving.go` has
the search pass-by-pass, so copy its plan rather than re-deriving it.

The volume check paid off immediately and cost minutes: `component` covers 98.6%
of `projects`, `component_metrics` covers *more* components than mining had
`git_stars` for, and a 40-component sample matched on version counts 37 times.
No blocker, and knowing that up front made the rest routine.

Two things to watch for:

- **go-models' `DBVersionModel` does not work against serving.** It selects
  `db_version.created_at`, which serving's `db_version` does not have, so the
  query fails and `/status` quietly stops reporting the knowledge base version.
  Serving carries `db_release` instead, a `YY.MM.DD.HH.MM` build stamp.
- **Check what the existing tests actually assert before trusting them.** Two
  components tests asserted that a search found nothing, which was true only
  because `RunQueries` abandons the batch on the first failing pass and the
  caller discarded the error. Migrating fixed the search, and the tests failed.
  A test asserting an absence is worth verifying against the fixture before
  concluding your change broke it.

### What cryptography cost, and what it found

The `url_hash` indirection disappears entirely: mining went purl → `all_urls` →
`package_hash` → `component_crypto`, and serving keys crypto by
`(purl_id, version)`. That deleted `all_urls.go` and most of the per-endpoint
plumbing rather than merely rewriting a query.

Three findings that will recur:

- **Check which mining table the export is actually a copy of.** This branch
  recorded a blocker - "33.7% of rows unrepresented, a further 17.2% collapsed
  into `shax`/`chacha`" - that was not real. It compared serving against mining's
  `component_crypto(url_hash, algorithm_name, strength)`, a table mining had
  itself superseded with `component_has_crypto` + `crypto_algorithm`. The export
  mirrors the *current* model: 219 algorithms, 18 tags, 659 tag assignments, with
  identifiers identical on both sides. Measured against what mining runs, 5 of
  224 names are absent, all legacy spellings, 0.46% of rows. Before declaring an
  export gap, list the mining tables in the domain and check which one the export
  resembles - `\dt *crypto*` would have shown three newer tables next to the one
  being compared.
- **Verify the join key on a sample before trusting a count of zero.**
  `component_has_crypto.url_hash` joins to `all_urls.package_hash`, not
  `all_urls.url_hash`, despite the column name. Every comparison built on the
  obvious key returned nothing, which reads as "this component has no crypto"
  rather than "this join is wrong". A join that returns zero rows for a component
  you know has data is a broken join, not a finding.
- **A schema update can change a column's meaning without changing its name.**
  `crypto_algorithm` went from `(id, name)`, short name in `name`, to
  `(id, name, category, strength, spdx_id)`, short name in `id` and a long
  description in `name`. Both are non-empty strings, so a query selecting `name`
  keeps working and starts returning "Advanced Encryption Standard" where the API
  contract wants "aes". Nothing fails; the answers are just wrong. Assert on a
  known value in a test, not merely on a non-empty result.

The same update turned `strength` from derived back into stored. An earlier
revision computed it from the SPDX key sizes because the export had no such
column; it has one now, matching mining exactly, where the derivation resolved
for 118 of 219 algorithms and disagreed where it did (`aes` "256" against
"128-256"). Prefer the stored column when one appears.

Where the reference is coarser than the data, prefer the data: `scanoss.api`
treats crypto as package-level in its versions-in-range endpoint, but
`component_version_crypto.version` is genuinely per-version (216.2M rows carry a
concrete version), so the legacy per-version split is preserved.

## Testing

Tests run on SQLite against `pkg/models/test_schema.go`, a transcription of the
serving schema taken from the production file with
`SELECT sql FROM duckdb_tables()`. DuckDB `UUID` and `DATE` become `TEXT`, which
the queries already tolerate: they cast the UUIDs, and `OnlyDate` scans a date
string as readily as a `time.Time`.

Two traps worth knowing.

The schema constant is loaded more than once by some tests, so rewrite
`CREATE TABLE`/`CREATE INDEX` into their `IF NOT EXISTS` form at load time
(`idempotentDDL`) rather than putting the guard in the constant, which must stay
a faithful transcription.

And an in-memory SQLite database is **per connection**, so the tests cap the pool
at one. Nothing may then check a connection out and hold it - four tests across
two services did, and only worked because their queries went through the very
connection they held. When you re-point a model at the pool, those deadlock. Nothing may then check a connection out and hold it -
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

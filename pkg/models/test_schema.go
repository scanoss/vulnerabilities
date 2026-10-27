// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018-2025 SCANOSS.COM
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// The serving schema, used to build the database the tests run against.
//
// Tests deliberately run on this schema rather than on per-fixture CREATE TABLE
// statements. The fixtures used to carry their own, describing tables that do not
// exist - DATETIME dates, an integer[] cpe_ids array, surrogate id columns - and that
// is what let queries referencing non-existent columns pass CI. Fixtures under tests/
// carry data only.
//
// This is a transcription of the serving schema, taken from the production DuckDB
// file with `SELECT sql FROM duckdb_tables()`. The types are the SQLite equivalents,
// since the tests run on SQLite: DuckDB UUID and DATE both become TEXT, which the
// queries already tolerate - they CAST the UUID columns to VARCHAR and OnlyDate scans
// a date string as readily as a time.Time.
//
// Keep this in step with the real database. It is a transcription, so it can drift;
// when a query fails in production but passes here, suspect this file first.

package models

// testSchemaDDL is the schema every DB-backed test is built from.
const testSchemaDDL = `
CREATE TABLE db_version (package_name TEXT NOT NULL, schema_version TEXT NOT NULL, db_release TEXT NOT NULL);

-- Component identity. purl is the versionless purl string; purl_id and
-- source_purl_id are UUID in DuckDB, TEXT here.
CREATE TABLE component (purl TEXT, vendor TEXT, component TEXT, source_purl_id TEXT, purl_id TEXT);
CREATE INDEX idx_component_purl ON component (purl);
CREATE INDEX idx_component_purl_id ON component (purl_id);

CREATE TABLE component_version (purl_id TEXT, version TEXT, version_name TEXT, version_semver TEXT);
CREATE INDEX idx_component_version_purl_id ON component_version (purl_id);

-- NVD. The version is denormalised onto cpe, so there is no versions table, and
-- cve_match_criteria replaces the delimited cves.match_criteria_ids list.
CREATE TABLE cpe (id INTEGER, cpe TEXT, short_cpe_id INTEGER, version_name TEXT, version_semver TEXT, github_url TEXT);
CREATE INDEX idx_cpe_short_cpe_id ON cpe (short_cpe_id);

CREATE TABLE short_cpe_purl (short_cpe_id INTEGER, purl TEXT, short_cpe TEXT);
CREATE INDEX idx_short_cpe_purl_purl ON short_cpe_purl (purl);

CREATE TABLE nvd_match_criteria (
    match_criteria_id TEXT, short_cpe_id INTEGER,
    version_start_including TEXT, version_start_excluding TEXT,
    version_end_including TEXT, version_end_excluding TEXT,
    cpe_ids TEXT
);
CREATE INDEX idx_nvd_match_criteria_short_cpe_id ON nvd_match_criteria (short_cpe_id);

CREATE TABLE cve_match_criteria (cve_id INTEGER, match_criteria_id TEXT);
CREATE INDEX idx_cve_match_criteria_mc ON cve_match_criteria (match_criteria_id);
CREATE INDEX idx_cve_match_criteria_cve ON cve_match_criteria (cve_id);

CREATE TABLE cve (id INTEGER, cve TEXT, severity TEXT, published TEXT, modified TEXT, summary TEXT, match_criteria_ids TEXT);
CREATE INDEX idx_cve_id ON cve (id);
CREATE INDEX idx_cve_cve ON cve (cve);

CREATE TABLE epss (cve TEXT, epss REAL, percentile REAL);
CREATE INDEX idx_epss_cve ON epss (cve);

-- OSV. Unchanged from the mining export apart from two trailing columns.
CREATE TABLE osv (
    id TEXT, ecosystem TEXT, purl TEXT,
    introduced_version TEXT, last_affected TEXT, fixed_version TEXT,
    affected_versions TEXT, aliases TEXT,
    summary TEXT, severity TEXT,
    published TEXT, modified TEXT, indexed_date TEXT,
    upstream TEXT, related TEXT, range_type TEXT, affected_index INTEGER
);
CREATE INDEX idx_osv_purl ON osv (purl);

CREATE TABLE osv_severity (id TEXT, type TEXT, score TEXT);
CREATE INDEX idx_osv_severity_id ON osv_severity (id);
`

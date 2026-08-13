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

// The production schema, used to build the database the tests run against.
//
// Tests deliberately run on this schema rather than on per-fixture CREATE TABLE
// statements. The fixtures used to carry their own, describing tables that do not
// exist - DATETIME dates, an integer[] cpe_ids array, surrogate id columns - and that
// is what let queries referencing non-existent columns pass CI. Fixtures under tests/
// now carry data only.
//
// Keep this in step with the real database. It is a transcription, so it can drift;
// when a query fails in production but passes here, suspect this file first. Dump the
// live schema with `sqlite3 <db> .schema` to compare.

package models

// testSchemaDDL is the schema every DB-backed test is built from.
const testSchemaDDL = `
CREATE TABLE db_version (
                package_name TEXT NOT NULL,
                schema_version TEXT NOT NULL,
                created_at TEXT NOT NULL,
                db_release TEXT NOT NULL
            );
CREATE TABLE all_urls (
    package_hash TEXT, component TEXT, purl_name TEXT, mine_id TEXT, vendor TEXT, version TEXT,
    version_id TEXT, date TEXT, license_id TEXT, is_mined TEXT, indexed_date TEXT, version_status TEXT,
    version_status_change_date TEXT, total_files TEXT, indexed_files TEXT, source_files TEXT,
    ignored_files TEXT, package_size TEXT
);
CREATE INDEX idx_allurls_name ON all_urls (purl_name, mine_id, license_id, version_id);
CREATE INDEX idx_allurls_comp ON all_urls (component, vendor, mine_id);
CREATE INDEX idx_allurls_phash ON all_urls (purl_name, package_hash, mine_id, version_id);
CREATE TABLE golang_projects (mine_id TEXT, purl_name TEXT, component TEXT, license_id TEXT, version_id TEXT, version_date TEXT, is_indexed TEXT);
CREATE INDEX idx_golang_projects_purl_name_is_indexed_license_id_version_id ON golang_projects (purl_name, is_indexed, license_id, version_id);
CREATE TABLE licenses (id TEXT, license_name TEXT, spdx_id TEXT, is_spdx TEXT);
CREATE INDEX idx_license_id_license_name_spdx_id_is_spdx ON licenses (id, license_name, spdx_id, is_spdx);
CREATE TABLE mines (id TEXT, purl_type TEXT, mine_name TEXT, can_download TEXT, repository_url TEXT);
CREATE INDEX idx_mines_purl_type ON mines (purl_type, id);
CREATE TABLE projects (
    mine_id TEXT, purl_name TEXT, vendor TEXT, component TEXT, versions TEXT, license_id TEXT,
    git_license_id TEXT, first_version_date TEXT, git_created_at TEXT, git_forks TEXT, git_stars TEXT,
    first_indexed_date TEXT, last_indexed_date TEXT, status TEXT, status_change_date TEXT,
    source_mine_id TEXT, source_purl_name TEXT
);
CREATE INDEX idx_projects ON projects (purl_name, mine_id, license_id, git_license_id);
CREATE TABLE versions (id TEXT, version_name TEXT, semver TEXT);
CREATE INDEX idx_versions_version_name_id_semver ON versions (version_name, id, semver);
CREATE INDEX idx_versions_id_version_name_semver ON versions (id, version_name, semver);
CREATE TABLE countries (id TEXT, country_name TEXT);
CREATE INDEX idx_countries_id ON countries (id);
CREATE TABLE vendors (id TEXT, username TEXT, type TEXT, mine_id TEXT);
CREATE INDEX idx_vendors_username_type_mine_id ON vendors (username, type, mine_id);
CREATE TABLE github_contributors (purl_name TEXT, contributor TEXT);
CREATE INDEX idx_github_contributors_purl_name ON github_contributors (purl_name);
CREATE INDEX idx_github_contributors_contributor ON github_contributors (contributor);
CREATE TABLE vendor_locations (vendor_id TEXT, declared_location TEXT, curated_countries_ids TEXT);
CREATE INDEX idx_vendor_locations_vendor_id ON vendor_locations (vendor_id);
CREATE INDEX idx_vendor_locations_declared_location ON vendor_locations (declared_location);
CREATE TABLE cpes (cpe TEXT, version_id TEXT, short_cpe_id TEXT);
CREATE TABLE short_cpe_purl (cpe_id TEXT, purl_id TEXT, purl TEXT);
CREATE INDEX short_cpe_purl_purl ON short_cpe_purl (purl);
CREATE TABLE nvd_match_criteria_ids (
    match_criteria_id TEXT, short_cpe_id TEXT, version_start_including TEXT,
    version_start_excluding TEXT, version_end_including TEXT, version_end_excluding TEXT
);
CREATE TABLE short_cpes (id TEXT);
CREATE TABLE cves (cve TEXT, severity TEXT, published TEXT, modified TEXT, summary TEXT, match_criteria_ids TEXT);
CREATE INDEX idx_cves_match_criteria_ids ON cves (match_criteria_ids);
CREATE TABLE purls (purl TEXT, id TEXT);
CREATE INDEX idx_purls_purl ON purls (purl);
CREATE TABLE composer_dependencies (purl_name TEXT, version TEXT, dep_data TEXT);
CREATE INDEX idx_composer_dependencies_purl_name_version ON composer_dependencies (purl_name, version);
CREATE TABLE crates_dependencies (purl_name TEXT, version TEXT, dep_data TEXT);
CREATE INDEX idx_crates_dependencies_purl_name_version ON crates_dependencies (purl_name, version);
CREATE TABLE maven_dependencies (purl_name TEXT, version TEXT, dep_data TEXT);
CREATE INDEX idx_maven_dependencies_purl_name_version ON maven_dependencies (purl_name, version);
CREATE TABLE npmjs_dependencies (purl_name TEXT, version TEXT, dep_data TEXT);
CREATE INDEX idx_npmjs_dependencies_purl_name_version ON npmjs_dependencies (purl_name, version);
CREATE TABLE ruby_dependencies (purl_name TEXT, version TEXT, dep_data TEXT);
CREATE INDEX idx_ruby_dependencies_purl_name_version ON ruby_dependencies (purl_name, version);
CREATE TABLE epss_data (cve TEXT, epss TEXT, percentile TEXT);
CREATE INDEX idx_epss_data_cve ON epss_data (cve);
CREATE INDEX idx_nmci_short_cpe_id ON nvd_match_criteria_ids (short_cpe_id);
CREATE TABLE osv (
    id TEXT, ecosystem TEXT, purl TEXT,
    introduced_version TEXT, last_affected TEXT, fixed_version TEXT,
    affected_versions TEXT, aliases TEXT,
    summary TEXT, severity TEXT,
    published TEXT, modified TEXT, indexed_date TEXT,
    upstream TEXT, related TEXT
);
CREATE INDEX idx_osv_purl ON osv (purl);
CREATE TABLE osv_severity (id TEXT, type TEXT, score TEXT);
CREATE INDEX idx_osv_severity_id ON osv_severity (id);
`

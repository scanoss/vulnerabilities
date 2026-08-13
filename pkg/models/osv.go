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

// Reading OSV vulnerabilities from the database instead of the OSV HTTP API.
//
// Two things the API did for us have to happen here instead:
//
//   - Version matching. The API took a version and returned only the applicable
//     vulnerabilities. The table exposes the raw bounds, and OSV uses two mechanisms
//     that both have to be honoured: an explicit list in affected_versions, and a
//     range built from introduced_version / fixed_version / last_affected. Which one a
//     row uses varies by ecosystem - pypi is almost all lists, golang almost all ranges.
//
//   - One row per vulnerability. The table is keyed by
//     (id, ecosystem, purl, introduced_version, fixed_version), so it averages 15.6
//     rows per vulnerability, one per affected range. The API returns a single entry,
//     so rows are collapsed by id here.
//
// CVSS vectors live in osv_severity, one row per vector, because a vulnerability can
// carry up to five. They are fetched in a second query rather than joined, to avoid
// multiplying the already-duplicated rows of the main query.

package models

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
	"scanoss.com/vulnerabilities/pkg/utils"
)

// OSVModel queries the OSV tables.
type OSVModel struct {
	db *sqlx.DB
	s  *zap.SugaredLogger
}

// OSVVulnerability is one OSV vulnerability, already collapsed to a single entry and
// carrying every CVSS vector recorded for it.
type OSVVulnerability struct {
	ID         string
	Aliases    []string
	Summary    string
	Severity   string
	Published  utils.OnlyDate
	Modified   utils.OnlyDate
	Severities []OSVSeverity
}

// OSVSeverity is a single scoring entry. Type is kept alongside Score because not
// everything OSV publishes is a CVSS vector: 54,565 rows are of type "Ubuntu" with
// values like "medium". Callers decide what to do with those.
type OSVSeverity struct {
	Type  string `db:"type"`
	Score string `db:"score"`
}

// osvRow is one (vulnerability, affected range) pair as stored.
type osvRow struct {
	ID                string         `db:"id"`
	Aliases           string         `db:"aliases"`
	Summary           string         `db:"summary"`
	Severity          string         `db:"severity"`
	Published         utils.OnlyDate `db:"published"`
	Modified          utils.OnlyDate `db:"modified"`
	IntroducedVersion string         `db:"introduced_version"`
	LastAffected      string         `db:"last_affected"`
	FixedVersion      string         `db:"fixed_version"`
	AffectedVersions  string         `db:"affected_versions"`
}

// osvByPurlQuery returns every stored range for a purl. The CAST on the array columns
// is what keeps this portable: PostgreSQL renders them as {a,b}, and the SQLite export
// stores that same text, so one query serves both engines. COALESCE guards the columns
// the schema allows to be null.
const osvByPurlQuery = `SELECT
	o.id,
	CAST(o.aliases AS TEXT) AS aliases,
	COALESCE(o.summary, '') AS summary,
	COALESCE(o.severity, '') AS severity,
	o.published,
	o.modified,
	COALESCE(o.introduced_version, '') AS introduced_version,
	COALESCE(o.last_affected, '') AS last_affected,
	COALESCE(o.fixed_version, '') AS fixed_version,
	CAST(o.affected_versions AS TEXT) AS affected_versions
FROM osv o
WHERE o.purl = $1
ORDER BY o.id`

// NewOSVModel creates a new instance of the OSV Model.
func NewOSVModel(s *zap.SugaredLogger, db *sqlx.DB) *OSVModel {
	return &OSVModel{db: db, s: s}
}

// GetVulnsByPurl returns the OSV vulnerabilities affecting the given purl. An empty
// version means every vulnerability recorded for the purl, matching what the API
// returns when no version is supplied.
func (m *OSVModel) GetVulnsByPurl(ctx context.Context, purl string, version string) ([]OSVVulnerability, error) {
	if len(strings.TrimSpace(purl)) == 0 {
		m.s.Error("Please specify a valid Purl to query")
		return nil, errors.New("please specify a valid Purl to query")
	}
	var rows []osvRow
	err := m.db.SelectContext(ctx, &rows, osvByPurlQuery, strings.TrimSpace(purl))
	if err != nil {
		m.s.Errorf("Failed to query the osv table for %v: %v", purl, err)
		return nil, fmt.Errorf("failed to query the osv table: %v", err)
	}
	vulns := collapseOSVRows(rows, version)
	if len(vulns) == 0 {
		return vulns, nil
	}
	if err = m.attachSeverities(ctx, vulns); err != nil {
		// The vulnerabilities themselves are still usable without their vectors.
		m.s.Warnf("Failed to load CVSS vectors for %v: %v", purl, err)
	}
	m.s.Debugf("Found %v OSV vulnerabilities for %v (version %v)", len(vulns), purl, version)
	return vulns, nil
}

// collapseOSVRows reduces the rows to one entry per vulnerability, keeping only the
// vulnerabilities that have at least one range covering the requested version. Order
// follows the query, so the result is stable.
//
// Which row supplies the vulnerability's own fields is not arbitrary. Those fields are
// meant to be identical across the rows of one id, but in practice they are not:
// 137,302 (id, purl) pairs disagree on at least one of them, overwhelmingly on
// modified. The most recently modified row is the one that agrees with osv_json, and
// therefore with what the API returns, so that is the row used - even when a different
// row is the one that matched the version.
func collapseOSVRows(rows []osvRow, version string) []OSVVulnerability {
	type candidate struct {
		newest  osvRow
		matched bool
	}
	byID := make(map[string]*candidate, len(rows))
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		found, ok := byID[row.ID]
		if !ok {
			byID[row.ID] = &candidate{newest: row, matched: row.affects(version)}
			ids = append(ids, row.ID)
			continue
		}
		if time.Time(row.Modified).After(time.Time(found.newest.Modified)) {
			found.newest = row
		}
		if row.affects(version) {
			found.matched = true
		}
	}
	vulns := make([]OSVVulnerability, 0, len(ids))
	for _, id := range ids {
		found := byID[id]
		if !found.matched {
			continue
		}
		vulns = append(vulns, OSVVulnerability{
			ID:        found.newest.ID,
			Aliases:   osvArrayValues(found.newest.Aliases),
			Summary:   found.newest.Summary,
			Severity:  found.newest.Severity,
			Published: found.newest.Published,
			Modified:  found.newest.Modified,
		})
	}
	return vulns
}

// affects reports whether this stored range covers the given version. An empty version
// matches, so a caller that does not know the version still gets the vulnerability.
func (r osvRow) affects(version string) bool {
	version = strings.TrimSpace(version)
	if len(version) == 0 {
		return true
	}
	// OSV allows an affected entry to carry both an explicit version list and ranges;
	// either one matching is enough.
	if osvArrayContains(r.AffectedVersions, version) {
		return true
	}
	introduced := strings.TrimSpace(r.IntroducedVersion)
	fixed := strings.TrimSpace(r.FixedVersion)
	lastAffected := strings.TrimSpace(r.LastAffected)
	// With no bounds at all and no list, the row says nothing about versions. Treat a
	// bare list that did not match as a miss, rather than as an unbounded range.
	if len(introduced) == 0 && len(fixed) == 0 && len(lastAffected) == 0 {
		return len(osvArrayValues(r.AffectedVersions)) == 0
	}
	key := naturalSortKey(version)
	// "0" is OSV's way of saying "since the beginning".
	if len(introduced) > 0 && introduced != "0" && key < naturalSortKey(introduced) {
		return false
	}
	// fixed_version is exclusive: the fix landed in it, so it is not affected.
	if len(fixed) > 0 && key >= naturalSortKey(fixed) {
		return false
	}
	// last_affected is inclusive.
	if len(lastAffected) > 0 && key > naturalSortKey(lastAffected) {
		return false
	}
	return true
}

// attachSeverities fills in the CVSS vectors for the given vulnerabilities.
func (m *OSVModel) attachSeverities(ctx context.Context, vulns []OSVVulnerability) error {
	ids := make([]string, 0, len(vulns))
	for _, v := range vulns {
		ids = append(ids, v.ID)
	}
	type severityRow struct {
		ID    string `db:"id"`
		Type  string `db:"type"`
		Score string `db:"score"`
	}
	query, args, err := sqlx.In(
		"SELECT id, COALESCE(type, '') AS type, COALESCE(score, '') AS score FROM osv_severity WHERE id IN (?)", ids)
	if err != nil {
		return err
	}
	var rows []severityRow
	if err = m.db.SelectContext(ctx, &rows, m.db.Rebind(query), args...); err != nil {
		return err
	}
	byID := make(map[string][]OSVSeverity, len(rows))
	for _, row := range rows {
		byID[row.ID] = append(byID[row.ID], OSVSeverity{Type: row.Type, Score: row.Score})
	}
	for i := range vulns {
		vulns[i].Severities = byID[vulns[i].ID]
	}
	return nil
}

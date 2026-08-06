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

package models

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	purlhelper "github.com/scanoss/go-purl-helper/pkg"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	"scanoss.com/vulnerabilities/pkg/utils"
)

type VulnsForPurlModel struct {
	db *sqlx.DB
}

type VulnsForPurl struct {
	Cve       string         `db:"cve"`
	Severity  string         `db:"severity"`
	URL       string         `db:"url"`
	Published utils.OnlyDate `db:"published"`
	Modified  utils.OnlyDate `db:"modified"`
	Summary   string         `db:"summary"`
}

type OnlyPurl struct {
	Purl string `db:"purl"`
}

// NewVulnsForPurlModel creates a new instance of the CPE Purl Model.
func NewVulnsForPurlModel(db *sqlx.DB) *VulnsForPurlModel {
	return &VulnsForPurlModel{db: db}
}

// GetVulnsByPurl gets vulnerabilities by purl.
func (m *VulnsForPurlModel) GetVulnsByPurl(ctx context.Context, purl string, version string) ([]VulnsForPurl, error) {
	if len(purl) == 0 {
		zlog.S.Errorf("Please specify a valid Purl String to query")
		return []VulnsForPurl{}, errors.New("please specify a valid Purl String to query")
	}

	// used to valid the PURL
	_, err := purlhelper.PurlFromString(purl)
	if err != nil {
		return []VulnsForPurl{}, err
	}

	purlName := utils.PurlRemoveFromVersionComponent(purl) // Remove everything after the component name

	if len(version) > 0 {
		return m.GetVulnsByPurlVersion(ctx, purlName, version)
	}
	return m.GetVulnsByPurlName(ctx, purlName)
}

// vulnsForPurlQuery returns every CVE reachable from a purl, paired with the version
// bounds of the match criterion that connects the two. The path through the schema is
// purl -> short_cpe_purl.cpe_id -> nvd_match_criteria_ids.short_cpe_id ->
// match_criteria_id -> cves.match_criteria_ids.
//
// cves.match_criteria_ids holds a delimited list of criteria ids, so the last join
// has to test for membership textually. The CAST keeps that working whether the column
// is TEXT (SQLite) or an array (PostgreSQL), and COALESCE guards the nullable columns.
//
// Version filtering is deliberately absent here; it happens in Go, see version_range.go.
const vulnsForPurlQuery = `SELECT DISTINCT
	c.cve,
	COALESCE(c.severity, '') AS severity,
	c.published,
	c.modified,
	COALESCE(c.summary, '') AS summary,
	COALESCE(nmci.version_start_including, '') AS version_start_including,
	COALESCE(nmci.version_start_excluding, '') AS version_start_excluding,
	COALESCE(nmci.version_end_including, '') AS version_end_including,
	COALESCE(nmci.version_end_excluding, '') AS version_end_excluding
FROM short_cpe_purl scp
INNER JOIN nvd_match_criteria_ids nmci ON nmci.short_cpe_id = scp.cpe_id
INNER JOIN cves c ON CAST(c.match_criteria_ids AS TEXT) LIKE '%' || nmci.match_criteria_id || '%'
WHERE scp.purl = $1
ORDER BY c.cve`

// vulnRow is a single (CVE, match criterion) pair returned by vulnsForPurlQuery. One
// CVE can appear more than once, via different criteria.
type vulnRow struct {
	VulnsForPurl
	StartIncluding string `db:"version_start_including"`
	StartExcluding string `db:"version_start_excluding"`
	EndIncluding   string `db:"version_end_including"`
	EndExcluding   string `db:"version_end_excluding"`
}

// bounds returns the version limits carried by this row.
func (r vulnRow) bounds() versionBounds {
	return versionBounds{
		StartIncluding: r.StartIncluding,
		StartExcluding: r.StartExcluding,
		EndIncluding:   r.EndIncluding,
		EndExcluding:   r.EndExcluding,
	}
}

// queryVulnRows runs the shared query for the given purl name.
func (m *VulnsForPurlModel) queryVulnRows(ctx context.Context, purlName string) ([]vulnRow, error) {
	var rows []vulnRow
	err := m.db.SelectContext(ctx, &rows, vulnsForPurlQuery, strings.TrimSpace(purlName))
	if err != nil {
		zlog.S.Errorf("Failed to query short_cpe for %s: %v", purlName, err)
		return nil, fmt.Errorf("failed to query the table: %v", err)
	}
	return rows, nil
}

// collapseByCve reduces the rows to one entry per CVE, keeping only those whose match
// criterion satisfies keep. A nil keep accepts every row. Query order is preserved.
func collapseByCve(rows []vulnRow, keep func(versionBounds) bool) []VulnsForPurl {
	vulns := make([]VulnsForPurl, 0, len(rows))
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		if keep != nil && !keep(row.bounds()) {
			continue
		}
		if seen[row.Cve] {
			continue
		}
		seen[row.Cve] = true
		vulns = append(vulns, row.VulnsForPurl)
	}
	return vulns
}

// GetVulnsByPurlName searches for component details of the specified Purl Name/Type (and optional requirement).
func (m *VulnsForPurlModel) GetVulnsByPurlName(ctx context.Context, purlName string) ([]VulnsForPurl, error) {
	if len(purlName) == 0 {
		zlog.S.Errorf("Please specify a valid Purl Name to query")
		return []VulnsForPurl{}, errors.New("please specify a valid Purl Name to query")
	}
	rows, err := m.queryVulnRows(ctx, purlName)
	if err != nil {
		return []VulnsForPurl{}, err
	}
	vulns := collapseByCve(rows, nil)
	zlog.S.Debugf("Found %v results for %v.", len(vulns), purlName)

	return vulns, nil
}

// GetVulnsByPurlVersion searches for the vulnerabilities of the specified Purl Name/Type
// that apply to a given version. An empty version matches only the criteria that place
// no bound on the version at all.
func (m *VulnsForPurlModel) GetVulnsByPurlVersion(ctx context.Context, purlName string, purlVersion string) ([]VulnsForPurl, error) {
	if len(purlName) == 0 {
		zlog.S.Errorf("Please specify a valid Purl Name to query")
		return []VulnsForPurl{}, errors.New("please specify a valid Purl Name to query")
	}
	rows, err := m.queryVulnRows(ctx, purlName)
	if err != nil {
		return []VulnsForPurl{}, err
	}
	vulns := collapseByCve(rows, func(b versionBounds) bool {
		return b.covers(purlVersion)
	})
	zlog.S.Debugf("Found %v results for %v (version %v).", len(vulns), purlName, purlVersion)

	return vulns, nil
}

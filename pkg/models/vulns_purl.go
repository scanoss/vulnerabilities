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

	purlhelper "github.com/scanoss/go-purl-helper/pkg"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"

	"github.com/jmoiron/sqlx"
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

// GetVulnsByPurlName searches for component details of the specified Purl Name/Type (and optional requirement).
func (m *VulnsForPurlModel) GetVulnsByPurlName(ctx context.Context, purlName string) ([]VulnsForPurl, error) {
	if len(purlName) == 0 {
		zlog.S.Errorf("Please specify a valid Purl Name to query")
		return []VulnsForPurl{}, errors.New("please specify a valid Purl Name to query")
	}

	var vulns []VulnsForPurl
	purlName = strings.TrimSpace(purlName)
	err := m.db.SelectContext(ctx, &vulns,
		"SELECT c2.cve, c2.severity, c2.published, c2.modified, c2.summary "+
			"FROM short_cpe_purl scp "+
			"INNER JOIN cpes c ON scp.cpe_id = c.id "+
			"INNER JOIN nvd_match_criteria_ids nmci ON trim(CAST(nmci.cpe_ids AS TEXT), '{}') LIKE '%' || scp.cpe_id || '%' "+
			"INNER JOIN cves c2 ON trim(CAST(nmci.cpe_ids AS TEXT), '{}') LIKE  '%' || nmci.match_criteria_id || '%' "+
			"WHERE "+
			"scp.purl = $1",
		purlName)

	if err != nil {
		zlog.S.Errorf("Failed to query short_cpe for %s: %v", purlName, err)
		return []VulnsForPurl{}, fmt.Errorf("failed to query the table: %v", err)
	}
	zlog.S.Debugf("Found %v results for %v.", len(vulns), purlName)

	return vulns, nil
}

func (m *VulnsForPurlModel) GetVulnsByPurlVersion(ctx context.Context, purlName string, purlVersion string) ([]VulnsForPurl, error) {
	if len(purlName) == 0 {
		zlog.S.Errorf("Please specify a valid Purl Name to query")
		return []VulnsForPurl{}, errors.New("please specify a valid Purl Name to query")
	}

	var vulns []VulnsForPurl
	purlName = strings.TrimSpace(purlName)
	query := `WITH matching_criteria AS (
	  SELECT array_agg(nmci.match_criteria_id) as criteria_ids
	  FROM short_cpe_purl scp
	  INNER JOIN short_cpes sc ON sc.id = scp.cpe_id
	  INNER JOIN nvd_match_criteria_ids nmci ON nmci.short_cpe_id = sc.id
	  WHERE scp.purl = $1
		AND (
			$2 = nmci.version_start_including
			OR $2 = nmci.version_end_including
			OR (
				(
					(nmci.version_start_excluding = '' AND nmci.version_start_including = '')
					OR (nmci.version_start_excluding != '' AND natural_sort_order($2, 20) > natural_sort_order(nmci.version_start_excluding, 20))
					OR (nmci.version_start_including != '' AND natural_sort_order($2, 20) > natural_sort_order(nmci.version_start_including, 20))
				)
				AND (
					(nmci.version_end_excluding = '' AND nmci.version_end_including = '')
					OR (nmci.version_end_excluding != '' AND natural_sort_order($2, 20) < natural_sort_order(nmci.version_end_excluding, 20))
					OR (nmci.version_end_including != '' AND natural_sort_order($2, 20) < natural_sort_order(nmci.version_end_including, 20))
				)
			)
		)
	)
	SELECT DISTINCT
		c2.cve,
		c2.severity,
		c2.published,
		c2.modified,
		c2.summary
	FROM cves c2, matching_criteria mc
	WHERE c2.match_criteria_ids && mc.criteria_ids
	ORDER BY c2.cve, c2.severity, c2.published, c2.modified, c2.summary;`

	err := m.db.SelectContext(ctx, &vulns, query, purlName, purlVersion)

	if err != nil {
		zlog.S.Errorf("Failed to query short_cpe for %s: %v", purlName, err)
		return []VulnsForPurl{}, fmt.Errorf("failed to query the table: %v", err)
	}

	zlog.S.Debugf("Found %v results for %v.", len(vulns), purlName)
	return vulns, nil
}

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

	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"

	"github.com/jmoiron/sqlx"
	"scanoss.com/vulnerabilities/pkg/utils"
)

type VulnsForPurlModel struct {
	ctx  context.Context
	conn *sqlx.Conn
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
func NewVulnsForPurlModel(ctx context.Context, conn *sqlx.Conn) *VulnsForPurlModel {
	return &VulnsForPurlModel{ctx: ctx, conn: conn}
}

// GetVulnsByPurl gets vulnerabilities by purl.
func (m *VulnsForPurlModel) GetVulnsByPurl(purl string, version string) ([]VulnsForPurl, error) {
	if len(purl) == 0 {
		zlog.S.Errorf("Please specify a valid Purl String to query")
		return []VulnsForPurl{}, errors.New("please specify a valid Purl String to query")
	}

	// used to valid the PURL
	_, err := utils.PurlFromString(purl)
	if err != nil {
		return []VulnsForPurl{}, err
	}

	purlName := utils.PurlRemoveFromVersionComponent(purl) // Remove everything after the component name

	if len(version) > 0 {
		return m.GetVulnsByPurlVersion(purlName, version)
	}
	return m.GetVulnsByPurlName(purlName)
}

// GetVulnsByPurlName searches for component details of the specified Purl Name/Type (and optional requirement).
func (m *VulnsForPurlModel) GetVulnsByPurlName(purlName string) ([]VulnsForPurl, error) {
	if len(purlName) == 0 {
		zlog.S.Errorf("Please specify a valid Purl Name to query")
		return []VulnsForPurl{}, errors.New("please specify a valid Purl Name to query")
	}

	var vulns []VulnsForPurl
	purlName = strings.TrimSpace(purlName)
	err := m.conn.SelectContext(m.ctx, &vulns,
		"SELECT c2.cve, c2.severity, c2.published, c2.modified, c2.summary "+
			"FROM t_short_cpe_purl_exported tscpe "+
			"INNER JOIN cpes c ON tscpe.cpe_id = c.id "+
			"INNER JOIN nvd_match_criteria_ids nmci ON trim(CAST(nmci.cpe_ids AS TEXT), '{}') LIKE '%' || tscpe.cpe_id || '%' "+
			"INNER JOIN cves c2 ON trim(CAST(nmci.cpe_ids AS TEXT), '{}') LIKE  '%' || nmci.match_criteria_id || '%' "+
			"WHERE "+
			"tscpe.purl = $1",
		purlName)

	if err != nil {
		zlog.S.Errorf("Failed to query short_cpe for %s: %v", purlName, err)
		return []VulnsForPurl{}, fmt.Errorf("failed to query the table: %v", err)
	}
	zlog.S.Debugf("Found %v results for %v.", len(vulns), purlName)

	return vulns, nil
}

func (m *VulnsForPurlModel) GetVulnsByPurlVersion(purlName string, purlVersion string) ([]VulnsForPurl, error) {
	if len(purlName) == 0 {
		zlog.S.Errorf("Please specify a valid Purl Name to query")
		return []VulnsForPurl{}, errors.New("please specify a valid Purl Name to query")
	}

	var vulns []VulnsForPurl
	purlName = strings.TrimSpace(purlName)
	err := m.conn.SelectContext(m.ctx, &vulns,
		"select distinct c2.cve, c2.severity, c2.published, c2.modified, c2.summary "+
			"from "+
			"t_short_cpe_purl_exported tscpe, "+
			"short_cpes sc, "+
			"cves c2 "+
			"inner join nvd_match_criteria_ids nmci "+
			"on "+
			"nmci.match_criteria_id = any(c2.match_criteria_ids) "+
			"where "+
			"tscpe.purl = $1 "+
			"and ($2 = nmci.version_start_including or $2 = nmci.version_end_including "+
			"or "+
			"( "+
			"( "+
			"(nmci.version_start_excluding = '' and nmci.version_start_including = '') "+
			"or "+
			"(nmci.version_start_excluding != '' and natural_sort_order($2, 20) > natural_sort_order(nmci.version_start_excluding, 20)) "+
			"or "+
			"(nmci.version_start_including != '' and natural_sort_order($2, 20) > natural_sort_order(nmci.version_start_including, 20)) "+
			") and "+
			"( "+
			"(nmci.version_end_excluding = '' and nmci.version_end_including = '') "+
			"or "+
			"(nmci.version_end_excluding != '' and natural_sort_order($2, 20) < natural_sort_order(nmci.version_end_excluding, 20))"+
			"or "+
			"(nmci.version_end_including != '' and natural_sort_order($2, 20) < natural_sort_order(nmci.version_end_including, 20)) "+
			")"+
			")"+
			")"+
			"and tscpe.cpe_id = sc.id "+
			"and sc.id = nmci.short_cpe_id;", purlName, purlVersion)

	if err != nil {
		zlog.S.Errorf("Failed to query short_cpe for %s: %v", purlName, err)
		return []VulnsForPurl{}, fmt.Errorf("failed to query the table: %v", err)
	}

	zlog.S.Debugf("Found %v results for %v.", len(vulns), purlName)
	return vulns, nil
}

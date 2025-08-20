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
	"strconv"
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

type VulnWithVersionRange struct {
	VulnsForPurl
	VersionStartIncluding string `db:"version_start_including"`
	VersionStartExcluding string `db:"version_start_excluding"`
	VersionEndIncluding   string `db:"version_end_including"`
	VersionEndExcluding   string `db:"version_end_excluding"`
}

type OnlyPurl struct {
	Purl string `db:"purl"`
}

// compareVersions compares two version strings semantically
// Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func compareVersions(v1, v2 string) int {
	if v1 == v2 {
		return 0
	}
	
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")
	
	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}
	
	for i := 0; i < maxLen; i++ {
		var p1, p2 int
		var err error
		
		if i < len(parts1) {
			p1, err = strconv.Atoi(parts1[i])
			if err != nil {
				return strings.Compare(v1, v2)
			}
		}
		
		if i < len(parts2) {
			p2, err = strconv.Atoi(parts2[i])
			if err != nil {
				return strings.Compare(v1, v2)
			}
		}
		
		if p1 < p2 {
			return -1
		}
		if p1 > p2 {
			return 1
		}
	}
	
	return 0
}

// isVersionInRange checks if a version falls within the specified range
func isVersionInRange(version string, startIncl, startExcl, endIncl, endExcl string) bool {
	// Handle exact matches first
	if startIncl != "" && version == startIncl {
		return true
	}
	if endIncl != "" && version == endIncl {
		return true
	}
	
	// Check start range
	startOk := true
	if startExcl != "" {
		startOk = compareVersions(version, startExcl) > 0
	} else if startIncl != "" {
		startOk = compareVersions(version, startIncl) >= 0
	}
	
	// Check end range
	endOk := true
	if endExcl != "" {
		endOk = compareVersions(version, endExcl) < 0
	} else if endIncl != "" {
		endOk = compareVersions(version, endIncl) <= 0
	}
	
	return startOk && endOk
}

// NewVulnsForPurlModel creates a new instance of the CPE Purl Model.
func NewVulnsForPurlModel(ctx context.Context, conn *sqlx.Conn) *VulnsForPurlModel {
	return &VulnsForPurlModel{ctx: ctx, conn: conn}
}

// GetVulnsByPurl gets vulnerabilities by purl.
func (m *VulnsForPurlModel) GetVulnsByPurl(purlString, purlReq string) ([]VulnsForPurl, error) {
	if len(purlString) == 0 {
		zlog.S.Errorf("Please specify a valid Purl String to query")
		return []VulnsForPurl{}, errors.New("please specify a valid Purl String to query")
	}

	purl, err := utils.PurlFromString(purlString)
	if err != nil {
		return []VulnsForPurl{}, err
	}

	purlName := utils.PurlRemoveFromVersionComponent(purlString) // Remove everything after the component name

	if len(purl.Version) == 0 && len(purlReq) > 0 { // No version specified, but we might have a specific version in the Requirement
		ver := utils.GetVersionFromReq(purlReq)
		if len(ver) > 0 {
			purl.Version = ver // Switch to exact version search (faster)
		}
	}

	if len(purl.Version) > 0 {
		return m.GetVulnsByPurlVersion(purlName, purl.Version)
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

	var vulnsWithRange []VulnWithVersionRange
	purlName = strings.TrimSpace(purlName)
	err := m.conn.SelectContext(m.ctx, &vulnsWithRange,
		"select distinct c2.cve, c2.severity, c2.published, c2.modified, c2.summary, "+
			"nmci.version_start_including, nmci.version_start_excluding, "+
			"nmci.version_end_including, nmci.version_end_excluding "+
			"from "+
			"t_short_cpe_purl_exported tscpe, "+
			"short_cpes sc, "+
			"cves c2, "+
			"nvd_match_criteria_ids nmci "+
			"where "+
			"tscpe.purl = $1 "+
			"and tscpe.cpe_id = sc.id "+
			"and sc.id = nmci.short_cpe_id "+
			"and trim(CAST(c2.match_criteria_ids AS TEXT), '{}') LIKE '%' || nmci.match_criteria_id || '%'", purlName)

	if err != nil {
		zlog.S.Errorf("Failed to query short_cpe for %s: %v", purlName, err)
		return []VulnsForPurl{}, fmt.Errorf("failed to query the table: %v", err)
	}

	var vulns []VulnsForPurl
	for _, v := range vulnsWithRange {
		if isVersionInRange(purlVersion, v.VersionStartIncluding, v.VersionStartExcluding, 
			v.VersionEndIncluding, v.VersionEndExcluding) {
			vulns = append(vulns, v.VulnsForPurl)
		}
	}

	zlog.S.Debugf("Found %v results for %v.", len(vulns), purlName)
	return vulns, nil
}

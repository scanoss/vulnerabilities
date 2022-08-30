// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018-2022 SCANOSS.COM
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
	zlog "scanoss.com/vulnerabilities/pkg/logger"
	"scanoss.com/vulnerabilities/pkg/utils"
)

type VulnsForPurlModel struct {
	ctx  context.Context
	conn *sqlx.Conn
}

type VulnsForPurl struct {
	Cve      string `db:"cve"`
	Url      string `db:"url"`
	Version  string `db:"version_name"`
	Semver   string `db:"semver"`
	Summary  string `db:"summary"`
	Severity string `db:"severity"`
}

type OnlyPurl struct {
	Purl string `db:"purl"`
}

// NewCpePurlModel creates a new instance of the CPE Purl Model
func NewVulnsForPurlModel(ctx context.Context, conn *sqlx.Conn) *VulnsForPurlModel {
	return &VulnsForPurlModel{ctx: ctx, conn: conn}
}

// GetCpeByPurlString searches for CPE details of the specified Purl string (and optional requirement)
// Lets do all checks before querying db and if all ok, then do magic
func (m *VulnsForPurlModel) GetVulnsByPurlString(purlString, purlReq string) ([]VulnsForPurl, error) {
	if len(purlString) == 0 {
		zlog.S.Errorf("Please specify a valid Purl String to query")
		return []VulnsForPurl{}, errors.New("please specify a valid Purl String to query")
	}
	purl, err := utils.PurlFromString(purlString)
	if err != nil {
		return []VulnsForPurl{}, err
	}
	purlName, err := utils.PurlNameFromString(purlString) // Make sure we just have the bare minimum for a Purl Name
	if err != nil {
		return []VulnsForPurl{}, err
	}
	if len(purl.Version) == 0 && len(purlReq) > 0 { // No version specified, but we might have a specific version in the Requirement
		ver := utils.GetVersionFromReq(purlReq)
		if len(ver) > 0 {
			// TODO check what to do if we get a "file" requirement
			purl.Version = ver // Switch to exact version search (faster)
			purlReq = ""
		}
	}
	if len(purl.Version) > 0 {
		// TODO  Implement ,.GetCpeByPurlNameType
		//return m.GetUrlsByPurlNameTypeVersion(purlName, purl.Type, purl.Version)
	}
	return m.GetVulnsByPurlName(purlName)
}

// GetUrlsByPurlNameType searches for component details of the specified Purl Name/Type (and optional requirement)
func (m *VulnsForPurlModel) GetVulnsByPurlName(purlName string) ([]VulnsForPurl, error) {
	if len(purlName) == 0 {
		zlog.S.Errorf("Please specify a valid Purl Name to query")
		return []VulnsForPurl{}, errors.New("please specify a valid Purl Name to query")
	}

	var vulns []VulnsForPurl
	purlName = strings.TrimSpace(purlName)
	err := m.conn.SelectContext(m.ctx, &vulns,
		"select  cve, severity, v.version_name, v.semver "+
			"from t_purl tpurl "+
			"left join t_short_cpe_purl tscp on id = purl_id "+
			"right join t_cpe tc on tc.short_cpe_id = tscp.short_cpe_id "+
			"left join t_cpe_cve tcc on tc.id = tcc.cpe_id "+
			"left join t_cve tcve on tcc.cve_id =tcve.id "+
			"left join versions v on tc.version_id = v.id "+
			"where tpurl.purl  = $1 and cve is not null limit 100000", purlName)

	if err != nil {
		zlog.S.Errorf("Failed to query short_cpe for %s: %v", purlName, err)
		return []VulnsForPurl{}, fmt.Errorf("failed to query the table: %v", err)
	}
	zlog.S.Debugf("Found %v results for %v.", len(vulns), purlName)

	return vulns, nil
}

//  searches for component details of the specified Purl Name/Type and version
func (m *VulnsForPurlModel) GetVulnsByPurlNameVersion(purlName string, purlVersion string) ([]VulnsForPurl, error) {
	if len(purlName) == 0 {
		zlog.S.Errorf("Please specify a valid Purl Name to query")
		return []VulnsForPurl{}, errors.New("please specify a valid Purl Name to query")
	}

	if len(purlVersion) == 0 {
		zlog.S.Errorf("Please specify a valid Purl Version to query")
		return []VulnsForPurl{}, errors.New("please specify a valid Purl Version to query")
	}
	var vulnsForPurl []VulnsForPurl
	err := m.conn.SelectContext(m.ctx, &vulnsForPurl,
		"select  v.version_name, v.semver,  cve, severity "+
			"from t_purl tpurl "+
			"left join t_short_cpe_purl tscp on tpurl.id = tscp.purl_id "+
			"right join t_cpe tc on tc.short_cpe_id =tscp.short_cpe_id "+
			"left join t_cpe_cve tcc on tc.id =tcc.cpe_id "+
			"left join t_cve tcve on tcc.cve_id =tcve.id "+
			"left join versions v on tc.version_id = v.id "+
			"where tpurl.purl  = 'pkg:github/qos-ch/slf4j' and cve is not null limit 100000; ",
		purlName, purlVersion)
	if err != nil {
		zlog.S.Errorf("Failed to query all urls table for %v - %v: %v", purlName, err)
		return []VulnsForPurl{}, fmt.Errorf("failed to query the all urls table: %v", err)
	}

	return vulnsForPurl, nil
}

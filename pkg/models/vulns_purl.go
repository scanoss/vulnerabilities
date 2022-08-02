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
	Summary  string `db:"summary"`
	Severity string `db:"severity"`
	Reported string `db:"reported"`
	Patched  string `db:"patched"`
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

	//zlog.S.Debugf("ctx %v", m.ctx)
	purlName = strings.TrimSpace(purlName)
	err := m.conn.SelectContext(m.ctx, &vulns,
		"select  cve, severity from t_purl tpurl "+
			"left join t_short_cpe_purl tscp on id = purl_id "+
			"right join t_cpe tc on tc.short_cpe_id =tscp.short_cpe_id "+
			"left join t_cpe_cve tcc on tc.id =tcc.cpe_id "+
			"left join t_cve tcve on tcc.cve_id =tcve.id "+
			"where tpurl.purl  = $1 and cve is not null limit 100000", purlName)

	/*	"SELECT cpe as summary, vuln_id as cve, severity "+
		"FROM (SELECT scp.purl, scp.short_cpe "+
		"FROM short_cpe_purl scp "+
		"WHERE purl = $1) scpe "+
		"INNER JOIN "+
		"(SELECT c.cpe, c.vuln_id, vli.severity "+
		"FROM cpe_cve c "+
		"LEFT JOIN vuln_info vli on c.vuln_id = vli.vuln_id) fcpe "+
		"ON fcpe.cpe LIKE CONCAT(scpe.short_cpe, '%')"*/
	/*"select  tcve.cve as cve, tcve.severity as severity from t_purl tpurl ,t_short_cpe_purl tscp, t_cpe tc, t_cpe_cve tcpecve ,t_cve tcve "+
	"where  tpurl.purl ='pkg:github/torvalds/linux' and tpurl.id =tscp.purl_id and tscp.short_cpe_id =tc.short_cpe_id and tcpecve.cpe_id =tc.id and tcve.id =tcpecve.cve_id")
	*/
	if err != nil {
		zlog.S.Errorf("Failed to query short_cpe for %s: %v", purlName, err)
		return []VulnsForPurl{}, fmt.Errorf("failed to query the table: %v", err)
	}
	zlog.S.Debugf("Found %v results for %v.", len(vulns), purlName)
	// Pick one URL to return (checking for license details also)
	return vulns, nil
}

// GetUrlsByPurlNameTypeVersion searches for component details of the specified Purl Name/Type and version
/*func (m *CpePurlModel) GetCpesByPurlNameVersion(purlName, purlVersion string) ([]CpePurl, error) {
	if len(purlName) == 0 {
		zlog.S.Errorf("Please specify a valid Purl Name to query")
		return []CpePurl{}, errors.New("please specify a valid Purl Name to query")
	}

	if len(purlVersion) == 0 {
		zlog.S.Errorf("Please specify a valid Purl Version to query")
		return []CpePurl{}, errors.New("please specify a valid Purl Version to query")
	}
	var cpuPurls []CpePurl
	err := m.conn.SelectContext(m.ctx, &cpuPurls,
		"SELECT cc.cpe, cc.vuln_id "+
			"FROM short_cpe_purl scp, cpe_cve cc "+
			"WHERE scp.purl = $1 and cc.cpe like concat (scp.short_cpe,'%') order by (cc.vuln_id)",
		purlName, purlVersion)
	if err != nil {
		zlog.S.Errorf("Failed to query all urls table for %v - %v: %v", purlName, err)
		return []CpePurl{}, fmt.Errorf("failed to query the all urls table: %v", err)
	}
	zlog.S.Debugf("Found %v results for %v, %v.", len(cpuPurls), purlName)
	// Pick one URL to return (checking for license details also)
	return cpuPurls, nil
}*/

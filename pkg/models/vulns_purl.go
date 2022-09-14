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
	"github.com/jmoiron/sqlx"
	zlog "scanoss.com/vulnerabilities/pkg/logger"
	"scanoss.com/vulnerabilities/pkg/utils"
	"strings"
)

type VulnsForPurlModel struct {
	ctx  context.Context
	conn *sqlx.Conn
}

type VulnsForPurl struct {
	Cve       string         `db:"cve"`
	Severity  string         `db:"severity"`
	Url       string         `db:"url"`
	Published utils.OnlyDate `db:"published"`
	Modified  utils.OnlyDate `db:"modified"`
	Summary   string         `db:"summary"`
}

type OnlyPurl struct {
	Purl string `db:"purl"`
}

// NewCpePurlModel creates a new instance of the CPE Purl Model
func NewVulnsForPurlModel(ctx context.Context, conn *sqlx.Conn) *VulnsForPurlModel {
	return &VulnsForPurlModel{ctx: ctx, conn: conn}
}

// GetVulnsByPurlString
func (m *VulnsForPurlModel) GetVulnsByPurlString(purlString, purlReq string) ([]VulnsForPurl, error) {
	if len(purlString) == 0 {
		zlog.S.Errorf("Please specify a valid Purl String to query")
		return []VulnsForPurl{}, errors.New("please specify a valid Purl String to query")
	}

	purl, err := utils.PurlFromString(purlString)
	if err != nil {
		return []VulnsForPurl{}, err
	}

	purlName := utils.PurlRemoveFromVersionComponent(purlString) //Remove everything after the component name

	if len(purl.Version) == 0 && len(purlReq) > 0 { // No version specified, but we might have a specific version in the Requirement
		ver := utils.GetVersionFromReq(purlReq)
		if len(ver) > 0 {
			purl.Version = ver // Switch to exact version search (faster)
			purlReq = ""
		}
	}

	if len(purl.Version) > 0 {
		return m.GetVulnsByPurlNameVersion(purlName, purl.Version)
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
		"select distinct t_cve.cve, t_cve.severity, t_cve.published, t_cve.modified, t_cve.summary "+
			"from t_purl p "+
			"inner join t_short_cpe_purl tscp on p.id = tscp.purl_id "+
			"inner join t_cpe tc on tscp.short_cpe_id = tc.short_cpe_id "+
			"inner join t_cpe_cve tcc on tc.id = tcc.cpe_id "+
			"inner join t_cve on t_cve.id = tcc.cve_id "+
			"where p.purl = $1;", purlName)

	if err != nil {
		zlog.S.Errorf("Failed to query short_cpe for %s: %v", purlName, err)
		return []VulnsForPurl{}, fmt.Errorf("failed to query the table: %v", err)
	}
	zlog.S.Debugf("Found %v results for %v.", len(vulns), purlName)

	return vulns, nil
}

func (m *VulnsForPurlModel) GetVulnsByPurlNameVersion(purlName string, purlVersion string) ([]VulnsForPurl, error) {
	if len(purlName) == 0 {
		zlog.S.Errorf("Please specify a valid Purl Name to query")
		return []VulnsForPurl{}, errors.New("please specify a valid Purl Name to query")
	}

	var vulns []VulnsForPurl
	purlName = strings.TrimSpace(purlName)
	err := m.conn.SelectContext(m.ctx, &vulns,
		"select t_cve.cve, t_cve.severity, t_cve.published, t_cve.modified, t_cve.summary "+
			"from t_purl p "+
			"inner join t_short_cpe_purl tscp on p.id = tscp.purl_id "+
			"inner join t_cpe tc on tscp.short_cpe_id = tc.short_cpe_id "+
			"inner join t_cpe_cve tcc on tc.id = tcc.cpe_id "+
			"inner join t_cve on t_cve.id = tcc.cve_id "+
			"where p.purl = $1 and tc.version = $2;", purlName, purlVersion)

	if err != nil {
		zlog.S.Errorf("Failed to query short_cpe for %s: %v", purlName, err)
		return []VulnsForPurl{}, fmt.Errorf("failed to query the table: %v", err)
	}
	zlog.S.Debugf("Found %v results for %v.", len(vulns), purlName)

	return vulns, nil
}

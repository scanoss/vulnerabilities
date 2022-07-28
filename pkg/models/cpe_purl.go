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
)

type CpePurlModel struct {
	ctx  context.Context
	conn *sqlx.Conn
}

type CpePurl struct {
	Cpe    string `db:"cpe"`
	Purl   string `db:"purl"`
	IsMain string `db:"int"`
}

// NewCpePurlModel creates a new instance of the CPE Purl Model
func NewCpePurlModel(ctx context.Context, conn *sqlx.Conn) *CpePurlModel {
	return &CpePurlModel{ctx: ctx, conn: conn}
}

// GetCpeByPurlString searches for CPE details of the specified Purl string (and optional requirement)
// Lets do all checks before querying db and if all ok, then do magic
func (m *CpePurlModel) GetCpeByPurlString(purlString, purlReq string) ([]CpePurl, error) {
	if len(purlString) == 0 {
		zlog.S.Errorf("Please specify a valid Purl String to query")
		return []CpePurl{}, errors.New("please specify a valid Purl String to query")
	}
	purl, err := utils.PurlFromString(purlString)
	if err != nil {
		return []CpePurl{}, err
	}
	purlName, err := utils.PurlNameFromString(purlString) // Make sure we just have the bare minimum for a Purl Name
	if err != nil {
		return []CpePurl{}, err
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
	return m.GetCpesByPurlName(purlName)
}

// GetUrlsByPurlNameType searches for component details of the specified Purl Name/Type (and optional requirement)
func (m *CpePurlModel) GetCpesByPurlName(purlName string) ([]CpePurl, error) {
	if len(purlName) == 0 {
		zlog.S.Errorf("Please specify a valid Purl Name to query")
		return []CpePurl{}, errors.New("please specify a valid Purl Name to query")
	}

	var allCpes []CpePurl
	err := m.conn.SelectContext(m.ctx, &allCpes,
		"SELECT cpe.cpe"+
			" FROM cpe "+
			" LEFT JOIN short_cpe_purl scp ON cpe.short_cpe_id = scp.short_cpe_id"+
			" LEFT JOIN purl p ON scp.purl_id = p.id"+
			" WHERE p.purl = $1;",
		purlName)

	if err != nil {
		zlog.S.Errorf("Failed to query short_cpu for %v - %v: %v", purlName, err)
		return []CpePurl{}, fmt.Errorf("failed to query the table: %v", err)
	}
	zlog.S.Debugf("Found %v results for %v.", len(allCpes), purlName)
	// Pick one URL to return (checking for license details also)
	return allCpes, nil
}

// GetUrlsByPurlNameTypeVersion searches for component details of the specified Purl Name/Type and version
func (m *CpePurlModel) GetCpesByPurlNameVersion(purlName, purlVersion string) ([]CpePurl, error) {
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
}

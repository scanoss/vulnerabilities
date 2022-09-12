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

// GetUrlsByPurlNameType searches for component details of the specified Purl Name/Type (and optional requirement)
func (m *VulnsForPurlModel) GetVulnsByPurlName(purlName string) ([]VulnsForPurl, error) {
	if len(purlName) == 0 {
		zlog.S.Errorf("Please specify a valid Purl Name to query")
		return []VulnsForPurl{}, errors.New("please specify a valid Purl Name to query")
	}

	purlName = utils.PurlRemoveFromVersionComponent(purlName) // Make sure we just have the bare minimum for a Purl Name

	var vulns []VulnsForPurl
	purlName = strings.TrimSpace(purlName)
	err := m.conn.SelectContext(m.ctx, &vulns,
		"select t_cve.cve, t_cve.severity, v.semver, v.version_name "+
			"from t_purl p "+
			"inner join t_short_cpe_purl tscp on p.id = tscp.purl_id "+
			"inner join t_cpe tc on tscp.short_cpe_id = tc.short_cpe_id "+
			"inner join t_cpe_cve tcc on tc.id = tcc.cpe_id "+
			"inner join t_cve on t_cve.id = tcc.cve_id "+
			"inner join versions v on tc.version_id = v.id "+
			"where p.purl = $1;", purlName)

	if err != nil {
		zlog.S.Errorf("Failed to query short_cpe for %s: %v", purlName, err)
		return []VulnsForPurl{}, fmt.Errorf("failed to query the table: %v", err)
	}
	zlog.S.Debugf("Found %v results for %v.", len(vulns), purlName)

	return vulns, nil
}

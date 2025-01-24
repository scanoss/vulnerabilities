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

	"github.com/Masterminds/semver/v3"
	"github.com/jmoiron/sqlx"
	zlog "scanoss.com/vulnerabilities/pkg/logger"
	"scanoss.com/vulnerabilities/pkg/utils"
)

type CpePurlModel struct {
	ctx  context.Context
	conn *sqlx.Conn
}

type CpePurl struct {
	Cpe     string `db:"cpe"`
	Version string `db:"version_name"`
	SemVer  string `db:"semver"`
}

// NewCpePurlModel creates a new instance of the CPE Purl Model
func NewCpePurlModel(ctx context.Context, conn *sqlx.Conn) *CpePurlModel {
	return &CpePurlModel{ctx: ctx, conn: conn}
}

// GetCpeByPurl searches for CPE details of the specified Purl string (and optional requirement).
// If version is specified in purl string the requirement is ignored
func (m *CpePurlModel) GetCpeByPurl(purlString, purlReq string) ([]CpePurl, error) {
	if len(purlString) == 0 {
		zlog.S.Errorf("Please specify a valid Purl String to query")
		return []CpePurl{}, errors.New("please specify a valid Purl String to query")
	}
	purl, err := utils.PurlFromString(purlString)
	if err != nil {
		return []CpePurl{}, err
	}
	purlVersion := purl.Version

	purlString = utils.PurlRemoveFromVersionComponent(purlString) //Make sure to get the minimum purl pkg:github...

	if len(purlVersion) == 0 && len(purlReq) > 0 { // No version specified, but we might have a specific version in the Requirement
		ver := utils.GetVersionFromReq(purlReq)
		if len(ver) > 0 {
			purlVersion = ver // Switch to exact version search (faster)
			purlReq = ""
		}
	}

	if len(purlVersion) > 0 {
		return m.GetCpesByPurlStringVersion(purlString, purlVersion)
	}
	return m.GetCpesByPurlString(purlString, purlReq)
}

// GetCpesByPurlNameType searches for component details of the specified Purl Name/Type (and optional requirement)
func (m *CpePurlModel) GetCpesByPurlString(purlString string, purlReq string) ([]CpePurl, error) {
	if len(purlString) == 0 {
		zlog.S.Errorf("Please specify a valid Purl Name to query")
		return []CpePurl{}, errors.New("please specify a valid Purl Name to query")
	}

	var allCpes []CpePurl
	zlog.S.Debugf("ctx %v", m.ctx)
	err := m.conn.SelectContext(m.ctx, &allCpes,
		"SELECT tcp.cpe, v.version_name, v.semver "+
			"FROM cpes tcp "+
			"INNER JOIN t_short_cpe_purl_exported tscp ON tcp.short_cpe_id = tscp.cpe_id  "+
			"INNER JOIN purls tp ON tscp.purl_id = tp.id "+
			"INNER JOIN versions v ON tcp.version_id = v.id "+
			"WHERE tp.purl  = $1"+
			" ORDER BY v.version_name NULLS LAST;",
		purlString)

	if err != nil {
		zlog.S.Errorf("Failed to query Cpe for %v - %v", purlString, err)
		return []CpePurl{}, fmt.Errorf("failed to query the CPE table: %v", err)
	}
	zlog.S.Debugf("Found %v results for %v.", len(allCpes), purlString)

	if len(purlReq) > 0 {
		allCpes = FilterCpesByRequirement(allCpes, purlReq)
	}

	return allCpes, nil
}

// GetCpesByPurlStringVersion searches for CPEs of the specified Purl Name/Type and version
func (m *CpePurlModel) GetCpesByPurlStringVersion(purlString, purlVersion string) ([]CpePurl, error) {
	if len(purlString) == 0 {
		zlog.S.Errorf("Please specify a valid Purl Name to query")
		return []CpePurl{}, errors.New("please specify a valid Purl Name to query")
	}

	var cpuPurls []CpePurl
	err := m.conn.SelectContext(m.ctx, &cpuPurls,
		"SELECT tc.cpe, v.version_name, v.semver "+
			"FROM cpes tc "+
			"INNER JOIN t_short_cpe_purl_exported scp ON tc.short_cpe_id = scp.cpe_id "+
			"INNER JOIN purls p ON scp.purl_id = p.id "+
			"INNER JOIN versions v ON tc.version_id = v.id "+
			" WHERE p.purl = $1 AND v.version_name=$2;",
		purlString, purlVersion)
	if err != nil {
		zlog.S.Errorf("Failed to query cpe table for %v - %v", purlString, err)
		return []CpePurl{}, fmt.Errorf("failed to query the cpe table: %v", err)
	}
	zlog.S.Debugf("Found %v results for %v", len(cpuPurls), purlString)
	return cpuPurls, nil
}

func FilterCpesByRequirement(cpes []CpePurl, purlReq string) []CpePurl {

	if len(cpes) == 0 {
		zlog.S.Infof("No cpes in filterCpes()")
		return []CpePurl{}
	}

	var c *semver.Constraints

	if len(purlReq) > 0 {
		zlog.S.Debugf("Building version constraint for %v", purlReq)
		var err error
		c, err = semver.NewConstraint(purlReq)
		if err != nil {
			zlog.S.Warnf("Encountered an issue parsing version constraint string '%v' (%v,%v): %v", purlReq, err)
		}
	}

	zlog.S.Debugf("Filtering cpes by requirement...")
	output := []CpePurl{}
	for _, cpe := range cpes {
		if len(cpe.SemVer) > 0 || len(cpe.Version) > 0 {
			v, err := semver.NewVersion(cpe.Version)
			if err != nil && len(cpe.SemVer) > 0 {
				zlog.S.Debugf("Failed to parse SemVer: '%v'. Trying Version instead: %v (%v)", cpe.Version, cpe.SemVer, err)
				v, err = semver.NewVersion(cpe.SemVer) // Semver failed, try the normal version
			}
			if err != nil {
				zlog.S.Warnf("Encountered an issue parsing version string '%v' (%v) for %v: %v. Using v0.0.0", cpe.Version, cpe.SemVer, cpe, err)
				v, err = semver.NewVersion("v0.0.0") // Semver failed, just use a standard version zero (for now)
			}
			if err == nil {
				if c == nil || c.Check(v) {
					output = append(output, cpe)
				}
			}
		} else {
			zlog.S.Warnf("Skipping match as it doesn't have a version: %#v", cpe)
		}
	}
	return output
}

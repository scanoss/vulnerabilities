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

package usecase

import (
	"context"
	"errors"
	"fmt"
	"github.com/jmoiron/sqlx"
	myconfig "scanoss.com/vulnerabilities/pkg/config"
	"scanoss.com/vulnerabilities/pkg/dtos"
	"scanoss.com/vulnerabilities/pkg/models"

	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
)

type LocalVulnerabilityUseCase struct {
	ctx        context.Context
	conn       *sqlx.Conn
	vulnsPurl  *models.VulnsForPurlModel
	versionMod *models.VersionModel
}

// NewLocalVulnerabilitiesUseCase creates a new instance of the vulnerability Use Case.
func NewLocalVulnerabilitiesUseCase(ctx context.Context, conn *sqlx.Conn, config *myconfig.ServerConfig) *LocalVulnerabilityUseCase {
	return &LocalVulnerabilityUseCase{ctx: ctx, conn: conn,
		vulnsPurl:  models.NewVulnsForPurlModel(ctx, conn),
		versionMod: models.NewVersionModel(ctx, conn),
	}
}

func (d LocalVulnerabilityUseCase) GetVulnerabilities(request []dtos.ComponentDTO) (dtos.VulnerabilityOutput, error) {
	var vulnOutputs []dtos.VulnerabilityComponentOutput
	var problems = false
	for _, c := range request {
		if len(c.Purl) == 0 {
			zlog.S.Infof("Empty Purl string supplied for: %v. Skipping", c)
			continue
		}

		// VulnerabilitiesOutput
		var item dtos.VulnerabilityComponentOutput
		item.Purl = c.Purl
		item.Requirement = c.Requirement
		item.Version = c.Version

		vulnPurls, err := d.vulnsPurl.GetVulnsByPurl(c.Purl, c.Version)

		if err != nil {
			zlog.S.Errorf("Problem encountered extracting CPEs for: %v - %v.", c, err)
			problems = true
			continue
		}

		for _, cve := range vulnPurls {
			var vulnerabilitiesForThisPurl dtos.VulnerabilitiesOutput
			vulnerabilitiesForThisPurl.ID = cve.Cve
			vulnerabilitiesForThisPurl.Cve = cve.Cve
			vulnerabilitiesForThisPurl.Severity = cve.Severity
			vulnerabilitiesForThisPurl.Modified = cve.Modified
			vulnerabilitiesForThisPurl.Published = cve.Published
			vulnerabilitiesForThisPurl.Summary = cve.Summary
			vulnerabilitiesForThisPurl.URL = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve.Cve)

			vulnerabilitiesForThisPurl.Source = "NVD"
			item.Vulnerabilities = append(item.Vulnerabilities, vulnerabilitiesForThisPurl)
		}

		vulnOutputs = append(vulnOutputs, item)
	}

	if problems {
		zlog.S.Errorf("Encountered issues while processing vulnerabilities: %v", request)
		return dtos.VulnerabilityOutput{}, errors.New("encountered issues while processing vulnerabilities")
	}

	return dtos.VulnerabilityOutput{Components: vulnOutputs}, nil
}

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
	"regexp"

	"github.com/jmoiron/sqlx"
	myconfig "scanoss.com/vulnerabilities/pkg/config"
	"scanoss.com/vulnerabilities/pkg/dtos"
	zlog "scanoss.com/vulnerabilities/pkg/logger"
	"scanoss.com/vulnerabilities/pkg/models"
)

var reRemoveConstraint = regexp.MustCompile(`>|<|=|>=|<=|~|!=`)
var reExtractSemver = regexp.MustCompile(`(?P<version>\d*\.?\d*\.?\d*)(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)

type LocalVulnerabilityUseCase struct {
	ctx        context.Context
	conn       *sqlx.Conn
	vulnsPurl  *models.VulnsForPurlModel
	versionMod *models.VersionModel
}

// NewLocalVulnerabilitiesUseCase creates a new instance of the vulnerability Use Case
func NewLocalVulnerabilitiesUseCase(ctx context.Context, conn *sqlx.Conn, config *myconfig.ServerConfig) *LocalVulnerabilityUseCase {
	return &LocalVulnerabilityUseCase{ctx: ctx, conn: conn,
		vulnsPurl:  models.NewVulnsForPurlModel(ctx, conn),
		versionMod: models.NewVersionModel(ctx, conn)}
}

func (d LocalVulnerabilityUseCase) GetVulnerabilities(request dtos.VulnerabilityRequestDTO) (dtos.VulnerabilityOutput, error) {

	var vulnOutputs []dtos.VulnerabilityPurlOutput

	var problems = false
	for _, purl := range request.Purls {
		if len(purl.Purl) == 0 {
			zlog.S.Infof("Empty Purl string supplied for: %v. Skipping", purl)
			continue
		}

		//VulnerabilitiesOutput
		var item dtos.VulnerabilityPurlOutput

		item.Purl = purl.Purl + "@" + purl.Requirement
		vulnPurls, err := d.vulnsPurl.GetVulnsByPurl(purl.Purl, purl.Requirement)

		if err != nil {
			zlog.S.Errorf("Problem encountered extracting CPEs for: %v - %v.", purl, err)
			problems = true
			continue
			//TODO add a placeholder in the response?
		}

		for _, cve := range vulnPurls {

			var vulnerabilitiesForThisPurl dtos.VulnerabilitiesOutput
			vulnerabilitiesForThisPurl.Id = cve.Cve
			vulnerabilitiesForThisPurl.Cve = cve.Cve
			vulnerabilitiesForThisPurl.Severity = cve.Severity
			vulnerabilitiesForThisPurl.Modified = cve.Modified
			vulnerabilitiesForThisPurl.Published = cve.Published
			vulnerabilitiesForThisPurl.Summary = cve.Summary
			vulnerabilitiesForThisPurl.Url = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve.Cve)

			vulnerabilitiesForThisPurl.Source = "NVD"
			item.Vulnerabilities = append(item.Vulnerabilities, vulnerabilitiesForThisPurl)
		}

		vulnOutputs = append(vulnOutputs, item)
	}

	if problems {
		zlog.S.Errorf("Encountered issues while processing vulnerabilities: %v", request)
		return dtos.VulnerabilityOutput{}, errors.New("encountered issues while processing vulnerabilities")
	}

	return dtos.VulnerabilityOutput{Purls: vulnOutputs}, nil
}

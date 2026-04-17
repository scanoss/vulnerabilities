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
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	compHelper "github.com/scanoss/go-component-helper/componenthelper"
	"go.uber.org/zap"
	"scanoss.com/vulnerabilities/pkg/config"
	"scanoss.com/vulnerabilities/pkg/dtos"
	"scanoss.com/vulnerabilities/pkg/models"
)

// LocalVulnerabilityUseCase handles vulnerability lookups against a local database.
// It provides concurrent processing of component vulnerability queries using a worker pool pattern.
type LocalVulnerabilityUseCase struct {
	ctx        context.Context
	vulnsPurl  *models.VulnsForPurlModel
	versionMod *models.VersionModel
	s          *zap.SugaredLogger
	config     *config.ServerConfig
}

// NewLocalVulnerabilitiesUseCase creates a new instance of the vulnerability Use Case.
func NewLocalVulnerabilitiesUseCase(ctx context.Context, s *zap.SugaredLogger, config *config.ServerConfig, db *sqlx.DB) *LocalVulnerabilityUseCase {
	return &LocalVulnerabilityUseCase{
		ctx:        ctx,
		vulnsPurl:  models.NewVulnsForPurlModel(db),
		versionMod: models.NewVersionModel(db),
		s:          s,
		config:     config,
	}
}

// vulnerabilityWorker is a worker goroutine that processes component vulnerability lookups.
// It reads components from the jobs channel, queries the local database for vulnerabilities,
// and sends the results to the results channel. The worker terminates when the jobs channel is closed.
func (d *LocalVulnerabilityUseCase) vulnerabilityWorker(ctx context.Context, jobs chan compHelper.Component, results chan dtos.VulnerabilityComponentOutput) {
	for {
		select {
		case <-ctx.Done():
			d.s.Debugf("Vulnerability worker cancelled: %v", ctx.Err())
			return
		case c, ok := <-jobs:
			if !ok {
				d.s.Debugf("Vulnerability worker channel closed. Exiting.")
				return
			}
			if len(c.Purl) == 0 {
				d.s.Debugf("Empty Purl string supplied for: %v. Skipping", c)
				results <- dtos.VulnerabilityComponentOutput{}
				continue
			}
			// VulnerabilitiesOutput
			var item dtos.VulnerabilityComponentOutput
			item.Purl = c.Purl
			item.Requirement = c.Requirement
			item.Version = c.Version
			item.ComponentStatus = c.Status
			// v should be trimmed because data is saved without a v prefix
			vulnPurls, err := d.vulnsPurl.GetVulnsByPurl(ctx, c.Purl, strings.TrimPrefix(c.Version, "v"))
			if err != nil {
				d.s.Errorf("Problem encountered extracting vulnerabilities for: %v - %v.", c, err)
				results <- item
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
			results <- item
		}
	}
}

// GetVulnerabilities retrieves vulnerabilities for a list of components from the local database.
// It spawns a pool of workers (up to MaxWorkers) to process requests concurrently and returns
// aggregated vulnerability information for all components.
func (d *LocalVulnerabilityUseCase) GetVulnerabilities(ctx context.Context, components []compHelper.Component) (dtos.VulnerabilityOutput, error) {
	numJobs := len(components)
	jobs := make(chan compHelper.Component, numJobs)
	results := make(chan dtos.VulnerabilityComponentOutput, numJobs)
	numWorkers := min(d.config.Source.SCANOSS.MaxWorkers, numJobs)
	for i := 0; i < numWorkers; i++ {
		go d.vulnerabilityWorker(ctx, jobs, results)
	}
	for _, component := range components {
		jobs <- component
	}
	close(jobs)
	var vulnOutputs = make([]dtos.VulnerabilityComponentOutput, numJobs)
	for i := 0; i < numJobs; i++ {
		select {
		case <-ctx.Done():
			return dtos.VulnerabilityOutput{Components: vulnOutputs}, ctx.Err()
		case vulnOutputs[i] = <-results:
		}
	}
	return dtos.VulnerabilityOutput{Components: vulnOutputs}, nil
}

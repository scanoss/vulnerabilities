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

// Package usecase implements the vulnerabilities service business logic.
//
// OSV vulnerabilities are read from the database rather than from api.osv.dev. The HTTP
// client, its worker pool sizing and the GIT-ecosystem fallback are gone: the osv table
// stores purls directly, including pkg:github ones, so a component is looked up by its
// purl with no translation to a repository URL and no retry.
//
// The response shape is unchanged. VULN_OSV_API_BASE_URL is no longer used;
// VULN_OSV_VULNERABILITY_INFO_BASE_URL still is, because it builds the URL of each
// returned vulnerability. VULN_OSV_API_WORKERS keeps its role as the concurrency limit,
// now over database lookups instead of HTTP calls.
package usecase

import (
	"context"
	"time"

	"github.com/jmoiron/sqlx"
	compHelper "github.com/scanoss/go-component-helper/componenthelper"
	"github.com/scanoss/go-grpc-helper/pkg/grpc/domain"
	"go.uber.org/zap"
	"scanoss.com/vulnerabilities/pkg/config"
	"scanoss.com/vulnerabilities/pkg/dtos"
	"scanoss.com/vulnerabilities/pkg/models"
	"scanoss.com/vulnerabilities/pkg/utils"
)

// osvSource is the value reported in the source field of every OSV vulnerability.
const osvSource = "OSV"

type OSVUseCase struct {
	OSVInfoBaseURL string
	maxWorkers     int
	model          *models.OSVModel
	s              *zap.SugaredLogger
}

func NewOSVUseCase(s *zap.SugaredLogger, config *config.ServerConfig, db *sqlx.DB) *OSVUseCase {
	workers := config.Source.OSV.APIWorkers
	if workers < 1 {
		workers = 1
	}
	return &OSVUseCase{
		OSVInfoBaseURL: config.Source.OSV.InfoBaseURL,
		maxWorkers:     workers,
		model:          models.NewOSVModel(s, db),
		s:              s,
	}
}

func (us OSVUseCase) Execute(ctx context.Context, components []compHelper.Component) dtos.VulnerabilityOutput {
	numJobs := len(components)
	response := dtos.VulnerabilityOutput{Components: []dtos.VulnerabilityComponentOutput{}}
	if numJobs == 0 {
		return response
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	jobs := make(chan compHelper.Component, numJobs)
	results := make(chan dtos.VulnerabilityComponentOutput, numJobs)
	workers := min(us.maxWorkers, numJobs)
	for i := 0; i < workers; i++ {
		go us.processComponent(ctx, jobs, results)
	}
	for _, c := range components {
		jobs <- c
	}
	close(jobs)
	for i := 0; i < numJobs; i++ {
		response.Components = append(response.Components, <-results)
	}
	return response
}

// processComponent is a worker that looks up each component and sends the result on.
func (us OSVUseCase) processComponent(ctx context.Context, jobs chan compHelper.Component,
	results chan dtos.VulnerabilityComponentOutput) {
	for {
		select {
		case c, ok := <-jobs:
			if !ok {
				return // channel closed, stop worker
			}
			results <- us.lookup(ctx, c)
		case <-ctx.Done():
			us.s.Debugf("Worker: Cancellation signal received, stopping.")
			return
		}
	}
}

// lookup queries the OSV tables for one component.
func (us OSVUseCase) lookup(ctx context.Context, c compHelper.Component) dtos.VulnerabilityComponentOutput {
	response := dtos.VulnerabilityComponentOutput{
		Purl:        c.Purl,
		Requirement: c.Requirement,
		Version:     c.Version,
		ComponentStatus: domain.ComponentStatus{
			Message:    "",
			StatusCode: domain.Success,
		},
	}
	// The stored purls carry no version, so strip one if the caller left it in.
	purl := utils.PurlRemoveFromVersionComponent(c.Purl)
	vulns, err := us.model.GetVulnsByPurl(ctx, purl, c.Version)
	if err != nil {
		// Reported as a lookup failure rather than as "nothing found", so a broken query
		// cannot be mistaken for a clean component.
		us.s.Errorf("Failed to get OSV vulnerabilities for %v: %v", c.Purl, err)
		response.ComponentStatus = domain.ComponentStatus{
			Message:    "Failed to query OSV data for: " + c.Purl,
			StatusCode: domain.NoInfo,
		}
		return response
	}
	response.Vulnerabilities = us.mapVulnerabilities(vulns)
	if len(response.Vulnerabilities) == 0 {
		response.ComponentStatus = domain.ComponentStatus{
			Message:    "No vulnerabilities found for: " + c.Purl,
			StatusCode: domain.NoInfo,
		}
	}
	return response
}

// mapVulnerabilities converts stored OSV vulnerabilities into the response DTO.
func (us OSVUseCase) mapVulnerabilities(vulns []models.OSVVulnerability) []dtos.VulnerabilitiesOutput {
	out := make([]dtos.VulnerabilitiesOutput, 0, len(vulns))
	for _, vuln := range vulns {
		// Prefer the first alias, which is where the CVE lands when OSV has one.
		cve := vuln.ID
		if len(vuln.Aliases) > 0 {
			cve = vuln.Aliases[0]
		}
		var cvss []dtos.CVSS
		for _, severity := range vuln.Severities {
			// Not every score is a CVSS vector - 54,565 rows are Ubuntu severities like
			// "medium". Those are skipped, exactly as they were when the API returned them.
			parsed, err := utils.GetCVSS(severity.Score)
			if err != nil {
				us.s.Warnf("Failed to get CVSS severity and score from %v (%v): %v",
					severity.Score, severity.Type, err)
				continue
			}
			cvss = append(cvss, dtos.CVSS{
				Cvss:         severity.Score,
				CvssSeverity: parsed.Severity,
				CvssScore:    parsed.Score,
			})
		}
		out = append(out, dtos.VulnerabilitiesOutput{
			ID:        vuln.ID,
			Cve:       cve,
			Summary:   vuln.Summary,
			Severity:  vuln.Severity,
			Published: vuln.Published,
			Modified:  vuln.Modified,
			Source:    osvSource,
			URL:       us.OSVInfoBaseURL + "/" + cve,
			Cvss:      cvss,
		})
	}
	return out
}

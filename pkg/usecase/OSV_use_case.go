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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"scanoss.com/vulnerabilities/pkg/config"

	"scanoss.com/vulnerabilities/pkg/dtos"
	"scanoss.com/vulnerabilities/pkg/utils"

	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
)

type OSVPackageRequest struct {
	Purl string `json:"purl,omitempty"`
	Name string `json:"name,omitempty"`
}

type OSVRequest struct {
	Version     string            `json:"version,omitempty"`
	Package     OSVPackageRequest `json:"package"`
	Requirement string            `json:"requirement,omitempty"`
}

type OSVUseCase struct {
	OSVAPIBaseURL  string
	OSVInfoBaseURL string
	client         *http.Client // Single shared
	MaxAPIWorkers  int
}

func NewOSVUseCase(config *config.ServerConfig) *OSVUseCase {
	return &OSVUseCase{
		OSVAPIBaseURL:  config.Source.OSV.APIBaseURL,
		OSVInfoBaseURL: config.Source.OSV.InfoBaseURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		MaxAPIWorkers: config.Source.OSV.APIWorkers,
	}
}

func (us OSVUseCase) getOSVRequestsFromDTO(dto []dtos.ComponentDTO) []OSVRequest {
	var osvRequests []OSVRequest
	for _, element := range dto {
		if element.Requirement != "" {
			osvRequest := OSVRequest{
				Package: OSVPackageRequest{
					Purl: element.Purl,
				},
				Version:     element.Version,
				Requirement: element.Requirement,
			}
			osvRequests = append(osvRequests, osvRequest)
		}
	}
	return osvRequests
}

func (us OSVUseCase) Execute(dto []dtos.ComponentDTO) dtos.VulnerabilityOutput {
	osvRequests := us.getOSVRequestsFromDTO(dto)
	return us.processRequests(osvRequests)
}

func (us OSVUseCase) processRequests(requests []OSVRequest) dtos.VulnerabilityOutput {
	jobs := make(chan OSVRequest, len(requests))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := make(chan dtos.VulnerabilityComponentOutput, len(requests))
	for i := 0; i < us.MaxAPIWorkers; i++ {
		go us.processRequest(ctx, jobs, results)
	}

	for _, r := range requests {
		jobs <- r
	}
	close(jobs)

	// Collect all results into a slice
	var response = dtos.VulnerabilityOutput{
		Components: []dtos.VulnerabilityComponentOutput{},
	}

	for i := 0; i < len(requests); i++ {
		result := <-results
		response.Components = append(response.Components, result)
	}

	return response
}

func (us OSVUseCase) processRequest(ctx context.Context, jobs chan OSVRequest, results chan dtos.VulnerabilityComponentOutput) {
	for {
		select {
		case j, ok := <-jobs:
			if !ok {
				return // Channel closed, stop worker
			}

			response := dtos.VulnerabilityComponentOutput{
				Purl:        j.Package.Purl,
				Requirement: j.Requirement,
				Version:     j.Version,
			}

			out, err := json.Marshal(struct {
				Version string            `json:"version,omitempty"`
				Package OSVPackageRequest `json:"package"`
			}{
				Version: j.Version,
				Package: j.Package,
			})
			if err != nil {
				zlog.S.Errorf("Failed to marshal request: %s", err)
				results <- response
				continue
			}

			req, err := http.NewRequest(http.MethodPost, us.OSVAPIBaseURL+"/query", bytes.NewBuffer(out))
			if err != nil {
				zlog.S.Errorf("Failed to create HTTP request: %s", err)
				results <- response
				continue
			}
			req.Header.Set("Content-Type", "application/json")

			// Use a shared HTTP client to avoid creating a new one every call
			resp, err := us.client.Do(req)
			if err != nil {
				zlog.S.Errorf("HTTP request failed: %s", err)
				results <- response
				continue
			}

			// Check for non-200 HTTP responses
			if resp.StatusCode != http.StatusOK {
				zlog.S.Errorf("Unexpected HTTP status: %d", resp.StatusCode)
				resp.Body.Close()
				results <- response
				continue
			}

			var OSVResponse dtos.OSVResponseDTO
			err = json.NewDecoder(resp.Body).Decode(&OSVResponse)
			resp.Body.Close() // Close AFTER reading

			if err != nil {
				zlog.S.Errorf("Failed to decode response: %s", err)
				results <- response
				continue
			}
			response.Vulnerabilities = us.mapOSVVulnerabilities(OSVResponse.Vulns)
			results <- response
		case <-ctx.Done():
			// Cancellation signal received: stop working and return immediately
			fmt.Println("Worker: Cancellation signal received, stopping.")
			return
		}
	}
}

// mapOSVVulnerabilities converts OSV vulnerabilities to the required DTO structure.
func (us OSVUseCase) mapOSVVulnerabilities(vulns []dtos.Entry) []dtos.VulnerabilitiesOutput {
	vulnerabilities := make([]dtos.VulnerabilitiesOutput, 0, len(vulns))
	for _, vul := range vulns {
		// Select CVE or use the ID as fallback
		cve := vul.ID
		if len(vul.Aliases) > 0 {
			cve = vul.Aliases[0]
		}

		// Determine severity
		severity := ""
		if vul.DatabaseSpecific.Severity != "" {
			severity = vul.DatabaseSpecific.Severity
		}

		cvss := []dtos.CVSS{}
		if vul.Severity != nil {
			for _, s := range vul.Severity {
				cvssResult, err := utils.GetCVSS(s.Score)
				if err != nil {
					zlog.S.Warnf("Failed to get CVSS severity and score from: %v, %v", s, err)
					continue
				}
				cvss = append(cvss, dtos.CVSS{
					Cvss:         s.Score,
					CvssSeverity: cvssResult.Severity,
					CvssScore:    cvssResult.Score,
				})
			}
		}

		// Map to VulnerabilitiesOutput DTO
		vulnerabilities = append(vulnerabilities, dtos.VulnerabilitiesOutput{
			ID:        vul.ID,
			Cve:       cve,
			Summary:   vul.Summary,
			Severity:  severity,
			Published: utils.OnlyDate(vul.Published),
			Modified:  utils.OnlyDate(vul.Modified),
			Source:    "OSV",
			URL:       us.OSVInfoBaseURL + "/" + cve,
			Cvss:      cvss,
		})
	}
	return vulnerabilities
}

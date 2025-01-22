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
	"io"
	_ "log"
	"net/http"
	"scanoss.com/vulnerabilities/pkg/dtos"
	"scanoss.com/vulnerabilities/pkg/utils"
	"strings"
	"sync"
	"time"

	zlog "scanoss.com/vulnerabilities/pkg/logger"
)

type OSVPackageRequest struct {
	Purl string `json:"purl,omitempty"`
	Name string `json:"name,omitempty"`
}

type OSVRequest struct {
	Version string            `json:"version,omitempty"`
	Package OSVPackageRequest `json:"package"`
}

type OSVUseCase struct {
	OSVAPIBaseURL  string
	OSVInfoBaseURL string
	maxWorkers     int
	semaphore      chan struct{} // Used to limit concurrent requests
	client         *http.Client  // Single shared
}

func NewOSVUseCase(OSVAPIBaseUrl string, OSVInfoBaseURL string) *OSVUseCase {
	return &OSVUseCase{
		OSVAPIBaseURL:  OSVAPIBaseUrl,
		OSVInfoBaseURL: OSVInfoBaseURL,
		semaphore:      make(chan struct{}, 4),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (us OSVUseCase) getOSVRequestsFromDTO(dto dtos.VulnerabilityRequestDTO) []OSVRequest {
	var osvRequests []OSVRequest
	for _, element := range dto.Purls {
		if element.Requirement != "" {
			osvRequest := OSVRequest{
				Package: OSVPackageRequest{
					Purl: element.Purl + "@" + element.Requirement,
				},
			}
			osvRequests = append(osvRequests, osvRequest)
		}
	}
	return osvRequests
}

func (us OSVUseCase) Execute(dto dtos.VulnerabilityRequestDTO) dtos.VulnerabilityOutput {
	osvRequests := us.getOSVRequestsFromDTO(dto)
	return us.processRequests(osvRequests)
}

func (us OSVUseCase) processRequests(requests []OSVRequest) dtos.VulnerabilityOutput {
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	results := make(chan dtos.VulnerabilityPurlOutput, len(requests))
	defer cancel()
	for _, request := range requests {
		wg.Add(1)
		go func(req OSVRequest) {
			defer wg.Done()
			// Try to acquire semaphore
			us.semaphore <- struct{}{}        // Will block if 4 requests are already running
			defer func() { <-us.semaphore }() // Release when done

			select {
			case <-ctx.Done():
				return
			default:
				r, _ := us.processRequest(req)
				results <- r
			}
		}(request)
	}
	wg.Wait()
	close(results)

	// Collect all results into a slice
	var response = dtos.VulnerabilityOutput{
		Purls: []dtos.VulnerabilityPurlOutput{},
	}
	for result := range results {
		response.Purls = append(response.Purls, result)
	}

	return response
}

func (us OSVUseCase) processRequest(osvRequest OSVRequest) (dtos.VulnerabilityPurlOutput, error) {
	out, err := json.Marshal(osvRequest)
	if err != nil {
		zlog.S.Errorf("Failed to marshal request: %s", err)
		return dtos.VulnerabilityPurlOutput{}, err
	}

	req, err := http.NewRequest("POST", us.OSVAPIBaseURL+"/query", bytes.NewBuffer(out))
	if err != nil {
		zlog.S.Errorf("Failed to create HTTP request: %s", err)
		return dtos.VulnerabilityPurlOutput{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	// Use a shared HTTP client to avoid creating a new one every call
	resp, err := us.client.Do(req)
	if err != nil {
		zlog.S.Errorf("HTTP request failed: %s", err)
		return dtos.VulnerabilityPurlOutput{}, err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			zlog.S.Errorf("Failed to close HTTP response body: %s", err)
		}
	}(resp.Body)

	// Check for non-200 HTTP responses
	if resp.StatusCode != http.StatusOK {
		zlog.S.Errorf("Unexpected HTTP status: %d", resp.StatusCode)
		return dtos.VulnerabilityPurlOutput{}, err
	}

	var OSVResponse dtos.OSVResponseDTO
	err = json.NewDecoder(resp.Body).Decode(&OSVResponse)
	if err != nil {
		// Handle error
		zlog.S.Errorf("Failed to decode response: %s", err)
		return dtos.VulnerabilityPurlOutput{}, err
	}

	response := dtos.VulnerabilityPurlOutput{
		Purl:            strings.Split(osvRequest.Package.Purl, "@")[0],
		Vulnerabilities: us.mapOSVVulnerabilities(OSVResponse.Vulns),
	}

	return response, nil
}

// mapOSVVulnerabilities converts OSV vulnerabilities to the required DTO structure
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

		// Map to VulnerabilitiesOutput DTO
		vulnerabilities = append(vulnerabilities, dtos.VulnerabilitiesOutput{
			Id:        vul.ID,
			Cve:       cve,
			Summary:   vul.Summary,
			Severity:  severity,
			Published: utils.OnlyDate(vul.Published),
			Modified:  utils.OnlyDate(vul.Modified),
			Source:    "OSV",
			Url:       us.OSVInfoBaseURL + "/" + cve,
		})
	}
	return vulnerabilities
}

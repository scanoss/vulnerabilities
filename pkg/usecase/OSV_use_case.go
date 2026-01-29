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
	"net/url"
	"time"

	"github.com/package-url/packageurl-go"
	"go.uber.org/zap"

	"scanoss.com/vulnerabilities/pkg/config"

	"scanoss.com/vulnerabilities/pkg/dtos"
	"scanoss.com/vulnerabilities/pkg/utils"

	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
)

type OSVPackageRequest struct {
	Purl      string `json:"purl,omitempty"`
	Name      string `json:"name,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

type OSVRequest struct {
	Version         string             `json:"version,omitempty"`
	Package         OSVPackageRequest  `json:"package"`
	Requirement     string             `json:"-"`
	OriginalPurl    string             `json:"-"`
	FallbackPackage *OSVPackageRequest `json:"-"`
}

type OSVUseCase struct {
	OSVAPIBaseURL  string
	OSVInfoBaseURL string
	client         *http.Client // Single shared
	MaxAPIWorkers  int
	s              *zap.SugaredLogger
}

func NewOSVUseCase(s *zap.SugaredLogger, config *config.ServerConfig) *OSVUseCase {
	return &OSVUseCase{
		OSVAPIBaseURL:  config.Source.OSV.APIBaseURL,
		OSVInfoBaseURL: config.Source.OSV.InfoBaseURL,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
		MaxAPIWorkers: config.Source.OSV.APIWorkers,
		s:             s,
	}
}

// getRepoURL converts a PURL string into a Git repository URL if the PURL refers to a known git host.
//
// It supports two resolution strategies:
//
//  1. repository_url qualifier: If the PURL contains a "repository_url" qualifier, its value is used directly.
//     This is the standard mechanism for hosts without a dedicated PURL type (e.g., pkg:/...?repository_url=https://gitlab.gnome.org/GNOME/gimp).
//
//  2. Direct type-based: For PURL types that have a spec-defined default repository URL, the host is resolved
//     from the type (e.g., pkg:github/owner/repo -> https://github.com/owner/repo).
//
// Supported PURL types with default URLs (defined in spec):
//   - github:    https://github.com    (see: https://github.com/package-url/purl-spec/blob/main/types-doc/github-definition.md)
//   - bitbucket: https://bitbucket.org (see: https://github.com/package-url/purl-spec/blob/main/types-doc/bitbucket-definition.md)
//
// Supported PURL types with default URLs (not yet in spec):
//   - gitlab: https://gitlab.com  (candidate: https://github.com/package-url/purl-spec/blob/main/docs/candidate-purl-types.md)
//   - gitee:  https://gitee.com   (not in spec or candidates)
//
// Not handled: git hosts without a dedicated PURL type and without a "repository_url" qualifier
// (e.g., gitlab.gnome.org, gitlab.freedesktop.org, gitlab.xiph.org, vcgit.hhi.fraunhofer.de,
// git.codelinaro.org, yoctoproject.org, trustedfirmware.org, sourceware.org, gitcode.com,
// eclipse.org, invent.kde.org). These hosts have no defined PURL type in the spec.
//
// Reference: https://github.com/package-url/purl-spec
//
// Returns a pointer to the repository URL string, or nil if the PURL is invalid or does not match any known git host.
func (us OSVUseCase) getRepoURL(purlString string) *string {
	// Parse PURL to check if it's a git-based package
	purl, err := packageurl.FromString(purlString)
	if err != nil {
		return nil
	}
	repoURL := purl.Qualifiers.Map()["repository_url"]
	if repoURL != "" {
		decoded, errUnescape := url.QueryUnescape(repoURL)
		if errUnescape != nil {
			return nil
		}
		return &decoded
	}

	// Default URLs by purl type
	gitHosts := map[string]string{
		"github":    "https://github.com",
		"gitlab":    "https://gitlab.com", // not defined in the purl spec. See: https://github.com/package-url/purl-spec/blob/main/docs/candidate-purl-types.md
		"bitbucket": "https://bitbucket.org",
		"gitee":     "https://gitee.com",
	}
	host, hostFound := gitHosts[purl.Type]
	namespace := purl.Namespace
	if hostFound {
		repoURL := fmt.Sprintf("%s/%s/%s", host, namespace, purl.Name)
		return &repoURL
	}
	return nil
}

// getOSVRequestsFromDTO converts a slice of ComponentDTOs into OSVRequest objects.
// For git-based packages (GitHub, GitLab, Bitbucket), it constructs a repository URL
// and sets the ecosystem to "GIT", with the original PURL as a fallback.
// For all other packages, the PURL is used directly.
func (us OSVUseCase) getOSVRequestsFromDTO(componentDTOs []dtos.ComponentDTO) []OSVRequest {
	var osvRequests []OSVRequest
	for _, c := range componentDTOs {
		osvRequest := OSVRequest{
			Version:      c.Version,
			Requirement:  c.Requirement,
			OriginalPurl: c.Purl,
		}
		// Parse PURL to check if it's a git-based package
		repoURL := us.getRepoURL(c.Purl)

		if repoURL != nil {
			osvRequest.Package = OSVPackageRequest{
				Name:      *repoURL,
				Ecosystem: "GIT",
			}
			fallback := OSVPackageRequest{
				Purl: c.Purl,
			}
			osvRequest.FallbackPackage = &fallback
		}
		if osvRequest.Package == (OSVPackageRequest{}) {
			// For other packages, use the PURL directly
			osvRequest.Package = OSVPackageRequest{
				Purl: c.Purl,
			}
		}
		osvRequests = append(osvRequests, osvRequest)
	}
	return osvRequests
}

func (us OSVUseCase) Execute(ctx context.Context, dto []dtos.ComponentDTO) dtos.VulnerabilityOutput {
	osvRequests := us.getOSVRequestsFromDTO(dto)
	return us.processRequests(ctx, osvRequests)
}

func (us OSVUseCase) processRequests(ctx context.Context, requests []OSVRequest) dtos.VulnerabilityOutput {
	numJobs := len(requests)
	jobs := make(chan OSVRequest, numJobs)
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	results := make(chan dtos.VulnerabilityComponentOutput, numJobs)
	workers := min(us.MaxAPIWorkers, numJobs)
	for i := 0; i < workers; i++ {
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
	for i := 0; i < numJobs; i++ {
		result := <-results
		response.Components = append(response.Components, result)
	}
	return response
}

// processRequest is a worker function that processes OSV vulnerability requests concurrently.
// It reads requests from the jobs channel, queries the OSV API for each request, and sends
// the results to the results channel. The worker terminates when the jobs channel is closed
// or when the context is cancelled.
func (us OSVUseCase) processRequest(ctx context.Context, jobs chan OSVRequest, results chan dtos.VulnerabilityComponentOutput) {
	for {
		select {
		case j, ok := <-jobs:
			if !ok {
				return // Channel closed, stop worker
			}
			response := dtos.VulnerabilityComponentOutput{
				Purl:        j.OriginalPurl,
				Requirement: j.Requirement,
				Version:     j.Version,
			}
			response.Vulnerabilities = us.queryOSV(ctx, j)

			// Fallback: if GIT ecosystem returned no results, retry with the PURL directly
			if len(response.Vulnerabilities) == 0 && j.FallbackPackage != nil {
				us.s.Debugf("No vulnerabilities found for GIT ecosystem, falling back to PURL query for: %s", j.OriginalPurl)
				fallbackReq := OSVRequest{
					Version:      j.Version,
					Package:      *j.FallbackPackage,
					OriginalPurl: j.OriginalPurl,
				}
				fallbackVulns := us.queryOSV(ctx, fallbackReq)
				if fallbackVulns != nil {
					response.Vulnerabilities = fallbackVulns
				}
			}
			results <- response
		case <-ctx.Done():
			// Cancellation signal received: stop working and return immediately
			us.s.Debugf("Worker: Cancellation signal received, stopping.")
			return
		}
	}
}

// queryOSV performs a single OSV API query and returns mapped vulnerabilities, or nil on error.
func (us OSVUseCase) queryOSV(ctx context.Context, r OSVRequest) []dtos.VulnerabilitiesOutput {
	out, err := json.Marshal(struct {
		Version string            `json:"version,omitempty"`
		Package OSVPackageRequest `json:"package"`
	}{
		Version: r.Version,
		Package: r.Package,
	})
	if err != nil {
		us.s.Errorf("Failed to marshal request: %s", err)
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, us.OSVAPIBaseURL+"/query", bytes.NewBuffer(out))
	if err != nil {
		us.s.Errorf("Failed to create HTTP request: %s", err)
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := us.client.Do(req)
	if err != nil {
		us.s.Errorf("HTTP request failed: %s", err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		us.s.Errorf("Unexpected HTTP status: %d", resp.StatusCode)
		return nil
	}
	var osvResponse dtos.OSVResponseDTO
	err = json.NewDecoder(resp.Body).Decode(&osvResponse)
	if err != nil {
		us.s.Errorf("Failed to decode response: %s", err)
		return nil
	}
	return us.mapOSVVulnerabilities(osvResponse.Vulns)
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

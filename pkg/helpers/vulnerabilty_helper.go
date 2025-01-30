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

package helpers

import (
	"scanoss.com/vulnerabilities/pkg/dtos"
)

// Create a helper function to convert vulnerability to output DTO.
func toVulnerabilityOutput(vul dtos.VulnerabilitiesOutput) dtos.VulnerabilitiesOutput {
	return dtos.VulnerabilitiesOutput{
		ID:        vul.ID,
		Cve:       vul.Cve,
		URL:       vul.URL,
		Summary:   vul.Summary,
		Severity:  vul.Severity,
		Published: vul.Published,
		Modified:  vul.Modified,
		Source:    vul.Source,
	}
}

func convertToVulnerabilityOutput(vulnerabilitiesMap map[string][]dtos.VulnerabilitiesOutput) dtos.VulnerabilityOutput {
	var output dtos.VulnerabilityOutput
	// Pre-allocate slice with capacity
	output.Purls = make([]dtos.VulnerabilityPurlOutput, 0, len(vulnerabilitiesMap))
	// Convert map entries to VulnerabilityPurlOutput structs
	for purl, vulnerabilities := range vulnerabilitiesMap {
		purlOutput := dtos.VulnerabilityPurlOutput{
			Purl:            purl,
			Vulnerabilities: vulnerabilities,
		}
		output.Purls = append(output.Purls, purlOutput)
	}
	return output
}

func processVulnerabilities(uniqueVulnerabilities map[string]bool,
	vulnerabilities map[string][]dtos.VulnerabilitiesOutput, input dtos.VulnerabilityOutput) {
	for _, osv := range input.Purls {
		if _, exists := vulnerabilities[osv.Purl]; exists {
			for _, vul := range osv.Vulnerabilities {
				if !uniqueVulnerabilities[osv.Purl+vul.Cve] {
					vulnerability := toVulnerabilityOutput(vul)
					uniqueVulnerabilities[osv.Purl+vul.Cve] = true
					vulnerabilities[osv.Purl] = append(vulnerabilities[osv.Purl], vulnerability)
				}
			}
			continue
		}
		vulnerabilities[osv.Purl] = osv.Vulnerabilities
	}
}

func MergeOSVAndLocalVulnerabilities(localVulnerabilities dtos.VulnerabilityOutput, osvVulnerabilities dtos.VulnerabilityOutput) dtos.VulnerabilityOutput {
	uniqueVulnerabilities := make(map[string]bool)
	vulnerabilities := map[string][]dtos.VulnerabilitiesOutput{}
	processVulnerabilities(uniqueVulnerabilities, vulnerabilities, osvVulnerabilities)
	processVulnerabilities(uniqueVulnerabilities, vulnerabilities, localVulnerabilities)
	return convertToVulnerabilityOutput(vulnerabilities)
}

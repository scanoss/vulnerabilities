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

func convertToVulnerabilityOutput(componentVulnerabilityMap map[string]dtos.VulnerabilityComponentOutput) dtos.VulnerabilityOutput {
	var output dtos.VulnerabilityOutput
	// Pre-allocate slice with capacity
	output.Components = make([]dtos.VulnerabilityComponentOutput, 0, len(componentVulnerabilityMap))
	// Convert map entries to VulnerabilityPurlOutput structs
	for _, vulnerabilityComponent := range componentVulnerabilityMap {
		purlOutput := dtos.VulnerabilityComponentOutput{
			Purl:            vulnerabilityComponent.Purl,
			Requirement:     vulnerabilityComponent.Requirement,
			Version:         vulnerabilityComponent.Version,
			Vulnerabilities: vulnerabilityComponent.Vulnerabilities,
		}
		output.Components = append(output.Components, purlOutput)
	}
	return output
}

func aggregateVulnerabilities(componentVulnerabilityMap map[string]dtos.VulnerabilityComponentOutput,
	vulnerabilities dtos.VulnerabilityOutput) {
	// Process local vulnerabilities
	for _, c := range vulnerabilities.Components {
		key := c.Purl + "@" + c.Version
		if component, ok := componentVulnerabilityMap[key]; ok {
			component.Vulnerabilities = append(component.Vulnerabilities, c.Vulnerabilities...)
			componentVulnerabilityMap[key] = component
		} else {
			componentVulnerabilityMap[key] = c
		}
	}
}

func removeDuplicatedVulnerabilities(vulnerabilityComponentMap map[string]dtos.VulnerabilityComponentOutput) {
	for _, vulnerabilityComponent := range vulnerabilityComponentMap {
		vulnerabilityMap := make(map[string]dtos.VulnerabilitiesOutput)
		for _, vulnerability := range vulnerabilityComponent.Vulnerabilities {
			key := vulnerability.Source + vulnerability.Cve
			vulnerabilityMap[key] = vulnerability
		}
		vulnerabilityComponent.Vulnerabilities = make([]dtos.VulnerabilitiesOutput, 0, len(vulnerabilityMap))
		for _, vulnerability := range vulnerabilityMap {
			vulnerabilityComponent.Vulnerabilities = append(vulnerabilityComponent.Vulnerabilities, vulnerability)
		}
	}
}

func MergeOSVAndLocalVulnerabilities(localVulnerabilities dtos.VulnerabilityOutput, osvVulnerabilities dtos.VulnerabilityOutput) dtos.VulnerabilityOutput {
	componentVulnerabilityMap := make(map[string]dtos.VulnerabilityComponentOutput)
	aggregateVulnerabilities(componentVulnerabilityMap, localVulnerabilities)
	aggregateVulnerabilities(componentVulnerabilityMap, osvVulnerabilities)
	removeDuplicatedVulnerabilities(componentVulnerabilityMap)
	return convertToVulnerabilityOutput(componentVulnerabilityMap)
}

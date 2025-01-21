package helpers

import (
	"scanoss.com/vulnerabilities/pkg/dtos"
)

// Create a helper function to convert vulnerability to output DTO
func toVulnerabilityOutput(vul dtos.VulnerabilitiesOutput) dtos.VulnerabilitiesOutput {
	return dtos.VulnerabilitiesOutput{
		Id:        vul.Id,
		Cve:       vul.Cve,
		Url:       vul.Url,
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
				if !uniqueVulnerabilities[vul.Cve] {
					vulnerability := toVulnerabilityOutput(vul)
					uniqueVulnerabilities[vul.Cve] = true
					vulnerabilities[osv.Purl] = append(vulnerabilities[osv.Purl], vulnerability)
				}
			}
			continue
		}
		vulnerabilities[osv.Purl] = osv.Vulnerabilities
	}
}

func MergeOSVAndLocalVulnerabilities(localVulnerabilities dtos.VulnerabilityOutput, OSVVulnerabilities dtos.VulnerabilityOutput) dtos.VulnerabilityOutput {
	uniqueVulnerabilities := make(map[string]bool)
	vulnerabilities := map[string][]dtos.VulnerabilitiesOutput{}
	processVulnerabilities(uniqueVulnerabilities, vulnerabilities, OSVVulnerabilities)
	processVulnerabilities(uniqueVulnerabilities, vulnerabilities, localVulnerabilities)
	return convertToVulnerabilityOutput(vulnerabilities)
}

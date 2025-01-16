package usecase

import (
	"bytes"
	"context"
	"encoding/json"
	_ "io"
	"log"
	"net/http"
	"scanoss.com/vulnerabilities/pkg/dtos"
	u "scanoss.com/vulnerabilities/pkg/utils"
	"strings"
	"sync"

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
	OSVBaseURL string
	maxWorkers int
	semaphore  chan struct{} // Used to limit concurrent requests

}

func NewOSVUseCase(OSVBaseUrl string) *OSVUseCase {
	return &OSVUseCase{
		OSVBaseURL: OSVBaseUrl,
		maxWorkers: 4,
		semaphore:  make(chan struct{}, 4),
	}
}

func (us OSVUseCase) Execute(dto dtos.VulnerabilityRequestDTO) dtos.VulnerabilityOutput {
	zlog.S.Infof("OSV Base URL: %s", us.OSVBaseURL)

	osvRequests := []OSVRequest{}
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
	zlog.S.Infof("OSV Requests: %+v", osvRequests)
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
				r := us.processRequest(req)
				results <- r
			}
		}(request)
	}
	wg.Wait()

	// Start a goroutine to close channel after all work is done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect all results into a slice
	var response = dtos.VulnerabilityOutput{
		Purls: []dtos.VulnerabilityPurlOutput{},
	}
	for result := range results {
		response.Purls = append(response.Purls, result)
	}

	return response
}

func (us OSVUseCase) processRequest(osvRequest OSVRequest) (osvResponseDTO dtos.VulnerabilityPurlOutput) {
	out, err := json.Marshal(osvRequest)
	if err != nil {
		log.Fatal(err)
	}
	req, err := http.NewRequest("POST", us.OSVBaseURL+"/query", bytes.NewBuffer(out))
	// Set the content type header
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Request failed: %s", err)
	}

	defer resp.Body.Close()
	var OSVResponse dtos.OSVResponseDTO
	err = json.NewDecoder(resp.Body).Decode(&OSVResponse)
	if err != nil {
		// Handle error
		zlog.S.Errorf("Failed to decode response: %s", err)
	}

	vulnerabilities := []dtos.VulnerabilitiesOutput{}
	for _, vul := range OSVResponse.Vulns {
		cve := vul.ID
		if len(vul.Aliases) > 0 {
			cve = vul.Aliases[0]
		}

		severity := ""
		if vul.DatabaseSpecific.Severity != "" {
			cve = vul.DatabaseSpecific.Severity
		}

		osvVulnerability := dtos.VulnerabilitiesOutput{
			Id:        vul.ID,
			Cve:       cve,
			Summary:   vul.Summary,
			Severity:  severity,
			Published: u.OnlyDate(vul.Published),
			Modified:  u.OnlyDate(vul.Modified),
			Source:    "OSV",
		}
		vulnerabilities = append(vulnerabilities, osvVulnerability)
	}

	response := dtos.VulnerabilityPurlOutput{
		Purl:            strings.Split(osvRequest.Package.Purl, "@")[0],
		Vulnerabilities: vulnerabilities,
	}

	return response
}

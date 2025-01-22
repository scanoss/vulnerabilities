package usecase

import (
	"scanoss.com/vulnerabilities/pkg/dtos"
	"testing"
	"time"
)

func parseTime(t string) time.Time {
	timeValue, err := time.Parse(time.DateOnly, "2023-04-28")
	if err != nil {
		panic(err)
	}
	return timeValue
}

func TestOSVUseCase(t *testing.T) {

	testCases := []struct {
		name  string
		input dtos.VulnerabilityRequestDTO
	}{
		{
			name: "OSV Use Case Test",
			input: dtos.VulnerabilityRequestDTO{
				Purls: []dtos.VulnPurlInput{
					{
						Purl:        "pkg:pypi/mlflow",
						Requirement: "2.3.0",
					},
					{
						Purl: "pkg:golang/github.com/navidrome/navidrome",
					},
				},
			},
		},
	}
	OSVBaseURL := "https://api.osv.dev/v1"
	OSVInfoBaseURL := "https://test.osv.dev/vulnerability"
	OSVUseCase := NewOSVUseCase(OSVBaseURL, OSVInfoBaseURL)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := OSVUseCase.Execute(tc.input)
			if len(r.Purls) <= 0 {
				t.Errorf("Expected Purls to have elements, got empty slice")
			}
		})
	}

}

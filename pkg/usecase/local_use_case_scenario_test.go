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

// End-to-end coverage for the local use case, asserting on the vulnerabilities it
// returns rather than only on the absence of an error.
//
// vulnerabilityWorker swallows query failures: it logs the error and emits the
// component with no vulnerabilities attached (local_use_case.go). That means a
// completely broken SQL query still produces a successful, empty response, and the
// pre-existing TestGetVulnerabilityUseCase cannot tell the difference because it makes
// no assertions on the result.

package usecase

import (
	"context"
	"testing"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/jmoiron/sqlx"
	"github.com/scanoss/go-component-helper/componenthelper"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	_ "modernc.org/sqlite"
	"scanoss.com/vulnerabilities/pkg/config"
	"scanoss.com/vulnerabilities/pkg/models"
)

const scenarioPurl = "pkg:github/scanoss/testcomp"

func newScenarioUseCase(t *testing.T) (*LocalVulnerabilityUseCase, context.Context) {
	t.Helper()
	if err := zlog.NewSugaredDevLogger(); err != nil {
		t.Fatalf("failed to open a sugared logger: %v", err)
	}
	t.Cleanup(zlog.SyncZap)
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
	s := ctxzap.Extract(ctx).Sugar()
	db, err := sqlx.Connect("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open a stub database connection: %v", err)
	}
	t.Cleanup(func() { models.CloseDB(db) })
	if err = models.LoadTestSQLData(db, ctx, nil); err != nil {
		t.Fatalf("failed to load test data: %v", err)
	}
	serverConfig, err := config.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}
	return NewLocalVulnerabilitiesUseCase(ctx, s, serverConfig, db), ctx
}

// TestGetVulnerabilitiesReturnsResults checks vulnerabilities actually reach the
// use case output, for a component with and without a version.
func TestGetVulnerabilitiesReturnsResults(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		wantCves []string
	}{
		{
			name:     "no version returns every CVE for the component",
			version:  "",
			wantCves: []string{"CVE-TEST-0001", "CVE-TEST-0002", "CVE-TEST-0003", "CVE-TEST-0004"},
		},
		{
			name:     "version 1.0.0 returns only the CVEs whose range covers it",
			version:  "1.0.0",
			wantCves: []string{"CVE-TEST-0001", "CVE-TEST-0003"},
		},
		{
			name:     "a v prefix on the version is trimmed before querying",
			version:  "v1.0.0",
			wantCves: []string{"CVE-TEST-0001", "CVE-TEST-0003"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vulnUc, ctx := newScenarioUseCase(t)
			components := []componenthelper.Component{
				{Purl: scenarioPurl, Version: tt.version},
			}
			out, err := vulnUc.GetVulnerabilities(ctx, components)
			if err != nil {
				t.Fatalf("GetVulnerabilities() unexpected error: %v", err)
			}
			if len(out.Components) != 1 {
				t.Fatalf("GetVulnerabilities() returned %d components, want 1", len(out.Components))
			}
			got := make(map[string]bool)
			for _, v := range out.Components[0].Vulnerabilities {
				got[v.Cve] = true
			}
			if len(got) != len(tt.wantCves) {
				t.Errorf("GetVulnerabilities() returned %d CVEs (%v), want %d (%v)",
					len(got), got, len(tt.wantCves), tt.wantCves)
			}
			for _, want := range tt.wantCves {
				if !got[want] {
					t.Errorf("GetVulnerabilities() missing expected CVE %v, got %v", want, got)
				}
			}
		})
	}
}

// TestGetVulnerabilitiesPopulatesFields guards the fields carried through to the
// output, including the dates that come out of TEXT columns.
func TestGetVulnerabilitiesPopulatesFields(t *testing.T) {
	vulnUc, ctx := newScenarioUseCase(t)
	out, err := vulnUc.GetVulnerabilities(ctx, []componenthelper.Component{
		{Purl: scenarioPurl, Version: "1.0.0"},
	})
	if err != nil {
		t.Fatalf("GetVulnerabilities() unexpected error: %v", err)
	}
	if len(out.Components) != 1 {
		t.Fatalf("GetVulnerabilities() returned %d components, want 1", len(out.Components))
	}
	var found bool
	for _, v := range out.Components[0].Vulnerabilities {
		if v.Cve != "CVE-TEST-0003" {
			continue
		}
		found = true
		if v.Severity != "CRITICAL" {
			t.Errorf("Severity = %q, want %q", v.Severity, "CRITICAL")
		}
		if v.Source != "NVD" {
			t.Errorf("Source = %q, want %q", v.Source, "NVD")
		}
		wantURL := "https://nvd.nist.gov/vuln/detail/CVE-TEST-0003"
		if v.URL != wantURL {
			t.Errorf("URL = %q, want %q", v.URL, wantURL)
		}
		if v.Summary != "affects exactly 1.0.0" {
			t.Errorf("Summary = %q, want %q", v.Summary, "affects exactly 1.0.0")
		}
	}
	if !found {
		t.Errorf("CVE-TEST-0003 missing from the use case output")
	}
}

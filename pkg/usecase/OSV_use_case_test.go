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

// These tests used to call api.osv.dev over the network, so they needed internet and
// exercised whatever OSV happened to return that day. They now run against the osv
// tables in SQLite, seeded from pkg/models/tests/osv_scenario.sql.
//
// TestGetRepoURL is gone along with getRepoURL: the table stores pkg:github purls
// directly, so nothing translates a purl into a repository URL any more.

package usecase

import (
	"context"
	"sort"
	"testing"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/jmoiron/sqlx"
	compHelper "github.com/scanoss/go-component-helper/componenthelper"
	"github.com/scanoss/go-grpc-helper/pkg/grpc/domain"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	_ "modernc.org/sqlite"
	"scanoss.com/vulnerabilities/pkg/config"
	"scanoss.com/vulnerabilities/pkg/models"
)

const osvScenarioPurl = "pkg:npm/testosv"

func newOSVUseCase(t *testing.T) (*OSVUseCase, context.Context) {
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
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { models.CloseDB(db) })
	if err = models.LoadTestSQLData(db, ctx, nil); err != nil {
		t.Fatalf("failed to load test data: %v", err)
	}
	serverConfig, err := config.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}
	return NewOSVUseCase(s, serverConfig, db), ctx
}

func osvCveNames(vulns []struct {
	Cve string
}) []string {
	out := make([]string, 0, len(vulns))
	for _, v := range vulns {
		out = append(out, v.Cve)
	}
	sort.Strings(out)
	return out
}

// TestOSVUseCaseVersionMatching walks the version bounds the scenario encodes.
func TestOSVUseCaseVersionMatching(t *testing.T) {
	us, ctx := newOSVUseCase(t)
	tests := []struct {
		version string
		wantIDs []string
		reason  string
	}{
		{
			version: "1.2.0",
			wantIDs: []string{"OSV-TEST-0001", "OSV-TEST-0003", "OSV-TEST-0005"},
			reason:  "inside 1.0.0-2.0.0, inside 0-1.5.0, and inside the open 0-9.9.9",
		},
		{
			version: "2.0.0",
			wantIDs: []string{"OSV-TEST-0005"},
			reason:  "fixed_version 2.0.0 is exclusive, and 2.0.0 is past 1.5.0",
		},
		{
			version: "3.0.1",
			wantIDs: []string{"OSV-TEST-0002", "OSV-TEST-0005"},
			reason:  "3.0.1 is in the explicit affected_versions list",
		},
		{
			version: "3.0.2",
			wantIDs: []string{"OSV-TEST-0005"},
			reason:  "a version list that does not contain it is a miss, not an open range",
		},
		{
			version: "4.1.0",
			wantIDs: []string{"OSV-TEST-0003", "OSV-TEST-0005"},
			reason:  "matches the second range of 0003; 0004 only starts at 4.5.0",
		},
		{
			version: "4.6.0",
			wantIDs: []string{"OSV-TEST-0004", "OSV-TEST-0005"},
			reason:  "inside 4.5.0 to 5.0.0, and past the 4.2.0 fix of 0003's second range",
		},
		{
			version: "5.0.0",
			wantIDs: []string{"OSV-TEST-0004", "OSV-TEST-0005"},
			reason:  "last_affected 5.0.0 is inclusive",
		},
		{
			version: "5.0.1",
			wantIDs: []string{"OSV-TEST-0005"},
			reason:  "past last_affected",
		},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			out := us.Execute(ctx, []compHelper.Component{
				{Purl: osvScenarioPurl, Version: tt.version, Status: domain.ComponentStatus{StatusCode: domain.Success}},
			})
			if len(out.Components) != 1 {
				t.Fatalf("returned %d components, want 1", len(out.Components))
			}
			var got []string
			for _, v := range out.Components[0].Vulnerabilities {
				got = append(got, v.ID)
			}
			sort.Strings(got)
			if len(got) != len(tt.wantIDs) {
				t.Errorf("version %v returned %v, want %v (%s)", tt.version, got, tt.wantIDs, tt.reason)
				return
			}
			for i := range tt.wantIDs {
				if got[i] != tt.wantIDs[i] {
					t.Errorf("version %v returned %v, want %v (%s)", tt.version, got, tt.wantIDs, tt.reason)
					return
				}
			}
		})
	}
}

// TestOSVUseCaseOutputFields checks every field of the response, which is what has to
// stay identical now that the data comes from the database.
func TestOSVUseCaseOutputFields(t *testing.T) {
	us, ctx := newOSVUseCase(t)
	out := us.Execute(ctx, []compHelper.Component{
		{Purl: osvScenarioPurl, Version: "1.2.0", Requirement: "1.2.0"},
	})
	if len(out.Components) != 1 {
		t.Fatalf("returned %d components, want 1", len(out.Components))
	}
	component := out.Components[0]
	if component.Purl != osvScenarioPurl {
		t.Errorf("Purl = %q, want %q", component.Purl, osvScenarioPurl)
	}
	if component.ComponentStatus.StatusCode != domain.Success {
		t.Errorf("StatusCode = %v, want Success", component.ComponentStatus.StatusCode)
	}
	var found bool
	for _, v := range component.Vulnerabilities {
		if v.ID != "OSV-TEST-0001" {
			continue
		}
		found = true
		if v.Cve != "CVE-2026-0001" {
			t.Errorf("Cve = %q, want the first alias %q", v.Cve, "CVE-2026-0001")
		}
		if v.Severity != "HIGH" {
			t.Errorf("Severity = %q, want %q", v.Severity, "HIGH")
		}
		if v.Summary != "affects 1.x only" {
			t.Errorf("Summary = %q, want %q", v.Summary, "affects 1.x only")
		}
		if v.Source != "OSV" {
			t.Errorf("Source = %q, want %q", v.Source, "OSV")
		}
		if want := us.OSVInfoBaseURL + "/CVE-2026-0001"; v.URL != want {
			t.Errorf("URL = %q, want %q", v.URL, want)
		}
		// two vectors, which is why they live in their own table
		if len(v.Cvss) != 2 {
			t.Errorf("Cvss has %d entries, want 2: %+v", len(v.Cvss), v.Cvss)
		}
		for _, c := range v.Cvss {
			if c.CvssScore == 0 {
				t.Errorf("vector %q parsed to a zero score", c.Cvss)
			}
			if c.CvssSeverity == "" {
				t.Errorf("vector %q parsed to an empty severity", c.Cvss)
			}
		}
	}
	if !found {
		t.Errorf("OSV-TEST-0001 missing from the response")
	}
}

// TestOSVUseCaseFallsBackToIDWhenNoAlias covers the cve field when OSV has no alias.
func TestOSVUseCaseFallsBackToIDWhenNoAlias(t *testing.T) {
	us, ctx := newOSVUseCase(t)
	out := us.Execute(ctx, []compHelper.Component{{Purl: osvScenarioPurl, Version: "5.0.0"}})
	if len(out.Components) != 1 {
		t.Fatalf("returned %d components, want 1", len(out.Components))
	}
	var found bool
	for _, v := range out.Components[0].Vulnerabilities {
		if v.ID != "OSV-TEST-0004" {
			continue
		}
		found = true
		if v.Cve != "OSV-TEST-0004" {
			t.Errorf("Cve = %q, want the id itself when there is no alias", v.Cve)
		}
		// its only score is an Ubuntu severity, not a CVSS vector, so it is skipped
		if len(v.Cvss) != 0 {
			t.Errorf("Cvss = %+v, want empty: a non-CVSS score must be skipped", v.Cvss)
		}
	}
	if !found {
		t.Errorf("OSV-TEST-0004 missing from the response")
	}
}

// TestOSVUseCaseUsesNewestRow pins which row wins when rows of one vulnerability
// disagree, as 137,302 production pairs do.
func TestOSVUseCaseUsesNewestRow(t *testing.T) {
	us, ctx := newOSVUseCase(t)
	out := us.Execute(ctx, []compHelper.Component{{Purl: osvScenarioPurl, Version: "1.0.0"}})
	if len(out.Components) != 1 {
		t.Fatalf("returned %d components, want 1", len(out.Components))
	}
	var found bool
	for _, v := range out.Components[0].Vulnerabilities {
		if v.ID != "OSV-TEST-0005" {
			continue
		}
		found = true
		if v.Summary != "current summary" {
			t.Errorf("Summary = %q, want the newest row's %q", v.Summary, "current summary")
		}
		if v.Cve != "CVE-CURRENT" {
			t.Errorf("Cve = %q, want %q", v.Cve, "CVE-CURRENT")
		}
		if v.Severity != "HIGH" {
			t.Errorf("Severity = %q, want %q", v.Severity, "HIGH")
		}
	}
	if !found {
		t.Errorf("OSV-TEST-0005 missing from the response")
	}
}

// TestOSVUseCaseIgnoresOtherComponents guards against leaking another purl's data.
func TestOSVUseCaseIgnoresOtherComponents(t *testing.T) {
	us, ctx := newOSVUseCase(t)
	out := us.Execute(ctx, []compHelper.Component{{Purl: osvScenarioPurl, Version: "1.0.0"}})
	for _, v := range out.Components[0].Vulnerabilities {
		if v.ID == "OSV-TEST-9999" {
			t.Errorf("response leaked a vulnerability belonging to another component")
		}
	}
}

// TestOSVUseCaseNoVulnerabilities checks the status when a component is clean.
func TestOSVUseCaseNoVulnerabilities(t *testing.T) {
	us, ctx := newOSVUseCase(t)
	out := us.Execute(ctx, []compHelper.Component{{Purl: "pkg:npm/nothing-here", Version: "1.0.0"}})
	if len(out.Components) != 1 {
		t.Fatalf("returned %d components, want 1", len(out.Components))
	}
	if len(out.Components[0].Vulnerabilities) != 0 {
		t.Errorf("returned %d vulnerabilities, want 0", len(out.Components[0].Vulnerabilities))
	}
	if out.Components[0].ComponentStatus.StatusCode != domain.NoInfo {
		t.Errorf("StatusCode = %v, want NoInfo", out.Components[0].ComponentStatus.StatusCode)
	}
}

// TestOSVUseCaseHandlesSeveralComponents exercises the worker pool.
func TestOSVUseCaseHandlesSeveralComponents(t *testing.T) {
	us, ctx := newOSVUseCase(t)
	out := us.Execute(ctx, []compHelper.Component{
		{Purl: osvScenarioPurl, Version: "1.2.0"},
		{Purl: "pkg:npm/unrelated", Version: "1.0.0"},
		{Purl: "pkg:npm/nothing-here", Version: "1.0.0"},
	})
	if len(out.Components) != 3 {
		t.Errorf("returned %d components, want 3", len(out.Components))
	}
}

// TestOSVUseCaseEmptyInput checks the empty case returns an empty response, not a panic.
func TestOSVUseCaseEmptyInput(t *testing.T) {
	us, ctx := newOSVUseCase(t)
	out := us.Execute(ctx, nil)
	if len(out.Components) != 0 {
		t.Errorf("returned %d components, want 0", len(out.Components))
	}
}

// TestOSVUseCaseStripsEmbeddedVersion checks a purl carrying its version still matches
// the stored purls, which never carry one.
func TestOSVUseCaseStripsEmbeddedVersion(t *testing.T) {
	us, ctx := newOSVUseCase(t)
	out := us.Execute(ctx, []compHelper.Component{
		{Purl: osvScenarioPurl + "@1.2.0", Version: "1.2.0"},
	})
	if len(out.Components) != 1 {
		t.Fatalf("returned %d components, want 1", len(out.Components))
	}
	if len(out.Components[0].Vulnerabilities) == 0 {
		t.Errorf("a purl with an embedded version returned nothing; it must be stripped before the lookup")
	}
}

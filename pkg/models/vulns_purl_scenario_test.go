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

// Tests that exercise the vulnerability queries against real data, on the production
// schema. The pre-existing tests in vulns_purl_test.go only cover the
// error paths (empty purl, closed connection), which is why a query referencing
// columns that do not exist could pass CI.

package models

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	_ "modernc.org/sqlite"
	"scanoss.com/vulnerabilities/pkg/utils"
)

const scenarioPurl = "pkg:github/scanoss/testcomp"

// newScenarioDB returns a DB loaded with the production schema and all test fixtures.
func newScenarioDB(t *testing.T) (*sqlx.DB, context.Context) {
	t.Helper()
	if err := zlog.NewSugaredDevLogger(); err != nil {
		t.Fatalf("failed to open a sugared logger: %v", err)
	}
	t.Cleanup(zlog.SyncZap)
	ctx := context.Background()
	db, err := sqlx.Connect("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open a stub database connection: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { CloseDB(db) })
	if err = LoadTestSQLData(db, ctx, nil); err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}
	return db, ctx
}

func timeOf(d utils.OnlyDate) time.Time {
	return time.Time(d)
}

func cveNames(vulns []VulnsForPurl) []string {
	out := make([]string, 0, len(vulns))
	for _, v := range vulns {
		out = append(out, v.Cve)
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestGetVulnsByPurlNameWithData checks every CVE reachable from a purl is returned,
// and that criteria belonging to other components are not.
func TestGetVulnsByPurlNameWithData(t *testing.T) {
	db, ctx := newScenarioDB(t)
	model := NewVulnsForPurlModel(db)

	vulns, err := model.GetVulnsByPurlName(ctx, scenarioPurl)
	if err != nil {
		t.Fatalf("GetVulnsByPurlName() unexpected error: %v", err)
	}
	want := []string{"CVE-TEST-0001", "CVE-TEST-0002", "CVE-TEST-0003", "CVE-TEST-0004"}
	if got := cveNames(vulns); !equalStrings(got, want) {
		t.Errorf("GetVulnsByPurlName() = %v, want %v", got, want)
	}
	for _, v := range vulns {
		if v.Cve == "CVE-TEST-9999" {
			t.Errorf("GetVulnsByPurlName() returned a CVE from an unrelated component")
		}
	}
}

// TestGetVulnsByPurlNameFieldsPopulated guards the scan of every selected column.
// cves.published and cves.modified are TEXT in the schema, so this is what
// catches utils.OnlyDate not implementing sql.Scanner.
func TestGetVulnsByPurlNameFieldsPopulated(t *testing.T) {
	db, ctx := newScenarioDB(t)
	model := NewVulnsForPurlModel(db)

	vulns, err := model.GetVulnsByPurlName(ctx, scenarioPurl)
	if err != nil {
		t.Fatalf("GetVulnsByPurlName() unexpected error: %v", err)
	}
	var found bool
	for _, v := range vulns {
		if v.Cve != "CVE-TEST-0003" {
			continue
		}
		found = true
		if v.Severity != "CRITICAL" {
			t.Errorf("Severity = %q, want %q", v.Severity, "CRITICAL")
		}
		if v.Summary != "affects exactly 1.0.0" {
			t.Errorf("Summary = %q, want %q", v.Summary, "affects exactly 1.0.0")
		}
		if got := utils.ParseTime("2019-03-25"); !got.Equal(timeOf(v.Published)) {
			t.Errorf("Published = %v, want %v", timeOf(v.Published), got)
		}
		if got := utils.ParseTime("2019-08-10"); !got.Equal(timeOf(v.Modified)) {
			t.Errorf("Modified = %v, want %v", timeOf(v.Modified), got)
		}
	}
	if !found {
		t.Errorf("CVE-TEST-0003 not returned by GetVulnsByPurlName()")
	}
}

// TestGetVulnsByPurlVersionWithData checks the version-bound filtering at its edges:
// inclusive and exclusive, upper and lower.
func TestGetVulnsByPurlVersionWithData(t *testing.T) {
	db, ctx := newScenarioDB(t)
	model := NewVulnsForPurlModel(db)

	tests := []struct {
		version string
		want    []string
		reason  string
	}{
		{
			version: "1.0.0",
			want:    []string{"CVE-TEST-0001", "CVE-TEST-0003"},
			reason:  "end_including 2.0.0 and the exact 1.0.0 match; start_excluding 1.0.0 must not",
		},
		{
			version: "2.0.0",
			want:    []string{"CVE-TEST-0001", "CVE-TEST-0004"},
			reason:  "end_including 2.0.0 is inclusive, and 2.0.0 sits strictly between 1.0.0 and 3.0.0",
		},
		{
			version: "3.0.0",
			want:    []string{"CVE-TEST-0002"},
			reason:  "start_including 3.0.0 matches; end_excluding 3.0.0 must not",
		},
		{
			version: "9.9.9",
			want:    []string{"CVE-TEST-0002"},
			reason:  "only the open-ended start_including 3.0.0 range applies",
		},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			vulns, err := model.GetVulnsByPurlVersion(ctx, scenarioPurl, tt.version)
			if err != nil {
				t.Fatalf("GetVulnsByPurlVersion(%q) unexpected error: %v", tt.version, err)
			}
			if got := cveNames(vulns); !equalStrings(got, tt.want) {
				t.Errorf("GetVulnsByPurlVersion(%q) = %v, want %v (%s)",
					tt.version, got, tt.want, tt.reason)
			}
		})
	}
}

// TestGetVulnsByPurlDispatch checks GetVulnsByPurl routes to the name or the version
// variant according to the version argument.
func TestGetVulnsByPurlDispatch(t *testing.T) {
	db, ctx := newScenarioDB(t)
	model := NewVulnsForPurlModel(db)

	withVersion, err := model.GetVulnsByPurl(ctx, scenarioPurl, "1.0.0")
	if err != nil {
		t.Fatalf("GetVulnsByPurl() with version, unexpected error: %v", err)
	}
	want := []string{"CVE-TEST-0001", "CVE-TEST-0003"}
	if got := cveNames(withVersion); !equalStrings(got, want) {
		t.Errorf("GetVulnsByPurl() with version = %v, want %v", got, want)
	}

	noVersion, err := model.GetVulnsByPurl(ctx, scenarioPurl, "")
	if err != nil {
		t.Fatalf("GetVulnsByPurl() without version, unexpected error: %v", err)
	}
	if len(noVersion) <= len(withVersion) {
		t.Errorf("GetVulnsByPurl() without version returned %d CVEs, expected more than the %d for a single version",
			len(noVersion), len(withVersion))
	}
}

// TestGetVulnsByPurlIgnoresEmbeddedVersion pins current behaviour: a version inside the
// purl string is stripped, not used to filter. Callers pass the version separately, as
// the local use case does.
func TestGetVulnsByPurlIgnoresEmbeddedVersion(t *testing.T) {
	db, ctx := newScenarioDB(t)
	model := NewVulnsForPurlModel(db)

	got, err := model.GetVulnsByPurl(ctx, scenarioPurl+"@1.0.0", "")
	if err != nil {
		t.Fatalf("GetVulnsByPurl() unexpected error: %v", err)
	}
	want := []string{"CVE-TEST-0001", "CVE-TEST-0002", "CVE-TEST-0003", "CVE-TEST-0004"}
	if names := cveNames(got); !equalStrings(names, want) {
		t.Errorf("GetVulnsByPurl(%q, \"\") = %v, want every CVE for the component %v",
			scenarioPurl+"@1.0.0", names, want)
	}
}

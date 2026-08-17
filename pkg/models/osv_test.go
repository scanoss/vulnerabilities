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

package models

import (
	"testing"
	"time"

	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"

	"scanoss.com/vulnerabilities/pkg/utils"
)

func onlyDate(value string) utils.OnlyDate {
	return utils.OnlyDate(utils.ParseTime(value))
}

func TestOSVRowAffects(t *testing.T) {
	tests := []struct {
		name    string
		row     osvRow
		version string
		want    bool
		why     string
	}{
		{
			name:    "explicit version list, present",
			row:     osvRow{AffectedVersions: "{5.1.11,5.1.12,5.1.13}"},
			version: "5.1.12", want: true,
			why: "pypi and npm rows mostly use an explicit list",
		},
		{
			name:    "explicit version list, absent",
			row:     osvRow{AffectedVersions: "{5.1.11,5.1.12}"},
			version: "5.1.99", want: false,
			why: "a list that does not contain the version is a miss, not an open range",
		},
		{
			name:    "introduced 0 means from the beginning",
			row:     osvRow{IntroducedVersion: "0", FixedVersion: "3.39.9"},
			version: "1.0.0", want: true,
			why: "0 is how OSV expresses an unbounded lower end",
		},
		{
			name:    "fixed version is exclusive",
			row:     osvRow{IntroducedVersion: "0", FixedVersion: "3.39.9"},
			version: "3.39.9", want: false,
			why: "the fix landed in that version, so it is not affected",
		},
		{
			name:    "just below the fix",
			row:     osvRow{IntroducedVersion: "0", FixedVersion: "3.39.9"},
			version: "3.39.8", want: true,
		},
		{
			name:    "below the introduced bound",
			row:     osvRow{IntroducedVersion: "1.2.0", FixedVersion: "1.5.15"},
			version: "1.1.0", want: false,
		},
		{
			name:    "inside a closed range",
			row:     osvRow{IntroducedVersion: "1.2.0", FixedVersion: "1.5.15"},
			version: "1.3.0", want: true,
		},
		{
			name:    "at the introduced bound, which is inclusive",
			row:     osvRow{IntroducedVersion: "1.2.0", FixedVersion: "1.5.15"},
			version: "1.2.0", want: true,
		},
		{
			name:    "last_affected is inclusive",
			row:     osvRow{IntroducedVersion: "1.0.0", LastAffected: "2.0.0"},
			version: "2.0.0", want: true,
		},
		{
			name:    "beyond last_affected",
			row:     osvRow{IntroducedVersion: "1.0.0", LastAffected: "2.0.0"},
			version: "2.0.1", want: false,
		},
		{
			name:    "open ended range with only introduced",
			row:     osvRow{IntroducedVersion: "2.0.0"},
			version: "99.0.0", want: true,
		},
		{
			name:    "no bounds and no list affects everything",
			row:     osvRow{},
			version: "1.0.0", want: true,
			why: "rows like this exist and mean the package is affected outright",
		},
		{
			name:    "empty version matches, so a caller without one still sees the vuln",
			row:     osvRow{IntroducedVersion: "1.0.0", FixedVersion: "2.0.0"},
			version: "", want: true,
		},
		{
			name:    "list and range together, matched by the list",
			row:     osvRow{AffectedVersions: "{9.9.9}", IntroducedVersion: "1.0.0", FixedVersion: "2.0.0"},
			version: "9.9.9", want: true,
			why: "OSV allows both on one entry; either matching is enough",
		},
		{
			name:    "list and range together, matched by the range",
			row:     osvRow{AffectedVersions: "{9.9.9}", IntroducedVersion: "1.0.0", FixedVersion: "2.0.0"},
			version: "1.5.0", want: true,
		},
		{
			name:    "numeric ordering, not string ordering",
			row:     osvRow{IntroducedVersion: "0", FixedVersion: "10.0.0"},
			version: "9.0.0", want: true,
			why: "a plain string compare would place 9.0.0 after 10.0.0 and miss it",
		},
		{
			name:    "version with a v prefix, as stored in affected_versions",
			row:     osvRow{AffectedVersions: "{v1.0.0,v1.0.1}"},
			version: "v1.0.1", want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.row.affects(tt.version); got != tt.want {
				t.Errorf("affects(%q) = %v, want %v (%s)", tt.version, got, tt.want, tt.why)
			}
		})
	}
}

// TestCollapseOSVRowsDeduplicates covers the row-per-range shape of the table: the API
// returns one entry per vulnerability, the table averages 15.6 rows.
func TestCollapseOSVRowsDeduplicates(t *testing.T) {
	rows := []osvRow{
		{ID: "GHSA-1", IntroducedVersion: "1.0.0", FixedVersion: "1.5.0", Summary: "one"},
		{ID: "GHSA-1", IntroducedVersion: "2.0.0", FixedVersion: "2.5.0", Summary: "one"},
		{ID: "GHSA-1", IntroducedVersion: "3.0.0", FixedVersion: "3.5.0", Summary: "one"},
	}
	got := collapseOSVRows(rows, "2.1.0")
	if len(got) != 1 {
		t.Fatalf("collapseOSVRows() returned %d entries, want 1", len(got))
	}
	if got[0].ID != "GHSA-1" {
		t.Errorf("ID = %q, want %q", got[0].ID, "GHSA-1")
	}
}

// TestCollapseOSVRowsMatchesOnAnyRange checks a vulnerability is kept when any of its
// ranges covers the version, even if earlier rows do not.
func TestCollapseOSVRowsMatchesOnAnyRange(t *testing.T) {
	rows := []osvRow{
		{ID: "GHSA-1", IntroducedVersion: "1.0.0", FixedVersion: "1.5.0"},
		{ID: "GHSA-1", IntroducedVersion: "3.0.0", FixedVersion: "3.5.0"},
	}
	if got := collapseOSVRows(rows, "3.1.0"); len(got) != 1 {
		t.Errorf("a version matching only the second range returned %d entries, want 1", len(got))
	}
	if got := collapseOSVRows(rows, "2.0.0"); len(got) != 0 {
		t.Errorf("a version matching no range returned %d entries, want 0", len(got))
	}
}

// TestCollapseOSVRowsUsesNewestRow pins which row supplies the vulnerability fields.
// 137,302 (id, purl) pairs in production disagree across rows, almost always on
// modified, and the newest row is the one that agrees with osv_json and the API.
func TestCollapseOSVRowsUsesNewestRow(t *testing.T) {
	rows := []osvRow{
		{
			ID: "GHSA-2g4f-4pwh-qvx6", Summary: "stale text", Severity: "LOW",
			Modified: onlyDate("2026-02-19"), Aliases: "{CVE-OLD}",
			IntroducedVersion: "0", FixedVersion: "9.9.9",
		},
		{
			ID: "GHSA-2g4f-4pwh-qvx6", Summary: "current text", Severity: "HIGH",
			Modified: onlyDate("2026-03-04"), Aliases: "{CVE-NEW}",
			IntroducedVersion: "0", FixedVersion: "9.9.9",
		},
	}
	got := collapseOSVRows(rows, "1.0.0")
	if len(got) != 1 {
		t.Fatalf("returned %d entries, want 1", len(got))
	}
	if got[0].Summary != "current text" {
		t.Errorf("Summary = %q, want the newest row's value %q", got[0].Summary, "current text")
	}
	if got[0].Severity != "HIGH" {
		t.Errorf("Severity = %q, want %q", got[0].Severity, "HIGH")
	}
	if len(got[0].Aliases) != 1 || got[0].Aliases[0] != "CVE-NEW" {
		t.Errorf("Aliases = %v, want [CVE-NEW]", got[0].Aliases)
	}
	if want := utils.ParseTime("2026-03-04"); !want.Equal(time.Time(got[0].Modified)) {
		t.Errorf("Modified = %v, want %v", time.Time(got[0].Modified), want)
	}
}

// TestCollapseOSVRowsNewestRowWinsRegardlessOfWhichMatched checks the newest row supplies
// the fields even when a different row is the one covering the version.
func TestCollapseOSVRowsNewestRowWinsRegardlessOfWhichMatched(t *testing.T) {
	rows := []osvRow{
		// this row matches the version
		{
			ID: "GHSA-1", Summary: "old", Modified: onlyDate("2026-01-01"),
			IntroducedVersion: "1.0.0", FixedVersion: "2.0.0",
		},
		// this one does not, but is newer
		{
			ID: "GHSA-1", Summary: "new", Modified: onlyDate("2026-06-01"),
			IntroducedVersion: "5.0.0", FixedVersion: "6.0.0",
		},
	}
	got := collapseOSVRows(rows, "1.5.0")
	if len(got) != 1 {
		t.Fatalf("returned %d entries, want 1", len(got))
	}
	if got[0].Summary != "new" {
		t.Errorf("Summary = %q, want %q: the newest row supplies the fields even when "+
			"another row matched the version", got[0].Summary, "new")
	}
}

// TestCollapseOSVRowsPreservesOrder guards a stable response ordering.
func TestCollapseOSVRowsPreservesOrder(t *testing.T) {
	rows := []osvRow{
		{ID: "GHSA-a"}, {ID: "GHSA-b"}, {ID: "GHSA-a"}, {ID: "GHSA-c"},
	}
	got := collapseOSVRows(rows, "1.0.0")
	want := []string{"GHSA-a", "GHSA-b", "GHSA-c"}
	if len(got) != len(want) {
		t.Fatalf("returned %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].ID != want[i] {
			t.Errorf("entry %d = %q, want %q", i, got[i].ID, want[i])
		}
	}
}

// TestGetVulnsByPurlExcludesRepackagers pins the ecosystem filtering. Repackager
// advisories (Vendor:LanguageEcosystem, such as TuxCare:npm) sit under the same purl as
// the upstream package and are excluded; distro ecosystems also contain a colon
// (Ubuntu:22.04:LTS) and must be kept.
//
// This is the test to update if osvRepackagerEcosystems is ever emptied to bring them
// back. Filtering on "contains a colon" instead would drop 69% of the production table,
// every Debian and Ubuntu advisory included.
func TestGetVulnsByPurlExcludesRepackagers(t *testing.T) {
	db, ctx := newScenarioDB(t)
	model := NewOSVModel(zlog.S, db)

	vulns, err := model.GetVulnsByPurl(ctx, "pkg:npm/testosv", "1.0.0")
	if err != nil {
		t.Fatalf("GetVulnsByPurl() unexpected error: %v", err)
	}
	var sawRepackager, sawDistro bool
	for _, v := range vulns {
		switch v.ID {
		case "CLSA-TEST-0001":
			sawRepackager = true
		case "UBUNTU-TEST-0001":
			sawDistro = true
		}
	}
	if sawRepackager {
		t.Errorf("a TuxCare:npm advisory was returned; repackager ecosystems must be excluded")
	}
	if !sawDistro {
		t.Errorf("the Ubuntu:22.04:LTS advisory was not returned; distro ecosystems contain a " +
			"colon too and must not be filtered out")
	}
}

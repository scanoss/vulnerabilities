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

import "testing"

// TestNaturalSortKeyMatchesPostgres pins naturalSortKey against the output of the
// natural_sort_order PostgreSQL function it ports. Every expected value below was
// produced by that function on the production database with max_length 20:
//
//	SELECT v, natural_sort_order(v, 20) FROM (VALUES ('1.0.0'), ...) t(v);
//
// If this test fails, the port has drifted and the two engines will disagree about
// which vulnerabilities apply to a version.
func TestNaturalSortKeyMatchesPostgres(t *testing.T) {
	tests := []struct{ in, want string }{
		{"1.0.0", "00000000000000000001.00000000000000000000.00000000000000000000"},
		{"9.0.0", "00000000000000000009.00000000000000000000.00000000000000000000"},
		{"10.0.0", "00000000000000000010.00000000000000000000.00000000000000000000"},
		{"1.10.0", "00000000000000000001.00000000000000000010.00000000000000000000"},
		{"1.10.0-rc1", "00000000000000000001.00000000000000000010.00000000000000000000-rc00000000000000000001"},
		{"1.2.3-alpha", "00000000000000000001.00000000000000000002.00000000000000000003-alpha"},
		{"*", "*"},
		{"-", "-"},
		{".", "."},
		{"", ""},
		{"00.00.01a", "00000000000000000000.00000000000000000000.00000000000000000001a"},
		{"0.0.0.1", "00000000000000000000.00000000000000000000.00000000000000000000.00000000000000000001"},
		{"0.001.00.060", "00000000000000000000.00000000000000000001.00000000000000000000.00000000000000000060"},
		{"v1.0.0", "v00000000000000000001.00000000000000000000.00000000000000000000"},
		{"2017a", "00000000000000002017a"},
		{"r32-p4", "r00000000000000000032-p00000000000000000004"},
		{"1.0.0.RELEASE", "00000000000000000001.00000000000000000000.00000000000000000000.RELEASE"},
		// more digits than max_length: the overflow digit is emitted as a plain character
		{"123456789012345678901234", "12345678901234567890100000000000000000234"},
		{"a1b2", "a00000000000000000001b00000000000000000002"},
		{"1a2b3", "00000000000000000001a00000000000000000002b00000000000000000003"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := naturalSortKey(tt.in, 20); got != tt.want {
				t.Errorf("naturalSortKey(%q, 20)\n got %q\nwant %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestNaturalSortKeyMaxLengthBounds covers the guard the original function applies.
func TestNaturalSortKeyMaxLengthBounds(t *testing.T) {
	// out of range values fall back to 75
	for _, maxLength := range []int{0, -1, 151} {
		got := naturalSortKey("1", maxLength)
		if len(got) != 75 {
			t.Errorf("naturalSortKey(%q, %d) length = %d, want 75", "1", maxLength, len(got))
		}
	}
	if got := naturalSortKey("1", 5); got != "00001" {
		t.Errorf("naturalSortKey(%q, 5) = %q, want %q", "1", got, "00001")
	}
}

// TestNaturalSortKeyOrdering states the ordering properties the range matching relies on.
func TestNaturalSortKeyOrdering(t *testing.T) {
	tests := []struct {
		name      string
		lower     string
		higher    string
		whyItRuns string
	}{
		{
			name: "zero padding keeps numeric order", lower: "9.0.0", higher: "10.0.0",
			whyItRuns: "a plain string sort would put 10.0.0 first",
		},
		{
			name: "minor versions order numerically", lower: "1.9.0", higher: "1.10.0",
			whyItRuns: "same reason, one level down",
		},
		{
			name: "a pre-release sorts after its release", lower: "1.10.0", higher: "1.10.0-rc1",
			whyItRuns: "opposite of semver, and the reason a pre-release inherits its release's CVEs",
		},
		{
			name: "patch beats minor", lower: "1.0.0", higher: "1.0.1",
			whyItRuns: "ordinary case",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lo, hi := naturalSortKey(tt.lower, 20), naturalSortKey(tt.higher, 20)
			if !(lo < hi) {
				t.Errorf("expected %q < %q (%s)\n lower key %q\nhigher key %q",
					tt.lower, tt.higher, tt.whyItRuns, lo, hi)
			}
		})
	}
}

func TestVersionBoundsCovers(t *testing.T) {
	tests := []struct {
		name   string
		bounds versionBounds
		// version -> whether the bounds should cover it
		cases map[string]bool
	}{
		{
			name:   "no bounds covers everything",
			bounds: versionBounds{},
			cases:  map[string]bool{"1.0.0": true, "99.0.0": true, "not-a-version": true, "*": true},
		},
		{
			name:   "end including is inclusive",
			bounds: versionBounds{EndIncluding: "2.0.0"},
			cases:  map[string]bool{"1.0.0": true, "2.0.0": true, "2.0.1": false, "3.0.0": false},
		},
		{
			name:   "end excluding is exclusive",
			bounds: versionBounds{EndExcluding: "2.0.0"},
			cases:  map[string]bool{"1.9.9": true, "2.0.0": false, "3.0.0": false},
		},
		{
			name:   "start including is inclusive",
			bounds: versionBounds{StartIncluding: "2.0.0"},
			cases:  map[string]bool{"1.9.9": false, "2.0.0": true, "2.0.1": true},
		},
		{
			name:   "start excluding is exclusive",
			bounds: versionBounds{StartExcluding: "2.0.0"},
			cases:  map[string]bool{"1.9.9": false, "2.0.0": false, "2.0.1": true},
		},
		{
			name:   "closed inclusive range",
			bounds: versionBounds{StartIncluding: "1.0.0", EndIncluding: "2.0.0"},
			cases:  map[string]bool{"0.9.9": false, "1.0.0": true, "1.5.0": true, "2.0.0": true, "2.0.1": false},
		},
		{
			name:   "closed exclusive range",
			bounds: versionBounds{StartExcluding: "1.0.0", EndExcluding: "3.0.0"},
			cases:  map[string]bool{"1.0.0": false, "2.0.0": true, "3.0.0": false},
		},
		{
			name:   "single version range",
			bounds: versionBounds{StartIncluding: "1.0.0", EndIncluding: "1.0.0"},
			cases:  map[string]bool{"1.0.0": true, "1.0.1": false, "0.9.9": false},
		},
		{
			name:   "numeric ordering, not string ordering",
			bounds: versionBounds{EndIncluding: "10.0.0"},
			// a plain string sort would place 9.0.0 after 10.0.0 and wrongly exclude it
			cases: map[string]bool{"9.0.0": true, "10.0.0": true, "11.0.0": false},
		},
		{
			name: "a pre-release is covered by a range ending at its release",
			// natural sort places 1.10.0-rc1 after 1.10.0, so the rc inherits the CVEs of
			// its release. This is what production does today; semver would exclude it.
			bounds: versionBounds{StartIncluding: "1.10.0"},
			cases:  map[string]bool{"1.10.0-rc1": true, "1.10.0": true, "1.9.0": false},
		},
		{
			name: "versions that are not semver still compare",
			// 48% of production version names are not valid semver. Dropping them would
			// lose real vulnerabilities, so they are compared as natural sort keys.
			bounds: versionBounds{StartIncluding: "0.0.0", EndIncluding: "1.0.0"},
			cases:  map[string]bool{"00.00.01a": true, "0.0.0.1": true, "0.001.00.060": true},
		},
		{
			name:   "placeholder versions still fall in range",
			bounds: versionBounds{EndIncluding: "2.0.0"},
			// '*' and '-' are left untouched by the key, and both sort below '0', so they
			// land inside an upper-bounded range. Production relies on this: dropping
			// them instead cost 24 CVEs across two sampled components.
			cases: map[string]bool{"*": true, "-": true},
		},
		{
			name: "an exact match on an inclusive bound wins over the opposite bound",
			// mirrors the SQL: the equality check short-circuits before the range tests
			bounds: versionBounds{StartIncluding: "5.0.0", EndExcluding: "1.0.0"},
			cases:  map[string]bool{"5.0.0": true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for version, want := range tt.cases {
				if got := tt.bounds.covers(version); got != want {
					t.Errorf("versionBounds%+v.covers(%q) = %v, want %v", tt.bounds, version, got, want)
				}
			}
		})
	}
}

func TestVersionBoundsIsOpen(t *testing.T) {
	tests := []struct {
		name   string
		bounds versionBounds
		want   bool
	}{
		{name: "all empty", bounds: versionBounds{}, want: true},
		{name: "start including set", bounds: versionBounds{StartIncluding: "1.0.0"}, want: false},
		{name: "start excluding set", bounds: versionBounds{StartExcluding: "1.0.0"}, want: false},
		{name: "end including set", bounds: versionBounds{EndIncluding: "1.0.0"}, want: false},
		{name: "end excluding set", bounds: versionBounds{EndExcluding: "1.0.0"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.bounds.isOpen(); got != tt.want {
				t.Errorf("versionBounds%+v.isOpen() = %v, want %v", tt.bounds, got, tt.want)
			}
		})
	}
}

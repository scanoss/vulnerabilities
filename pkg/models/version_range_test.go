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
			cases:  map[string]bool{"1.0.0": true, "99.0.0": true, "not-a-version": true, "": true},
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
			name:   "semantic ordering, not string ordering",
			bounds: versionBounds{EndIncluding: "10.0.0"},
			// a string sort would put "9.0.0" after "10.0.0" and wrongly exclude it
			cases: map[string]bool{"9.0.0": true, "10.0.0": true, "11.0.0": false},
		},
		{
			name:   "pre-release ordering",
			bounds: versionBounds{StartIncluding: "1.0.0"},
			cases:  map[string]bool{"1.0.0-alpha": false, "1.0.0": true, "1.0.1-beta": true},
		},
		{
			name:   "a version equal to an inclusive bound matches even when unparseable",
			bounds: versionBounds{StartIncluding: "1.5.2.3", EndIncluding: "2.0"},
			cases:  map[string]bool{"1.5.2.3": true, "2.0": true},
		},
		{
			name:   "an unparseable version matches nothing else",
			bounds: versionBounds{EndIncluding: "2.0.0"},
			cases:  map[string]bool{"not-a-version": false, "": false},
		},
		{
			name: "an unparseable bound is ignored rather than excluding the version",
			// Losing a real vulnerability is worse than reporting a borderline one.
			bounds: versionBounds{StartIncluding: "garbage", EndIncluding: "2.0.0"},
			cases:  map[string]bool{"1.0.0": true, "3.0.0": false},
		},
		{
			name:   "surrounding whitespace is tolerated",
			bounds: versionBounds{EndIncluding: "  2.0.0  "},
			cases:  map[string]bool{" 1.0.0 ": true, "2.0.0": true, "3.0.0": false},
		},
		{
			name:   "a v prefix is accepted on both sides",
			bounds: versionBounds{EndIncluding: "v2.0.0"},
			cases:  map[string]bool{"v1.0.0": true, "v3.0.0": false},
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
		{name: "whitespace only", bounds: versionBounds{StartIncluding: "  ", EndExcluding: "\t"}, want: true},
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

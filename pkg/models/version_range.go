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

// Version range matching for NVD match criteria.
//
// This used to live in SQL, comparing versions with natural_sort_order, a custom
// PostgreSQL function. Comparing here instead keeps the queries portable across
// PostgreSQL and SQLite, and gives proper semantic version ordering rather than a
// string sort - the same approach FilterCpesByRequirement already takes in cpe_purl.go.

package models

import (
	"strings"

	"github.com/Masterminds/semver/v3"
)

// versionBounds holds the version limits of an NVD match criterion. An empty bound
// means the range is open on that side.
type versionBounds struct {
	StartIncluding string
	StartExcluding string
	EndIncluding   string
	EndExcluding   string
}

// isOpen reports whether the criterion constrains the version at all.
func (b versionBounds) isOpen() bool {
	return len(strings.TrimSpace(b.StartIncluding)) == 0 &&
		len(strings.TrimSpace(b.StartExcluding)) == 0 &&
		len(strings.TrimSpace(b.EndIncluding)) == 0 &&
		len(strings.TrimSpace(b.EndExcluding)) == 0
}

// covers reports whether the given version falls inside the bounds.
func (b versionBounds) covers(version string) bool {
	version = strings.TrimSpace(version)
	// An exact match on an inclusive bound settles it without parsing, so versions that
	// are not valid semver still match the criteria that name them outright. The query
	// this replaces short-circuited the same way.
	if len(version) > 0 &&
		(version == strings.TrimSpace(b.StartIncluding) || version == strings.TrimSpace(b.EndIncluding)) {
		return true
	}
	if b.isOpen() {
		return true
	}
	target, err := semver.NewVersion(version)
	if err != nil {
		// Nothing left to compare against: only the shortcut above could have matched.
		return false
	}
	// cmp is the target compared against the bound.
	checks := []struct {
		bound string
		ok    func(cmp int) bool
	}{
		{b.StartIncluding, func(cmp int) bool { return cmp >= 0 }},
		{b.StartExcluding, func(cmp int) bool { return cmp > 0 }},
		{b.EndIncluding, func(cmp int) bool { return cmp <= 0 }},
		{b.EndExcluding, func(cmp int) bool { return cmp < 0 }},
	}
	for _, c := range checks {
		bound := strings.TrimSpace(c.bound)
		if len(bound) == 0 {
			continue
		}
		bv, err := semver.NewVersion(bound)
		if err != nil {
			// Skip a bound we cannot parse rather than treat it as a mismatch: missing a
			// real vulnerability is worse than reporting a borderline one.
			continue
		}
		if !c.ok(target.Compare(bv)) {
			return false
		}
	}
	return true
}

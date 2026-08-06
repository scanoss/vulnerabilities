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
// PostgreSQL function that SQLite has no equivalent for. The comparison happens here
// instead so the queries stay portable across both engines.
//
// naturalSortKey is a faithful port of that function rather than a semantic version
// comparison, and covers reproduces the exact boolean shape of the original SQL. That
// is deliberate: the data does not support semver ordering. 48% of the version names
// and 39.5% of the version bounds in the production database are not valid semver -
// values like "*", "-", "00.00.01a", "0.001.00.060" or buildbot branch names. Comparing
// those semantically means either dropping them or guessing, and dropping them loses
// real vulnerabilities. Measured against production data, a semver implementation
// returned fewer CVEs than the SQL it replaced on 3 of 48 sampled purl/version pairs.
//
// Note that the zero padding preserves numeric ordering, so 9.0.0 still sorts before
// 10.0.0. Where this differs from semver is pre-releases: 1.10.0-rc1 sorts *after*
// 1.10.0, because it shares its prefix and carries extra characters. A pre-release
// therefore inherits the vulnerabilities of its release, which is the behaviour the
// service has in production today.

package models

import (
	"strings"
)

// nsoMaxLength is the digit padding width. The SQL passed 20 at every call site, so
// that is fixed here; the original function's guard for out-of-range widths is
// unreachable at this width and is not reproduced.
const nsoMaxLength = 20

// naturalSortKey ports the natural_sort_order PostgreSQL function: each run of digits
// is left-padded with zeros to nsoMaxLength so that numbers compare in numeric order,
// while every other character is copied through. Comparing two keys as plain strings
// then yields the same ordering the database produced.
func naturalSortKey(value string) string {
	var result, digits strings.Builder
	flushDigits := func() {
		if digits.Len() == 0 {
			return
		}
		if pad := nsoMaxLength - digits.Len(); pad > 0 {
			result.WriteString(strings.Repeat("0", pad))
		}
		result.WriteString(digits.String())
		digits.Reset()
	}
	for _, char := range value {
		// A digit past nsoMaxLength is emitted as a plain character, as the original does.
		if char >= '0' && char <= '9' && digits.Len() < nsoMaxLength {
			digits.WriteRune(char)
			continue
		}
		flushDigits()
		result.WriteRune(char)
	}
	flushDigits()
	return result.String()
}

// versionBounds holds the version limits of an NVD match criterion. An empty bound
// means the range is open on that side.
type versionBounds struct {
	StartIncluding string
	StartExcluding string
	EndIncluding   string
	EndExcluding   string
}

// covers reports whether the given version falls inside the bounds. It mirrors the
// boolean structure of the SQL it replaces, quirks included: an exact match against an
// inclusive bound short-circuits on its own, so it wins even when the opposite bound
// would exclude the version, and the range tests are strict comparisons because that
// equality case is already handled.
func (b versionBounds) covers(version string) bool {
	if version == b.StartIncluding || version == b.EndIncluding {
		return true
	}
	key := naturalSortKey(version)
	// Lower bound: unconstrained, or past whichever start bound is set.
	afterStart := (len(b.StartExcluding) == 0 && len(b.StartIncluding) == 0) ||
		(len(b.StartExcluding) > 0 && key > naturalSortKey(b.StartExcluding)) ||
		(len(b.StartIncluding) > 0 && key > naturalSortKey(b.StartIncluding))
	// Upper bound: unconstrained, or short of whichever end bound is set.
	beforeEnd := (len(b.EndExcluding) == 0 && len(b.EndIncluding) == 0) ||
		(len(b.EndExcluding) > 0 && key < naturalSortKey(b.EndExcluding)) ||
		(len(b.EndIncluding) > 0 && key < naturalSortKey(b.EndIncluding))
	return afterStart && beforeEnd
}

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

package utils

import (
	"strings"
)

// PurlRemoveFromVersionComponent strips the version, qualifiers and subpath from a
// purl string, leaving the minimum pkg:type/namespace/name.
// See purl specs scheme:type/namespace/name@version?qualifiers#subpath.
//
// Only an '@' in the last path segment is a version separator: a scoped npm
// namespace (pkg:npm/@scope/name) is a segment of its own, and cutting at the first
// '@' would reduce it to "pkg:npm/".
func PurlRemoveFromVersionComponent(purlString string) string {
	if i := strings.IndexAny(purlString, "?#"); i >= 0 {
		purlString = purlString[:i]
	}
	if slash := strings.LastIndexByte(purlString, '/'); slash >= 0 {
		if at := strings.IndexByte(purlString[slash:], '@'); at >= 0 {
			purlString = purlString[:slash+at]
		}
	}
	return purlString
}

// PurlSpellings returns the spellings of a versionless purl to match against the
// tables keyed by purl string (osv, short_cpe_purl).
//
// A scoped npm or jsr namespace is stored both ways: osv writes pkg:npm/%40scope/name
// throughout, while short_cpe_purl holds 184 scoped purls encoded and 228 with a raw
// '@'. The caller's own spelling is either, so both are tried.
func PurlSpellings(purl string) []string {
	purl = strings.TrimSpace(purl)
	spellings := []string{purl}
	if alt := strings.Replace(purl, "/%40", "/@", 1); alt != purl {
		spellings = append(spellings, alt)
	} else if alt = strings.Replace(purl, "/@", "/%40", 1); alt != purl {
		spellings = append(spellings, alt)
	}
	return spellings
}

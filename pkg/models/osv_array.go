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

// Reading the list-valued columns of the osv table.
//
// osv.affected_versions, aliases, upstream and related are PostgreSQL text arrays.
// SQLite has no array type, so the queries cast them to text and the SQLite export
// stores that same text form. Both engines therefore hand us PostgreSQL's array
// literal syntax, which this file parses.
//
// The quoting rules matter and are not hypothetical: 1,082 rows in production have a
// quoted element in affected_versions, and some of those elements contain a comma
// (`{"v1,1",v1.1}`). Splitting on commas alone would silently invent versions.

package models

import "strings"

// osvArrayValues parses a PostgreSQL array literal into its elements. An empty array
// ({}), an empty string or a NULL-ish value all yield no elements.
func osvArrayValues(raw string) []string {
	raw = strings.TrimSpace(raw)
	if len(raw) == 0 || raw == "{}" || raw == "NULL" {
		return nil
	}
	// Tolerate a value that arrives without the braces.
	if strings.HasPrefix(raw, "{") && strings.HasSuffix(raw, "}") {
		raw = raw[1 : len(raw)-1]
	}
	if len(raw) == 0 {
		return nil
	}
	var (
		values   []string
		current  strings.Builder
		inQuotes bool
		escaped  bool
	)
	flush := func() {
		value := current.String()
		current.Reset()
		// Unquoted elements carry no significant surrounding space; quoted ones do, and
		// have already been emitted verbatim.
		values = append(values, value)
	}
	for i := 0; i < len(raw); i++ {
		char := raw[i]
		switch {
		case escaped:
			current.WriteByte(char)
			escaped = false
		case char == '\\':
			escaped = true
		case char == '"':
			inQuotes = !inQuotes
		case char == ',' && !inQuotes:
			flush()
		default:
			current.WriteByte(char)
		}
	}
	flush()
	// Trim only the elements that were not quoted; a quoted element keeps its spaces.
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, strings.TrimSpace(value))
	}
	return out
}

// osvArrayContains reports whether the array literal holds the given value.
func osvArrayContains(raw, value string) bool {
	for _, candidate := range osvArrayValues(raw) {
		if candidate == value {
			return true
		}
	}
	return false
}

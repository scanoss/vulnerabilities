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

import "testing"

func TestStripSemverOperator(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "greater than operator",
			input:    ">2.3.0",
			expected: "2.3.0",
		},
		{
			name:     "greater than or equal operator",
			input:    ">=1.0.0",
			expected: "1.0.0",
		},
		{
			name:     "less than operator",
			input:    "<3.0.0",
			expected: "3.0.0",
		},
		{
			name:     "no operator",
			input:    "1.2.3",
			expected: "1.2.3",
		},
		{
			name:     "version with 'v'",
			input:    "v1.2.3",
			expected: "1.2.3",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := StripSemverOperator(tc.input)
			if result != tc.expected {
				t.Errorf("StripSemverOperator(%q) = %q, want %q",
					tc.input, result, tc.expected)
			}
		})
	}
}

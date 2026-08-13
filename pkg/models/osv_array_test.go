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
	"reflect"
	"testing"
)

func TestOSVArrayValues(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{name: "empty array", raw: "{}", want: nil},
		{name: "empty string", raw: "", want: nil},
		{name: "single value", raw: "{0.0.1}", want: []string{"0.0.1"}},
		{
			name: "several values",
			raw:  "{v1.0.0,v1.0.1,v1.1.0}",
			want: []string{"v1.0.0", "v1.0.1", "v1.1.0"},
		},
		{
			name: "single alias",
			raw:  "{CVE-2018-16342}",
			want: []string{"CVE-2018-16342"},
		},
		{
			name: "two aliases, as the cve field is derived from the first",
			raw:  "{CVE-2026-56812,GHSA-63mc-hw7g-86rr}",
			want: []string{"CVE-2026-56812", "GHSA-63mc-hw7g-86rr"},
		},
		{
			// production row: the quoted element contains a comma, so splitting on commas
			// alone would yield "v1" and "1" - two versions that do not exist
			name: "quoted value containing a comma",
			raw:  `{"v1,1",v1.1}`,
			want: []string{"v1,1", "v1.1"},
		},
		{
			// production row from affected_versions
			name: "quoted value with spaces and operators",
			raw:  `{3.2.0-beta1,"beta: <= 3.2.0.beta2",v3.1.1}`,
			want: []string{"3.2.0-beta1", "beta: <= 3.2.0.beta2", "v3.1.1"},
		},
		{
			name: "quoted value with an equals sign",
			raw:  `{"= 1.6.0",v1.6.0}`,
			want: []string{"= 1.6.0", "v1.6.0"},
		},
		{
			name: "escaped quote inside a value",
			raw:  `{"a\"b",c}`,
			want: []string{`a"b`, "c"},
		},
		{
			name: "escaped backslash",
			raw:  `{"a\\b"}`,
			want: []string{`a\b`},
		},
		{name: "value without braces is tolerated", raw: "1.0.0", want: []string{"1.0.0"}},
		{name: "NULL text", raw: "NULL", want: nil},
		{
			name: "surrounding whitespace on unquoted values",
			raw:  "{ 1.0.0 , 2.0.0 }",
			want: []string{"1.0.0", "2.0.0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := osvArrayValues(tt.raw); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("osvArrayValues(%q) = %#v, want %#v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestOSVArrayContains(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		value string
		want  bool
	}{
		{name: "present", raw: "{1.0.0,2.0.0}", value: "2.0.0", want: true},
		{name: "absent", raw: "{1.0.0,2.0.0}", value: "3.0.0", want: false},
		{name: "empty array", raw: "{}", value: "1.0.0", want: false},
		{name: "exact match only, not a prefix", raw: "{1.0.0}", value: "1.0", want: false},
		{name: "quoted value with comma", raw: `{"v1,1",v1.1}`, value: "v1,1", want: true},
		{
			name: "a comma inside a quoted value is not a separator",
			raw:  `{"v1,1"}`, value: "v1", want: false,
		},
		{name: "v prefix is significant", raw: "{v1.0.0}", value: "1.0.0", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := osvArrayContains(tt.raw, tt.value); got != tt.want {
				t.Errorf("osvArrayContains(%q, %q) = %v, want %v", tt.raw, tt.value, got, tt.want)
			}
		})
	}
}

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
	"reflect"
	"testing"
)

func TestPurlRemoveFromVersionComponent(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "With version",
			input: "pkg:maven/io.prestosql/Presto-main@v1.0",
			want:  "pkg:maven/io.prestosql/Presto-main",
		},
		{
			name:  "Without version",
			input: "pkg:npm/%40babel/Core",
			want:  "pkg:npm/%40babel/Core",
		},
		{
			name:  "Without version",
			input: "pkg:npm/%40babel/Core?arch=x64",
			want:  "pkg:npm/%40babel/Core",
		},
		{
			name:  "Without version",
			input: "pkg:npm/%40babel/Core#googleapis/api/annotations",
			want:  "pkg:npm/%40babel/Core",
		},
		{
			name:  "Without version",
			input: "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?packaging=sources",
			want:  "pkg:maven/org.apache.xmlgraphics/batik-anim",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PurlRemoveFromVersionComponent(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("utils.PurlRemoveFromVersionComponent() = %v, want %v", got, tt.want)
			}
		})
	}
}

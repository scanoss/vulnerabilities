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

// OnlyDate has to survive being scanned out of a database column. The schema declares
// cves.published and cves.modified as TEXT, so the driver hands back a string; a
// PostgreSQL date column hands back a time.Time. Both must work, since the service
// supports both engines.

package utils

import (
	"testing"
	"time"
)

func TestOnlyDateScan(t *testing.T) {
	want := time.Date(2020, 1, 15, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		src     interface{}
		want    time.Time
		wantErr bool
	}{
		{name: "string date, as SQLite returns TEXT", src: "2020-01-15", want: want},
		{name: "byte slice date", src: []byte("2020-01-15"), want: want},
		{name: "time.Time, as PostgreSQL returns date", src: want, want: want},
		{name: "timestamp string with time part", src: "2020-01-15 10:30:00", want: want},
		{name: "nil is the zero date", src: nil, want: time.Time{}},
		{name: "empty string is the zero date", src: "", want: time.Time{}},
		{name: "unparseable string", src: "not-a-date", wantErr: true},
		{name: "unsupported type", src: 12345, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d OnlyDate
			err := d.Scan(tt.src)
			if (err != nil) != tt.wantErr {
				t.Fatalf("OnlyDate.Scan(%v) error = %v, wantErr %v", tt.src, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got := time.Time(d); !got.Equal(tt.want) {
				t.Errorf("OnlyDate.Scan(%v) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

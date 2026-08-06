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
	"database/sql/driver"
	"fmt"
	"strings"
	"time"
)

type OnlyDate time.Time

const ctLayout = "2006-01-02"

// UnmarshalJSON Parses the json string in the custom format.
func (ct *OnlyDate) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	nt, err := time.Parse(ctLayout, s)
	if err != nil {
		return err
	}
	*ct = OnlyDate(nt)
	return nil
}

// MarshalJSON writes a quoted string in the custom format.
func (ct OnlyDate) MarshalJSON() ([]byte, error) {
	return []byte(ct.String()), nil
}

// String returns the time in the custom format.
func (ct *OnlyDate) String() string {
	t := time.Time(*ct)
	return fmt.Sprintf("%q", t.Format(ctLayout))
}

// scanLayouts are the formats accepted when reading a date from a database column,
// most specific first. A time part, if present, is discarded.
var scanLayouts = []string{
	ctLayout,
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05",
	time.RFC3339,
}

// Scan implements sql.Scanner. A date reaches us differently depending on the engine:
// the schema declares cves.published as TEXT so SQLite hands back a string, while a
// PostgreSQL date column hands back a time.Time. Both are accepted.
func (ct *OnlyDate) Scan(src interface{}) error {
	switch v := src.(type) {
	case nil:
		*ct = OnlyDate(time.Time{})
		return nil
	case time.Time:
		*ct = OnlyDate(dateOnly(v))
		return nil
	case []byte:
		return ct.scanString(string(v))
	case string:
		return ct.scanString(v)
	default:
		return fmt.Errorf("cannot scan %T into OnlyDate", src)
	}
}

// Value implements driver.Valuer, so a date is written in a form both engines accept.
func (ct OnlyDate) Value() (driver.Value, error) {
	t := time.Time(ct)
	if t.IsZero() {
		return nil, nil
	}
	return t.Format(ctLayout), nil
}

// scanString parses a date out of a textual column value.
func (ct *OnlyDate) scanString(s string) error {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		*ct = OnlyDate(time.Time{})
		return nil
	}
	for _, layout := range scanLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			*ct = OnlyDate(dateOnly(t))
			return nil
		}
	}
	return fmt.Errorf("cannot parse %q as a date", s)
}

// dateOnly drops the time part, keeping the calendar date in UTC.
func dateOnly(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

func ParseTime(t string) time.Time {
	timeValue, err := time.Parse(time.DateOnly, t)
	if err != nil {
		panic(err)
	}
	return timeValue
}

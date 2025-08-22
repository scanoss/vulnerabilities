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

func ParseTime(t string) time.Time {
	timeValue, err := time.Parse(time.DateOnly, t)
	if err != nil {
		panic(err)
	}
	return timeValue
}

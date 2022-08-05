// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018-2022 SCANOSS.COM
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
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/jmoiron/sqlx"
	zlog "scanoss.com/vulnerabilities/pkg/logger"
)

func TestGetCpesByPurlName(t *testing.T) {
	ctx := context.Background()
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	db, err := sqlx.Connect("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer CloseDB(db)
	conn, err := db.Connx(ctx) // Get a connection from the pool
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer CloseConn(conn)
	err = LoadTestSqlData(db, ctx, conn)
	if err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}

	cpeModel := NewCpePurlModel(ctx, conn)

	fmt.Printf("Searching cpes for purl: %v\n", "pkg:apache/sling")
	cpes, err := cpeModel.GetCpesByPurlName("pkg:apache/sling", "")
	if err != nil {
		t.Errorf("cpeModel.GetCpesByPurlName() error = %v", err)
	}
	if len(cpes) == 0 {
		t.Errorf("cpeModel.GetCpesByPurlName() No version returned from query")
	}
	fmt.Printf("Cpes: %#v\n", cpes)

	fmt.Printf("Searching cpes for purl: %v\n", "pkg:apache/sling")
	cpes, err = cpeModel.GetCpesByPurlNameVersion("pkg:apache/sling", "2.2.0")
	if err != nil {
		t.Errorf("cpeModel.GetCpesByPurlName() error = %v", err)
	}
	if len(cpes) == 0 {
		t.Errorf("versions.GetVersionByName() No version returned from query")
	}
	fmt.Printf("Cpes: %#v\n", cpes)

}

func TestFilterCpesByRequirement(t *testing.T) {

	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}

	tests := map[string]struct {
		req           string
		cpes          []CpePurl
		want          []CpePurl
		expectedError bool
	}{
		"Requirement equals to version": {
			req: "=2.2.0",
			cpes: []CpePurl{
				{Cpe: "cpe:2.3:a:apache:org.apache.sling.servlets.post:2.2.0:*:*:*:*:*:*:*", Version: "2.2.0", SemVer: "2.2.0"},
				{Cpe: "cpe:2.3:o:zyxel:zywall_atp200_firmware:4.35:*:*:*:*:*:*:*", Version: "4.35", SemVer: "4.35.0"},
				{Cpe: "cpe:2.3:a:101_project:101:0.15.0:*:*:*:*:node.js:*:*", Version: "0.15.0", SemVer: "0.15.0"},
			},
			want: []CpePurl{
				{Cpe: "cpe:2.3:a:apache:org.apache.sling.servlets.post:2.2.0:*:*:*:*:*:*:*", Version: "2.2.0", SemVer: "2.2.0"},
			},
			expectedError: false,
		},
		"Requirement not matching the cpe list": {
			req: "=8.0.0",
			cpes: []CpePurl{
				{Cpe: "cpe:2.3:a:apache:org.apache.sling.servlets.post:2.2.0:*:*:*:*:*:*:*", Version: "2.2.0", SemVer: "2.2.0"},
				{Cpe: "cpe:2.3:o:zyxel:zywall_atp200_firmware:4.35:*:*:*:*:*:*:*", Version: "4.35", SemVer: "4.35.0"},
				{Cpe: "cpe:2.3:a:101_project:101:0.15.0:*:*:*:*:node.js:*:*", Version: "0.15.0", SemVer: "0.15.0"},
			},
			want:          []CpePurl(nil),
			expectedError: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, _ := FilterCpesByRequirement(tc.cpes, tc.req)
			if !reflect.DeepEqual(tc.want, got) {
				t.Fatalf("expected: %#v, got: %#v", tc.want, got)
			}
		})
	}
}

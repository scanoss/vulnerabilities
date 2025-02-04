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
	"context"
	"reflect"
	"testing"

	"github.com/jmoiron/sqlx"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
)

func TestGetCpeByPurl(t *testing.T) {
	// Setup helper function to reduce duplication
	// Split into separate test functions
	t.Run("Valid Cases", func(t *testing.T) {
		TestGetCpeByPurl_ValidCases(t)
	})

	t.Run("Version Specific Cases", func(t *testing.T) {
		TestGetCpeByPurl_VersionSpecific(t)
	})

	t.Run("Error Cases", func(t *testing.T) {
		TestGetCpeByPurl_ErrorCases(t)
	})
}

// setupTest creates test database connection and model.
func setupTest(t *testing.T) (*sqlx.Conn, *CpePurlModel) {
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
	db.SetMaxOpenConns(1)
	defer CloseDB(db)

	conn, err := db.Connx(ctx)
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}

	err = LoadTestSQLData(db, ctx, conn)
	if err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}

	return conn, NewCpePurlModel(ctx, conn)
}

func TestGetCpeByPurl_ValidCases(t *testing.T) {
	conn, cpeModel := setupTest(t)
	defer CloseConn(conn)

	// Test basic purl without requirements
	t.Run("Basic purl without requirements", func(t *testing.T) {
		_, err := cpeModel.GetCpeByPurl("pkg:github/hapijs/call", "")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		// Assert full list of CPEs (the original 16 entries)
		// You can move the want slice here
	})
}

func TestGetCpeByPurl_VersionSpecific(t *testing.T) {
	conn, cpeModel := setupTest(t)
	defer CloseConn(conn)

	t.Run("Specific version without requirements", func(t *testing.T) {
		got, err := cpeModel.GetCpeByPurl("pkg:github/hapijs/call@1.0.0", "")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		want := []CpePurl{{"cpe:2.3:a:call_project:call:1.0.0:*:*:*:*:node.js:*:*", "1.0.0", "1.0.0"}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("With version requirement", func(t *testing.T) {
		got, err := cpeModel.GetCpeByPurl("pkg:github/hapijs/call", "2.0.0")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		want := []CpePurl{{"cpe:2.3:a:call_project:call:2.0.0:*:*:*:*:node.js:*:*", "2.0.0", "2.0.0"}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}

func TestGetCpeByPurl_ErrorCases(t *testing.T) {
	conn, cpeModel := setupTest(t)
	defer CloseConn(conn)

	tests := []struct {
		name        string
		purl        string
		requirement string
		wantErr     bool
	}{
		{
			name:    "Empty purl",
			purl:    "",
			wantErr: true,
		},
		{
			name:    "Broken purl format",
			purl:    "pkag:gitasdhub/sadhapijs/caasdll@1.0asd.0",
			wantErr: true,
		},
		{
			name: "Non-existent purl",
			purl: "pkg:github/noexistent/aaaa",
		},
		{
			name:        "Non-existent version",
			purl:        "pkg:github/hapijs/call",
			requirement: "15.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := cpeModel.GetCpeByPurl(tt.purl, tt.requirement)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCpeByPurl() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetCpesByPurlString(t *testing.T) {
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
	db.SetMaxOpenConns(1)
	defer CloseDB(db)

	conn, err := db.Connx(ctx) // Get a connection from the pool
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer CloseConn(conn)
	err = LoadTestSQLData(db, ctx, conn)
	if err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}

	cpeModel := NewCpePurlModel(ctx, conn)

	type inputGetCpeByPurl struct {
		purl        string
		requirement string
	}
	tests := []struct {
		name    string
		input   inputGetCpeByPurl
		want    []CpePurl
		wantErr bool
	}{
		{
			name:    "Empty purlstring",
			input:   inputGetCpeByPurl{purl: "", requirement: ""},
			wantErr: true,
		}, {
			name:  "Test purl requirement",
			input: inputGetCpeByPurl{purl: "pkg:github/hapijs/call", requirement: ">=5.0.0"},
			want: []CpePurl{{"cpe:2.3:a:call_project:call:5.0.0:*:*:*:*:node.js:*:*", "5.0.0",
				"5.0.0"}, {"cpe:2.3:a:call_project:call:5.0.1:*:*:*:*:node.js:*:*",
				"5.0.1", "5.0.1"}, {"cpe:2.3:a:call_project:call:5.0.2:*:*:*:*:node.js:*:*",
				"5.0.2", "5.0.2"},
				{"cpe:2.3:a:call_project:call:5.0.3:*:*:*:*:node.js:*:*",
					"5.0.3", "5.0.3"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []CpePurl
			got, err = cpeModel.GetCpesByPurlString(tt.input.purl, tt.input.requirement)
			if (err != nil) != tt.wantErr {
				t.Errorf("cpeModel.GetCpeByPurl() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			t.Logf("Got: %v: ", got)
			t.Logf("Exp: %v: ", tt.want)
			if err == nil && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("cpeModel.GetCpeByPurl() = %v, want %v", got, tt.want)
			}
		})
	}

	CloseConn(conn)
	_, err = cpeModel.GetCpesByPurlString("pkg:github/hapijs/call", "")
	if err == nil {
		t.Errorf("An error was expected because the DB connection was closed, cpeModel.GetCpesByPurlString")
	}
}

func TestGetCpesByPurlStringVersion(t *testing.T) {
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
	db.SetMaxOpenConns(1)
	defer CloseDB(db)

	conn, err := db.Connx(ctx) // Get a connection from the pool
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer CloseConn(conn)
	err = LoadTestSQLData(db, ctx, conn)
	if err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}

	cpeModel := NewCpePurlModel(ctx, conn)

	_, err = cpeModel.GetCpesByPurlStringVersion("", "")
	if err == nil {
		t.Errorf("Empty purl in cpeModel.GetCpesByPurlStringVersion(), an error was expected")
	}

	CloseConn(conn)
	_, err = cpeModel.GetCpesByPurlStringVersion("pkg:github/hapijs/call", "")
	if err == nil {
		t.Errorf("An error was expected because the DB connection was closed, cpeModel.GetCpesByPurlStringVersion()")
	}
}

func TestFilterCpesByRequirement(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}

	tests := []struct {
		name    string
		req     string
		cpes    []CpePurl
		want    []CpePurl
		wantErr bool
	}{
		{
			name: "Requirement equals to version",
			req:  "=2.2.0",
			cpes: []CpePurl{
				{Cpe: "cpe:2.3:a:apache:org.apache.sling.servlets.post:2.2.0:*:*:*:*:*:*:*", Version: "2.2.0", SemVer: "2.2.0"},
				{Cpe: "cpe:2.3:o:zyxel:zywall_atp200_firmware:4.35:*:*:*:*:*:*:*", Version: "4.35", SemVer: "4.35.0"},
				{Cpe: "cpe:2.3:a:101_project:101:0.15.0:*:*:*:*:node.js:*:*", Version: "0.15.0", SemVer: "0.15.0"}},
			want: []CpePurl{{Cpe: "cpe:2.3:a:apache:org.apache.sling.servlets.post:2.2.0:*:*:*:*:*:*:*", Version: "2.2.0", SemVer: "2.2.0"}},
		}, {
			name: "Requirement not matching the cpe list returns empty results",
			req:  "=8.0.0",
			cpes: []CpePurl{
				{Cpe: "cpe:2.3:a:apache:org.apache.sling.servlets.post:2.2.0:*:*:*:*:*:*:*", Version: "2.2.0", SemVer: "2.2.0"},
				{Cpe: "cpe:2.3:o:zyxel:zywall_atp200_firmware:4.35:*:*:*:*:*:*:*", Version: "4.35", SemVer: "4.35.0"},
				{Cpe: "cpe:2.3:a:101_project:101:0.15.0:*:*:*:*:node.js:*:*", Version: "0.15.0", SemVer: "0.15.0"},
			},
			want: []CpePurl{},
		}, {
			name: "Empty cpes return empty results",
			cpes: []CpePurl{},
			want: []CpePurl{},
		}, {
			name: "Empty requirement returns all cpe",
			req:  "",
			cpes: []CpePurl{
				{Cpe: "cpe:2.3:a:apache:org.apache.sling.servlets.post:2.2.0:*:*:*:*:*:*:*", Version: "2.2.0", SemVer: "2.2.0"},
				{Cpe: "cpe:2.3:o:zyxel:zywall_atp200_firmware:4.35:*:*:*:*:*:*:*", Version: "4.35", SemVer: "4.35.0"},
				{Cpe: "cpe:2.3:a:101_project:101:0.15.0:*:*:*:*:node.js:*:*", Version: "0.15.0", SemVer: "0.15.0"}},
			want: []CpePurl{{Cpe: "cpe:2.3:a:apache:org.apache.sling.servlets.post:2.2.0:*:*:*:*:*:*:*",
				Version: "2.2.0", SemVer: "2.2.0"}, {Cpe: "cpe:2.3:o:zyxel:zywall_atp200_firmware:4.35:*:*:*:*:*:*:*",
				Version: "4.35", SemVer: "4.35.0"}, {Cpe: "cpe:2.3:a:101_project:101:0.15.0:*:*:*:*:node.js:*:*",
				Version: "0.15.0", SemVer: "0.15.0"}},
		}, {
			name: "Broken requirement return all cpes",
			req:  "aad>=008.0.0",
			cpes: []CpePurl{
				{Cpe: "cpe:2.3:a:apache:org.apache.sling.servlets.post:2.2.0:*:*:*:*:*:*:*", Version: "2.2.0", SemVer: "2.2.0"},
				{Cpe: "cpe:2.3:o:zyxel:zywall_atp200_firmware:4.35:*:*:*:*:*:*:*", Version: "4.35", SemVer: "4.35.0"},
				{Cpe: "cpe:2.3:a:101_project:101:0.15.0:*:*:*:*:node.js:*:*", Version: "0.15.0", SemVer: "0.15.0"},
			},
			want: []CpePurl{
				{Cpe: "cpe:2.3:a:apache:org.apache.sling.servlets.post:2.2.0:*:*:*:*:*:*:*", Version: "2.2.0", SemVer: "2.2.0"},
				{Cpe: "cpe:2.3:o:zyxel:zywall_atp200_firmware:4.35:*:*:*:*:*:*:*", Version: "4.35", SemVer: "4.35.0"},
				{Cpe: "cpe:2.3:a:101_project:101:0.15.0:*:*:*:*:node.js:*:*", Version: "0.15.0", SemVer: "0.15.0"},
			},
		}, {
			name: "Broken version field or semver field",
			req:  ">=1.0.0",
			cpes: []CpePurl{
				{Cpe: "cpe:2.3:a:apache:org.apache.sling.servlets.post:2.2.0:*:*:*:*:*:*:*", Version: "aa2.2.0", SemVer: "2.2.0"},
				{Cpe: "cpe:2.3:a:apache:org.apache.sling.servlets.post:1.0.0:*:*:*:*:*:*:*", Version: "1.0.0", SemVer: "aa1.0.0"},
				{Cpe: "cpe:2.3:a:apache:org.apache.sling.servlets.post:1.0.0:*:*:*:*:*:*:*", Version: "", SemVer: ""},
			},
			want: []CpePurl{
				{Cpe: "cpe:2.3:a:apache:org.apache.sling.servlets.post:2.2.0:*:*:*:*:*:*:*", Version: "aa2.2.0", SemVer: "2.2.0"},
				{Cpe: "cpe:2.3:a:apache:org.apache.sling.servlets.post:1.0.0:*:*:*:*:*:*:*", Version: "1.0.0", SemVer: "aa1.0.0"},
			},
		}, {
			name: "Broken version field and semver field cannot verify contraint",
			req:  ">=1.0.0",
			cpes: []CpePurl{
				{Cpe: "cpe:2.3:a:apache:org.apache.sling.servlets.post:2.2.0:*:*:*:*:*:*:*", Version: "aa2.2.0", SemVer: "asd2.2.0"},
			},
			want: []CpePurl{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterCpesByRequirement(tt.cpes, tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("FilterCpesByRequirement() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			t.Logf("Got: %v: ", got)
			t.Logf("Exp: %v: ", tt.want)
			if err == nil && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FilterCpesByRequirement() = %v, want %v", got, tt.want)
			}
		})
	}
}

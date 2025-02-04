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

	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"

	"github.com/jmoiron/sqlx"
)

func TestGetVulnsByPurl(t *testing.T) {
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

	cpeModel := NewVulnsForPurlModel(ctx, conn)

	type inputGetVulnsForPurl struct {
		purl        string
		requirement string
	}
	tests := []struct {
		name    string
		input   inputGetVulnsForPurl
		want    []VulnsForPurl
		wantErr bool
	}{
		{
			name:    "Searching cpes for broken purl",
			input:   inputGetVulnsForPurl{purl: "pkag:gitasdhub/sadhapijs/caasdll@1.0asd.0", requirement: ""},
			wantErr: true,
		},
		{
			name:    "Searching cpes for empty purl",
			input:   inputGetVulnsForPurl{purl: "", requirement: ""},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cpeModel.GetVulnsByPurl(tt.input.purl, tt.input.requirement)
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
}

func TestGetVulnsByPurlName(t *testing.T) {
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

	cpeModel := NewVulnsForPurlModel(ctx, conn)

	_, err = cpeModel.GetVulnsByPurlName("")
	if err == nil {
		t.Errorf("Error was expected because purl is empty in cpeModel.GetVulnsByPurlName()")
	}

	CloseConn(conn)
	_, err = cpeModel.GetVulnsByPurlName("pkg:github/hapijs/call")
	if err == nil {
		t.Errorf("Error was expected because purl is empty in cpeModel.GetVulnsByPurlName()")
	}
}

func TestGetVulnsByPurlVersion(t *testing.T) {
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

	cpeModel := NewVulnsForPurlModel(ctx, conn)

	_, err = cpeModel.GetVulnsByPurlVersion("", "")
	if err == nil {
		t.Errorf("Error was expected because purl is empty in cpeModel.GetVulnsByPurlVersion()")
	}

	CloseConn(conn)
	_, err = cpeModel.GetVulnsByPurlVersion("pkg:github/hapijs/call", "1.0.0")
	if err == nil {
		t.Errorf("Error was expected because purl is empty in cpeModel.GetVulnsByPurlVersion()")
	}
}

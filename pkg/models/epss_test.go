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

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"

	"testing"

	myconfig "scanoss.com/vulnerabilities/pkg/config"

	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"
)

func TestGetEPSSByCVEs(t *testing.T) {
	ctx := context.Background()
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()

	s := ctxzap.Extract(ctx).Sugar()

	db, err := sqlx.Connect("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer CloseDB(db)

	err = loadTestSQLDataFilesWithSchema(db, nil, nil, []string{"./tests/epss.sql"})
	if err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}

	serverConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}

	epssModel := NewEPSSModel(s, serverConfig, db)

	// Test with multiple CVEs
	cves := []string{"CVE-2017-9302", "CVE-2015-0269", "CVE-2018-10083"}
	results, err := epssModel.GetEPSSByCVEs(ctx, cves)
	if err != nil {
		t.Errorf("GetEPSSByCVEs() error = %v", err)
	}
	if len(results) != 3 {
		t.Errorf("GetEPSSByCVEs() expected 3 results, got %d", len(results))
	}
	// The scores must survive the scan, not just the row count. epss_data columns are
	// TEXT like the rest of the schema, so this covers the TEXT to float32 conversion.
	want := map[string][2]float32{
		"CVE-2017-9302":  {0.00143, 0.5124},
		"CVE-2015-0269":  {0.00285, 0.6832},
		"CVE-2018-10083": {0.00891, 0.8215},
	}
	for _, got := range results {
		exp, ok := want[got.Cve]
		if !ok {
			t.Errorf("GetEPSSByCVEs() returned unexpected CVE %v", got.Cve)
			continue
		}
		if got.Epss != exp[0] {
			t.Errorf("GetEPSSByCVEs() %v epss = %v, want %v", got.Cve, got.Epss, exp[0])
		}
		if got.Percentile != exp[1] {
			t.Errorf("GetEPSSByCVEs() %v percentile = %v, want %v", got.Cve, got.Percentile, exp[1])
		}
	}
}

func TestGetEPSSByCVEsEmpty(t *testing.T) {
	ctx := context.Background()
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	s := ctxzap.Extract(ctx).Sugar()

	db, err := sqlx.Connect("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer CloseDB(db)

	serverConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}

	err = loadTestSQLDataFilesWithSchema(db, nil, nil, []string{"./tests/epss.sql"})
	if err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}

	epssModel := NewEPSSModel(s, serverConfig, db)

	// Test with empty slice
	results, err := epssModel.GetEPSSByCVEs(ctx, []string{})
	if err != nil {
		t.Errorf("GetEPSSByCVEs() with empty slice error = %v", err)
	}
	if len(results) != 0 {
		t.Errorf("GetEPSSByCVEs() with empty slice expected 0 results, got %d", len(results))
	}
}

func TestGetEPSSByCVEsNotFound(t *testing.T) {
	ctx := context.Background()
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	s := ctxzap.Extract(ctx).Sugar()

	db, err := sqlx.Connect("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer CloseDB(db)

	serverConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}

	err = loadTestSQLDataFilesWithSchema(db, nil, nil, []string{"./tests/epss.sql"})
	if err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}

	epssModel := NewEPSSModel(s, serverConfig, db)

	// Test with non-existent CVEs
	cves := []string{"CVE-NONEXISTENT-1", "CVE-NONEXISTENT-2"}
	results, err := epssModel.GetEPSSByCVEs(ctx, cves)
	if err != nil {
		t.Errorf("GetEPSSByCVEs() error = %v", err)
	}
	if len(results) != 0 {
		t.Errorf("GetEPSSByCVEs() with non-existent CVEs expected 0 results, got %d", len(results))
	}
}

func TestGetEPSSByCVEsSingleCVE(t *testing.T) {
	ctx := context.Background()
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	s := ctxzap.Extract(ctx).Sugar()

	db, err := sqlx.Connect("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer CloseDB(db)

	serverConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}

	err = loadTestSQLDataFilesWithSchema(db, nil, nil, []string{"./tests/epss.sql"})
	if err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}

	epssModel := NewEPSSModel(s, serverConfig, db)

	// Test with single CVE
	cves := []string{"CVE-2018-10083"}
	results, err := epssModel.GetEPSSByCVEs(ctx, cves)
	if err != nil {
		t.Errorf("GetEPSSByCVEs() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("GetEPSSByCVEs() expected 1 result, got %d", len(results))
	}
	if len(results) > 0 && results[0].Cve != "CVE-2018-10083" {
		t.Errorf("GetEPSSByCVEs() expected CVE-2018-10083, got %s", results[0].Cve)
	}
}

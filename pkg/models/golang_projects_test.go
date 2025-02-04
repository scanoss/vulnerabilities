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
	"fmt"
	"testing"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	pkggodevclient "github.com/guseggert/pkggodev-client"
	"github.com/jmoiron/sqlx"

	"scanoss.com/vulnerabilities/pkg/config"
	zlog "scanoss.com/vulnerabilities/pkg/logger"
)

const ScanossPapiURL = "github.com/scanoss/papi"
const VersionV001 = "v0.0.1"
const VersionV002 = "v0.0.2"
const MITLicense = "MIT"

func TestGolangProjectUrlsSearch(t *testing.T) {
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
	err = LoadTestSQLData(db, ctx, conn)
	if err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}
	myConfig, err := config.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}
	myConfig.Components.CommitMissing = true
	myConfig.Database.Trace = true
	golangProjModel := NewGolangProjectModel(ctx, zlog.S, conn, myConfig)

	url, err := golangProjModel.GetGolangUrlsByPurlNameType("google.golang.org/grpc", "golang", "")
	if err != nil {
		t.Errorf("FAILED: golang_projects.GetUrlsByPurlName() error = %v", err)
	}
	if len(url.PurlName) == 0 {
		t.Errorf("FAILED: golang_projects.GetGoLangURLByPurlString() No URLs returned from query")
	}
	fmt.Printf("Golang URL: %#v\n", url)

	url, err = golangProjModel.GetGolangUrlsByPurlNameType("NONEXISTENT", "none", "")
	if err != nil {
		t.Errorf("FAILED: golang_projects.GetGolangUrlsByPurlNameType() error = %v", err)
	}
	if len(url.PurlName) > 0 {
		t.Errorf("FAILED: golang_projects.GetGolangUrlsByPurlNameType() URLs found when none should be: %v", golangProjModel)
	}
	fmt.Printf("No Urls: %v\n", url)

	_, err = golangProjModel.GetGolangUrlsByPurlNameType("NONEXISTENT", "", "")
	if err == nil {
		t.Errorf("FAILED: golang_projects.GetGolangUrlsByPurlNameType() error = did not get an error")
	} else {
		fmt.Printf("Got expected error = %v\n", err)
	}
	_, err = golangProjModel.GetGolangUrlsByPurlNameType("", "", "")
	if err == nil {
		t.Errorf("FAILED: golang_projects.GetURLsByPurlString() error = did not get an error")
	} else {
		fmt.Printf("Got expected error = %v\n", err)
	}
	_, err = golangProjModel.GetGoLangURLByPurlString("", "")
	if err == nil {
		t.Errorf("FAILED: golang_projects.GetURLsByPurlString() error = did not get an error")
	} else {
		fmt.Printf("Got expected error = %v\n", err)
	}
	_, err = golangProjModel.GetGoLangURLByPurlString("rubbish-purl", "")
	if err == nil {
		t.Errorf("FAILED: golang_projects.GetGoLangURLByPurlString() error = did not get an error")
	} else {
		fmt.Printf("Got expected error = %v\n", err)
	}
	url, err = golangProjModel.GetGoLangURLByPurlString("pkg:golang/google.golang.org/grpc", "")
	if err != nil {
		t.Errorf("FAILED: golang_projects.GetGoLangURLByPurlString() error = %v", err)
	}
	if len(url.PurlName) == 0 {
		t.Errorf("FAILED: golang_projects.GetGoLangURLByPurlString() No URLs returned from query")
	}
	fmt.Printf("Golang URL: %v\n", url)
}

func TestGolangProjectsSearchVersion(t *testing.T) {
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
	err = LoadTestSQLData(db, ctx, conn)
	if err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}
	myConfig, err := config.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("FAILED: failed to load Config: %v", err)
	}
	myConfig.Components.CommitMissing = true
	myConfig.Database.Trace = true
	golangProjModel := NewGolangProjectModel(ctx, zlog.S, conn, myConfig)

	url, err := golangProjModel.GetGolangUrlsByPurlNameTypeVersion("google.golang.org/grpc", "golang", "1.19.0")
	if err != nil {
		t.Errorf("FAILED: golang_projects.GetGolangUrlsByPurlNameTypeVersion() error = %v", err)
	}
	if len(url.PurlName) == 0 {
		t.Errorf("FAILED: golang_projects.GetGolangUrlsByPurlNameTypeVersion() No URLs returned from query")
	}
	fmt.Printf("Golang URL Version: %#v\n", url)

	url, err = golangProjModel.GetGoLangURLByPurlString("pkg:golang/google.golang.org/grpc@v1.19.0", "")
	if err != nil {
		t.Errorf("FAILED: golang_projects.GetGoLangURLByPurlString() error = failed to find purl by version string")
	}
	fmt.Printf("Golang URL Version: %#v\n", url)

	_, err = golangProjModel.GetGolangUrlsByPurlNameTypeVersion("", "", "")
	if err == nil {
		t.Errorf("FAILED: golang_projects.GetGolangUrlsByPurlNameTypeVersion() error = did not get an error")
	} else {
		fmt.Printf("Got expected error = %v\n", err)
	}

	_, err = golangProjModel.GetGolangUrlsByPurlNameTypeVersion("NONEXISTENT", "", "")
	if err == nil {
		t.Errorf("FAILED: golang_projects.GetGolangUrlsByPurlNameTypeVersion() error = did not get an error")
	} else {
		fmt.Printf("Got expected error = %v\n", err)
	}

	_, err = golangProjModel.GetGolangUrlsByPurlNameTypeVersion("NONEXISTENT", "NONEXISTENT", "")
	if err == nil {
		t.Errorf("FAILED: golang_projects.GetGolangUrlsByPurlNameTypeVersion() error = did not get an error")
	} else {
		fmt.Printf("Got expected error = %v\n", err)
	}

	url, err = golangProjModel.GetGoLangURLByPurlString("pkg:golang/google.golang.org/grpc", "22.22.22") // Shouldn't exist
	if err != nil {
		t.Errorf("FAILED: golang_projects.GetGoLangURLByPurlString() error = failed to find purl by version string")
	}
	url, err = golangProjModel.GetGoLangURLByPurlString("pkg:golang/google.golang.org/grpc", "=v1.19.0")
	if err != nil {
		t.Errorf("FAILED: golang_projects.GetGoLangURLByPurlString() error = %v", err)
	}
	if len(url.PurlName) == 0 {
		t.Errorf("FAILED: golang_projects.GetGoLangURLByPurlString() No URLs returned from query")
	}
	fmt.Printf("Golang URL: %v\n", url)
	url, err = golangProjModel.GetGoLangURLByPurlString("pkg:golang/google.golang.org/grpc", "==v1.19.0")
	if err != nil {
		t.Errorf("FAILED: golang_projects.GetGoLangURLByPurlString() error = %v", err)
	}
	if len(url.PurlName) == 0 {
		t.Errorf("FAILED: golang_projects.GetGoLangURLByPurlString() No URLs returned from query")
	}
	fmt.Printf("Golang URL: %v\n", url)

	url, err = golangProjModel.GetGoLangURLByPurlString("pkg:golang/google.golang.org/grpc@1.7.0", "") // Should be missing license
	if err != nil {
		t.Errorf("FAILED: golang_projects.GetGoLangURLByPurlString() error = %v", err)
	}
	if len(url.License) == 0 {
		t.Errorf("FAILED: golang_projects.GetGoLangURLByPurlString() No URL License returned from query")
	}
	fmt.Printf("Golang URL: %v\n", url)
}

func TestGolangProjectsSearchVersionRequirement(t *testing.T) {
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
	err = LoadTestSQLData(db, ctx, conn)
	if err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}
	myConfig, err := config.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}
	myConfig.Components.CommitMissing = true
	golangProjModel := NewGolangProjectModel(ctx, zlog.S, conn, myConfig)

	url, err := golangProjModel.GetGoLangURLByPurlString("pkg:golang/google.golang.org/grpc", ">0.0.4")
	if err != nil {
		t.Errorf("FAILED: golang_projects.GetUrlsByPurlName() error = %v", err)
	}
	if len(url.PurlName) == 0 {
		t.Errorf("FAILED: golang_projects.GetUrlsByPurlName() No URLs returned from query")
	}
	fmt.Printf("Golang URL Version: %#v\n", url)

	url, err = golangProjModel.GetGoLangURLByPurlString("pkg:golang/google.golang.org/grpc", "v0.0.0-201910101010-s3333")
	if err != nil {
		t.Errorf("FAILED: golang_projects.GetUrlsByPurlName() error = %v", err)
	}
	if len(url.PurlName) == 0 {
		t.Errorf("FAILED: golang_projects.GetUrlsByPurlName() No URLs returned from query")
	}
	fmt.Printf("Golang URL Version: %#v\n", url)
}

func TestGolangPkgGoDev(t *testing.T) {
	// Setup test environment and models
	golangProjModel, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Run subtests
	t.Run("QueryPkgGoDev", testQueryPkgGoDev(golangProjModel))
	t.Run("GetLatestPkgGoDev", testGetLatestPkgGoDev(golangProjModel))
	t.Run("SavePkg", testSavePkg(golangProjModel))
}

// setupTestEnvironment creates the test environment and returns cleanup function.
func setupTestEnvironment(t *testing.T) (*GolangProjects, func()) {
	t.Helper()
	ctx := context.Background()

	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}

	db, err := sqlx.Connect("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}

	conn, err := db.Connx(ctx)
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}

	err = LoadTestSQLData(db, ctx, conn)
	if err != nil {
		t.Fatalf("failed to load SQL test data: %v", err)
	}

	myConfig, err := config.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}
	myConfig.Components.CommitMissing = true

	golangProjModel := NewGolangProjectModel(ctx, zlog.S, conn, myConfig)

	cleanup := func() {
		CloseConn(conn)
		CloseDB(db)
		zlog.SyncZap()
	}

	return golangProjModel, cleanup
}

func testQueryPkgGoDev(model *GolangProjects) func(t *testing.T) {
	return func(t *testing.T) {
		_, _, _, err := model.queryPkgGoDev("", "")
		if err == nil {
			t.Error("FAILED: golang_projects.queryPkgGoDev() error = did not get an error")
		}
	}
}

func testGetLatestPkgGoDev(model *GolangProjects) func(t *testing.T) {
	return func(t *testing.T) {
		t.Run("GRPC Package", func(t *testing.T) {
			url, err := model.getLatestPkgGoDev("google.golang.org/grpc", "golang", "v0.0.0-201910101010-s3333")
			if err != nil {
				t.Errorf("error = %v", err)
			}
			if len(url.PurlName) == 0 {
				t.Error("No URLs returned from query")
			}
		})

		t.Run("Scanoss Package", func(t *testing.T) {
			url, err := model.getLatestPkgGoDev(ScanossPapiURL, "golang", "v0.0.3")
			if err != nil {
				t.Errorf("error = %v", err)
			}
			if len(url.PurlName) == 0 {
				t.Error("No URLs returned from query")
			}
		})
	}
}

func testSavePkg(model *GolangProjects) func(t *testing.T) {
	return func(t *testing.T) {
		t.Run("Empty URL", func(t *testing.T) {
			var allURL AllURL
			var license License
			var version Version

			err := model.savePkg(allURL, version, license, nil)
			if err == nil {
				t.Error("expected error with empty URL")
			}
		})

		t.Run("Missing MineID", func(t *testing.T) {
			allURL := AllURL{PurlName: ScanossPapiURL}
			var license License
			var version Version

			err := model.savePkg(allURL, version, license, nil)
			if err == nil {
				t.Error("expected error with missing MineID")
			}
		})

		t.Run("Valid Package", func(t *testing.T) {
			allURL, version, license, comp := createValidTestData()
			err := model.savePkg(allURL, version, license, &comp)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})

		t.Run("Updated Version", func(t *testing.T) {
			allURL, version, license, comp := createValidTestData()
			allURL.Version = VersionV002
			version.VersionName = VersionV002
			comp.Version = VersionV002

			err := model.savePkg(allURL, version, license, &comp)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func createValidTestData() (AllURL, Version, License, pkggodevclient.Package) {
	allURL := AllURL{
		PurlName: ScanossPapiURL,
		MineID:   45,
		Version:  VersionV001,
	}

	version := Version{
		VersionName: VersionV001,
		ID:          5958021,
	}

	license := License{
		LicenseName: MITLicense,
		ID:          5614,
	}

	comp := pkggodevclient.Package{
		Package:                   ScanossPapiURL,
		IsPackage:                 true,
		IsModule:                  true,
		Version:                   VersionV001,
		License:                   MITLicense,
		HasRedistributableLicense: true,
		HasStableVersion:          true,
		HasTaggedVersion:          true,
		HasValidGoModFile:         true,
		Repository:                ScanossPapiURL,
	}

	return allURL, version, license, comp
}

func TestGolangProjectsSearchBadSql(t *testing.T) {
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
	s := ctxzap.Extract(ctx).Sugar()
	myConfig, err := config.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}
	myConfig.Components.CommitMissing = true
	golangProjModel := NewGolangProjectModel(ctx, s, conn, myConfig)

	_, err = golangProjModel.GetGoLangURLByPurlString("pkg:golang/google.golang.org/grpc", "")
	if err == nil {
		t.Errorf("FAILED: golang_projects.GetGoLangURLByPurlString() error = did not get an error")
	} else {
		fmt.Printf("Got expected error = %v\n", err)
	}
	_, err = golangProjModel.GetGoLangURLByPurlString("pkg:golang/google.golang.org/grpc@1.19.0", "")
	if err == nil {
		t.Errorf("FAILED: golang_projects.GetGoLangURLByPurlString() error = did not get an error")
	} else {
		fmt.Printf("Got expected error = %v\n", err)
	}
	_, err = golangProjModel.getLatestPkgGoDev("github.com/scanoss/does-not-exist", "golang", "v0.0.99")
	if err == nil {
		t.Errorf("FAILED: golang_projects.getLatestPkgGoDev() error = did not get an error: %v", err)
	} else {
		fmt.Printf("Got expected error = %v\n", err)
	}
}

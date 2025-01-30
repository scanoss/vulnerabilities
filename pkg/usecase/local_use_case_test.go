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

package usecase

import (
	"context"
	"fmt"
	"testing"

	myconfig "scanoss.com/vulnerabilities/pkg/config"
	"scanoss.com/vulnerabilities/pkg/dtos"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	zlog "scanoss.com/vulnerabilities/pkg/logger"
	"scanoss.com/vulnerabilities/pkg/models"
)

func TestGetVulneraibilityUseCase(t *testing.T) {
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
	defer models.CloseDB(db)
	conn, err := db.Connx(ctx) // Get a connection from the pool
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer models.CloseConn(conn)
	err = models.LoadTestSQLData(db, ctx, conn)
	if err != nil {
		t.Fatalf("an error '%v' was not expected when loading test data", err)
	}
	var vulnRequestData = `
		{
			"purls": [
	   	 		{
	   	   			"purl": "pkg:github/tseliot/screen-resolution-extra"
	   	 		},{
					"purl": ""
				},
	  	 		{
	   	   			"purl": "pkg:github/candlepin/candlepin"
	   	 		}
			]
		}`

	myConfig, err := myconfig.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}
	vulnUc := NewLocalVulnerabilitiesUseCase(ctx, conn, myConfig)
	requestDto, err := dtos.ParseVulnerabilityInput([]byte(vulnRequestData))
	if err != nil {
		t.Fatalf("an error '%s' was not expected when parsing input json", err)
	}
	zlog.S.Infof("Request DTO: %+v", requestDto)
	vulns, err := vulnUc.GetVulnerabilities(requestDto)
	if err != nil {
		t.Fatalf("an error '%s' was not expected when getting vulnerabilities", err)
	}
	fmt.Printf("Vulneravility response: %+v\n", vulns)

	// Broken purl
	var vulnRequestDataBad = `
			{
			  "purls": [
				{
				  "purl": "pkg:github/"
				}
			  ]
			}
		`
	requestDto, err = dtos.ParseVulnerabilityInput([]byte(vulnRequestDataBad))
	if err != nil {
		t.Fatalf("an error '%s' was not expected when parsing input json", err)
	}
	vulns, err = vulnUc.GetVulnerabilities(requestDto)
	if err == nil {
		t.Fatalf("did not get an expected error: %v", vulns)
	}
	fmt.Printf("Got expected error: %+v\n", err)
}

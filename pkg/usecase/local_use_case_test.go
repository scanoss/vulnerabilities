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

	"scanoss.com/vulnerabilities/pkg/config"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"

	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	"scanoss.com/vulnerabilities/pkg/dtos"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"scanoss.com/vulnerabilities/pkg/models"
)

func TestGetVulnerabilityUseCase(t *testing.T) {
	err := zlog.NewSugaredDevLogger()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a sugared logger", err)
	}
	defer zlog.SyncZap()
	ctx := ctxzap.ToContext(context.Background(), zlog.L)
	s := ctxzap.Extract(ctx).Sugar()
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
	serverConfig, err := config.NewServerConfig(nil)
	if err != nil {
		t.Fatalf("failed to load Config: %v", err)
	}
	components := []dtos.ComponentDTO{
		{
			Purl: "pkg:github/tseliot/screen-resolution-extra",
		},
		{
			Purl: "",
		},
		{
			Purl: "pkg:github/candlepin/candlepin",
		},
	}
	vulnUc := NewLocalVulnerabilitiesUseCase(ctx, s, serverConfig, db)
	vulns, err := vulnUc.GetVulnerabilities(ctx, components)
	if err != nil {
		t.Fatalf("an error '%s' was not expected when getting vulnerabilities", err)
	}
	fmt.Printf("Vulneravility response: %+v\n", vulns)
}

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
	cpes, err := cpeModel.GetCpesByPurlName("pkg:apache/sling")
	if err != nil {
		t.Errorf("cpeModel.GetCpesByPurlName() error = %v", err)
	}
	if len(cpes) == 0 {
		t.Errorf("versions.GetVersionByName() No version returned from query")
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

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

// Helpers shared by the tests in this package. They live in a _test.go file so they do
// not ship in the binary; LoadTestSchema and LoadTestSQLData stay in common.go because
// tests in other packages call them.

package models

import (
	"context"

	"github.com/jmoiron/sqlx"
)

// loadTestSQLDataFilesWithSchema loads the production schema followed by the given data
// fixtures. Use this instead of loadTestSQLDataFiles when a test only needs a subset of
// the fixtures, since the fixtures do not create their own tables.
func loadTestSQLDataFilesWithSchema(db *sqlx.DB, ctx context.Context, conn *sqlx.Conn, files []string) error {
	if err := LoadTestSchema(db, ctx, conn); err != nil {
		return err
	}
	return loadTestSQLDataFiles(db, ctx, conn, files)
}

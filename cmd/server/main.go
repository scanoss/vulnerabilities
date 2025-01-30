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

// Package main loads the gRPC Vulneravility Server Service
package main

import (
	"fmt"
	"os"

	"scanoss.com/vulnerabilities/pkg/cmd"
)

// main starts the gRPC Vulneravility Service.
func main() {
	// Launch the Vulnerabilities Server Service
	if err := cmd.RunServer(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "ERROR: Server launch error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

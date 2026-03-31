// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018-2026 SCANOSS.COM
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

package entities

import "github.com/scanoss/go-grpc-helper/pkg/grpc/domain"

type Component struct {
	Purl        string `json:"purl"`
	Requirement string `json:"requirement,omitempty"`
	Version     string `json:"version,omitempty"`
	Status      domain.ComponentStatus
}

// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2025 SCANOSS.COM
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

package service

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/scanoss/go-grpc-helper/pkg/grpc/interceptors"
	common "github.com/scanoss/papi/api/commonv2"
)

// TestEmptyComponentsIsBadRequest pins that an empty batch is answered as the
// caller's error. Before, it fell through to the interceptor's default and reached
// REST clients as HTTP 500 "internal server error".
func TestEmptyComponentsIsBadRequest(t *testing.T) {
	s := vulnerabilityServer{}
	ctx := context.Background()
	empty := &common.ComponentsRequest{}

	_, errVulns := s.GetComponentsVulnerabilities(ctx, empty)
	_, errCpes := s.GetComponentsCpes(ctx, empty)
	for name, err := range map[string]error{"GetComponentsVulnerabilities": errVulns, "GetComponentsCpes": errCpes} {
		var re *interceptors.ResponseError
		if !errors.As(err, &re) {
			t.Errorf("%s(empty) error = %v, want a ResponseError", name, err)
			continue
		}
		if re.HTTPCode != http.StatusBadRequest {
			t.Errorf("%s(empty) HTTPCode = %d, want %d", name, re.HTTPCode, http.StatusBadRequest)
		}
	}
}

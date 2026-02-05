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

	"github.com/scanoss/go-grpc-helper/pkg/grpc/domain"
	"go.uber.org/zap"
	"scanoss.com/vulnerabilities/pkg/entities"
	"scanoss.com/vulnerabilities/pkg/helpers"

	"github.com/jmoiron/sqlx"
	myconfig "scanoss.com/vulnerabilities/pkg/config"
	"scanoss.com/vulnerabilities/pkg/dtos"
	"scanoss.com/vulnerabilities/pkg/models"

	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
)

type CpeUseCase struct {
	ctx     context.Context
	conn    *sqlx.Conn
	cpePurl *models.CpePurlModel
	db      *sqlx.DB
	config  *myconfig.ServerConfig
	s       *zap.SugaredLogger
}

// NewCpe creates a new instance of the vulnerability Use Case.
func NewCpe(ctx context.Context, conn *sqlx.Conn, config *myconfig.ServerConfig, db *sqlx.DB, s *zap.SugaredLogger) *CpeUseCase {
	return &CpeUseCase{
		ctx:     ctx,
		conn:    conn,
		cpePurl: models.NewCpePurlModel(ctx, conn),
		db:      db,
		config:  config,
		s:       s,
	}
}

func (d CpeUseCase) GetCpes(componentDTOs []dtos.ComponentDTO) ([]dtos.CpeComponentOutput, error) {
	components := helpers.SanitizeComponents(componentDTOs)
	processedComponents := helpers.GetComponentsVersion(d.ctx, d.config, d.s, d.db, components)
	var validComponents []entities.Component
	var out []dtos.CpeComponentOutput
	for _, c := range processedComponents {
		if c.Status.StatusCode == domain.Success {
			validComponents = append(validComponents, c)
			continue
		}
		out = append(out, dtos.CpeComponentOutput{
			Requirement:     c.Requirement,
			Version:         c.Requirement,
			Purl:            c.Purl,
			Cpes:            []string{},
			ComponentStatus: c.Status,
		})
	}

	for _, c := range validComponents {
		var item dtos.CpeComponentOutput
		item.Version = c.Requirement
		item.Requirement = c.Requirement
		item.Purl = c.Purl
		item.Cpes = []string{}
		item.ComponentStatus = c.Status

		cpePurl, err := d.cpePurl.GetCpeByPurl(c.Purl, c.Version)
		if err != nil {
			zlog.S.Errorf("Problem encountered extracting CPEs for: %v - %v.", c, err)
			item.ComponentStatus = domain.ComponentStatus{
				Message:    fmt.Sprintf("Problem encountered extracting CPEs for: %v", c.Purl),
				StatusCode: domain.ComponentWithoutInfo,
			}
			out = append(out, item)
			continue
		}
		for i := range cpePurl {
			item.Cpes = append(item.Cpes, cpePurl[i].Cpe)
		}
		if len(item.Cpes) == 0 {
			item.ComponentStatus = domain.ComponentStatus{
				Message:    fmt.Sprintf("No CPEs found for: %v", c.Purl),
				StatusCode: domain.ComponentWithoutInfo,
			}
		}
		out = append(out, item)
	}
	return out, nil
}

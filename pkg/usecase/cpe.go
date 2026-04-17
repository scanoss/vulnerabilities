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
	"strings"

	"github.com/jmoiron/sqlx"
	compHelper "github.com/scanoss/go-component-helper/componenthelper"
	compoHelperUtils "github.com/scanoss/go-component-helper/componenthelper/utils"
	"github.com/scanoss/go-grpc-helper/pkg/grpc/domain"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
	"go.uber.org/zap"
	myconfig "scanoss.com/vulnerabilities/pkg/config"
	"scanoss.com/vulnerabilities/pkg/dtos"
	"scanoss.com/vulnerabilities/pkg/models"
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

func (d CpeUseCase) GetCpes(componentDTOs []compHelper.ComponentDTO) ([]dtos.CpeComponentOutput, error) {
	processedComponents := compHelper.GetComponentsVersion(compHelper.ComponentVersionCfg{
		Ctx:        d.ctx,
		S:          d.s,
		DB:         d.db,
		Input:      componentDTOs,
		MaxWorkers: d.config.Source.SCANOSS.MaxWorkers,
	})
	var validComponents []compHelper.Component
	var out []dtos.CpeComponentOutput
	for _, c := range processedComponents {
		switch c.Status.StatusCode { //nolint:exhaustive // deprecated codes and unrelated codes intentionally omitted
		case domain.ComponentNotFound, domain.VersionNotFound:
			if !compoHelperUtils.HasSemverOperator(c.Requirement) {
				c.Version = c.Requirement
				validComponents = append(validComponents, c)
			} else {
				out = append(out, dtos.CpeComponentOutput{
					Requirement:     c.Requirement,
					Version:         c.Version,
					Purl:            c.Purl,
					Cpes:            []string{},
					ComponentStatus: c.Status,
				})
			}
		case domain.Success:
			validComponents = append(validComponents, c)
		case domain.InvalidPurl, domain.NoInfo, domain.InvalidSemver:
			out = append(out, dtos.CpeComponentOutput{
				Requirement:     c.Requirement,
				Version:         c.Version,
				Purl:            c.Purl,
				Cpes:            []string{},
				ComponentStatus: c.Status,
			})
		}
	}

	for _, c := range validComponents {
		var item dtos.CpeComponentOutput
		item.Version = c.Version
		item.Requirement = c.Requirement
		item.Purl = c.Purl
		item.Cpes = []string{}

		cpePurl, err := d.cpePurl.GetCpeByPurl(c.Purl, strings.TrimPrefix(c.Version, "v"))
		if err != nil {
			zlog.S.Errorf("Problem encountered extracting CPEs for: %v - %v.", c, err)
			item.ComponentStatus = domain.ComponentStatus{
				Message:    fmt.Sprintf("Problem encountered extracting CPEs for: %v", c.Purl),
				StatusCode: domain.NoInfo,
			}
			out = append(out, item)
			continue
		}
		for i := range cpePurl {
			item.Cpes = append(item.Cpes, cpePurl[i].Cpe)
		}
		if len(item.Cpes) == 0 {
			if c.Status.StatusCode == domain.VersionNotFound || c.Status.StatusCode == domain.ComponentNotFound {
				item.ComponentStatus = c.Status
			} else {
				item.ComponentStatus = domain.ComponentStatus{
					Message:    fmt.Sprintf("No CPEs found for: %v", c.Purl),
					StatusCode: domain.NoInfo,
				}
			}
			out = append(out, item)
			continue
		}

		item.ComponentStatus = domain.ComponentStatus{
			Message:    "",
			StatusCode: domain.Success,
		}
		out = append(out, item)
	}
	return out, nil
}

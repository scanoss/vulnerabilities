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
	"errors"

	"github.com/jmoiron/sqlx"
	"github.com/scanoss/go-models/pkg/scanoss"
	"github.com/scanoss/go-models/pkg/types"
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
}

// NewCpe creates a new instance of the vulnerability Use Case.
func NewCpe(ctx context.Context, conn *sqlx.Conn, config *myconfig.ServerConfig, db *sqlx.DB) *CpeUseCase {
	return &CpeUseCase{ctx: ctx, conn: conn, cpePurl: models.NewCpePurlModel(ctx, conn), db: db}
}

func (d CpeUseCase) GetCpes(components []dtos.ComponentDTO) ([]dtos.CpeComponentOutput, error) {
	sc := scanoss.New(d.db)
	var out []dtos.CpeComponentOutput
	var problems = false
	for _, c := range components {
		if len(c.Purl) == 0 {
			zlog.S.Infof("Empty Purl string supplied for: %v. Skipping", c)
			continue
		}
		// VulnerabilitiesOutput
		var item dtos.CpeComponentOutput
		item.Requirement = c.Requirement
		item.Purl = c.Purl
		item.Cpes = []string{}

		component, err := sc.Component.GetComponent(d.ctx, types.ComponentRequest{Purl: c.Purl, Requirement: c.Requirement})
		if err != nil {
			zlog.S.Errorf("Problem encountered extracting CPEs for: %v - %v.", c, err)
			problems = true
			continue
		}
		item.Version = component.Version

		cpePurl, err := d.cpePurl.GetCpeByPurl(component.Purl, component.Version)
		for i := range cpePurl {
			item.Cpes = append(item.Cpes, cpePurl[i].Cpe)
		}
		zlog.S.Debugf("Output Vulnerabilities: %v", cpePurl)
		if err != nil {
			zlog.S.Errorf("Problem encountered extracting CPEs for: %v - %v.", c, err)
			problems = true
			continue
			// TODO add a placeholder in the response?
		}
		out = append(out, item)
	}

	if problems {
		zlog.S.Errorf("Encountered issues while processing vulnerabilities: %v", components)
		return []dtos.CpeComponentOutput{}, errors.New("encountered issues while processing vulnerabilities")
	}

	return out, nil
}

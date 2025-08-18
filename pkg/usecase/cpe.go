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

	myconfig "scanoss.com/vulnerabilities/pkg/config"
	"scanoss.com/vulnerabilities/pkg/dtos"
	"scanoss.com/vulnerabilities/pkg/models"

	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
)

type CpeUseCase struct {
	ctx     context.Context
	conn    *sqlx.Conn
	cpePurl *models.CpePurlModel
}

// NewCpe creates a new instance of the vulnerability Use Case.
func NewCpe(ctx context.Context, conn *sqlx.Conn, config *myconfig.ServerConfig) *CpeUseCase {
	return &CpeUseCase{ctx: ctx, conn: conn, cpePurl: models.NewCpePurlModel(ctx, conn)}
}

func (d CpeUseCase) GetCpes(components []dtos.Component) ([]dtos.CpeComponentOutput, error) {
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
		cpePurl, err := d.cpePurl.GetCpeByPurl(c.Purl, c.Requirement)
		for i := range cpePurl {
			item.Cpes = append(item.Cpes, cpePurl[i].Cpe)
			item.Version = cpePurl[i].Version
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

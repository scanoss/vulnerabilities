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
	"scanoss.com/vulnerabilities/pkg/resolver"
)

// cpeLookup is what one CPE fallback hop returns.
type cpeLookup struct {
	cpes       []string
	sourcePurl string
}

// cpesFromSourcePurl retries a component that has no CPEs of its own against the
// purl its source_purl_id points at.
func (d CpeUseCase) cpesFromSourcePurl(c compHelper.Component) (cpeLookup, bool) {
	return resolver.RecoverFromSource(d.ctx, c.Purl, c.Requirement,
		d.resolver.SourcePurlFor,
		func(_ context.Context, purl, requirement string) (cpeLookup, error) {
			found, err := d.cpePurl.GetCpeByPurl(purl, strings.TrimPrefix(requirement, "v"))
			if err != nil {
				return cpeLookup{}, err
			}
			cpes := make([]string, 0, len(found))
			for i := range found {
				cpes = append(cpes, found[i].Cpe)
			}
			return cpeLookup{cpes: cpes}, nil
		},
		func(r cpeLookup) bool { return len(r.cpes) > 0 },
		func(r cpeLookup, sourcePurl string) cpeLookup {
			r.sourcePurl = sourcePurl
			return r
		})
}

type CpeUseCase struct {
	ctx      context.Context
	cpePurl  *models.CpePurlModel
	db       *sqlx.DB
	config   *myconfig.ServerConfig
	s        *zap.SugaredLogger
	resolver *resolver.Resolver
}

// NewCpe creates a new instance of the vulnerability Use Case.
func NewCpe(ctx context.Context, config *myconfig.ServerConfig, db *sqlx.DB, s *zap.SugaredLogger) *CpeUseCase {
	return &CpeUseCase{
		ctx:      ctx,
		cpePurl:  models.NewCpePurlModel(ctx, db),
		db:       db,
		config:   config,
		s:        s,
		resolver: resolver.New(s, db),
	}
}

func (d CpeUseCase) GetCpes(componentDTOs []compHelper.ComponentDTO) ([]dtos.CpeComponentOutput, error) {
	processedComponents := resolver.ResolveComponents(d.ctx, d.s, d.resolver, componentDTOs,
		d.config.Source.SCANOSS.MaxWorkers)
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
			// Nothing under this purl: a package that shares its code with an
			// upstream repository carries no CPEs of its own, so retry there.
			if recovered, ok := d.cpesFromSourcePurl(c); ok {
				item.Cpes = recovered.cpes
				item.ComponentStatus = domain.ComponentStatus{
					Message:    resolver.SourceFallbackMessage(recovered.sourcePurl),
					StatusCode: resolver.SourceFallbackStatus,
				}
				out = append(out, item)
				continue
			}
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

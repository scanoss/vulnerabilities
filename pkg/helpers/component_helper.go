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

package helpers

import (
	"context"
	"strings"
	"sync"

	"github.com/jmoiron/sqlx"
	"github.com/scanoss/go-models/pkg/scanoss"
	"github.com/scanoss/go-models/pkg/types"
	"go.uber.org/zap"
	"scanoss.com/vulnerabilities/pkg/config"

	"github.com/scanoss/go-grpc-helper/pkg/grpc/domain"
	purlhelper "github.com/scanoss/go-purl-helper/pkg"
	"scanoss.com/vulnerabilities/pkg/dtos"
	"scanoss.com/vulnerabilities/pkg/entities"
	"scanoss.com/vulnerabilities/pkg/utils"
)

func SanitizeComponents(componentDTOs []dtos.ComponentDTO) []entities.Component {
	var components []entities.Component
	for _, dto := range componentDTOs {
		// Check for empty purl
		if dto.Purl == "" {
			components = append(components, entities.Component{
				Purl:        dto.Purl,
				Requirement: dto.Requirement,
				Status: domain.ComponentStatus{
					Message:    "Empty Purl",
					StatusCode: domain.InvalidPurl,
				},
			})
			continue
		}
		purlParts := strings.Split(dto.Purl, "@")
		// If version contains a semver operator, move it to requirement and strip from purl
		if len(purlParts) == 2 && utils.HasSemverOperator(purlParts[1]) {
			dto.Requirement = purlParts[1]
			dto.Purl = purlParts[0]
		}
		_, err := purlhelper.PurlFromString(dto.Purl)
		if err != nil {
			components = append(components, entities.Component{
				Purl:        dto.Purl,
				Requirement: dto.Requirement,
				Status: domain.ComponentStatus{
					Message:    "Invalid Purl",
					StatusCode: domain.InvalidPurl,
				},
			})
			continue
		}
		if dto.Requirement == "" && len(purlParts) == 2 {
			dto.Purl = purlParts[0]
			dto.Requirement = purlParts[1]
		}
		components = append(components, entities.Component{
			Requirement: dto.Requirement,
			Purl:        dto.Purl,
			Status: domain.ComponentStatus{
				Message:    "",
				StatusCode: domain.Success,
			},
		})
	}
	return components
}

// componentVersionWorker processes components from the jobs channel, resolving each component's
// version by querying the SCANOSS API. If a resolved version is found, it replaces the original;
// otherwise the existing version is preserved.
func componentVersionWorker(ctx context.Context, s *zap.SugaredLogger, db *sqlx.DB, jobs chan entities.Component, results chan entities.Component, wg *sync.WaitGroup) {
	defer wg.Done()
	sc := scanoss.New(db)
	for j := range jobs {
		processedComponent := entities.Component{
			Purl:        j.Purl,
			Requirement: j.Requirement,
			Version:     j.Version,
			Status:      j.Status,
		}

		if processedComponent.Status.StatusCode != domain.Success {
			results <- processedComponent
			continue
		}

		// Set by default version = requirement
		var component types.ComponentResponse
		component, err := sc.Component.GetComponent(ctx, types.ComponentRequest{
			Purl:        j.Purl,
			Requirement: j.Requirement,
		})
		if err != nil {
			s.Warnf("Failed to get component: %s, %s", j.Purl, j.Requirement)
			results <- processedComponent
			continue
		}
		if component.Version != "" {
			processedComponent.Version = component.Version
		}
		results <- processedComponent
	}
}

// GetComponentsVersion resolves the concrete version for each component using a fan-out/fan-in
// concurrency pattern. It spawns up to MaxWorkers goroutines (capped by the number of components)
// to query versions in parallel, then collects and returns the results.
func GetComponentsVersion(ctx context.Context, config *config.ServerConfig, s *zap.SugaredLogger, db *sqlx.DB, components []entities.Component) []entities.Component {
	numJobs := len(components)
	jobs := make(chan entities.Component, numJobs)
	results := make(chan entities.Component, numJobs)
	numWorkers := min(config.Source.SCANOSS.MaxWorkers, numJobs)
	wg := sync.WaitGroup{}
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go componentVersionWorker(ctx, s, db, jobs, results, &wg)
	}
	for _, c := range components {
		jobs <- c
	}
	close(jobs)
	go func() {
		wg.Wait()
		close(results)
	}()
	var processedComponents []entities.Component
	for r := range results {
		processedComponents = append(processedComponents, r)
	}
	return processedComponents
}

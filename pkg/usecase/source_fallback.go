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
	"sync"

	compHelper "github.com/scanoss/go-component-helper/componenthelper"
	"github.com/scanoss/go-grpc-helper/pkg/grpc/domain"
	"scanoss.com/vulnerabilities/pkg/dtos"
	"scanoss.com/vulnerabilities/pkg/helpers"
	"scanoss.com/vulnerabilities/pkg/resolver"
)

// sourceLookup is what one fallback hop returns: the vulnerabilities found and,
// when they came from a source purl, which one.
type sourceLookup struct {
	vulnerabilities []dtos.VulnerabilitiesOutput
	sourcePurl      string
}

// applySourceFallback fills in components that came back with nothing by looking
// them up again under their linked source-code purl.
//
// Vulnerability data is keyed by purl string, so a package that shares its code
// with an upstream repository has no rows of its own: pkg:npm/browser-mjml-table
// carries none, while pkg:github/mjmlio/mjml does. Recovered results are marked
// WARNING with the source purl named in the message, so a caller can tell them
// apart from a direct hit.
//
// Only components that found nothing are retried, and each retry is one point
// lookup per source, so a batch of clean components costs one source resolution
// each rather than a second full pass.
func (us VulnerabilityUseCase) applySourceFallback(ctx context.Context,
	vulnerabilities *dtos.VulnerabilityOutput, components []compHelper.Component,
) {
	byPurl := make(map[string]compHelper.Component, len(components))
	for _, c := range components {
		byPurl[c.Purl] = c
	}

	var pending []int
	for i := range vulnerabilities.Components {
		if len(vulnerabilities.Components[i].Vulnerabilities) == 0 {
			pending = append(pending, i)
		}
	}
	if len(pending) == 0 {
		return
	}

	jobs := make(chan int, len(pending))
	wg := sync.WaitGroup{}
	workers := min(max(us.config.Source.SCANOSS.MaxWorkers, 1), len(pending))
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				us.recoverComponent(ctx, &vulnerabilities.Components[idx], byPurl)
			}
		}()
	}
	for _, idx := range pending {
		jobs <- idx
	}
	close(jobs)
	wg.Wait()
}

// recoverComponent retries one empty component against its source purl and, on a
// hit, rewrites the entry in place.
func (us VulnerabilityUseCase) recoverComponent(ctx context.Context,
	component *dtos.VulnerabilityComponentOutput, byPurl map[string]compHelper.Component,
) {
	if err := ctx.Err(); err != nil {
		return
	}
	requirement := component.Requirement
	if resolved, ok := byPurl[component.Purl]; ok {
		requirement = resolved.Requirement
	}

	recovered, ok := resolver.RecoverFromSource(ctx, component.Purl, requirement,
		us.resolver.SourcePurlFor,
		us.vulnerabilitiesForPurl,
		func(r sourceLookup) bool { return len(r.vulnerabilities) > 0 },
		func(r sourceLookup, sourcePurl string) sourceLookup {
			r.sourcePurl = sourcePurl
			return r
		})
	if !ok {
		return
	}

	component.Vulnerabilities = recovered.vulnerabilities
	component.ComponentStatus = domain.ComponentStatus{
		Message:    resolver.SourceFallbackMessage(recovered.sourcePurl),
		StatusCode: resolver.SourceFallbackStatus,
	}
}

// vulnerabilitiesForPurl resolves one purl and gathers its vulnerabilities from
// every enabled source, merged the same way the main path merges them.
func (us VulnerabilityUseCase) vulnerabilitiesForPurl(ctx context.Context, purl, requirement string) (sourceLookup, error) {
	resolved := resolver.ResolveComponents(ctx, us.s, us.resolver,
		[]compHelper.ComponentDTO{{Purl: purl, Requirement: requirement}}, 1)
	if len(resolved) == 0 {
		return sourceLookup{}, nil
	}
	component := resolved[0]
	// A version the source does not publish is not fatal here: the OSV tables may
	// still carry it, exactly as the main path treats an unresolved version.
	if component.Status.StatusCode == domain.InvalidPurl {
		return sourceLookup{}, nil
	}

	var local, osv dtos.VulnerabilityOutput
	if us.config.Source.SCANOSS.Enabled {
		out, err := NewLocalVulnerabilitiesUseCase(ctx, us.s, us.config, us.db).
			GetVulnerabilities(ctx, []compHelper.Component{component})
		if err != nil {
			return sourceLookup{}, err
		}
		local = out
	}
	if us.config.Source.OSV.Enabled {
		osv = NewOSVUseCase(us.s, us.config, us.db).Execute(ctx, []compHelper.Component{component})
	}

	merged := helpers.MergeOSVAndLocalVulnerabilities(local, osv)
	var found []dtos.VulnerabilitiesOutput
	for _, c := range merged.Components {
		found = append(found, c.Vulnerabilities...)
	}
	return sourceLookup{vulnerabilities: found}, nil
}

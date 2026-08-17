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

// Parity check between OSVModel and the OSV HTTP API it replaces. This is what
// validates the version matching in osv.go: the API used to decide which
// vulnerabilities applied to a version, and now we do.
//
// Skipped unless both PG_DSN and OSV_PARITY are set, so it never runs in CI and never
// reaches the network unless asked:
//
//	PG_DSN='postgres://user:pass@host:5432/db?sslmode=disable' OSV_PARITY=1 \
//	  go test ./pkg/models/ -run TestOSVParity -v -timeout 900s
//
// Anything the API reports that the model misses is a false negative: a vulnerability
// the service would stop reporting. Those are the ones that matter.

package models

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
)

// osvAPIQuery asks the live OSV API which vulnerabilities affect a purl at a version.
func osvAPIQuery(t *testing.T, client *http.Client, purl, version string) []string {
	t.Helper()
	body, err := json.Marshal(map[string]interface{}{
		"package": map[string]string{"purl": purl},
		"version": version,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, "https://api.osv.dev/v1/query", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Logf("  API call failed for %v@%v: %v", purl, version, err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Logf("  API returned %d for %v@%v", resp.StatusCode, purl, version)
		return nil
	}
	var decoded struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Logf("  decode failed for %v@%v: %v", purl, version, err)
		return nil
	}
	ids := make([]string, 0, len(decoded.Vulns))
	for _, v := range decoded.Vulns {
		ids = append(ids, v.ID)
	}
	sort.Strings(ids)
	return ids
}

func TestOSVParity(t *testing.T) {
	dsn := os.Getenv("PG_DSN")
	if dsn == "" || os.Getenv("OSV_PARITY") == "" {
		t.Skip("PG_DSN and OSV_PARITY not both set")
	}
	_ = zlog.NewSugaredDevLogger()
	defer zlog.SyncZap()
	ctx := context.Background()
	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer db.Close()
	model := NewOSVModel(zlog.S, db)
	client := &http.Client{Timeout: 30 * time.Second}

	// Sample real (purl, version) pairs across ecosystems, drawn from stored ranges so
	// the version is one the data actually says something about.
	type sample struct {
		Purl    string `db:"purl"`
		Version string `db:"version"`
	}
	var samples []sample
	err = db.SelectContext(ctx, &samples, `
		SELECT purl, version FROM (
			SELECT o.purl,
			       coalesce(nullif(o.affected_versions[1], ''), nullif(o.introduced_version,''), '') AS version,
			       row_number() OVER (PARTITION BY split_part(o.purl,'/',1) ORDER BY o.id) AS rn
			FROM osv o
			WHERE split_part(o.purl,'/',1) IN ('pkg:npm','pkg:pypi','pkg:maven','pkg:golang','pkg:cargo','pkg:gem')
			  AND o.purl NOT LIKE '%25%'
		) t WHERE version <> '' AND version <> '0' AND rn <= 4
		ORDER BY purl`)
	if err != nil {
		t.Fatalf("sampling failed: %v", err)
	}
	t.Logf("comparing %d purl/version pairs", len(samples))

	var checked, agree, falseNegatives, falsePositives int
	for _, s := range samples {
		apiIDs := osvAPIQuery(t, client, s.Purl, s.Version)
		vulns, err := model.GetVulnsByPurl(ctx, s.Purl, s.Version)
		if err != nil {
			t.Errorf("%v@%v: model failed: %v", s.Purl, s.Version, err)
			continue
		}
		dbIDs := make([]string, 0, len(vulns))
		for _, v := range vulns {
			dbIDs = append(dbIDs, v.ID)
		}
		sort.Strings(dbIDs)

		inAPI := map[string]bool{}
		for _, id := range apiIDs {
			inAPI[id] = true
		}
		inDB := map[string]bool{}
		for _, id := range dbIDs {
			inDB[id] = true
		}
		var missing, extra []string
		for _, id := range apiIDs {
			if !inDB[id] {
				missing = append(missing, id)
			}
		}
		for _, id := range dbIDs {
			if !inAPI[id] {
				extra = append(extra, id)
			}
		}
		checked++
		switch {
		case len(missing) == 0 && len(extra) == 0:
			agree++
			fmt.Printf("  OK    %-45s %-12s api=%-3d db=%-3d\n", s.Purl, s.Version, len(apiIDs), len(dbIDs))
		default:
			if len(missing) > 0 {
				falseNegatives++
			}
			if len(extra) > 0 {
				falsePositives++
			}
			fmt.Printf("  DIFF  %-45s %-12s api=%-3d db=%-3d missing=%d extra=%d\n",
				s.Purl, s.Version, len(apiIDs), len(dbIDs), len(missing), len(extra))
			if len(missing) > 0 {
				fmt.Printf("          missing (API has, model does not): %v\n", missing)
			}
			if len(extra) > 0 {
				fmt.Printf("          extra   (model has, API does not): %v\n", extra)
			}
		}
	}
	fmt.Printf("\nchecked=%d agree=%d with_false_negatives=%d with_false_positives=%d\n",
		checked, agree, falseNegatives, falsePositives)
	if checked == 0 {
		t.Errorf("no pairs were compared")
	}
	// False negatives are the failure that matters: vulnerabilities the service would
	// stop reporting relative to the API.
	if falseNegatives > 0 {
		t.Errorf("%d of %d pairs miss vulnerabilities the API reports", falseNegatives, checked)
	}
}

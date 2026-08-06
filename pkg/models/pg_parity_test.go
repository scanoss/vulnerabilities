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

// Parity check between the rewritten queries and the SQL they replaced, run against a
// real PostgreSQL database. Skipped unless PG_DSN is set, so it does not run in CI.
//
// This is the test that justifies the port in version_range.go. Run it after touching
// the queries or the version matching:
//
//	PG_DSN='postgres://user:pass@host:5432/db?sslmode=disable' \
//	  go test ./pkg/models/ -run TestComparePostgres -v -timeout 900s
//
// Expect lost=0 everywhere. Anything lost means the rewrite reports fewer
// vulnerabilities than production does, which is a regression regardless of whether the
// new answer is arguably more correct.
//
// Last run against the production database: 48 purl/version pairs, lost=0, gained=0.
// The variant without a version gains rows by design - the query it replaces joined
// cpes.id and nvd_match_criteria_ids.cpe_ids in a way that never matched, so it
// returned 0 CVEs for every purl.

package models

import (
	"context"
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	zlog "github.com/scanoss/zap-logging-helper/pkg/logger"
)

func TestComparePostgres(t *testing.T) {
	dsn := os.Getenv("PG_DSN")
	if dsn == "" {
		t.Skip("PG_DSN not set")
	}
	_ = zlog.NewSugaredDevLogger()
	defer zlog.SyncZap()
	ctx := context.Background()
	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer db.Close()
	model := NewVulnsForPurlModel(db)

	oldNameQuery := `SELECT DISTINCT c2.cve FROM short_cpe_purl scp
		INNER JOIN cpes c ON scp.cpe_id = c.id
		INNER JOIN nvd_match_criteria_ids nmci ON trim(CAST(nmci.cpe_ids AS TEXT), '{}') LIKE '%' || scp.cpe_id || '%'
		INNER JOIN cves c2 ON trim(CAST(nmci.cpe_ids AS TEXT), '{}') LIKE '%' || nmci.match_criteria_id || '%'
		WHERE scp.purl = $1`

	oldVersionQuery := `WITH matching_criteria AS (
	  SELECT array_agg(nmci.match_criteria_id) as criteria_ids
	  FROM short_cpe_purl scp
	  INNER JOIN short_cpes sc ON sc.id = scp.cpe_id
	  INNER JOIN nvd_match_criteria_ids nmci ON nmci.short_cpe_id = sc.id
	  WHERE scp.purl = $1
		AND (
			$2 = nmci.version_start_including
			OR $2 = nmci.version_end_including
			OR (
				(
					(nmci.version_start_excluding = '' AND nmci.version_start_including = '')
					OR (nmci.version_start_excluding != '' AND natural_sort_order($2, 20) > natural_sort_order(nmci.version_start_excluding, 20))
					OR (nmci.version_start_including != '' AND natural_sort_order($2, 20) > natural_sort_order(nmci.version_start_including, 20))
				)
				AND (
					(nmci.version_end_excluding = '' AND nmci.version_end_including = '')
					OR (nmci.version_end_excluding != '' AND natural_sort_order($2, 20) < natural_sort_order(nmci.version_end_excluding, 20))
					OR (nmci.version_end_including != '' AND natural_sort_order($2, 20) < natural_sort_order(nmci.version_end_including, 20))
				)
			)
		)
	)
	SELECT DISTINCT c2.cve
	FROM cves c2, matching_criteria mc
	WHERE c2.match_criteria_ids && mc.criteria_ids`

	set := func(s []string) map[string]bool {
		m := map[string]bool{}
		for _, v := range s {
			m[v] = true
		}
		return m
	}
	diff := func(a, b map[string]bool) []string {
		var out []string
		for k := range a {
			if !b[k] {
				out = append(out, k)
			}
		}
		sort.Strings(out)
		return out
	}

	purls := []string{"pkg:apache/ant", "pkg:apache/arrow", "pkg:anuko/time-tracker", "pkg:apache/allura"}
	comparisons := 0

	fmt.Println("\n########## variant WITHOUT version ##########")
	for _, purl := range purls {
		var oldCves []string
		if err := db.SelectContext(ctx, &oldCves, oldNameQuery, purl); err != nil {
			t.Errorf("%s: original query failed, parity cannot be checked: %v", purl, err)
			continue
		}
		newVulns, err := model.GetVulnsByPurlName(ctx, purl)
		if err != nil {
			t.Errorf("%s: GetVulnsByPurlName failed: %v", purl, err)
			continue
		}
		var newCves []string
		for _, v := range newVulns {
			newCves = append(newCves, v.Cve)
		}
		o, n := set(oldCves), set(newCves)
		lost := diff(o, n)
		fmt.Printf("  %-28s old=%-4d new=%-4d lost=%d gained=%d\n",
			purl, len(o), len(n), len(lost), len(diff(n, o)))
		if len(lost) > 0 {
			t.Errorf("%s: rewrite lost %d CVEs the original returned: %v", purl, len(lost), lost)
		}
	}

	fmt.Println("\n########## variant WITH version ##########")
	for _, purl := range purls {
		// real versions this component has CPEs for
		var versions []string
		err := db.SelectContext(ctx, &versions, `SELECT DISTINCT v.version_name
			FROM short_cpe_purl scp
			JOIN cpes c ON c.short_cpe_id = scp.cpe_id
			JOIN versions v ON v.id = c.version_id
			WHERE scp.purl = $1 AND v.version_name <> '' ORDER BY v.version_name LIMIT 12`, purl)
		if err != nil {
			t.Errorf("%s: could not list versions: %v", purl, err)
			continue
		}
		for _, ver := range versions {
			var oldCves []string
			if err := db.SelectContext(ctx, &oldCves, oldVersionQuery, purl, ver); err != nil {
				t.Errorf("%s@%s: original query failed, parity cannot be checked: %v", purl, ver, err)
				continue
			}
			newVulns, err := model.GetVulnsByPurlVersion(ctx, purl, ver)
			if err != nil {
				t.Errorf("%s@%s: GetVulnsByPurlVersion failed: %v", purl, ver, err)
				continue
			}
			var newCves []string
			for _, v := range newVulns {
				newCves = append(newCves, v.Cve)
			}
			o, n := set(oldCves), set(newCves)
			lost, gained := diff(o, n), diff(n, o)
			flag := "  "
			if len(lost) > 0 {
				flag = "!!"
			}
			fmt.Printf("%s %-24s %-14s old=%-4d new=%-4d lost=%-3d gained=%-3d\n",
				flag, purl, ver, len(o), len(n), len(lost), len(gained))
			if len(lost) > 0 {
				t.Errorf("%s@%s: rewrite lost %d CVEs the original returned: %v",
					purl, ver, len(lost), lost)
			}
			comparisons++
		}
	}
	// A silent pass with nothing compared would look identical to a clean run.
	if comparisons == 0 {
		t.Errorf("no purl/version pairs were compared; the sample data may have changed")
	}
}

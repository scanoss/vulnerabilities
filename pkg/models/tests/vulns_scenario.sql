-- Test data only. The schema comes from testSchemaDDL in pkg/models/test_schema.go; do not add DDL here.
--
-- A deterministic vulnerability scenario for one component, wired the way the real
-- schema links things: purl -> short_cpe_purl.short_cpe_id -> nvd_match_criteria.short_cpe_id
-- -> match_criteria_id -> cve_match_criteria -> cve.
--
-- The base fixtures cannot exercise this path at all: every row in
-- nvd_match_criteria.sql has short_cpe_id = null, so nothing joins through to a cve.
--
-- Component: pkg:github/scanoss/testcomp, versions 1.0.0 / 2.0.0 / 3.0.0.
-- The four match criteria below cover each version-bound combination, so the
-- version filtering can be asserted at its edges.

INSERT INTO short_cpe_purl (short_cpe_id, purl) VALUES (900001, 'pkg:github/scanoss/testcomp');

INSERT INTO cpe (id, cpe, short_cpe_id, version_name, version_semver) VALUES (900001, 'cpe:2.3:a:scanoss:testcomp:1.0.0:*:*:*:*:*:*:*', 900001, '1.0.0', '1.0.0');
INSERT INTO cpe (id, cpe, short_cpe_id, version_name, version_semver) VALUES (900002, 'cpe:2.3:a:scanoss:testcomp:2.0.0:*:*:*:*:*:*:*', 900001, '2.0.0', '2.0.0');
INSERT INTO cpe (id, cpe, short_cpe_id, version_name, version_semver) VALUES (900003, 'cpe:2.3:a:scanoss:testcomp:3.0.0:*:*:*:*:*:*:*', 900001, '3.0.0', '3.0.0');

INSERT INTO nvd_match_criteria (match_criteria_id, short_cpe_id, version_start_including, version_start_excluding, version_end_including, version_end_excluding) VALUES ('MC-END-INCL-2', 900001, '', '', '2.0.0', '');
INSERT INTO nvd_match_criteria (match_criteria_id, short_cpe_id, version_start_including, version_start_excluding, version_end_including, version_end_excluding) VALUES ('MC-START-INCL-3', 900001, '3.0.0', '', '', '');
INSERT INTO nvd_match_criteria (match_criteria_id, short_cpe_id, version_start_including, version_start_excluding, version_end_including, version_end_excluding) VALUES ('MC-EXACT-1', 900001, '1.0.0', '', '1.0.0', '');
INSERT INTO nvd_match_criteria (match_criteria_id, short_cpe_id, version_start_including, version_start_excluding, version_end_including, version_end_excluding) VALUES ('MC-BETWEEN-EXCL', 900001, '', '1.0.0', '', '3.0.0');
INSERT INTO nvd_match_criteria (match_criteria_id, short_cpe_id, version_start_including, version_start_excluding, version_end_including, version_end_excluding) VALUES ('MC-UNRELATED', 900099, '', '', '', '');

INSERT INTO cve (id, cve, severity, published, modified, summary, match_criteria_ids) VALUES (900001, 'CVE-TEST-0001', 'HIGH', '2020-01-15', '2020-06-30', 'affects up to and including 2.0.0', '{MC-END-INCL-2}');
INSERT INTO cve (id, cve, severity, published, modified, summary, match_criteria_ids) VALUES (900002, 'CVE-TEST-0002', 'LOW', '2021-02-20', '2021-07-01', 'affects 3.0.0 and later', '{MC-START-INCL-3}');
INSERT INTO cve (id, cve, severity, published, modified, summary, match_criteria_ids) VALUES (900003, 'CVE-TEST-0003', 'CRITICAL', '2019-03-25', '2019-08-10', 'affects exactly 1.0.0', '{MC-EXACT-1}');
INSERT INTO cve (id, cve, severity, published, modified, summary, match_criteria_ids) VALUES (900004, 'CVE-TEST-0004', 'MEDIUM', '2022-04-05', '2022-09-15', 'affects strictly between 1.0.0 and 3.0.0', '{MC-BETWEEN-EXCL,MC-UNRELATED}');
INSERT INTO cve (id, cve, severity, published, modified, summary, match_criteria_ids) VALUES (900005, 'CVE-TEST-9999', 'HIGH', '2023-05-05', '2023-10-20', 'unrelated component', '{MC-UNRELATED}');

-- Test data only. The schema comes from testSchemaDDL in pkg/models/test_schema.go; do not add DDL here.
--
-- A deterministic vulnerability scenario for one component, wired the way the real
-- schema links things: purl -> short_cpe_purl.cpe_id -> nvd_match_criteria_ids.short_cpe_id
-- -> match_criteria_id -> cves.match_criteria_ids.
--
-- The pre-existing fixtures cannot exercise this path at all: every row in
-- ndv_match_criteria_ids.sql has short_cpe_id = null, because the old query joined
-- through a cpe_ids column the schema does not define.
--
-- Component: pkg:github/scanoss/testcomp, versions 1.0.0 / 2.0.0 / 3.0.0.
-- The four match criteria below cover each version-bound combination, so the
-- version filtering can be asserted at its edges.

INSERT INTO purls (purl, id) VALUES ('pkg:github/scanoss/testcomp', 900001);
INSERT INTO short_cpes (id) VALUES (900001);
INSERT INTO short_cpe_purl (cpe_id, purl_id, purl) VALUES (900001, 900001, 'pkg:github/scanoss/testcomp');

INSERT INTO versions (id, version_name, semver) VALUES (900001, '1.0.0', '1.0.0');
INSERT INTO versions (id, version_name, semver) VALUES (900002, '2.0.0', '2.0.0');
INSERT INTO versions (id, version_name, semver) VALUES (900003, '3.0.0', '3.0.0');

INSERT INTO cpes (cpe, version_id, short_cpe_id) VALUES ('cpe:2.3:a:scanoss:testcomp:1.0.0:*:*:*:*:*:*:*', 900001, 900001);
INSERT INTO cpes (cpe, version_id, short_cpe_id) VALUES ('cpe:2.3:a:scanoss:testcomp:2.0.0:*:*:*:*:*:*:*', 900002, 900001);
INSERT INTO cpes (cpe, version_id, short_cpe_id) VALUES ('cpe:2.3:a:scanoss:testcomp:3.0.0:*:*:*:*:*:*:*', 900003, 900001);

-- everything up to and including 2.0.0 -> matches 1.0.0, 2.0.0
INSERT INTO nvd_match_criteria_ids (match_criteria_id, short_cpe_id, version_start_including, version_start_excluding, version_end_including, version_end_excluding)
VALUES ('MC-END-INCL-2', 900001, '', '', '2.0.0', '');
-- everything from 3.0.0 upwards -> matches 3.0.0
INSERT INTO nvd_match_criteria_ids (match_criteria_id, short_cpe_id, version_start_including, version_start_excluding, version_end_including, version_end_excluding)
VALUES ('MC-START-INCL-3', 900001, '3.0.0', '', '', '');
-- exactly 1.0.0
INSERT INTO nvd_match_criteria_ids (match_criteria_id, short_cpe_id, version_start_including, version_start_excluding, version_end_including, version_end_excluding)
VALUES ('MC-EXACT-1', 900001, '1.0.0', '', '1.0.0', '');
-- strictly between 1.0.0 and 3.0.0 -> matches 2.0.0 only
INSERT INTO nvd_match_criteria_ids (match_criteria_id, short_cpe_id, version_start_including, version_start_excluding, version_end_including, version_end_excluding)
VALUES ('MC-BETWEEN-EXCL', 900001, '', '1.0.0', '', '3.0.0');
-- belongs to a different component: must never show up for testcomp
INSERT INTO nvd_match_criteria_ids (match_criteria_id, short_cpe_id, version_start_including, version_start_excluding, version_end_including, version_end_excluding)
VALUES ('MC-UNRELATED', 900099, '', '', '', '');

INSERT INTO cves (cve, severity, published, modified, summary, match_criteria_ids)
VALUES ('CVE-TEST-0001', 'HIGH', '2020-01-15', '2020-06-30', 'affects up to and including 2.0.0', '{MC-END-INCL-2}');
INSERT INTO cves (cve, severity, published, modified, summary, match_criteria_ids)
VALUES ('CVE-TEST-0002', 'LOW', '2021-02-20', '2021-07-01', 'affects 3.0.0 and later', '{MC-START-INCL-3}');
INSERT INTO cves (cve, severity, published, modified, summary, match_criteria_ids)
VALUES ('CVE-TEST-0003', 'CRITICAL', '2019-03-25', '2019-08-10', 'affects exactly 1.0.0', '{MC-EXACT-1}');
-- two criteria on one CVE, to check the row is matched via either of them
INSERT INTO cves (cve, severity, published, modified, summary, match_criteria_ids)
VALUES ('CVE-TEST-0004', 'MEDIUM', '2022-04-05', '2022-09-15', 'affects strictly between 1.0.0 and 3.0.0', '{MC-BETWEEN-EXCL,MC-UNRELATED}');
-- unrelated component only: must never show up for testcomp
INSERT INTO cves (cve, severity, published, modified, summary, match_criteria_ids)
VALUES ('CVE-TEST-9999', 'HIGH', '2023-05-05', '2023-10-20', 'unrelated component', '{MC-UNRELATED}');

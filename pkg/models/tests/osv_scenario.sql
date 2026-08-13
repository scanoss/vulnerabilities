-- Test data only. The schema comes from testSchemaDDL in pkg/models/test_schema.go; do not add DDL here.
--
-- A deterministic OSV scenario for one component, covering the shapes the real table
-- takes. Versions and vectors are made up, but the shapes are drawn from production:
--
--   * both matching mechanisms: an explicit affected_versions list, and a range built
--     from introduced_version / fixed_version / last_affected
--   * several rows per vulnerability, because the table is keyed by range and averages
--     15.6 rows per vulnerability while the response carries one entry
--   * rows of the same vulnerability disagreeing on modified, which is what decides
--     whose summary and aliases win (the newest)
--   * multiple CVSS vectors on one vulnerability, and a non-CVSS score of type Ubuntu
--     that the service is expected to skip
--
-- Component under test: pkg:npm/testosv

-- OSV-TEST-0001: single range, 1.0.0 <= v < 2.0.0. Two CVSS vectors.
INSERT INTO osv (id, ecosystem, purl, introduced_version, last_affected, fixed_version,
                 affected_versions, aliases, summary, severity, published, modified, indexed_date)
VALUES ('OSV-TEST-0001', 'npm', 'pkg:npm/testosv', '1.0.0', '', '2.0.0',
        '{}', '{CVE-2026-0001,GHSA-test-0001}', 'affects 1.x only', 'HIGH',
        '2026-01-15', '2026-02-20', '2026-03-01');

-- OSV-TEST-0002: explicit version list, no range at all. This is how 70.7% of
-- production rows look.
INSERT INTO osv (id, ecosystem, purl, introduced_version, last_affected, fixed_version,
                 affected_versions, aliases, summary, severity, published, modified, indexed_date)
VALUES ('OSV-TEST-0002', 'npm', 'pkg:npm/testosv', '', '', '',
        '{3.0.0,3.0.1}', '{CVE-2026-0002}', 'affects exactly 3.0.0 and 3.0.1', 'MODERATE',
        '2026-02-15', '2026-03-20', '2026-03-21');

-- OSV-TEST-0003: two rows, one per range. 1.0.0 <= v < 1.5.0 and 4.0.0 <= v < 4.2.0.
-- A version matching either range must return the vulnerability once.
INSERT INTO osv (id, ecosystem, purl, introduced_version, last_affected, fixed_version,
                 affected_versions, aliases, summary, severity, published, modified, indexed_date)
VALUES ('OSV-TEST-0003', 'npm', 'pkg:npm/testosv', '0', '', '1.5.0',
        '{}', '{CVE-2026-0003}', 'affects early and late', 'CRITICAL',
        '2026-03-15', '2026-04-20', '2026-04-21');
INSERT INTO osv (id, ecosystem, purl, introduced_version, last_affected, fixed_version,
                 affected_versions, aliases, summary, severity, published, modified, indexed_date)
VALUES ('OSV-TEST-0003', 'npm', 'pkg:npm/testosv', '4.0.0', '', '4.2.0',
        '{}', '{CVE-2026-0003}', 'affects early and late', 'CRITICAL',
        '2026-03-15', '2026-04-20', '2026-04-21');

-- OSV-TEST-0004: last_affected instead of fixed_version, so 5.0.0 itself is affected.
INSERT INTO osv (id, ecosystem, purl, introduced_version, last_affected, fixed_version,
                 affected_versions, aliases, summary, severity, published, modified, indexed_date)
VALUES ('OSV-TEST-0004', 'npm', 'pkg:npm/testosv', '4.5.0', '5.0.0', '',
        '{}', '{}', 'affects up to and including 5.0.0', 'LOW',
        '2026-04-15', '2026-05-20', '2026-05-21');

-- OSV-TEST-0005: two rows that disagree on modified, summary, severity and aliases.
-- 137,302 production (id, purl) pairs do this. The newest row must win.
INSERT INTO osv (id, ecosystem, purl, introduced_version, last_affected, fixed_version,
                 affected_versions, aliases, summary, severity, published, modified, indexed_date)
VALUES ('OSV-TEST-0005', 'npm', 'pkg:npm/testosv', '0', '', '9.9.9',
        '{}', '{CVE-STALE}', 'stale summary', 'LOW',
        '2026-05-15', '2026-05-16', '2026-05-17');
INSERT INTO osv (id, ecosystem, purl, introduced_version, last_affected, fixed_version,
                 affected_versions, aliases, summary, severity, published, modified, indexed_date)
VALUES ('OSV-TEST-0005', 'npm', 'pkg:npm/testosv', '0', '', '9.9.9',
        '{}', '{CVE-CURRENT}', 'current summary', 'HIGH',
        '2026-05-15', '2026-07-30', '2026-07-31');

-- A different component: must never appear in results for pkg:npm/testosv.
INSERT INTO osv (id, ecosystem, purl, introduced_version, last_affected, fixed_version,
                 affected_versions, aliases, summary, severity, published, modified, indexed_date)
VALUES ('OSV-TEST-9999', 'npm', 'pkg:npm/unrelated', '0', '', '9.9.9',
        '{}', '{CVE-2026-9999}', 'unrelated component', 'HIGH',
        '2026-06-15', '2026-07-20', '2026-07-21');

-- CVSS vectors. OSV-TEST-0001 carries two, which is why they live in their own table.
INSERT INTO osv_severity (id, type, score)
VALUES ('OSV-TEST-0001', 'CVSS_V3', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N');
INSERT INTO osv_severity (id, type, score)
VALUES ('OSV-TEST-0001', 'CVSS_V4', 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N');
INSERT INTO osv_severity (id, type, score)
VALUES ('OSV-TEST-0002', 'CVSS_V3', 'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H');
-- Not a CVSS vector: the service must skip it rather than fail, as it did with the API.
INSERT INTO osv_severity (id, type, score) VALUES ('OSV-TEST-0004', 'Ubuntu', 'medium');

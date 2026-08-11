-- Test data only. The schema comes from testSchemaDDL in pkg/models/test_schema.go; do not add DDL here.
INSERT INTO licenses (id, license_name, spdx_id, is_spdx) VALUES (15, 'GPL-2 or GPL-3', 'GPL-2.0-only/GPL-3.0-only/DoesNotExist', true);
INSERT INTO licenses (id, license_name, spdx_id, is_spdx) VALUES (109, '3-Clause BSD License', 'BSD-3-Clause', true);
INSERT INTO licenses (id, license_name, spdx_id, is_spdx) VALUES (552, 'Apache 2.0', 'Apache-2.0', true);
INSERT INTO licenses (id, license_name, spdx_id, is_spdx) VALUES (850, 'Apache License 2.0', 'Apache-2.0', true);
INSERT INTO licenses (id, license_name, spdx_id, is_spdx) VALUES (1378, 'BSD', '0BSD', true);
INSERT INTO licenses (id, license_name, spdx_id, is_spdx) VALUES (2815, 'GPL-2.0-only', 'GPL-2.0-only', true);
INSERT INTO licenses (id, license_name, spdx_id, is_spdx) VALUES (2821, 'GPL-3.0-only', 'GPL-3.0-only', true);
INSERT INTO licenses (id, license_name, spdx_id, is_spdx) VALUES (4863, 'ISC', 'ISC', true);
INSERT INTO licenses (id, license_name, spdx_id, is_spdx) VALUES (5236, 'LGPLv2.1+', 'LGPL-2.1-or-later', true);
INSERT INTO licenses (id, license_name, spdx_id, is_spdx) VALUES (5614, 'MIT', 'MIT', true);
INSERT INTO licenses (id, license_name, spdx_id, is_spdx) VALUES (9999, '', '', false);

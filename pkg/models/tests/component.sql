-- Test data only. The schema comes from testSchemaDDL in pkg/models/test_schema.go; do not add DDL here.
-- Serving `component`: the resolver's entry point, replacing the mining
-- all_urls/mines/versions lookup. source_purl_id links a package to the repository
-- it was built from, which is the link the source-purl fallback follows - the shape
-- production has for pkg:npm/log4js -> pkg:github/log4js-node/log4js-node.
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:deb/debian/capstone', NULL, NULL, '686718b7-a8c5-5c9c-b377-1b83efe62ea0', 'f44b8951-f046-5968-8bb0-622c45c59870');
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:deb/debian/jbigkit', NULL, NULL, 'e92a94de-e129-57e7-b0b3-0c86bc88bd6e', 'fa6c7b21-4bf9-5928-a623-d06ea81123f2');
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:deb/debian/node-cached-path-relative', NULL, NULL, '4ab860d2-e7c4-5981-84c2-5b5778db0e76', '6a77a6d3-a7a3-51ff-98b4-2c6a21469844');
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:deb/debian/snapd', NULL, NULL, 'fa047c91-ac23-5747-941c-22a20d2586bb', 'f9d42d01-a940-5c7b-b04f-1e3153efc6b9');
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:deb/ubuntu/jbigkit', NULL, NULL, '25698b28-c4f1-5c7f-baaf-db5e407c4a2d', 'fa6c7b21-4bf9-5928-a623-d06ea81123f2');
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:deb/ubuntu/maas', NULL, NULL, '3d4f75ca-7e98-5a4a-a652-2972be11e011', '7a14b6b4-e99a-5275-b766-092afd58754b');
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:deb/ubuntu/node-cached-path-relative', NULL, NULL, '7347d42c-c2c5-57f3-9a9f-84dc71a788f1', '6a77a6d3-a7a3-51ff-98b4-2c6a21469844');
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:deb/ubuntu/screen-resolution-extra', NULL, NULL, 'faec1735-27ee-5aed-882b-90ddebcdc8d2', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:deb/ubuntu/selinux', NULL, NULL, 'e8acd73d-f787-5d85-bdad-869c74927614', '03bdf8a3-9fb1-584b-b2c3-fbf53e613e55');
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:deb/ubuntu/snapd', NULL, NULL, '8e8362ab-9e88-5e8c-8b44-e353df3531d8', 'f9d42d01-a940-5c7b-b04f-1e3153efc6b9');
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:deb/ubuntu/update-manager', NULL, NULL, 'b937211d-6bcc-576c-b562-7f3106293fe6', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/ashaffer/cached-path-relative', NULL, NULL, '6a77a6d3-a7a3-51ff-98b4-2c6a21469844', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/c2fo/comb', NULL, NULL, 'a6b63eb6-80af-56c4-a823-1eaf7c94af45', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/calderawp/caldera-forms', NULL, NULL, '53e8f90d-5e22-596b-9c9f-9ceecc2d80ea', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/candlepin/candlepin', NULL, NULL, '508fd29b-30fd-5061-8df3-58259f5e71a7', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/cantemo/portal-docker', NULL, NULL, '5bcdba37-0ca4-5281-8e0e-e37504a34aa8', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/capstone-engine/capstone', NULL, NULL, 'f44b8951-f046-5968-8bb0-622c45c59870', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/cunaedy/cart-engine', NULL, NULL, '26bf4061-664e-5f69-a121-ec93a391a4ce', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/giuliomoro/checkinstall', NULL, NULL, '9bf8b136-8a0c-5719-9627-e1ac09a99dc0', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/hapijs/call', NULL, NULL, '5468d648-054b-5338-8135-8dc3c6c453ae', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/jaemk/cached', NULL, NULL, 'b7f13c4b-6668-58e9-9218-f9661806e265', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/lxc/lxd', NULL, NULL, '2bd5852f-0dbc-558a-b7f0-9ce32493f616', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/maas/maas', NULL, NULL, '7a14b6b4-e99a-5275-b766-092afd58754b', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/pld-linux/jbigkit', NULL, NULL, 'fa6c7b21-4bf9-5928-a623-d06ea81123f2', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/pld-linux/jbigkit/', NULL, NULL, '631ae197-1fe8-5a5d-927e-03002e50cedc', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/ruxkor/checkinstall', NULL, NULL, '6dab7798-31ca-5f14-883a-11d387cde772', '9bf8b136-8a0c-5719-9627-e1ac09a99dc0');
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/scanoss/testcomp', NULL, NULL, '8bc58e1f-5d09-5f52-bd21-dfb826656e87', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/selinuxproject/selinux', NULL, NULL, '03bdf8a3-9fb1-584b-b2c3-fbf53e613e55', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/snapcore/snapd', NULL, NULL, 'f9d42d01-a940-5c7b-b04f-1e3153efc6b9', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/swatinem/rust-cache', NULL, NULL, '7a1100b6-f4e5-5645-855a-47a35c0d1548', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/thtas/campaignmonitor', NULL, NULL, 'ce6f76eb-94e5-5644-b65b-977a4050a50f', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/tseliot/screen-resolution-extra', NULL, NULL, '9ce534da-a4cf-5af3-8862-91f8dabe9b14', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/ubports/ubuntu-download-manager', NULL, NULL, '7a2c30e0-8d5b-5b32-b59b-2dab709466fd', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/wp-plugins/caldera-forms', NULL, NULL, 'a5fcdf52-67ae-5f94-883f-535a89a76289', '53e8f90d-5e22-596b-9c9f-9ceecc2d80ea');
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/wp-plugins/candidate-application-form', NULL, NULL, '61eca4a8-298c-5da5-8cf1-182d82e23ee5', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/wp-plugins/konnichiwa', NULL, NULL, '3ac087e4-fbcc-5a76-b88c-1b165c679bf8', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/wpplugins/caldera-forms', NULL, NULL, '38b6fa13-4bc5-5266-873a-3380cbf5cc0d', '53e8f90d-5e22-596b-9c9f-9ceecc2d80ea');
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:github/wpplugins/candidate-application-form', NULL, NULL, '90e1878f-8932-529f-bb6a-a5f779eb1172', '61eca4a8-298c-5da5-8cf1-182d82e23ee5');
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:gitlab/redhat/jbigkit', NULL, NULL, 'ffbb284b-f996-51fd-87c7-76c218001223', 'fa6c7b21-4bf9-5928-a623-d06ea81123f2');
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:maven/org.webjars.npm/cached-path-relative', NULL, NULL, '0952805c-d68e-5182-8c15-f5c11e38c498', '6a77a6d3-a7a3-51ff-98b4-2c6a21469844');
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/%40hapi/call', NULL, NULL, '4e2dbb53-f3f8-594a-9939-fab3fb8ada90', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/@hapi/call', NULL, NULL, '208669fd-8715-52b1-8a1c-bee67adf6830', '5468d648-054b-5338-8135-8dc3c6c453ae');
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/cached-path-relative', NULL, NULL, 'de58a8aa-c6da-5154-9def-28466ad3fe62', '6a77a6d3-a7a3-51ff-98b4-2c6a21469844');
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/calmquist.static-server', NULL, NULL, '7ddc44e9-ed83-5592-90f7-102145446ad4', NULL);
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:npm/comb', NULL, NULL, 'c44f7aab-4483-5045-a37a-6721d2b13af1', 'a6b63eb6-80af-56c4-a823-1eaf7c94af45');
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:rpm/centos/jbigkit', NULL, NULL, '63c6b4b6-4007-5a20-becd-194de4578ed2', 'fa6c7b21-4bf9-5928-a623-d06ea81123f2');
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:rpm/fedora/capstone', NULL, NULL, '6d21a079-1931-58de-8828-f71c481bb366', 'f44b8951-f046-5968-8bb0-622c45c59870');
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:rpm/fedora/jbigkit', NULL, NULL, '4c49590b-77b1-5dc4-99d3-787acda9fc25', 'fa6c7b21-4bf9-5928-a623-d06ea81123f2');
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:rpm/fedora/snapd', NULL, NULL, 'a1f621e3-f3fb-5c80-ae41-c2e741f501a7', 'f9d42d01-a940-5c7b-b04f-1e3153efc6b9');
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:rpm/opensuse/capstone', NULL, NULL, '886563bc-de06-5ccd-ac5d-96fad4f88ce7', 'f44b8951-f046-5968-8bb0-622c45c59870');
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:rpm/opensuse/jbigkit', NULL, NULL, 'ded58386-58ef-5a44-88c2-2a318f53f628', 'fa6c7b21-4bf9-5928-a623-d06ea81123f2');
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:rpm/opensuse/lxd', NULL, NULL, 'afa89d77-c3a5-5011-b5d4-225f05ea9fa2', '2bd5852f-0dbc-558a-b7f0-9ce32493f616');
INSERT INTO component (purl, vendor, component, purl_id, source_purl_id) VALUES ('pkg:rpm/opensuse/snapd', NULL, NULL, '5439b74a-c004-5c6f-85cb-b34baec44c13', 'f9d42d01-a940-5c7b-b04f-1e3153efc6b9');

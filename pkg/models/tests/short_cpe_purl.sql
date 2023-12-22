DROP TABLE IF EXISTS t_short_cpe_purl_exported;
CREATE TABLE "t_short_cpe_purl_exported" (
                                  "cpe_id"	INTEGER NOT NULL,
                                  "purl_id"	INTEGER NOT NULL,
                                  "short_cpe" TEXT NOT NULL,
                                  "purl" TEXT NOT NULL,
                                  PRIMARY KEY("cpe_id","purl_id")
);

INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (4772, 19304, 'cpe:2.3:a:c2fo:comb', 'pkg:github/c2fo/comb');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (4772, 6781, 'cpe:2.3:a:c2fo:comb', 'pkg:npm/comb');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (40676, 12377, 'cpe:2.3:a:c97:cart_engine', 'pkg:github/cunaedy/cart-engine');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (6930, 22887, 'cpe:2.3:a:cached-path-relative_project:cached-path-relative', 'pkg:github/ashaffer/cached-path-relative');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (6930, 22665, 'cpe:2.3:a:cached-path-relative_project:cached-path-relative', 'pkg:deb/debian/node-cached-path-relative');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (6930, 18591, 'cpe:2.3:a:cached-path-relative_project:cached-path-relative', 'pkg:deb/ubuntu/node-cached-path-relative');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (6930, 10060, 'cpe:2.3:a:cached-path-relative_project:cached-path-relative', 'pkg:maven/org.webjars.npm/cached-path-relative');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (6930, 22890, 'cpe:2.3:a:cached-path-relative_project:cached-path-relative', 'pkg:npm/cached-path-relative');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (54546, 25014, 'cpe:2.3:a:cached_project:cached', 'pkg:github/jaemk/cached');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (9517, 24116, 'cpe:2.3:a:cazche_project:cache', 'pkg:github/swatinem/rust-cache');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (40143, 8505, 'cpe:2.3:a:calderalabs:caldera_forms', 'pkg:github/calderawp/caldera-forms');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (40143, 12025, 'cpe:2.3:a:calderalabs:caldera_forms', 'pkg:github/wp-plugins/caldera-forms');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (40143, 17269, 'cpe:2.3:a:calderalabs:caldera_forms', 'pkg:github/wp-plugins/caldera-forms');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (31044, 17507, 'cpe:2.3:a:calendarscripts:konnichiwa', 'pkg:github/wp-plugins/konnichiwa');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (50021, 4048, 'cpe:2.3:a:call_project:call', 'pkg:github/hapijs/call');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (50021, 10316, 'cpe:2.3:a:call_project:call', 'pkg:npm/%40hapi/call');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (24723, 24815, 'cpe:2.3:a:calmquist.static-server_project:calmquist.static-server', 'pkg:npm/calmquist.static-server');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (32816, 19906, 'cpe:2.3:a:cambridge_enterprise:jbig-kit', 'pkg:github/pld-linux/jbigkit/');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (32816, 23260, 'cpe:2.3:a:cambridge_enterprise:jbig-kit', 'pkg:rpm/fedora/jbigkit');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (32816, 1646, 'cpe:2.3:a:cambridge_enterprise:jbig-kit', 'pkg:rpm/opensuse/jbigkit');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (32816, 10692, 'cpe:2.3:a:cambridge_enterprise:jbig-kit', 'pkg:rpm/centos/jbigkit');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (32816, 3023, 'cpe:2.3:a:cambridge_enterprise:jbig-kit', 'pkg:deb/debian/jbigkit');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (32816, 5153, 'cpe:2.3:a:cambridge_enterprise:jbig-kit', 'pkg:deb/ubuntu/jbigkit');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (32816, 9550, 'cpe:2.3:a:cambridge_enterprise:jbig-kit', 'pkg:gitlab/redhat/jbigkit');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (44876, 11524, 'cpe:2.3:a:campaign_monitor_project:campaign_monitor', 'pkg:github/thtas/campaignmonitor');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (8270, 25794, 'cpe:2.3:a:candidate-application-form_project:candidate-application-form', 'pkg:github/wp-plugins/candidate-application-form');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (8270, 1176, 'cpe:2.3:a:candidate-application-form_project:candidate-application-form', 'pkg:github/wpplugins/candidate-application-form');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (23153, 22770, 'cpe:2.3:a:candlepinproject:candlepin', 'pkg:github/candlepin/candlepin');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (17559, 24096, 'cpe:2.3:a:canonical:checkinstall', 'pkg:github/giuliomoro/checkinstall');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (17559, 2429, 'cpe:2.3:a:canonical:checkinstall', 'pkg:github/ruxkor/checkinstall');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (36858, 15022, 'cpe:2.3:a:canonical:lxd', 'pkg:github/lxc/lxd');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (36858, 6062, 'cpe:2.3:a:canonical:lxd', 'pkg:rpm/opensuse/lxd');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (54486, 11962, 'cpe:2.3:a:canonical:metal_as_a_service', 'pkg:github/maas/maas');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (54486, 18047, 'cpe:2.3:a:canonical:metal_as_a_service', 'pkg:deb/ubuntu/maas');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (20819, 24539, 'cpe:2.3:a:canonical:screen-resolution-extra', 'pkg:github/tseliot/screen-resolution-extra');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (20819, 2595, 'cpe:2.3:a:canonical:screen-resolution-extra', 'pkg:deb/ubuntu/screen-resolution-extra');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (48168, 14558, 'cpe:2.3:a:canonical:selinux', 'pkg:github/selinuxproject/selinux');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (48168, 23242, 'cpe:2.3:a:canonical:selinux', 'pkg:deb/ubuntu/selinux');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (4970, 22410, 'cpe:2.3:a:canonical:ubuntu-core-launcher', 'pkg:github/snapcore/snapd');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (4970, 10569, 'cpe:2.3:a:canonical:ubuntu-core-launcher', 'pkg:rpm/fedora/snapd');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (4970, 7072, 'cpe:2.3:a:canonical:ubuntu-core-launcher', 'pkg:rpm/opensuse/snapd');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (4970, 17949, 'cpe:2.3:a:canonical:ubuntu-core-launcher', 'pkg:deb/debian/snapd');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (4970, 11242, 'cpe:2.3:a:canonical:ubuntu-core-launcher', 'pkg:deb/ubuntu/snapd');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (48783, 26613, 'cpe:2.3:a:canonical:ubuntu_download_manager', 'pkg:github/ubports/ubuntu-download-manager');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (11798, 20614, 'cpe:2.3:a:canonical:update-manager', 'pkg:deb/ubuntu/update-manager');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (6591, 9741, 'cpe:2.3:a:cantemo:portal', 'pkg:github/cantemo/portal-docker');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (8296, 6121, 'cpe:2.3:a:capstone-engine:capstone', 'pkg:github/capstone-engine/capstone');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (8296, 1739, 'cpe:2.3:a:capstone-engine:capstone', 'pkg:rpm/fedora/capstone');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (8296, 17342, 'cpe:2.3:a:capstone-engine:capstone', 'pkg:rpm/opensuse/capstone');
INSERT INTO t_short_cpe_purl_exported ("cpe_id", "purl_id", "short_cpe", "purl") VALUES (8296, 14642, 'cpe:2.3:a:capstone-engine:capstone', 'pkg:deb/debian/capstone');




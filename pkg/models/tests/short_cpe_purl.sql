DROP TABLE IF EXISTS t_short_cpe_purl_exported;

CREATE TABLE t_short_cpe_purl_exported
(
    cpe_id    integer NOT NULL,
    purl_id   integer NOT NULL,
    purl      text,
    short_cpe text,
    PRIMARY KEY(cpe_id,purl_id)
);

INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (4772, 19304, 'pkg:github/c2fo/comb', 'cpe:2.3:a:c2fo:comb');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (4772, 6781, 'pkg:npm/comb', 'cpe:2.3:a:c2fo:comb');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (40676, 12377, 'pkg:github/cunaedy/cart-engine', 'cpe:2.3:a:c97:cart_engine');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (6930, 22887, 'pkg:github/ashaffer/cached-path-relative', 'cpe:2.3:a:cached-path-relative_project:cached-path-relative');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (6930, 22665, 'pkg:deb/debian/node-cached-path-relative', 'cpe:2.3:a:cached-path-relative_project:cached-path-relative');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (6930, 18591, 'pkg:deb/ubuntu/node-cached-path-relative', 'cpe:2.3:a:cached-path-relative_project:cached-path-relative');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (6930, 10060, 'pkg:maven/org.webjars.npm/cached-path-relative', 'cpe:2.3:a:cached-path-relative_project:cached-path-relative');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (6930, 22890, 'pkg:npm/cached-path-relative', 'cpe:2.3:a:cached-path-relative_project:cached-path-relative');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (54546, 25014, 'pkg:github/jaemk/cached', 'cpe:2.3:a:cached_project:cached');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (9517, 24116, 'pkg:github/swatinem/rust-cache', 'cpe:2.3:a:cazche_project:cache');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (40143, 8505, 'pkg:github/calderawp/caldera-forms', 'cpe:2.3:a:calderalabs:caldera_forms');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (40143, 12025, 'pkg:github/wp-plugins/caldera-forms', 'cpe:2.3:a:calderalabs:caldera_forms');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (40143, 17269, 'pkg:github/wpplugins/caldera-forms', 'cpe:2.3:a:calderalabs:caldera_forms');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (31044, 17507, 'pkg:github/wp-plugins/konnichiwa', 'cpe:2.3:a:calendarscripts:konnichiwa');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (50021, 4048, 'pkg:github/hapijs/call', 'cpe:2.3:a:call_project:call');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (50021, 10316, 'pkg:npm/@hapi/call', 'cpe:2.3:a:call_project:call');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (24723, 24815, 'pkg:npm/calmquist.static-server', 'cpe:2.3:a:calmquist.static-server_project:calmquist.static-server');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (32816, 19906, 'pkg:github/pld-linux/jbigkit', 'cpe:2.3:a:cambridge_enterprise:jbig-kit');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (32816, 23260, 'pkg:rpm/fedora/jbigkit', 'cpe:2.3:a:cambridge_enterprise:jbig-kit');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (32816, 1646, 'pkg:rpm/opensuse/jbigkit', 'cpe:2.3:a:cambridge_enterprise:jbig-kit');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (32816, 10692, 'pkg:rpm/centos/jbigkit', 'cpe:2.3:a:cambridge_enterprise:jbig-kit');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (32816, 3023, 'pkg:deb/debian/jbigkit', 'cpe:2.3:a:cambridge_enterprise:jbig-kit');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (32816, 5153, 'pkg:deb/ubuntu/jbigkit', 'cpe:2.3:a:cambridge_enterprise:jbig-kit');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (32816, 9550, 'pkg:gitlab/redhat/jbigkit', 'cpe:2.3:a:cambridge_enterprise:jbig-kit');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (44876, 11524, 'pkg:github/thtas/campaignmonitor', 'cpe:2.3:a:campaign_monitor_project:campaign_monitor');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (8270, 25794, 'pkg:github/wp-plugins/candidate-application-form', 'cpe:2.3:a:candidate-application-form_project:candidate-application-form');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (8270, 1176, 'pkg:github/wpplugins/candidate-application-form', 'cpe:2.3:a:candidate-application-form_project:candidate-application-form');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (23153, 22770, 'pkg:github/candlepin/candlepin', 'cpe:2.3:a:candlepinproject:candlepin');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (17559, 24096, 'pkg:github/giuliomoro/checkinstall', 'cpe:2.3:a:canonical:checkinstall');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (17559, 2429, 'pkg:github/ruxkor/checkinstall', 'cpe:2.3:a:canonical:checkinstall');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (36858, 15022, 'pkg:github/lxc/lxd', 'cpe:2.3:a:canonical:lxd');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (36858, 6062, 'pkg:rpm/opensuse/lxd', 'cpe:2.3:a:canonical:lxd');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (54486, 11962, 'pkg:github/maas/maas', 'cpe:2.3:a:canonical:metal_as_a_service');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (54486, 18047, 'pkg:deb/ubuntu/maas', 'cpe:2.3:a:canonical:metal_as_a_service');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (158765, 24539, 'pkg:github/tseliot/screen-resolution-extra', 'cpe:2.3:a:canonical:screen-resolution-extra');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (20819, 2595, 'pkg:deb/ubuntu/screen-resolution-extra', 'cpe:2.3:a:canonical:screen-resolution-extra');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (48168, 14558, 'pkg:github/selinuxproject/selinux', 'cpe:2.3:a:canonical:selinux');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (48168, 23242, 'pkg:deb/ubuntu/selinux', 'cpe:2.3:a:canonical:selinux');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (4970, 22410, 'pkg:github/snapcore/snapd', 'cpe:2.3:a:canonical:ubuntu-core-launcher');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (4970, 10569, 'pkg:rpm/fedora/snapd', 'cpe:2.3:a:canonical:ubuntu-core-launcher');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (4970, 7072, 'pkg:rpm/opensuse/snapd', 'cpe:2.3:a:canonical:ubuntu-core-launcher');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (4970, 17949, 'pkg:deb/debian/snapd', 'cpe:2.3:a:canonical:ubuntu-core-launcher');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (4970, 11242, 'pkg:deb/ubuntu/snapd', 'cpe:2.3:a:canonical:ubuntu-core-launcher');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (48783, 26613, 'pkg:github/ubports/ubuntu-download-manager', 'cpe:2.3:a:canonical:ubuntu_download_manager');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (11798, 20614, 'pkg:deb/ubuntu/update-manager', 'cpe:2.3:a:canonical:update-manager');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (6591, 9741, 'pkg:github/cantemo/portal-docker', 'cpe:2.3:a:cantemo:portal');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (8296, 6121, 'pkg:github/capstone-engine/capstone', 'cpe:2.3:a:capstone-engine:capstone');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (8296, 1739, 'pkg:rpm/fedora/capstone', 'cpe:2.3:a:capstone-engine:capstone');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (8296, 17342, 'pkg:rpm/opensuse/capstone', 'cpe:2.3:a:capstone-engine:capstone');
INSERT INTO "t_short_cpe_purl_exported" ("cpe_id", "purl_id", "purl", "short_cpe") VALUES (8296, 14642, 'pkg:deb/debian/capstone', 'cpe:2.3:a:capstone-engine:capstone');
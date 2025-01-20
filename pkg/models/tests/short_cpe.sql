DROP TABLE IF EXISTS short_cpes;
CREATE TABLE "short_cpes" (
                             "id"	INTEGER NOT NULL,
                             "short_cpe"	TEXT NOT NULL UNIQUE,
                             PRIMARY KEY("id" AUTOINCREMENT)
);

INSERT INTO short_cpes ("id", "short_cpe") VALUES (4772, 'cpe:2.3:a:c2fo:comb');
INSERT INTO short_cpes ("id", "short_cpe") VALUES (4970, 'cpe:2.3:a:canonical:ubuntu-core-launcher');
INSERT INTO short_cpes ("id", "short_cpe") VALUES (6591, 'cpe:2.3:a:cantemo:portal');
INSERT INTO short_cpes ("id", "short_cpe") VALUES (6930, 'cpe:2.3:a:cached-path-relative_project:cached-path-relative');
INSERT INTO short_cpes ("id", "short_cpe") VALUES (8270, 'cpe:2.3:a:candidate-application-form_project:candidate-application-form');
INSERT INTO short_cpes ("id", "short_cpe") VALUES (8296, 'cpe:2.3:a:capstone-engine:capstone');
INSERT INTO short_cpes ("id", "short_cpe") VALUES (17559, 'cpe:2.3:a:canonical:checkinstall');
INSERT INTO short_cpes ("id", "short_cpe") VALUES (9517, 'cpe:2.3:a:cazche_project:cache');
INSERT INTO short_cpes ("id", "short_cpe") VALUES (11798, 'cpe:2.3:a:canonical:update-manager');
INSERT INTO short_cpes ("id", "short_cpe") VALUES (24723, 'cpe:2.3:a:calmquist.static-server_project:calmquist.static-server');
INSERT INTO short_cpes ("id", "short_cpe") VALUES (32816, 'cpe:2.3:a:cambridge_enterprise:jbig-kit');
INSERT INTO short_cpes ("id", "short_cpe") VALUES (20819, 'cpe:2.3:a:canonical:screen-resolution-extra');
INSERT INTO short_cpes ("id", "short_cpe") VALUES (31044, 'cpe:2.3:a:calendarscripts:konnichiwa');
INSERT INTO short_cpes ("id", "short_cpe") VALUES (23153, 'cpe:2.3:a:candlepinproject:candlepin');
INSERT INTO short_cpes ("id", "short_cpe") VALUES (36858, 'cpe:2.3:a:canonical:lxd');
INSERT INTO short_cpes ("id", "short_cpe") VALUES (40143, 'cpe:2.3:a:calderalabs:caldera_forms');
INSERT INTO short_cpes ("id", "short_cpe") VALUES (40676, 'cpe:2.3:a:c97:cart_engine');
INSERT INTO short_cpes ("id", "short_cpe") VALUES (44876, 'cpe:2.3:a:campaign_monitor_project:campaign_monitor');
INSERT INTO short_cpes ("id", "short_cpe") VALUES (48168, 'cpe:2.3:a:canonical:selinux');
INSERT INTO short_cpes ("id", "short_cpe") VALUES (48783, 'cpe:2.3:a:canonical:ubuntu_download_manager');
INSERT INTO short_cpes ("id", "short_cpe") VALUES (50021, 'cpe:2.3:a:call_project:call');
INSERT INTO short_cpes ("id", "short_cpe") VALUES (54486, 'cpe:2.3:a:canonical:metal_as_a_service');
INSERT INTO short_cpes ("id", "short_cpe") VALUES (54546, 'cpe:2.3:a:cached_project:cached');
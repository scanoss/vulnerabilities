DROP TABLE IF EXISTS short_cpe;
CREATE TABLE "short_cpe" (
                             "id"	INTEGER NOT NULL,
                             "short_cpe"	TEXT NOT NULL UNIQUE,
                             PRIMARY KEY("id" AUTOINCREMENT)
);

INSERT INTO "short_cpe" ("id", "short_cpe") VALUES ('1', 'cpe:2.3:a:apache:commons_messaging_mail');
INSERT INTO "short_cpe" ("id", "short_cpe") VALUES ('2', 'cpe:2.3:a:apache:org.apache.sling.servlets.post');
INSERT INTO "short_cpe" ("id", "short_cpe") VALUES ('3', 'cpe:2.3:a:apache:sling');
INSERT INTO "short_cpe" ("id", "short_cpe") VALUES ('4', 'cpe:2.3:a:apache:sling_api');
INSERT INTO "short_cpe" ("id", "short_cpe") VALUES ('5', 'cpe:2.3:a:apache:sling_auth_core_component');
INSERT INTO "short_cpe" ("id", "short_cpe") VALUES ('6', 'cpe:2.3:a:apache:sling_authentication_service');
INSERT INTO "short_cpe" ("id", "short_cpe") VALUES ('7', 'cpe:2.3:a:apache:sling_cms');
INSERT INTO "short_cpe" ("id", "short_cpe") VALUES ('8', 'cpe:2.3:a:apache:sling_commons_log');
INSERT INTO "short_cpe" ("id", "short_cpe") VALUES ('9', 'cpe:2.3:a:apache:sling_commons_messaging_mail');
INSERT INTO "short_cpe" ("id", "short_cpe") VALUES ('10', 'cpe:2.3:a:apache:sling_jcr_contentloader');
INSERT INTO "short_cpe" ("id", "short_cpe") VALUES ('11', 'cpe:2.3:a:apache:sling_servlets_post');
INSERT INTO "short_cpe" ("id", "short_cpe") VALUES ('12', 'cpe:2.3:a:apache:sling_xss_protection_api');
INSERT INTO "short_cpe" ("id", "short_cpe") VALUES ('13', 'cpe:2.3:a:apache:sling_xss_protection_api_compat');
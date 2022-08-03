DROP TABLE IF EXISTS t_cpe;
CREATE TABLE "t_cpe" (
                       "id"	INTEGER NOT NULL UNIQUE,
                       "cpe"	TEXT NOT NULL UNIQUE,
                       "short_cpe_id"	INTEGER NOT NULL,
                       "version_id"	INTEGER,
                       PRIMARY KEY("id")
);


INSERT INTO "t_cpe" ("id", "cpe", "short_cpe_id", "version_id") VALUES ('1', 'cpe:2.3:a:apache:org.apache.sling.servlets.post:2.2.0:*:*:*:*:*:*:*', '2', '1');
INSERT INTO "t_cpe" ("id", "cpe", "short_cpe_id", "version_id") VALUES ('2', 'cpe:2.3:a:apache:org.apache.sling.servlets.post:2.3.0:*:*:*:*:*:*:*', '2', '2');
INSERT INTO "t_cpe" ("id", "cpe", "short_cpe_id", "version_id") VALUES ('3', 'cpe:2.3:a:apache:org.apache.sling.servlets.post:2.1.0:*:*:*:*:*:*:*', '2', '3');
INSERT INTO "t_cpe" ("id", "cpe", "short_cpe_id", "version_id") VALUES ('4', 'cpe:2.3:a:apache:sling_cms:0.10.0:*:*:*:*:*:*:*', '3', '4');
INSERT INTO "t_cpe" ("id", "cpe", "short_cpe_id", "version_id") VALUES ('5', 'cpe:2.3:a:apache:sling_cms:0.11.0:*:*:*:*:*:*:*', '3', '5');
INSERT INTO "t_cpe" ("id", "cpe", "short_cpe_id", "version_id") VALUES ('6', 'cpe:2.3:a:apache:sling_cms:0.11.2:*:*:*:*:*:*:*', '3', '6');
INSERT INTO "t_cpe" ("id", "cpe", "short_cpe_id", "version_id") VALUES ('7', 'cpe:2.3:a:apache:sling_cms:0.12.0:*:*:*:*:*:*:*', '3', '7');
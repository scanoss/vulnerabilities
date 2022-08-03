DROP TABLE IF EXISTS t_cpe_cve;
CREATE TABLE "t_cpe_cve" (
                           "cpe_id"	INTEGER NOT NULL,
                           "cve_id"	INTEGER NOT NULL,
                           PRIMARY KEY("cpe_id","cve_id")
);

INSERT INTO "t_cpe_cve" ("cpe_id", "cve_id") VALUES ('1', '1');
INSERT INTO "t_cpe_cve" ("cpe_id", "cve_id") VALUES ('2', '1');
INSERT INTO "t_cpe_cve" ("cpe_id", "cve_id") VALUES ('3', '1');
INSERT INTO "t_cpe_cve" ("cpe_id", "cve_id") VALUES ('4', '1');
INSERT INTO "t_cpe_cve" ("cpe_id", "cve_id") VALUES ('5', '1');
INSERT INTO "t_cpe_cve" ("cpe_id", "cve_id") VALUES ('6', '1');
INSERT INTO "t_cpe_cve" ("cpe_id", "cve_id") VALUES ('7', '1');
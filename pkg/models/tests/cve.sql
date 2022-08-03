DROP TABLE IF EXISTS t_cve;
CREATE TABLE "t_cve" (
                        "id"	INTEGER,
                        "cve"	TEXT NOT NULL,
                        "severity"	TEXT,
                        PRIMARY KEY("cve")
);

INSERT INTO "t_cve" ("id", "cve", "severity") VALUES ('1', 'CVE-2020-1949', 'MEDIUM');
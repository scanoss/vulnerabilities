DROP TABLE IF EXISTS cve;
CREATE TABLE "cve" (
                        "id"	INTEGER,
                        "cve"	TEXT NOT NULL,
                        "severity"	TEXT,
                        PRIMARY KEY("cve")
);

INSERT INTO "cve" ("id", "cve", "severity") VALUES ('1', 'CVE-2020-1949', 'MEDIUM');
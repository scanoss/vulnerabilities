DROP TABLE IF EXISTS t_purl;
CREATE TABLE "t_purl" (
                        "id"	INTEGER NOT NULL,
                        "purl"	TEXT NOT NULL UNIQUE,
                        PRIMARY KEY("id" AUTOINCREMENT)
);


INSERT INTO "t_purl" ("id", "purl") VALUES ('1', 'pkg:apache/sling');
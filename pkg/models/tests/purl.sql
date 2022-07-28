DROP TABLE IF EXISTS purl;
CREATE TABLE "purl" (
                        "id"	INTEGER NOT NULL,
                        "purl"	TEXT NOT NULL UNIQUE,
                        PRIMARY KEY("id" AUTOINCREMENT)
);


INSERT INTO "purl" ("id", "purl") VALUES ('1', 'pkg:apache/sling');
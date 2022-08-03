DROP TABLE IF EXISTS versions;
CREATE TABLE versions
(
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    version_name text    not null unique,
    semver       text default ''
);



INSERT INTO "versions" ("id", "version_name", "semver") VALUES ('1', '2.2.0', 'v2.2.0');
INSERT INTO "versions" ("id", "version_name", "semver") VALUES ('2', '2.3.0', 'v2.3.0');
INSERT INTO "versions" ("id", "version_name", "semver") VALUES ('3', '2.1.0', 'v2.1.0');
INSERT INTO "versions" ("id", "version_name", "semver") VALUES ('4', '0.10.0', 'v0.10.0');
INSERT INTO "versions" ("id", "version_name", "semver") VALUES ('5', '0.11.0', 'v0.11.0');
INSERT INTO "versions" ("id", "version_name", "semver") VALUES ('6', '0.11.2', 'v0.1.2');
INSERT INTO "versions" ("id", "version_name", "semver") VALUES ('7', '0.12.0', 'v0.12.0');
INSERT INTO "versions" ("id", "version_name", "semver") VALUES ('8', '1.0.0', 'v1.0.0');

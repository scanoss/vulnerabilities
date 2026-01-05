DROP TABLE IF EXISTS epss_data;
CREATE TABLE "epss_data" (
    "cve" TEXT NOT NULL UNIQUE,
    "epss" REAL NOT NULL,
    "percentile" REAL NOT NULL,
    PRIMARY KEY ("cve")
);
INSERT INTO epss_data (cve, epss, percentile) VALUES ('CVE-2017-9302', 0.00143, 0.5124);
INSERT INTO epss_data (cve, epss, percentile) VALUES ('CVE-2015-0269', 0.00285, 0.6832);
INSERT INTO epss_data (cve, epss, percentile) VALUES ('CVE-2018-10083', 0.00891, 0.8215);
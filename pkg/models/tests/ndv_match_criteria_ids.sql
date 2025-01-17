DROP TABLE IF EXISTS nvd_match_criteria_ids;
CREATE TABLE nvd_match_criteria_ids
(
    match_criteria_id       text      not null
        constraint nvd_match_criteria_ids_pk_1
            primary key,
    cpe_ids                 integer[] not null,
    version_start_including text,
    version_start_excluding text,
    version_end_including   text,
    version_end_excluding   text,
    short_cpe_id            integer
);


INSERT INTO nvd_match_criteria_ids (match_criteria_id, cpe_ids, version_start_including, version_start_excluding, version_end_including, version_end_excluding, short_cpe_id) VALUES ('6AA6464B-7C66-4ABA-A655-E63CE3CD361B', '{}', '', '', '', '', null);
INSERT INTO nvd_match_criteria_ids (match_criteria_id, cpe_ids, version_start_including, version_start_excluding, version_end_including, version_end_excluding, short_cpe_id) VALUES ('31F486B4-9293-4C09-A7A5-CC0ED9643415', '{1958139}', '', '', '', '', null);
INSERT INTO nvd_match_criteria_ids (match_criteria_id, cpe_ids, version_start_including, version_start_excluding, version_end_including, version_end_excluding, short_cpe_id) VALUES ('3297FAF2-7DF3-4EAC-99DD-D83093846780', '{1822755}', '', '', '', '', null);
INSERT INTO nvd_match_criteria_ids (match_criteria_id, cpe_ids, version_start_including, version_start_excluding, version_end_including, version_end_excluding, short_cpe_id) VALUES ('BB3DD9A8-684A-4D3C-AAC1-795A5154B8FF', '{1958142}', '', '', '', '', null);
INSERT INTO nvd_match_criteria_ids (match_criteria_id, cpe_ids, version_start_including, version_start_excluding, version_end_including, version_end_excluding, short_cpe_id) VALUES ('CF27FE4D-4019-44CB-B86A-0F6EB22043EE', '{1958143}', '', '', '', '', null);
INSERT INTO nvd_match_criteria_ids (match_criteria_id, cpe_ids, version_start_including, version_start_excluding, version_end_including, version_end_excluding, short_cpe_id) VALUES ('2355C9C3-17D4-4024-B60A-55E698139269', '{1958144}', '', '', '', '', null);
INSERT INTO nvd_match_criteria_ids (match_criteria_id, cpe_ids, version_start_including, version_start_excluding, version_end_including, version_end_excluding, short_cpe_id) VALUES ('4BF4A874-DE47-4662-82E8-899258ABCAA4', '{1958145}', '', '', '', '', null);
INSERT INTO nvd_match_criteria_ids (match_criteria_id, cpe_ids, version_start_including, version_start_excluding, version_end_including, version_end_excluding, short_cpe_id) VALUES ('A088E6AE-B04B-4BF2-9710-875767A17644', '{1958146}', '', '', '', '', null);
INSERT INTO nvd_match_criteria_ids (match_criteria_id, cpe_ids, version_start_including, version_start_excluding, version_end_including, version_end_excluding, short_cpe_id) VALUES ('C499F62B-EE47-4F90-8E0C-BE5B3A95E6EB', '{1958147}', '', '', '', '', null);
INSERT INTO nvd_match_criteria_ids (match_criteria_id, cpe_ids, version_start_including, version_start_excluding, version_end_including, version_end_excluding, short_cpe_id) VALUES ('D9BE19EE-D1C3-4688-A614-0E906F949768', '{1958148}', '', '', '', '', null);

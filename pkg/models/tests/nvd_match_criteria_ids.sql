DROP TABLE IF EXISTS nvd_match_criteria_ids;

CREATE TABLE nvd_match_criteria_ids (
	match_criteria_id text NOT NULL,
	cpe_ids _int4 NOT NULL,
	short_cpe_id int4 NULL,
	version_start_excluding text NOT NULL DEFAULT '',
	version_start_including text NOT NULL DEFAULT '',
	version_end_including text NOT NULL DEFAULT '',
	version_end_excluding text NOT NULL DEFAULT '',
	CONSTRAINT nvd_match_criteria_ids_pk PRIMARY KEY (match_criteria_id)
);
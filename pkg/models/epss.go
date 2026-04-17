package models

import (
	"context"

	"github.com/jmoiron/sqlx"
	scdb "github.com/scanoss/go-grpc-helper/pkg/grpc/database"
	"go.uber.org/zap"
	"scanoss.com/vulnerabilities/pkg/config"
)

type EPSSModel struct {
	db     *sqlx.DB
	config *config.ServerConfig
	sc     *scdb.DBQueryContext
	s      *zap.SugaredLogger
}

type EPSS struct {
	Cve        string  `db:"cve"`
	Epss       float32 `db:"epss"`
	Percentile float32 `db:"percentile"`
}

// NewEPSSModel creates a new instance of the EPSS Model.
func NewEPSSModel(s *zap.SugaredLogger, config *config.ServerConfig, db *sqlx.DB) *EPSSModel {
	return &EPSSModel{
		db:     db,
		config: config,
		sc:     scdb.NewDBSelectContext(s, db, nil, config.App.Trace),
		s:      s,
	}
}

// GetEPSSByCVEs List of EPSS by CVEs.
func (m *EPSSModel) GetEPSSByCVEs(ctx context.Context, cves []string) ([]EPSS, error) {
	if len(cves) == 0 {
		return []EPSS{}, nil
	}
	var epss []EPSS
	query, args, err := sqlx.In("SELECT cve, epss, percentile FROM epss_data WHERE cve IN (?)", cves)
	if err != nil {
		return nil, err
	}
	query = m.db.Rebind(query)
	err = m.sc.SelectContext(ctx, &epss, query, args...)
	if err != nil {
		m.s.Errorf("Failed to get EPSS data for CVEs: %v", err)
		return nil, err
	}
	return epss, nil
}

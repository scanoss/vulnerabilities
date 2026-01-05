package models

import (
	"context"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"scanoss.com/vulnerabilities/pkg/config"

	"github.com/jmoiron/sqlx"

	scdb "github.com/scanoss/go-grpc-helper/pkg/grpc/database"
)

type EPSSModel struct {
	db     *sqlx.DB
	config *config.ServerConfig
}

type EPSS struct {
	Cve        string  `db:"cve"`
	Epss       float32 `db:"epss"`
	Percentile float32 `db:"percentile"`
}

// NewEPSSModel creates a new instance of the EPSS Model.
func NewEPSSModel(config *config.ServerConfig, db *sqlx.DB) *EPSSModel {
	return &EPSSModel{
		db:     db,
		config: config,
	}
}

// GetEPSSByCVEs List of EPSS by CVEs.
func (m *EPSSModel) GetEPSSByCVEs(ctx context.Context, cves []string) ([]EPSS, error) {
	if len(cves) == 0 {
		return []EPSS{}, nil
	}
	var epss []EPSS
	s := ctxzap.Extract(ctx).Sugar()
	selectContext := scdb.NewDBSelectContext(s, m.db, nil, m.config.App.Trace)
	query, args, err := sqlx.In("SELECT cve, epss, percentile FROM epss_data WHERE cve IN (?)", cves)
	if err != nil {
		return nil, err
	}
	query = m.db.Rebind(query)
	err = selectContext.SelectContext(ctx, &epss, query, args...)
	if err != nil {
		s.Errorf("Failed to get EPSS data for CVEs: %v", err)
		return nil, err
	}
	return epss, nil
}

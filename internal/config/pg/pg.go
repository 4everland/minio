package pg

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio/internal/config"
	"github.com/minio/pkg/env"
)

const (
	Dsn = "Dsn"

	EnvPgEnable = "MINIO_PG_ENABLE"
	EnvPgDsn    = "MINIO_PG_DSN"
)

// DefaultKVS - default KV settings for etcd.
var (
	DefaultKVS = config.KVS{
		config.KV{
			Key:   Dsn,
			Value: "",
		},
	}
)

// Config - server redis config.
type Config struct {
	Enabled bool   `json:"enabled"`
	Dsn     string `json:"dsn"`
}

// New - initialize new pg conn pool.
func New(cfg Config) (*pgxpool.Pool, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	pool, err := pgxpool.New(context.Background(), cfg.Dsn)
	if err != nil {
		return nil, err
	}

	return pool, nil
}

// Enabled returns if redis is enabled.
func Enabled(kvs config.KVS) bool {
	address := kvs.Get(Dsn)
	return address != ""
}

// LookupConfig - Initialize new redis config.
func LookupConfig(kvs config.KVS) (Config, error) {
	cfg := Config{}
	if err := config.CheckValidKeys(config.PgSubSys, kvs, DefaultKVS); err != nil {
		return cfg, err
	}

	dsn := env.Get(EnvPgDsn, kvs.Get(Dsn))
	if dsn == "" {
		return cfg, nil
	}

	cfg.Enabled = true
	cfg.Dsn = dsn

	return cfg, nil
}

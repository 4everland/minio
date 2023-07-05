package redis

import (
	"context"
	"github.com/minio/minio/internal/config"
	"github.com/minio/pkg/env"
	"github.com/redis/go-redis/v9"
	"time"
)

const (
	defaultDialTimeout = 5 * time.Second

	Address  = "address"
	Password = "password"
	DnsPath  = "dns_path"

	EnvRedisEnable   = "MINIO_REDIS_ENABLE"
	EnvRedisAddress  = "MINIO_REDIS_ADDRESS"
	EnvRedisPassword = "MINIO_REDIS_PASSWORD"
)

// DefaultKVS - default KV settings for etcd.
var (
	DefaultKVS = config.KVS{
		config.KV{
			Key:   Address,
			Value: "",
		},
		config.KV{
			Key:   Password,
			Value: "",
		},
		config.KV{
			Key:   DnsPath,
			Value: "/skydns",
		},
	}
)

// Config - server redis config.
type Config struct {
	Enabled     bool   `json:"enabled"`
	PathPrefix  string `json:"pathPrefix"`
	CoreDNSPath string `json:"coreDNSPath"`
	redis.Options
}

// New - initialize new redis client.
func New(cfg Config) (*redis.Client, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	cli := redis.NewClient(&cfg.Options)

	if err := cli.Ping(context.Background()).Err(); err != nil {
		return nil, err
	}

	return cli, nil
}

// Enabled returns if redis is enabled.
func Enabled(kvs config.KVS) bool {
	address := kvs.Get(Address)
	return address != ""
}

// LookupConfig - Initialize new redis config.
func LookupConfig(kvs config.KVS) (Config, error) {
	cfg := Config{}
	if err := config.CheckValidKeys(config.RedisSubSys, kvs, DefaultKVS); err != nil {
		return cfg, err
	}

	address := env.Get(EnvRedisAddress, kvs.Get(Address))
	if address == "" {
		return cfg, nil
	}

	cfg.Enabled = true
	cfg.DialTimeout = defaultDialTimeout
	cfg.Addr = address

	return cfg, nil
}

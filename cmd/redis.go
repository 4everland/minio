package cmd

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/minio/minio/internal/logger"
	"github.com/redis/go-redis/v9"
)

var errRedisUnreachable = errors.New("redis is unreachable, please check your endpoint")

func redisErrToErr(err error) error {
	if err == nil {
		return nil
	}
	switch err {
	case context.DeadlineExceeded:
		return errRedisUnreachable
	default:
		return fmt.Errorf("unexpected error %w from redis, please check your endpoint", err)
	}
}

func saveKeyRedis(ctx context.Context, client *redis.Client, key string, data []byte, opts ...options) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, defaultContextTimeout)
	defer cancel()
	if len(opts) > 0 {
		return client.Set(timeoutCtx, key, data, time.Duration(opts[0].ttl)*time.Second).Err()
	}
	return client.Set(timeoutCtx, key, data, 0).Err()
}

func deleteKeyRedis(ctx context.Context, client *redis.Client, key string) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, defaultContextTimeout)
	defer cancel()
	return client.Del(timeoutCtx, key).Err()
}

func readKeyRedis(ctx context.Context, client *redis.Client, key string) ([]byte, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, defaultContextTimeout)
	defer cancel()
	val, err := client.Get(timeoutCtx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, errConfigNotFound
		}
		logger.LogIf(ctx, err)
		return nil, redisErrToErr(err)
	}
	return val, nil
}

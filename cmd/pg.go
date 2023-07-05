package cmd

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

var errDBUnreachable = errors.New("database is unreachable, please check your connection")

func dbErrToErr(err error) error {
	if err == nil {
		return nil
	}
	switch err {
	case context.DeadlineExceeded:
		return errDBUnreachable
	default:
		return fmt.Errorf("unexpected error from database: %w", err)
	}
}

func saveKeyDB(ctx context.Context, client *pgxpool.Pool, table, key string, data []byte, opts ...options) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, defaultContextTimeout)
	defer cancel()
	var ttl int64
	if len(opts) > 0 {
		ttl = time.Now().Add(time.Second * time.Duration(opts[0].ttl)).Unix()
	}
	conn, err := client.Acquire(timeoutCtx)
	if err != nil {
		return err
	}
	defer conn.Release()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return dbErrToErr(err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(timeoutCtx, fmt.Sprintf(`INSERT INTO "%s" (key, data, ttl) VALUES ($1, $2, $3) ON CONFLICT(key) DO UPDATE SET data = $2, ttl = $3`, table), key, data, ttl)
	if err != nil {
		return dbErrToErr(err)
	}

	_, err = tx.Exec(timeoutCtx, fmt.Sprintf("select pg_notify('%s', $1)", iamConfigPrefix), pgNotifyPayload{IsCreated: true, Key: key}.toJson())
	if err != nil {
		return dbErrToErr(err)
	}

	err = tx.Commit(ctx)
	if err != nil {
		return dbErrToErr(err)
	}

	return nil
}

func deleteKeyDB(ctx context.Context, client *pgxpool.Pool, table, key string) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, defaultContextTimeout)
	defer cancel()
	conn, err := client.Acquire(timeoutCtx)
	if err != nil {
		return err
	}
	defer conn.Release()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return dbErrToErr(err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(timeoutCtx, fmt.Sprintf(`DELETE FROM "%s" WHERE key = $1`, table), key)
	if err != nil {
		return dbErrToErr(err)
	}

	_, err = tx.Exec(timeoutCtx, fmt.Sprintf("select pg_notify('%s', $1)", iamConfigPrefix), pgNotifyPayload{IsCreated: false, Key: key}.toJson())
	if err != nil {
		return dbErrToErr(err)
	}

	err = tx.Commit(ctx)
	if err != nil {
		return dbErrToErr(err)
	}

	return nil
}

func readKeyDB(ctx context.Context, client *pgxpool.Pool, table, key string) ([]byte, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, defaultContextTimeout)
	defer cancel()
	conn, err := client.Acquire(timeoutCtx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	var (
		data pgtype.PreallocBytes
		ttl  int64
	)
	if err = conn.QueryRow(timeoutCtx, fmt.Sprintf(`SELECT data, ttl FROM "%s" WHERE key = $1`, table), key).Scan(&data, &ttl); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errConfigNotFound
		}
		return nil, dbErrToErr(err)
	}

	if ttl != 0 && ttl < time.Now().Unix() {
		return nil, errConfigNotFound
	}

	return data, nil
}

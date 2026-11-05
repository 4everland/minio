package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const defaultIAMPgBatchSize = 10000

type pgIAMQuerier interface {
	Query(context.Context, string, ...interface{}) (pgx.Rows, error)
}

type pgIAMRow struct {
	key  string
	data []byte
	ttl  int64
}

// loadPgIAMPage buffers a bounded page and releases the pool connection before
// decoding IAM records. Decoding can be slow (including KMS calls), and expired
// users may need another connection to delete their credentials.
func loadPgIAMPage(ctx context.Context, db pgIAMQuerier, query string, args []interface{}, timeout time.Duration, withTTL bool) ([]pgIAMRow, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var page []pgIAMRow
	for rows.Next() {
		var row pgIAMRow
		dest := []interface{}{&row.key, &row.data}
		if withTTL {
			dest = append(dest, &row.ttl)
		}
		// Scan into []byte, not pgtype.DriverBytes: the page must own the data
		// after Next and Close release the driver's buffers.
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		page = append(page, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return page, nil
}

func loadPgIAMRows(ctx context.Context, db pgIAMQuerier, table string, batchSize int, timeout time.Duration, withTTL bool, consume func(pgIAMRow) error) error {
	if batchSize <= 0 {
		return fmt.Errorf("load IAM table %q: invalid page size %d", table, batchSize)
	}
	columns := "key, data"
	if withTTL {
		columns += ", ttl"
	}
	selectSQL := fmt.Sprintf("SELECT %s FROM %s", columns, pgx.Identifier{table}.Sanitize())
	var lastKey string
	for pageNumber := 1; ; pageNumber++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("load IAM table %q page %d: %w", table, pageNumber, err)
		}
		query := selectSQL + " ORDER BY key LIMIT $1"
		args := []interface{}{batchSize}
		if pageNumber > 1 {
			// Seek through the key index instead of re-scanning an ever-growing
			// OFFSET. Deleting an earlier row must not shift the next page.
			query = selectSQL + " WHERE key > $1 ORDER BY key LIMIT $2"
			args = []interface{}{lastKey, batchSize}
		}
		page, err := loadPgIAMPage(ctx, db, query, args, timeout, withTTL)
		if err != nil {
			return fmt.Errorf("load IAM table %q page %d (read): %w", table, pageNumber, err)
		}
		now := time.Now().Unix()
		for _, row := range page {
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("load IAM table %q page %d: %w", table, pageNumber, err)
			}
			if withTTL && row.ttl != 0 && row.ttl < now {
				continue
			}
			if err := consume(row); err != nil {
				return fmt.Errorf("load IAM table %q page %d (decode): %w", table, pageNumber, err)
			}
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("load IAM table %q page %d: %w", table, pageNumber, err)
		}
		// Count and advance over all fetched rows, even an entirely expired page.
		if len(page) < batchSize {
			return nil
		}
		lastKey = page[len(page)-1].key
	}
}

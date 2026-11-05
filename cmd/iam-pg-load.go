package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/minio/minio/internal/logger"
)

const defaultIAMPgBatchSize = 10000

type pgIAMQuerier interface {
	Query(context.Context, string, ...interface{}) (pgx.Rows, error)
}

type pgIAMTxBeginner interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

type pgIAMRow struct {
	key  string
	data []byte
	ttl  int64
}

// loadPgIAMPage buffers a bounded page and closes its result stream before
// decoding IAM records. Pool queries release their connection here; transaction
// queries keep it until commit or rollback. Decoding may include slow KMS calls.
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

func processPgIAMPage(ctx context.Context, page []pgIAMRow, withTTL bool, consume func(pgIAMRow) error) error {
	now := time.Now().Unix()
	for _, row := range page {
		if err := ctx.Err(); err != nil {
			return err
		}
		if withTTL && row.ttl != 0 && row.ttl < now {
			continue
		}
		if err := consume(row); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func logPgIAMPage(table, mode string, pageNumber, rows int, readTime, processTime time.Duration) {
	logger.Info("IAM PostgreSQL load: table=%q mode=%s page=%d rows=%d read=%s process=%s total=%s",
		table, mode, pageNumber, rows, readTime.Round(time.Microsecond),
		processTime.Round(time.Microsecond), (readTime + processTime).Round(time.Microsecond))
}

// loadPgIAMRows uses keyset pagination for loaders that may acquire another
// connection during processing, such as expired-user cleanup.
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
		readStart := time.Now()
		page, err := loadPgIAMPage(ctx, db, query, args, timeout, withTTL)
		readTime := time.Since(readStart)
		if err != nil {
			return fmt.Errorf("load IAM table %q page %d (read): %w", table, pageNumber, err)
		}
		processStart := time.Now()
		err = processPgIAMPage(ctx, page, withTTL, consume)
		logPgIAMPage(table, "keyset", pageNumber, len(page), readTime, time.Since(processStart))
		if err != nil {
			return fmt.Errorf("load IAM table %q page %d (process): %w", table, pageNumber, err)
		}
		// Count and advance over all fetched rows, even an entirely expired page.
		if len(page) < batchSize {
			return nil
		}
		lastKey = page[len(page)-1].key
	}
}

// loadPgIAMRowsByCursor scans read-only IAM records without imposing key order.
// The transaction pins one connection for the whole scan, so consume must not
// acquire another connection. Each database operation gets its own timeout;
// processing uses the caller's context rather than a FETCH deadline.
func loadPgIAMRowsByCursor(ctx context.Context, db pgIAMTxBeginner, table string, batchSize int, timeout time.Duration, withTTL bool, consume func(pgIAMRow) error) error {
	if batchSize <= 0 {
		return fmt.Errorf("load IAM table %q: invalid page size %d", table, batchSize)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("load IAM table %q (begin): %w", table, err)
	}

	beginCtx, cancel := context.WithTimeout(ctx, timeout)
	tx, err := db.BeginTx(beginCtx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	cancel()
	if err != nil {
		return fmt.Errorf("load IAM table %q (begin): %w", table, err)
	}
	defer func() {
		// The caller or FETCH context may already be canceled. A fresh,
		// bounded context still lets pgx roll back and release the connection.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_ = tx.Rollback(cleanupCtx)
	}()

	exec := func(query string) error {
		opCtx, opCancel := context.WithTimeout(ctx, timeout)
		defer opCancel()
		_, err := tx.Exec(opCtx, query)
		return err
	}
	// Startup consumes the entire cursor, rather than just its first few rows.
	if err := exec("SET LOCAL cursor_tuple_fraction = 1.0"); err != nil {
		return fmt.Errorf("load IAM table %q (configure cursor): %w", table, err)
	}
	columns := "key, data"
	if withTTL {
		columns += ", ttl"
	}
	cursor := pgx.Identifier{"minio_iam_load"}.Sanitize()
	declareSQL := fmt.Sprintf("DECLARE %s NO SCROLL CURSOR WITHOUT HOLD FOR SELECT %s FROM %s",
		cursor, columns, pgx.Identifier{table}.Sanitize())
	if err := exec(declareSQL); err != nil {
		return fmt.Errorf("load IAM table %q (declare): %w", table, err)
	}

	fetchSQL := fmt.Sprintf("FETCH FORWARD %d FROM %s", batchSize, cursor)
	for pageNumber := 1; ; pageNumber++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("load IAM table %q page %d: %w", table, pageNumber, err)
		}
		readStart := time.Now()
		// The same cursor name can later refer to a table with a different
		// projection (with/without ttl). Describe each FETCH instead of
		// reusing a cached statement's result column descriptions.
		page, err := loadPgIAMPage(ctx, tx, fetchSQL,
			[]interface{}{pgx.QueryExecModeDescribeExec}, timeout, withTTL)
		readTime := time.Since(readStart)
		if err != nil {
			return fmt.Errorf("load IAM table %q page %d (fetch): %w", table, pageNumber, err)
		}
		processStart := time.Now()
		err = processPgIAMPage(ctx, page, withTTL, consume)
		logPgIAMPage(table, "cursor", pageNumber, len(page), readTime, time.Since(processStart))
		if err != nil {
			return fmt.Errorf("load IAM table %q page %d (process): %w", table, pageNumber, err)
		}
		// An entirely expired batch still advances the cursor. Only the raw
		// number of rows returned by FETCH determines whether it reached EOF.
		if len(page) < batchSize {
			break
		}
	}

	commitCtx, cancel := context.WithTimeout(ctx, timeout)
	err = tx.Commit(commitCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("load IAM table %q (commit): %w", table, err)
	}
	return nil
}

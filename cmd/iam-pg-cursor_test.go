package cmd

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// pgIAMCursorTestDB models one cursor's forward-only position, independent of
// key order. Other pgx.Tx methods intentionally panic through the nil embed.
type pgIAMCursorTestDB struct {
	pgx.Tx
	t              *testing.T
	rows           []pgIAMRow
	batchSize      int
	withTTL        bool
	position       int
	fetches        int
	committed      bool
	rollbacks      int
	failAt         string
	failure        error
	operations     []string
	contexts       []context.Context
	lastRows       *pgIAMTestRows
	rollbackCtxErr error
}

func (db *pgIAMCursorTestDB) operation(ctx context.Context, name string) error {
	db.t.Helper()
	if len(db.contexts) > 0 && db.contexts[len(db.contexts)-1].Err() == nil {
		db.t.Fatalf("%s started before the previous operation context was released", name)
	}
	if _, ok := ctx.Deadline(); !ok {
		db.t.Fatalf("%s must have a bounded context", name)
	}
	db.contexts = append(db.contexts, ctx)
	db.operations = append(db.operations, name)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if db.failAt == name {
		return db.failure
	}
	return nil
}

func (db *pgIAMCursorTestDB) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	if opts.AccessMode != pgx.ReadOnly {
		db.t.Fatalf("cursor transaction must be read-only: %+v", opts)
	}
	if err := db.operation(ctx, "begin"); err != nil {
		return nil, err
	}
	return db, nil
}

func (db *pgIAMCursorTestDB) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	db.t.Helper()
	var stage string
	switch {
	case strings.HasPrefix(sql, "SET LOCAL"):
		stage = "setup"
		if sql != "SET LOCAL cursor_tuple_fraction = 1.0" {
			db.t.Fatalf("unexpected planner setup: %s", sql)
		}
	case strings.HasPrefix(sql, "DECLARE"):
		stage = "declare"
		columns := "key, data"
		if db.withTTL {
			columns += ", ttl"
		}
		want := `DECLARE "minio_iam_load" NO SCROLL CURSOR WITHOUT HOLD FOR SELECT ` + columns + ` FROM "config/iam/test/"`
		if sql != want {
			db.t.Fatalf("expected one unsorted cursor scan, got: %s", sql)
		}
	default:
		db.t.Fatalf("unexpected cursor command: %s", sql)
	}
	return pgconn.CommandTag{}, db.operation(ctx, stage)
}

func (db *pgIAMCursorTestDB) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	db.t.Helper()
	if sql != fmt.Sprintf(`FETCH FORWARD %d FROM "minio_iam_load"`, db.batchSize) {
		db.t.Fatalf("unexpected cursor fetch: %s", sql)
	}
	if !reflect.DeepEqual(args, []interface{}{pgx.QueryExecModeDescribeExec}) {
		db.t.Fatalf("FETCH must describe its varying result shape without caching: %v", args)
	}
	db.fetches++
	if err := db.operation(ctx, "fetch"); err != nil {
		return nil, err
	}
	end := db.position + db.batchSize
	if end > len(db.rows) {
		end = len(db.rows)
	}
	db.lastRows = &pgIAMTestRows{rows: db.rows[db.position:end]}
	db.position = end
	if db.failAt == "scan" {
		db.lastRows.scanErr = db.failure
	}
	if db.failAt == "iteration" {
		db.lastRows.iterationErr = db.failure
	}
	return db.lastRows, nil
}

func (db *pgIAMCursorTestDB) Commit(ctx context.Context) error {
	if err := db.operation(ctx, "commit"); err != nil {
		return err
	}
	db.committed = true
	return nil
}

func (db *pgIAMCursorTestDB) Rollback(ctx context.Context) error {
	db.rollbacks++
	db.rollbackCtxErr = ctx.Err()
	if err := db.operation(ctx, "rollback"); err != nil {
		return err
	}
	if db.committed {
		return pgx.ErrTxClosed
	}
	return nil
}

func (db *pgIAMCursorTestDB) checkReleased() {
	db.t.Helper()
	for i, ctx := range db.contexts {
		if ctx.Err() == nil {
			db.t.Errorf("%s context was not released", db.operations[i])
		}
	}
	if db.lastRows != nil && !db.lastRows.closed {
		db.t.Error("cursor result rows were not closed")
	}
}

func TestLoadPgIAMRowsByCursorPages(t *testing.T) {
	for _, tt := range []struct {
		name      string
		rows      []pgIAMRow
		withTTL   bool
		want      []string
		wantPages int
	}{
		{name: "empty", wantPages: 1},
		{name: "short", rows: []pgIAMRow{{key: "z"}}, want: []string{"z"}, wantPages: 1},
		{name: "exact", rows: []pgIAMRow{{key: "z"}, {key: "a"}}, want: []string{"z", "a"}, wantPages: 2},
		{name: "unordered", rows: []pgIAMRow{{key: "z"}, {key: "a"}, {key: "m"}}, want: []string{"z", "a", "m"}, wantPages: 2},
		{
			name: "fully expired page", withTTL: true,
			rows: []pgIAMRow{{key: "z", ttl: 1}, {key: "a", ttl: 1}, {key: "m"}},
			want: []string{"m"}, wantPages: 2,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			db := &pgIAMCursorTestDB{t: t, rows: tt.rows, batchSize: 2, withTTL: tt.withTTL}
			var seen []string
			err := loadPgIAMRowsByCursor(context.Background(), db, "config/iam/test/", 2, time.Second, tt.withTTL, func(row pgIAMRow) error {
				if !db.lastRows.closed || db.contexts[len(db.contexts)-1].Err() == nil || db.committed || db.rollbacks != 0 {
					t.Fatal("decoding must run after fetch cleanup, within the still-open transaction")
				}
				seen = append(seen, row.key)
				return nil
			})
			if err != nil || !reflect.DeepEqual(seen, tt.want) || db.fetches != tt.wantPages || !db.committed {
				t.Fatalf("err=%v, rows=%v, fetches=%d, committed=%v; want rows=%v, fetches=%d", err, seen, db.fetches, db.committed, tt.want, tt.wantPages)
			}
			db.checkReleased()
		})
	}
}

func TestLoadPgIAMRowsByCursorErrors(t *testing.T) {
	for _, stage := range []string{"begin", "setup", "declare", "fetch", "scan", "iteration", "consume", "commit"} {
		t.Run(stage, func(t *testing.T) {
			failure := errors.New("injected " + stage + " failure")
			if stage == "fetch" {
				failure = context.DeadlineExceeded
			}
			db := &pgIAMCursorTestDB{t: t, rows: []pgIAMRow{{key: "z"}}, batchSize: 2, failAt: stage, failure: failure}
			consumed := 0
			err := loadPgIAMRowsByCursor(context.Background(), db, "config/iam/test/", 2, time.Second, false, func(pgIAMRow) error {
				consumed++
				if stage == "consume" {
					return failure
				}
				return nil
			})
			if !errors.Is(err, failure) || !strings.Contains(err.Error(), "config/iam/test/") {
				t.Fatalf("failure lost its cause or table diagnostics: %v", err)
			}
			wantConsumed := 0
			if stage == "consume" || stage == "commit" {
				wantConsumed = 1
			}
			if consumed != wantConsumed || db.committed || (stage != "begin" && db.rollbacks != 1) {
				t.Fatalf("invalid failed transaction outcome: consumed=%d, committed=%v, rollbacks=%d", consumed, db.committed, db.rollbacks)
			}
			db.checkReleased()
		})
	}
}

func TestLoadPgIAMRowsByCursorCancellation(t *testing.T) {
	t.Run("before begin", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		db := &pgIAMCursorTestDB{t: t, batchSize: 2}
		err := loadPgIAMRowsByCursor(ctx, db, "config/iam/test/", 2, time.Second, false, func(pgIAMRow) error {
			t.Fatal("consumed a row after cancellation")
			return nil
		})
		if !errors.Is(err, context.Canceled) || len(db.operations) != 0 {
			t.Fatalf("canceled load started a transaction: err=%v, operations=%v", err, db.operations)
		}
	})
	for _, tt := range []struct {
		name string
		rows []pgIAMRow
	}{
		{name: "mid page", rows: []pgIAMRow{{key: "z"}, {key: "a"}}},
		{name: "last short page row", rows: []pgIAMRow{{key: "z"}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			db := &pgIAMCursorTestDB{t: t, rows: tt.rows, batchSize: 2}
			consumed := 0
			err := loadPgIAMRowsByCursor(ctx, db, "config/iam/test/", 2, time.Second, false, func(pgIAMRow) error {
				consumed++
				cancel()
				return nil
			})
			if !errors.Is(err, context.Canceled) || consumed != 1 || db.fetches != 1 || db.committed || db.rollbacks != 1 || db.rollbackCtxErr != nil {
				t.Fatalf("cancellation cleanup failed: err=%v, consumed=%d, fetches=%d, committed=%v, rollbacks=%d, rollback context=%v", err, consumed, db.fetches, db.committed, db.rollbacks, db.rollbackCtxErr)
			}
			db.checkReleased()
		})
	}
}

func TestLoadPgIAMRowsByCursorSlowDecode(t *testing.T) {
	db := &pgIAMCursorTestDB{t: t, rows: []pgIAMRow{{key: "z"}, {key: "a"}}, batchSize: 1}
	consumed := 0
	err := loadPgIAMRowsByCursor(context.Background(), db, "config/iam/test/", 1, 10*time.Millisecond, false, func(pgIAMRow) error {
		consumed++
		time.Sleep(20 * time.Millisecond)
		return nil
	})
	if err != nil || consumed != 2 || db.fetches != 3 || !db.committed {
		t.Fatalf("decode time exhausted a later operation's deadline: err=%v, consumed=%d, fetches=%d, committed=%v", err, consumed, db.fetches, db.committed)
	}
	db.checkReleased()
}

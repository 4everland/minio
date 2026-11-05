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
)

type pgIAMTestQuerier func(context.Context, string, ...interface{}) (pgx.Rows, error)

func (q pgIAMTestQuerier) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	return q(ctx, sql, args...)
}

type pgIAMTestRows struct {
	pgx.Rows
	rows                  []pgIAMRow
	index                 int
	closed                bool
	scanErr, iterationErr error
}

func (r *pgIAMTestRows) Close()     { r.closed = true }
func (r *pgIAMTestRows) Err() error { return r.iterationErr }

func (r *pgIAMTestRows) Next() bool {
	if r.index == len(r.rows) {
		r.Close()
		return false
	}
	r.index++
	return true
}

func (r *pgIAMTestRows) Scan(dest ...interface{}) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	row := r.rows[r.index-1]
	*dest[0].(*string) = row.key
	*dest[1].(*[]byte) = append([]byte(nil), row.data...)
	if len(dest) == 3 {
		*dest[2].(*int64) = row.ttl
	}
	return nil
}

func TestLoadPgIAMRowsPagination(t *testing.T) {
	for _, tt := range []struct {
		name      string
		rows      []pgIAMRow
		withTTL   bool
		want      []string
		wantPages int
	}{
		{name: "empty", wantPages: 1},
		{name: "partial", rows: []pgIAMRow{{key: "a"}}, want: []string{"a"}, wantPages: 1},
		{name: "exact", rows: []pgIAMRow{{key: "a"}, {key: "b"}}, want: []string{"a", "b"}, wantPages: 2},
		{name: "multiple", rows: []pgIAMRow{{key: "a"}, {key: "b"}, {key: "c"}}, want: []string{"a", "b", "c"}, wantPages: 2},
		{
			name: "expired page advances cursor", withTTL: true,
			rows: []pgIAMRow{{key: "a", ttl: 1}, {key: "b", ttl: 1}, {key: "c", ttl: time.Now().Add(time.Hour).Unix()}},
			want: []string{"c"}, wantPages: 2,
		},
		{
			name: "ttl ignored for policy documents",
			rows: []pgIAMRow{{key: "a", ttl: 1}}, want: []string{"a"}, wantPages: 1,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			remaining := append([]pgIAMRow(nil), tt.rows...)
			var seen []string
			var activeRows *pgIAMTestRows
			var queryCtx context.Context
			pages := 0
			lastKey := ""
			parent := context.Background()
			db := pgIAMTestQuerier(func(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
				pages++
				if pages > tt.wantPages {
					return nil, errors.New("pagination did not terminate")
				}
				if !strings.Contains(sql, `FROM "config/iam/test/"`) || !strings.Contains(sql, "ORDER BY key") {
					t.Fatalf("unexpected page query: %s", sql)
				}
				if tt.withTTL != strings.Contains(sql, "ttl") {
					t.Fatalf("unexpected TTL projection: %s", sql)
				}
				if pages == 1 {
					if strings.Contains(sql, "WHERE") || !reflect.DeepEqual(args, []interface{}{2}) {
						t.Fatalf("unexpected initial page: %s %v", sql, args)
					}
				} else if !strings.Contains(sql, "WHERE key > $1") || !reflect.DeepEqual(args, []interface{}{lastKey, 2}) {
					t.Fatalf("page did not resume after last raw key %q: %s %v", lastKey, sql, args)
				}
				if _, ok := ctx.Deadline(); !ok || ctx.Err() != nil {
					t.Fatalf("page must have a fresh, bounded context: %v", ctx.Err())
				}
				var page []pgIAMRow
				for _, row := range remaining {
					if pages == 1 || row.key > lastKey {
						page = append(page, row)
						if len(page) == 2 {
							break
						}
					}
				}
				if len(page) != 0 {
					lastKey = page[len(page)-1].key
				}
				activeRows = &pgIAMTestRows{rows: page}
				queryCtx = ctx
				return activeRows, nil
			})
			err := loadPgIAMRows(parent, db, "config/iam/test/", 2, time.Second, tt.withTTL, func(row pgIAMRow) error {
				if !activeRows.closed || queryCtx.Err() == nil || parent.Err() != nil {
					t.Fatal("page rows and query context must be released before processing with the live parent context")
				}
				seen = append(seen, row.key)
				// Expired-user cleanup can delete rows already read. Remaining
				// pages must still include every subsequent key.
				for i, existing := range remaining {
					if existing.key == row.key {
						remaining = append(remaining[:i], remaining[i+1:]...)
						break
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(seen, tt.want) || pages != tt.wantPages {
				t.Fatalf("loaded %v in %d pages, want %v in %d pages", seen, pages, tt.want, tt.wantPages)
			}
			if !activeRows.closed || queryCtx.Err() == nil {
				t.Fatal("final page resources were not released")
			}
		})
	}
}

func TestLoadPgIAMRowsErrors(t *testing.T) {
	for _, stage := range []string{"query", "query timeout", "scan", "iteration", "consume"} {
		t.Run(stage, func(t *testing.T) {
			wantErr := errors.New("injected " + stage + " failure")
			if stage == "query timeout" {
				wantErr = context.DeadlineExceeded
			}
			rows := &pgIAMTestRows{rows: []pgIAMRow{{key: "a"}}}
			var queryCtx context.Context
			calls, consumed := 0, 0
			db := pgIAMTestQuerier(func(ctx context.Context, _ string, _ ...interface{}) (pgx.Rows, error) {
				calls++
				queryCtx = ctx
				switch stage {
				case "query":
					return nil, wantErr
				case "query timeout":
					return nil, fmt.Errorf("timeout: %w", wantErr)
				case "scan":
					rows.scanErr = wantErr
				case "iteration":
					rows.iterationErr = wantErr
				}
				return rows, nil
			})
			err := loadPgIAMRows(context.Background(), db, "config/iam/test/", 2, time.Second, false, func(pgIAMRow) error {
				consumed++
				return wantErr
			})
			if !errors.Is(err, wantErr) {
				t.Fatalf("got %v, want wrapped %v", err, wantErr)
			}
			if !strings.Contains(err.Error(), "config/iam/test/") || !strings.Contains(err.Error(), "page 1") {
				t.Fatalf("missing table/page diagnostics: %v", err)
			}
			if calls != 1 || queryCtx.Err() == nil || (!strings.HasPrefix(stage, "query") && !rows.closed) {
				t.Fatal("failure did not stop loading and release page resources")
			}
			if (stage == "consume" && consumed != 1) || (stage != "consume" && consumed != 0) {
				t.Fatalf("consumed %d rows after %s failure", consumed, stage)
			}
		})
	}
}

func TestLoadPgIAMRowsParentCancellation(t *testing.T) {
	for _, tt := range []struct {
		name              string
		initiallyCanceled bool
		rows              []pgIAMRow
	}{
		{name: "before query", initiallyCanceled: true},
		{name: "mid page", rows: []pgIAMRow{{key: "a"}, {key: "b"}}},
		{name: "last row of short page", rows: []pgIAMRow{{key: "a"}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tt.initiallyCanceled {
				cancel()
			}
			queries, consumed := 0, 0
			db := pgIAMTestQuerier(func(ctx context.Context, _ string, _ ...interface{}) (pgx.Rows, error) {
				queries++
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				return &pgIAMTestRows{rows: tt.rows}, nil
			})
			err := loadPgIAMRows(ctx, db, "config/iam/test/", 2, time.Second, false, func(pgIAMRow) error {
				consumed++
				cancel()
				return nil
			})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("got %v, want cancellation", err)
			}
			if queries > 1 || (tt.initiallyCanceled && consumed != 0) || (!tt.initiallyCanceled && consumed != 1) {
				t.Fatalf("continued after cancellation: %d queries, %d consumed rows", queries, consumed)
			}
		})
	}
}

func TestLoadPgIAMRowsSlowDecode(t *testing.T) {
	queries, consumed := 0, 0
	db := pgIAMTestQuerier(func(ctx context.Context, _ string, _ ...interface{}) (pgx.Rows, error) {
		queries++
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if queries > 2 {
			return &pgIAMTestRows{}, nil
		}
		return &pgIAMTestRows{rows: []pgIAMRow{{key: fmt.Sprint(queries)}}}, nil
	})
	err := loadPgIAMRows(context.Background(), db, "config/iam/test/", 1, 10*time.Millisecond, false, func(pgIAMRow) error {
		consumed++
		// KMS/JSON work can outlive the database page's read deadline.
		time.Sleep(20 * time.Millisecond)
		return nil
	})
	if err != nil || queries != 3 || consumed != 2 {
		t.Fatalf("slow decode affected page read: err=%v, queries=%d, consumed=%d", err, queries, consumed)
	}
}

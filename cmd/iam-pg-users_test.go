package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/minio/minio/internal/auth"
)

type pgIAMUserTestDB struct {
	t             *testing.T
	cursor        *pgIAMCursorTestDB
	active        *pgIAMUserTestTx
	transactions  []*pgIAMUserTestTx
	identities    map[string]pgIAMRow
	mappings      map[string]bool
	notifications []pgNotifyPayload
	failAt        string
	failure       error
	afterDelete   func()
}

type pgIAMUserTestTx struct {
	pgx.Tx
	db            *pgIAMUserTestDB
	cursor        bool
	committed     bool
	rolledBack    bool
	lockedKey     string
	deletes       []string
	notifications []pgNotifyPayload
}

type pgIAMUserTestRow func(...interface{}) error

func (r pgIAMUserTestRow) Scan(dest ...interface{}) error { return r(dest...) }

func (db *pgIAMUserTestDB) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	db.t.Helper()
	if db.active != nil {
		db.t.Fatal("cleanup acquired a second connection while the cursor transaction was active")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tx := &pgIAMUserTestTx{db: db, cursor: opts.AccessMode == pgx.ReadOnly}
	if tx.cursor {
		if _, err := db.cursor.BeginTx(ctx, opts); err != nil {
			return nil, err
		}
	} else if opts.AccessMode != pgx.ReadWrite || opts.IsoLevel != pgx.ReadCommitted {
		db.t.Fatalf("cleanup needs a fresh read-committed write transaction: %+v", opts)
	}
	db.active = tx
	db.transactions = append(db.transactions, tx)
	return tx, nil
}

func (tx *pgIAMUserTestTx) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	if !tx.cursor {
		tx.db.t.Fatal("unexpected streaming query in cleanup transaction")
	}
	return tx.db.cursor.Query(ctx, sql, args...)
}

func (tx *pgIAMUserTestTx) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	tx.db.t.Helper()
	want := fmt.Sprintf(`SELECT data, ttl FROM "%s" WHERE key = $1 FOR UPDATE`, iamConfigUsersPrefix)
	if tx.cursor || sql != want || len(args) != 1 {
		tx.db.t.Fatalf("cleanup must lock the latest identity: %s %v", sql, args)
	}
	tx.lockedKey = args[0].(string)
	return pgIAMUserTestRow(func(dest ...interface{}) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		row, ok := tx.db.identities[tx.lockedKey]
		if !ok {
			return pgx.ErrNoRows
		}
		*dest[0].(*[]byte) = append([]byte(nil), row.data...)
		*dest[1].(*int64) = row.ttl
		return nil
	})
}

func (tx *pgIAMUserTestTx) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	if tx.cursor {
		// Reuse the existing cursor fake with this loader's real table name.
		sql = strings.ReplaceAll(sql, `"`+iamConfigUsersPrefix+`"`, `"config/iam/test/"`)
		return tx.db.cursor.Exec(ctx, sql, args...)
	}
	if err := ctx.Err(); err != nil {
		return pgconn.CommandTag{}, err
	}
	if tx.lockedKey == "" {
		tx.db.t.Fatal("cleanup wrote before locking and rechecking the identity")
	}
	var stage string
	switch {
	case strings.HasPrefix(sql, "DELETE"):
		key := args[0].(string)
		stage = "delete mapping"
		table := iamConfigPolicyDBUsersPrefix
		if key == tx.lockedKey {
			stage = "delete identity"
			table = iamConfigUsersPrefix
		}
		if sql != fmt.Sprintf(`DELETE FROM "%s" WHERE key = $1`, table) {
			tx.db.t.Fatalf("unexpected cleanup deletion: %s", sql)
		}
		tx.deletes = append(tx.deletes, key)
	case strings.Contains(sql, "pg_notify"):
		stage = "notify"
		if len(args) != 2 || args[0] != iamConfigPrefix {
			tx.db.t.Fatalf("unexpected notification arguments: %v", args)
		}
		var payload pgNotifyPayload
		if err := json.Unmarshal([]byte(args[1].(string)), &payload); err != nil {
			tx.db.t.Fatal(err)
		}
		tx.notifications = append(tx.notifications, payload)
	default:
		tx.db.t.Fatalf("unexpected cleanup SQL: %s", sql)
	}
	if tx.db.failAt == stage {
		return pgconn.CommandTag{}, tx.db.failure
	}
	if stage == "delete identity" && tx.db.afterDelete != nil {
		tx.db.afterDelete()
	}
	return pgconn.CommandTag{}, nil
}

func (tx *pgIAMUserTestTx) Commit(ctx context.Context) error {
	if tx.cursor {
		if err := tx.db.cursor.Commit(ctx); err != nil {
			return err
		}
	} else {
		if err := ctx.Err(); err != nil {
			return err
		}
		if tx.db.failAt == "commit" {
			return tx.db.failure
		}
		for _, key := range tx.deletes {
			delete(tx.db.identities, key)
			delete(tx.db.mappings, key)
		}
		tx.db.notifications = append(tx.db.notifications, tx.notifications...)
	}
	tx.committed = true
	tx.db.active = nil
	return nil
}

func (tx *pgIAMUserTestTx) Rollback(ctx context.Context) error {
	if tx.cursor {
		_ = tx.db.cursor.Rollback(ctx)
	} else if ctx.Err() != nil {
		tx.db.t.Fatalf("cleanup rollback inherited a canceled context: %v", ctx.Err())
	}
	tx.rolledBack = true
	if tx.db.active == tx {
		tx.db.active = nil
	}
	return nil
}

func pgIAMRegularUserTestRow(t *testing.T, user string, expired bool) pgIAMRow {
	t.Helper()
	cred := auth.Credentials{SecretKey: "test-secret", Status: auth.AccountOn}
	if expired {
		cred.Expiration = time.Now().Add(-time.Hour)
	}
	data, err := json.Marshal(newUserIdentity(cred))
	if err != nil {
		t.Fatal(err)
	}
	return pgIAMRow{key: getUserIdentityPath(user, regUser), data: data}
}

func TestLoadPgIAMRegularUsers(t *testing.T) {
	normal := pgIAMRegularUserTestRow(t, "normal", false)
	expired := pgIAMRegularUserTestRow(t, "expired", true)
	renewed := pgIAMRegularUserTestRow(t, "renewed", true)
	ttlExpired := pgIAMRegularUserTestRow(t, "ttl-expired", true)
	ttlExpired.ttl = 1
	db := &pgIAMUserTestDB{
		t: t, cursor: &pgIAMCursorTestDB{t: t, rows: []pgIAMRow{normal, expired, renewed, ttlExpired}, batchSize: 2, withTTL: true},
		identities: map[string]pgIAMRow{normal.key: normal, expired.key: expired, renewed.key: pgIAMRegularUserTestRow(t, "renewed", false), ttlExpired.key: ttlExpired},
		mappings:   map[string]bool{getMappedPolicyPath("expired", regUser, false): true, getMappedPolicyPath("renewed", regUser, false): true},
	}
	users := map[string]UserIdentity{}
	if err := loadPgIAMRegularUsers(context.Background(), db, 2, time.Second, users); err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || users["normal"].Credentials.AccessKey != "normal" || users["renewed"].Credentials.AccessKey != "renewed" || users["renewed"].Credentials.IsExpired() {
		t.Fatalf("normal/renewed identities were not loaded correctly: %v", users)
	}
	if len(db.transactions) != 3 || !db.transactions[0].committed || db.active != nil {
		t.Fatalf("cursor was not released before the two cleanup transactions: %+v", db.transactions)
	}
	if _, exists := db.identities[expired.key]; exists || db.mappings[getMappedPolicyPath("expired", regUser, false)] {
		t.Fatal("expired identity and mapping were not deleted together")
	}
	if _, exists := db.identities[renewed.key]; !exists || !db.mappings[getMappedPolicyPath("renewed", regUser, false)] {
		t.Fatal("concurrently renewed user was deleted")
	}
	wantNotifications := []pgNotifyPayload{{Key: expired.key}, {Key: getMappedPolicyPath("expired", regUser, false)}}
	if !reflect.DeepEqual(db.notifications, wantNotifications) {
		t.Fatalf("delete notifications = %v, want %v", db.notifications, wantNotifications)
	}
}

func TestLoadPgIAMRegularUsersCursorFailureSkipsCleanup(t *testing.T) {
	expired := pgIAMRegularUserTestRow(t, "expired", true)
	db := &pgIAMUserTestDB{t: t, cursor: &pgIAMCursorTestDB{t: t, rows: []pgIAMRow{expired, {key: "broken", data: []byte("invalid JSON")}}, batchSize: 2, withTTL: true}}
	err := loadPgIAMRegularUsers(context.Background(), db, 2, time.Second, map[string]UserIdentity{})
	if err == nil || len(db.transactions) != 1 || db.transactions[0].committed || !db.transactions[0].rolledBack || db.active != nil {
		t.Fatalf("failed scan started cleanup or leaked its transaction: err=%v, txs=%d", err, len(db.transactions))
	}
}

func TestLoadPgIAMRegularUsersAllExpired(t *testing.T) {
	for _, failCleanup := range []bool{false, true} {
		t.Run(fmt.Sprintf("cleanupFailure=%v", failCleanup), func(t *testing.T) {
			row := pgIAMRegularUserTestRow(t, "expired", true)
			failure := errors.New("mapping deletion failed")
			db := &pgIAMUserTestDB{
				t: t, cursor: &pgIAMCursorTestDB{t: t, rows: []pgIAMRow{row}, batchSize: 1, withTTL: true},
				identities: map[string]pgIAMRow{row.key: row}, mappings: map[string]bool{getMappedPolicyPath("expired", regUser, false): true},
				failure: failure,
			}
			if failCleanup {
				db.failAt = "delete mapping"
			}
			users := map[string]UserIdentity{}
			err := loadPgIAMRegularUsers(context.Background(), db, 1, time.Second, users)
			if err != nil {
				t.Fatalf("best-effort cleanup prevented loading: %v", err)
			}
			if len(users) != 0 || db.cursor.fetches != 2 || len(db.transactions) != 2 || !db.transactions[0].committed || db.active != nil {
				t.Fatalf("all-expired cursor did not finish before cleanup: users=%v, fetches=%d, transactions=%d", users, db.cursor.fetches, len(db.transactions))
			}
			if failCleanup {
				_, identityExists := db.identities[row.key]
				if !db.transactions[1].rolledBack || db.transactions[1].committed || !identityExists || !db.mappings[getMappedPolicyPath("expired", regUser, false)] || len(db.notifications) != 0 {
					t.Fatal("failed best-effort cleanup changed persisted identity or mapping")
				}
			}
		})
	}
}

func TestLoadPgIAMRegularUsersCleanupFailureContinues(t *testing.T) {
	expired := pgIAMRegularUserTestRow(t, "expired", true)
	renewed := pgIAMRegularUserTestRow(t, "renewed", true)
	db := &pgIAMUserTestDB{
		t: t, cursor: &pgIAMCursorTestDB{t: t, rows: []pgIAMRow{expired, renewed}, batchSize: 2, withTTL: true},
		identities: map[string]pgIAMRow{expired.key: expired, renewed.key: pgIAMRegularUserTestRow(t, "renewed", false)},
		mappings:   map[string]bool{getMappedPolicyPath("expired", regUser, false): true},
		failAt:     "delete mapping", failure: errors.New("mapping deletion failed"),
	}
	users := map[string]UserIdentity{}
	if err := loadPgIAMRegularUsers(context.Background(), db, 2, time.Second, users); err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users["renewed"].Credentials.AccessKey != "renewed" || users["renewed"].Credentials.IsExpired() {
		t.Fatalf("cleanup failure prevented restoring the next renewed user: %v", users)
	}
	if len(db.transactions) != 3 || !db.transactions[1].rolledBack || db.transactions[1].committed || !db.transactions[2].committed || db.active != nil {
		t.Fatal("failed cleanup did not roll back before processing the next candidate")
	}
}

func TestLoadPgIAMRegularUsersCleanupCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	expired := pgIAMRegularUserTestRow(t, "expired", true)
	next := pgIAMRegularUserTestRow(t, "next", true)
	db := &pgIAMUserTestDB{
		t: t, cursor: &pgIAMCursorTestDB{t: t, rows: []pgIAMRow{expired, next}, batchSize: 2, withTTL: true},
		identities:  map[string]pgIAMRow{expired.key: expired, next.key: next},
		mappings:    map[string]bool{getMappedPolicyPath("expired", regUser, false): true},
		afterDelete: cancel,
	}
	err := loadPgIAMRegularUsers(ctx, db, 2, time.Second, map[string]UserIdentity{})
	_, identityExists := db.identities[expired.key]
	if !errors.Is(err, context.Canceled) || len(db.transactions) != 2 || !db.transactions[1].rolledBack || !identityExists || !db.mappings[getMappedPolicyPath("expired", regUser, false)] || db.active != nil {
		t.Fatalf("loader ignored cancellation or continued cleanup: err=%v, transactions=%d", err, len(db.transactions))
	}
}

func TestReloadPgIAMExpiredRegularUserMissingOrTTLExpired(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprintf("missing=%v", missing), func(t *testing.T) {
			row := pgIAMRegularUserTestRow(t, "expired", true)
			row.ttl = 1
			mapping := getMappedPolicyPath("expired", regUser, false)
			db := &pgIAMUserTestDB{t: t, identities: map[string]pgIAMRow{}, mappings: map[string]bool{mapping: true}}
			if !missing {
				db.identities[row.key] = row
			}
			_, found, err := reloadPgIAMExpiredRegularUser(context.Background(), db, "expired", time.Second)
			if err != nil || found || !db.mappings[mapping] || len(db.notifications) != 0 || db.active != nil {
				t.Fatalf("missing/TTL-expired identity changed mapping or leaked a transaction: err=%v, found=%v", err, found)
			}
		})
	}
}

func TestReloadPgIAMExpiredRegularUserRollsBack(t *testing.T) {
	for _, stage := range []string{"delete identity", "delete mapping", "notify", "commit", "cancel after delete"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			row := pgIAMRegularUserTestRow(t, "expired", true)
			mapping := getMappedPolicyPath("expired", regUser, false)
			failure := errors.New("injected " + stage)
			db := &pgIAMUserTestDB{t: t, identities: map[string]pgIAMRow{row.key: row}, mappings: map[string]bool{mapping: true}, failAt: stage, failure: failure}
			if stage == "cancel after delete" {
				db.afterDelete = cancel
				failure = context.Canceled
			}
			_, found, err := reloadPgIAMExpiredRegularUser(ctx, db, "expired", time.Second)
			_, identityExists := db.identities[row.key]
			if !errors.Is(err, failure) || found || !identityExists || !db.mappings[mapping] || len(db.notifications) != 0 || db.active != nil || !db.transactions[0].rolledBack {
				t.Fatalf("failed cleanup was not atomic: err=%v, found=%v, identity=%v, mapping=%v, notifications=%v", err, found, identityExists, db.mappings[mapping], db.notifications)
			}
		})
	}
}

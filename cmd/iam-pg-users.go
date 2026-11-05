package cmd

import (
	"context"
	"errors"
	"fmt"
	"path"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/minio/minio/internal/logger"
)

// loadPgIAMRegularUsers keeps cursor processing free of database writes. Expired
// identities are rechecked only after the scan releases its connection, allowing
// even a single-connection pool to finish loading users.
func loadPgIAMRegularUsers(ctx context.Context, db pgIAMTxBeginner, batchSize int, timeout time.Duration, m map[string]UserIdentity) error {
	var expiredUsers []string
	err := loadPgIAMRowsByCursor(ctx, db, iamConfigUsersPrefix, batchSize, timeout, true, func(row pgIAMRow) error {
		var u UserIdentity
		if err := getIAMConfig(&u, row.data, row.key); err != nil {
			if errors.Is(err, errConfigNotFound) {
				return nil
			}
			return err
		}
		user := extractPathPrefixAndSuffix(row.key, iamConfigUsersPrefix, path.Base(row.key))
		if u.Credentials.IsExpired() {
			expiredUsers = append(expiredUsers, user)
			return nil
		}
		if u.Credentials.AccessKey == "" {
			u.Credentials.AccessKey = user
		}
		m[user] = u
		return nil
	})
	if err != nil || len(expiredUsers) == 0 {
		return err
	}

	cleanupStart := time.Now()
	rechecked, restored, failed := 0, 0, 0
	defer func() {
		logger.Info("IAM PostgreSQL user cleanup: table=%q candidates=%d rechecked=%d restored=%d failed=%d total=%s",
			iamConfigUsersPrefix, len(expiredUsers), rechecked, restored, failed, time.Since(cleanupStart).Round(time.Microsecond))
	}()
	for _, user := range expiredUsers {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("load IAM table %q (cleanup): %w", iamConfigUsersPrefix, err)
		}
		u, found, err := reloadPgIAMExpiredRegularUser(ctx, db, user, timeout)
		if err != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("load IAM table %q (cleanup): %w", iamConfigUsersPrefix, ctx.Err())
			}
			// Cleanup has always been best-effort. A stale expired record must
			// not prevent publishing the valid identities loaded above.
			failed++
			logger.LogIf(ctx, fmt.Errorf("load IAM table %q (cleanup user %q): %w", iamConfigUsersPrefix, user, err))
			continue
		}
		rechecked++
		if found {
			// A user may have been renewed after the cursor's snapshot. Load
			// the current identity instead of deleting or caching the old one.
			if u.Credentials.AccessKey == "" {
				u.Credentials.AccessKey = user
			}
			m[user] = u
			restored++
		}
	}
	return ctx.Err()
}

// reloadPgIAMExpiredRegularUser locks the latest identity before deciding to
// delete it. Renewal must not race between this check and deleting the identity
// and its policy mapping. Both deletes and their notifications commit together.
func reloadPgIAMExpiredRegularUser(ctx context.Context, db pgIAMTxBeginner, user string, timeout time.Duration) (UserIdentity, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return UserIdentity{}, false, err
	}
	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite})
	if err != nil {
		return UserIdentity{}, false, fmt.Errorf("begin: %w", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_ = tx.Rollback(cleanupCtx)
	}()

	identityPath := getUserIdentityPath(user, regUser)
	identityTable := pgx.Identifier{iamConfigUsersPrefix}.Sanitize()
	var data []byte
	var ttl int64
	err = tx.QueryRow(ctx, fmt.Sprintf("SELECT data, ttl FROM %s WHERE key = $1 FOR UPDATE", identityTable), identityPath).Scan(&data, &ttl)
	if errors.Is(err, pgx.ErrNoRows) {
		return UserIdentity{}, false, nil
	}
	if err != nil {
		return UserIdentity{}, false, fmt.Errorf("read current identity: %w", err)
	}
	// Preserve the existing behavior of skipping rows whose database TTL expired.
	if ttl != 0 && ttl < time.Now().Unix() {
		return UserIdentity{}, false, nil
	}
	var u UserIdentity
	if err := getIAMConfig(&u, data, identityPath); err != nil {
		return UserIdentity{}, false, fmt.Errorf("decode current identity: %w", err)
	}
	if !u.Credentials.IsExpired() {
		if err := tx.Commit(ctx); err != nil {
			return UserIdentity{}, false, fmt.Errorf("commit current identity: %w", err)
		}
		return u, true, nil
	}

	if _, err := tx.Exec(ctx, fmt.Sprintf("DELETE FROM %s WHERE key = $1", identityTable), identityPath); err != nil {
		return UserIdentity{}, false, fmt.Errorf("delete expired identity: %w", err)
	}
	policyPath := getMappedPolicyPath(user, regUser, false)
	policyTable := pgx.Identifier{iamConfigPolicyDBUsersPrefix}.Sanitize()
	if _, err := tx.Exec(ctx, fmt.Sprintf("DELETE FROM %s WHERE key = $1", policyTable), policyPath); err != nil {
		return UserIdentity{}, false, fmt.Errorf("delete expired policy mapping: %w", err)
	}
	for _, key := range []string{identityPath, policyPath} {
		payload := pgNotifyPayload{IsCreated: false, Key: key}.toJson()
		if _, err := tx.Exec(ctx, "SELECT pg_notify($1, $2)", iamConfigPrefix, payload); err != nil {
			return UserIdentity{}, false, fmt.Errorf("notify expired identity cleanup: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return UserIdentity{}, false, fmt.Errorf("commit expired identity cleanup: %w", err)
	}
	return UserIdentity{}, false, nil
}

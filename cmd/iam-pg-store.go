package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio/internal/config"
	"github.com/minio/minio/internal/kms"
	"github.com/minio/minio/internal/logger"
	"path"
	"strings"
	"sync"
	"time"
)

// IAMPgStore implements IAMStorageAPI
type IAMPgStore struct {
	sync.RWMutex

	*iamCache

	usersSysType UsersSysType

	client   *pgxpool.Pool
	prefixes []string
}

type PgKV struct {
	Key   string
	Value []byte
}

func newIAMPgStore(client *pgxpool.Pool, usersSysType UsersSysType) *IAMPgStore {
	prefixes := []string{
		iamConfigPolicyDBGroupsPrefix,
		iamConfigPolicyDBServiceAccountsPrefix,
		iamConfigPolicyDBSTSUsersPrefix,
		iamConfigPolicyDBUsersPrefix,
		iamConfigPolicyDBPrefix,

		iamConfigSTSPrefix,
		iamConfigPoliciesPrefix,
		iamConfigGroupsPrefix,
		iamConfigServiceAccountsPrefix,
		iamConfigUsersPrefix,
	}

	return &IAMPgStore{
		iamCache:     newIamCache(),
		client:       client,
		usersSysType: usersSysType,
		prefixes:     prefixes,
	}
}

func (ips *IAMPgStore) rlock() *iamCache {
	ips.RLock()
	return ips.iamCache
}

func (ips *IAMPgStore) runlock() {
	ips.RUnlock()
}

func (ips *IAMPgStore) lock() *iamCache {
	ips.Lock()
	return ips.iamCache
}

func (ips *IAMPgStore) unlock() {
	ips.Unlock()
}

func (ips *IAMPgStore) getUsersSysType() UsersSysType {
	return ips.usersSysType
}

func (ips *IAMPgStore) saveIAMConfig(ctx context.Context, item interface{}, itemPath string, opts ...options) error {
	data, err := json.Marshal(item)
	if err != nil {
		return err
	}
	if GlobalKMS != nil {
		data, err = config.EncryptBytes(GlobalKMS, data, kms.Context{
			minioMetaBucket: path.Join(minioMetaBucket, itemPath),
		})
		if err != nil {
			return err
		}
	}

	return saveKeyDB(ctx, ips.client, ips.tableName(itemPath), itemPath, data, opts...)
}

func (ips *IAMPgStore) loadIAMConfig(ctx context.Context, item interface{}, path string) error {
	data, err := readKeyDB(ctx, ips.client, ips.tableName(path), path)
	if err != nil {
		return err
	}
	return getIAMConfig(item, data, path)
}

func (ips *IAMPgStore) loadIAMConfigBytes(ctx context.Context, path string) ([]byte, error) {
	data, err := readKeyDB(ctx, ips.client, ips.tableName(path), path)
	if err != nil {
		return nil, err
	}
	return decryptData(data, path)
}

func (ips *IAMPgStore) deleteIAMConfig(ctx context.Context, path string) error {
	return deleteKeyDB(ctx, ips.client, ips.tableName(path), path)
}

func (ips *IAMPgStore) loadPolicyDoc(ctx context.Context, policy string, m map[string]PolicyDoc) error {
	data, err := ips.loadIAMConfigBytes(ctx, getPolicyDocPath(policy))
	if err != nil {
		if err == errConfigNotFound {
			return errNoSuchPolicy
		}
		return err
	}

	var p PolicyDoc
	err = p.parseJSON(data)
	if err != nil {
		return err
	}

	m[policy] = p
	return nil
}

func (ips *IAMPgStore) getPolicyDocKV(ctx context.Context, key string, value []byte, m map[string]PolicyDoc) error {
	data, err := decryptData(value, key)
	if err != nil {
		if err == errConfigNotFound {
			return errNoSuchPolicy
		}
		return err
	}

	var p PolicyDoc
	err = p.parseJSON(data)
	if err != nil {
		return err
	}

	policy := extractPathPrefixAndSuffix(key, iamConfigPoliciesPrefix, path.Base(key))
	m[policy] = p
	return nil
}

func (ips *IAMPgStore) loadPolicyDocs(ctx context.Context, m map[string]PolicyDoc) error {
	ctx, cancel := context.WithTimeout(ctx, defaultContextTimeout)
	defer cancel()
	conn, err := ips.client.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	iter, err := conn.Query(ctx, fmt.Sprintf(`SELECT key, data FROM "%s"`, ips.tableName(iamConfigPoliciesPrefix)))
	if err != nil {
		return dbErrToErr(err)
	}

	for iter.Next() {
		var (
			key  string
			data pgtype.DriverBytes
		)
		if err = iter.Scan(&key, &data); err != nil {
			return err
		}
		if err = ips.getPolicyDocKV(ctx, key, data, m); err != nil && err != errNoSuchPolicy {
			return err
		}
	}
	if err = iter.Err(); err != nil {
		return dbErrToErr(err)
	}
	return nil
}

func (ips *IAMPgStore) getUserKV(ctx context.Context, key string, value []byte, userType IAMUserType, m map[string]UserIdentity, basePrefix string) error {
	var u UserIdentity
	err := getIAMConfig(&u, value, key)
	if err != nil {
		if err == errConfigNotFound {
			return errNoSuchUser
		}
		return err
	}
	user := extractPathPrefixAndSuffix(key, basePrefix, path.Base(key))
	return ips.addUser(ctx, user, userType, u, m)
}

func (ips *IAMPgStore) addUser(ctx context.Context, user string, userType IAMUserType, u UserIdentity, m map[string]UserIdentity) error {
	if u.Credentials.IsExpired() {
		// Delete expired identity.
		p := getUserIdentityPath(user, userType)
		deleteKeyDB(ctx, ips.client, ips.tableName(p), p)
		p = getMappedPolicyPath(user, userType, false)
		deleteKeyDB(ctx, ips.client, ips.tableName(p), p)
		return nil
	}
	if u.Credentials.AccessKey == "" {
		u.Credentials.AccessKey = user
	}
	m[user] = u
	return nil
}

func (ips *IAMPgStore) loadUser(ctx context.Context, user string, userType IAMUserType, m map[string]UserIdentity) error {
	var u UserIdentity
	err := ips.loadIAMConfig(ctx, &u, getUserIdentityPath(user, userType))
	if err != nil {
		if err == errConfigNotFound {
			return errNoSuchUser
		}
		return err
	}
	return ips.addUser(ctx, user, userType, u, m)
}

func (ips *IAMPgStore) loadUsers(ctx context.Context, userType IAMUserType, m map[string]UserIdentity) error {
	var basePrefix string
	switch userType {
	case svcUser:
		basePrefix = iamConfigServiceAccountsPrefix
	case stsUser:
		basePrefix = iamConfigSTSPrefix
	default:
		basePrefix = iamConfigUsersPrefix
	}

	ctx, cancel := context.WithTimeout(ctx, defaultContextTimeout)
	defer cancel()

	conn, err := ips.client.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	iter, err := conn.Query(ctx, fmt.Sprintf(`SELECT key, data, ttl FROM "%s"`, ips.tableName(basePrefix)))
	if err != nil {
		return dbErrToErr(err)
	}

	now := time.Now().Unix()
	for iter.Next() {
		var (
			key  string
			data pgtype.DriverBytes
			ttl  int64
		)
		if err = iter.Scan(&key, &data, &ttl); err != nil {
			return err
		}
		if ttl != 0 && ttl < now {
			continue
		}
		if err = ips.getUserKV(ctx, key, data, userType, m, basePrefix); err != nil && err != errNoSuchUser {
			return err
		}
	}
	if err = iter.Err(); err != nil {
		return dbErrToErr(err)
	}
	return nil
}

func (ips *IAMPgStore) loadGroup(ctx context.Context, group string, m map[string]GroupInfo) error {
	var gi GroupInfo
	err := ips.loadIAMConfig(ctx, &gi, getGroupInfoPath(group))
	if err != nil {
		if err == errConfigNotFound {
			return errNoSuchGroup
		}
		return err
	}
	m[group] = gi
	return nil
}

func (ips *IAMPgStore) loadGroups(ctx context.Context, m map[string]GroupInfo) error {
	ctx, cancel := context.WithTimeout(ctx, defaultContextTimeout)
	defer cancel()

	conn, err := ips.client.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	iter, err := conn.Query(ctx, fmt.Sprintf(`SELECT key, data FROM "%s"`, iamConfigGroupsPrefix))
	if err != nil {
		return dbErrToErr(err)
	}
	var gi GroupInfo
	for iter.Next() {
		var (
			key  string
			data pgtype.DriverBytes
		)
		if err = iter.Scan(&key, &data); err != nil {
			return err
		}

		if err = getIAMConfig(&gi, data, getGroupInfoPath(key)); err != nil {
			return err
		}
		m[extractPathPrefixAndSuffix(key, iamConfigGroupsPrefix, path.Base(key))] = gi
	}
	if err = iter.Err(); err != nil {
		return dbErrToErr(err)
	}
	return nil
}

func (ips *IAMPgStore) loadMappedPolicy(ctx context.Context, name string, userType IAMUserType, isGroup bool, m map[string]MappedPolicy) error {
	var p MappedPolicy
	err := ips.loadIAMConfig(ctx, &p, getMappedPolicyPath(name, userType, isGroup))
	if err != nil {
		if err == errConfigNotFound {
			return errNoSuchPolicy
		}
		return err
	}
	m[name] = p
	return nil
}

func getPgMappedPolicy(ctx context.Context, key string, value []byte, userType IAMUserType, isGroup bool, m map[string]MappedPolicy, basePrefix string) error {
	var p MappedPolicy
	err := getIAMConfig(&p, value, key)
	if err != nil {
		if err == errConfigNotFound {
			return errNoSuchPolicy
		}
		return err
	}
	name := extractPathPrefixAndSuffix(key, basePrefix, ".json")
	m[name] = p
	return nil
}

func (ips *IAMPgStore) loadMappedPolicies(ctx context.Context, userType IAMUserType, isGroup bool, m map[string]MappedPolicy) error {
	ctx, cancel := context.WithTimeout(ctx, defaultContextTimeout)
	defer cancel()

	var basePrefix string
	if isGroup {
		basePrefix = iamConfigPolicyDBGroupsPrefix
	} else {
		switch userType {
		case svcUser:
			basePrefix = iamConfigPolicyDBServiceAccountsPrefix
		case stsUser:
			basePrefix = iamConfigPolicyDBSTSUsersPrefix
		default:
			basePrefix = iamConfigPolicyDBUsersPrefix
		}
	}

	conn, err := ips.client.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	now := time.Now().Unix()
	iter, err := conn.Query(ctx, fmt.Sprintf(`SELECT key, data, ttl FROM "%s"`, ips.tableName(basePrefix)))
	if err != nil {
		return dbErrToErr(err)
	}
	for iter.Next() {
		var (
			key  string
			data pgtype.DriverBytes
			ttl  int64
		)
		if err = iter.Scan(&key, &data, &ttl); err != nil {
			return err
		}
		if ttl != 0 && ttl < now {
			continue
		}

		if err = getPgMappedPolicy(ctx, key, data, userType, isGroup, m, basePrefix); err != nil && err != errNoSuchPolicy {
			return err
		}
	}
	if err = iter.Err(); err != nil {
		return dbErrToErr(err)
	}
	return nil
}

func (ips *IAMPgStore) savePolicyDoc(ctx context.Context, policyName string, p PolicyDoc) error {
	return ips.saveIAMConfig(ctx, &p, getPolicyDocPath(policyName))
}

func (ips *IAMPgStore) saveMappedPolicy(ctx context.Context, name string, userType IAMUserType, isGroup bool, mp MappedPolicy, opts ...options) error {
	return ips.saveIAMConfig(ctx, mp, getMappedPolicyPath(name, userType, isGroup), opts...)
}

func (ips *IAMPgStore) saveUserIdentity(ctx context.Context, name string, userType IAMUserType, u UserIdentity, opts ...options) error {
	return ips.saveIAMConfig(ctx, u, getUserIdentityPath(name, userType), opts...)
}

func (ips *IAMPgStore) saveGroupInfo(ctx context.Context, name string, gi GroupInfo) error {
	return ips.saveIAMConfig(ctx, gi, getGroupInfoPath(name))
}

func (ips *IAMPgStore) deletePolicyDoc(ctx context.Context, name string) error {
	err := ips.deleteIAMConfig(ctx, getPolicyDocPath(name))
	if err == errConfigNotFound {
		err = errNoSuchPolicy
	}
	return err
}

func (ips *IAMPgStore) deleteMappedPolicy(ctx context.Context, name string, userType IAMUserType, isGroup bool) error {
	err := ips.deleteIAMConfig(ctx, getMappedPolicyPath(name, userType, isGroup))
	if err == errConfigNotFound {
		err = errNoSuchPolicy
	}
	return err
}

func (ips *IAMPgStore) deleteUserIdentity(ctx context.Context, name string, userType IAMUserType) error {
	err := ips.deleteIAMConfig(ctx, getUserIdentityPath(name, userType))
	if err == errConfigNotFound {
		err = errNoSuchUser
	}
	return err
}

func (ips *IAMPgStore) deleteGroupInfo(ctx context.Context, name string) error {
	err := ips.deleteIAMConfig(ctx, getGroupInfoPath(name))
	if err == errConfigNotFound {
		err = errNoSuchGroup
	}
	return err
}

func (ips *IAMPgStore) watch(ctx context.Context, keyPath string) <-chan iamWatchEvent {
	ch := make(chan iamWatchEvent)
	go func() {
		for {
			conn, err := ips.client.Acquire(context.Background())
			if err != nil {
				logger.LogIf(ctx, fmt.Errorf("Failure in loading watch event: acquire - %v", err))
				time.Sleep(time.Second * 5)
				continue
			}

			_, err = conn.Exec(context.Background(), fmt.Sprintf(`listen "%s"`, keyPath))
			if err != nil {
				logger.LogIf(ctx, fmt.Errorf("Failure in loading watch event: exec - %v", err))
				time.Sleep(time.Second * 5)
				continue
			}

			if err := ips.waitForNotification(ctx, conn, ch); err != nil && errors.Is(ctx.Err(), err) {
				logger.LogIf(ctx, fmt.Errorf("Failure in loading watch event: waitForNotification - %v", err))
				return
			}
		}
	}()

	return ch
}

func (ips *IAMPgStore) waitForNotification(ctx context.Context, conn *pgxpool.Conn, ch chan<- iamWatchEvent) error {
	var data pgNotifyPayload
	for {
		msg, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			logger.LogIf(ctx, fmt.Errorf("Failure in loading watch event: %v", err))
			return err
		}

		_ = json.Unmarshal([]byte(msg.Payload), &data)
		ch <- iamWatchEvent{
			isCreated: data.IsCreated,
			keyPath:   data.Key,
		}
	}
}

func (ips *IAMPgStore) tableName(key string) string {
	for _, p := range ips.prefixes {
		if strings.HasPrefix(key, p) {
			return p
		}
	}

	return minioConfigPrefix
}

type pgNotifyPayload struct {
	IsCreated bool
	Key       string
}

func (p pgNotifyPayload) toJson() string {
	b, _ := json.Marshal(p)
	return string(b)
}

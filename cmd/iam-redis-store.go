package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/minio/minio/internal/config"
	"github.com/minio/minio/internal/kms"
	"github.com/redis/go-redis/v9"
	"path"
	"sync"
)

//func redisKeyToSet(prefix string, keys []string) set.StringSet {
//	users := set.NewStringSet()
//	for _, key := range keys {
//		user := extractPathPrefixAndSuffix(key, prefix, path.Base(key))
//		users.Add(user)
//	}
//	return users
//}

//// Extract path string by stripping off the `prefix` value and the suffix,
//// value, usually in the following form.
////
////	s := "config/iam/users/foo/config.json"
////	prefix := "config/iam/users/"
////	suffix := "config.json"
////	result is foo
//func extractPathPrefixAndSuffix(s string, prefix string, suffix string) string {
//	return pathClean(strings.TrimSuffix(strings.TrimPrefix(s, prefix), suffix))
//}

// IAMRedisStore implements IAMStorageAPI
type IAMRedisStore struct {
	sync.RWMutex

	*iamCache

	usersSysType UsersSysType

	client *redis.Client
}

type RedisKV struct {
	Key   string
	Value []byte
}

func newIAMRedisStore(client *redis.Client, usersSysType UsersSysType) *IAMRedisStore {
	return &IAMRedisStore{
		iamCache:     newIamCache(),
		client:       client,
		usersSysType: usersSysType,
	}
}

func (irs *IAMRedisStore) rlock() *iamCache {
	irs.RLock()
	return irs.iamCache
}

func (irs *IAMRedisStore) runlock() {
	irs.RUnlock()
}

func (irs *IAMRedisStore) lock() *iamCache {
	irs.Lock()
	return irs.iamCache
}

func (irs *IAMRedisStore) unlock() {
	irs.Unlock()
}

func (irs *IAMRedisStore) getUsersSysType() UsersSysType {
	return irs.usersSysType
}

func (irs *IAMRedisStore) saveIAMConfig(ctx context.Context, item interface{}, itemPath string, opts ...options) error {
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
	return saveKeyRedis(ctx, irs.client, itemPath, data, opts...)
}

func (irs *IAMRedisStore) loadIAMConfig(ctx context.Context, item interface{}, path string) error {
	data, err := readKeyRedis(ctx, irs.client, path)
	if err != nil {
		return err
	}
	return getIAMConfig(item, data, path)
}

func (irs *IAMRedisStore) loadIAMConfigBytes(ctx context.Context, path string) ([]byte, error) {
	data, err := readKeyRedis(ctx, irs.client, path)
	if err != nil {
		return nil, err
	}
	return decryptData(data, path)
}

func (irs *IAMRedisStore) deleteIAMConfig(ctx context.Context, path string) error {
	return deleteKeyRedis(ctx, irs.client, path)
}

func (irs *IAMRedisStore) loadPolicyDoc(ctx context.Context, policy string, m map[string]PolicyDoc) error {
	data, err := irs.loadIAMConfigBytes(ctx, getPolicyDocPath(policy))
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

func (irs *IAMRedisStore) getPolicyDocKV(ctx context.Context, kv *RedisKV, m map[string]PolicyDoc) error {
	data, err := decryptData(kv.Value, kv.Key)
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

	policy := extractPathPrefixAndSuffix(kv.Key, iamConfigPoliciesPrefix, path.Base(kv.Key))
	m[policy] = p
	return nil
}

func (irs *IAMRedisStore) loadPolicyDocs(ctx context.Context, m map[string]PolicyDoc) error {
	ctx, cancel := context.WithTimeout(ctx, defaultContextTimeout)
	defer cancel()

	iter := irs.client.Scan(ctx, 0, iamConfigPoliciesPrefix, 0).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		val, err := irs.client.Get(ctx, key).Bytes()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				return errNoSuchPolicy
			}
			return redisErrToErr(err)
		}

		kv := &RedisKV{Key: key, Value: val}
		if err = irs.getPolicyDocKV(ctx, kv, m); err != nil && err != errNoSuchPolicy {
			return err
		}
	}

	if err := iter.Err(); err != nil {
		return redisErrToErr(err)
	}

	return nil
}

func (irs *IAMRedisStore) getUserKV(ctx context.Context, userkv *RedisKV, userType IAMUserType, m map[string]UserIdentity, basePrefix string) error {
	var u UserIdentity
	err := getIAMConfig(&u, userkv.Value, userkv.Key)
	if err != nil {
		if err == errConfigNotFound {
			return errNoSuchUser
		}
		return err
	}
	user := extractPathPrefixAndSuffix(userkv.Key, basePrefix, path.Base(userkv.Key))
	return irs.addUser(ctx, user, userType, u, m)
}

func (irs *IAMRedisStore) addUser(ctx context.Context, user string, userType IAMUserType, u UserIdentity, m map[string]UserIdentity) error {
	if u.Credentials.IsExpired() {
		// Delete expired identity.
		deleteKeyRedis(ctx, irs.client, getUserIdentityPath(user, userType))
		deleteKeyRedis(ctx, irs.client, getMappedPolicyPath(user, userType, false))
		return nil
	}
	if u.Credentials.AccessKey == "" {
		u.Credentials.AccessKey = user
	}
	m[user] = u
	return nil
}

func (irs *IAMRedisStore) loadUser(ctx context.Context, user string, userType IAMUserType, m map[string]UserIdentity) error {
	var u UserIdentity
	err := irs.loadIAMConfig(ctx, &u, getUserIdentityPath(user, userType))
	if err != nil {
		if err == errConfigNotFound {
			return errNoSuchUser
		}
		return err
	}
	return irs.addUser(ctx, user, userType, u, m)
}

func (irs *IAMRedisStore) loadUsers(ctx context.Context, userType IAMUserType, m map[string]UserIdentity) error {
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

	iter := irs.client.Scan(ctx, 0, basePrefix, 0).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		val, err := irs.client.Get(ctx, key).Bytes()
		if err != nil {
			return err
		}
		kv := &RedisKV{Key: key, Value: val}
		if err = irs.getUserKV(ctx, kv, userType, m, basePrefix); err != nil && err != errNoSuchUser {
			return err
		}
	}

	if err := iter.Err(); err != nil {
		return redisErrToErr(err)
	}

	return nil
}

func (irs *IAMRedisStore) loadGroup(ctx context.Context, group string, m map[string]GroupInfo) error {
	var gi GroupInfo
	err := irs.loadIAMConfig(ctx, &gi, getGroupInfoPath(group))
	if err != nil {
		if err == errConfigNotFound {
			return errNoSuchGroup
		}
		return err
	}
	m[group] = gi
	return nil
}

func (irs *IAMRedisStore) loadGroups(ctx context.Context, m map[string]GroupInfo) error {
	ctx, cancel := context.WithTimeout(ctx, defaultContextTimeout)
	defer cancel()

	iter := irs.client.Scan(ctx, 0, iamConfigGroupsPrefix, 0).Iterator()
	for iter.Next(ctx) {
		group := iter.Val()
		if err := irs.loadGroup(ctx, group, m); err != nil && err != errNoSuchGroup {
			return err
		}
	}

	if err := iter.Err(); err != nil {
		return redisErrToErr(err)
	}

	return nil
}

func (irs *IAMRedisStore) loadMappedPolicy(ctx context.Context, name string, userType IAMUserType, isGroup bool, m map[string]MappedPolicy) error {
	var p MappedPolicy
	err := irs.loadIAMConfig(ctx, &p, getMappedPolicyPath(name, userType, isGroup))
	if err != nil {
		if err == errConfigNotFound {
			return errNoSuchPolicy
		}
		return err
	}
	m[name] = p
	return nil
}

func getRedisMappedPolicy(ctx context.Context, kv *RedisKV, userType IAMUserType, isGroup bool, m map[string]MappedPolicy, basePrefix string) error {
	var p MappedPolicy
	err := getIAMConfig(&p, kv.Value, kv.Key)
	if err != nil {
		if err == errConfigNotFound {
			return errNoSuchPolicy
		}
		return err
	}
	name := extractPathPrefixAndSuffix(kv.Key, basePrefix, ".json")
	m[name] = p
	return nil
}

func (irs *IAMRedisStore) loadMappedPolicies(ctx context.Context, userType IAMUserType, isGroup bool, m map[string]MappedPolicy) error {
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

	iter := irs.client.Scan(ctx, 0, basePrefix, 0).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		val, err := irs.client.Get(ctx, key).Bytes()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				return errNoSuchPolicy
			}
			return redisErrToErr(err)
		}

		kv := &RedisKV{Key: key, Value: val}
		if err = getRedisMappedPolicy(ctx, kv, userType, isGroup, m, basePrefix); err != nil && err != errNoSuchPolicy {
			return err
		}
	}

	if err := iter.Err(); err != nil {
		return redisErrToErr(err)
	}

	return nil
}

func (irs *IAMRedisStore) savePolicyDoc(ctx context.Context, policyName string, p PolicyDoc) error {
	return irs.saveIAMConfig(ctx, &p, getPolicyDocPath(policyName))
}

func (irs *IAMRedisStore) saveMappedPolicy(ctx context.Context, name string, userType IAMUserType, isGroup bool, mp MappedPolicy, opts ...options) error {
	return irs.saveIAMConfig(ctx, mp, getMappedPolicyPath(name, userType, isGroup), opts...)
}

func (irs *IAMRedisStore) saveUserIdentity(ctx context.Context, name string, userType IAMUserType, u UserIdentity, opts ...options) error {
	return irs.saveIAMConfig(ctx, u, getUserIdentityPath(name, userType), opts...)
}

func (irs *IAMRedisStore) saveGroupInfo(ctx context.Context, name string, gi GroupInfo) error {
	return irs.saveIAMConfig(ctx, gi, getGroupInfoPath(name))
}

func (irs *IAMRedisStore) deletePolicyDoc(ctx context.Context, name string) error {
	err := irs.deleteIAMConfig(ctx, getPolicyDocPath(name))
	if err == errConfigNotFound {
		err = errNoSuchPolicy
	}
	return err
}

func (irs *IAMRedisStore) deleteMappedPolicy(ctx context.Context, name string, userType IAMUserType, isGroup bool) error {
	err := irs.deleteIAMConfig(ctx, getMappedPolicyPath(name, userType, isGroup))
	if err == errConfigNotFound {
		err = errNoSuchPolicy
	}
	return err
}

func (irs *IAMRedisStore) deleteUserIdentity(ctx context.Context, name string, userType IAMUserType) error {
	err := irs.deleteIAMConfig(ctx, getUserIdentityPath(name, userType))
	if err == errConfigNotFound {
		err = errNoSuchUser
	}
	return err
}

func (irs *IAMRedisStore) deleteGroupInfo(ctx context.Context, name string) error {
	err := irs.deleteIAMConfig(ctx, getGroupInfoPath(name))
	if err == errConfigNotFound {
		err = errNoSuchGroup
	}
	return err
}

func (irs *IAMRedisStore) watch(ctx context.Context, keyPath string) <-chan iamWatchEvent {
	ch := make(chan iamWatchEvent)

	// go routine to read events from the Redis pubsub channel and send them
	// down `ch`
	go func() {
		pubsub := irs.client.Subscribe(ctx, keyPath)
		defer pubsub.Close()

		for {
			select {
			case <-ctx.Done():
				return
			case msg := <-pubsub.Channel():
				isCreateEvent := msg.Payload != ""
				isDeleteEvent := msg.Payload == ""

				switch {
				case isCreateEvent:
					ch <- iamWatchEvent{
						isCreated: true,
						keyPath:   msg.Channel,
					}
				case isDeleteEvent:
					ch <- iamWatchEvent{
						isCreated: false,
						keyPath:   msg.Channel,
					}
				}
			}
		}
	}()
	return ch
}

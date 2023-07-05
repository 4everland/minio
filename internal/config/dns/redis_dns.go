package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/coredns/coredns/plugin/etcd/msg"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/minio/minio-go/v7/pkg/set"
	"github.com/redis/go-redis/v9"
)

const redisKeySeparator = "/"

// Close closes the internal redis client and cannot be used further
func (c *RedisDNS) Close() error {
	return c.redisClient.Close()
}

// List - Retrieves list of DNS entries for the domain.
func (c *RedisDNS) List() (map[string][]SrvRecord, error) {
	srvRecords := map[string][]SrvRecord{}
	for _, domainName := range c.domainNames {
		key := msg.Path(fmt.Sprintf("%s.", domainName), c.prefixPath)
		records, err := c.list(key+redisKeySeparator, true)
		if err != nil {
			return srvRecords, err
		}
		for _, record := range records {
			if record.Key == "" {
				continue
			}
			srvRecords[record.Key] = append(srvRecords[record.Key], record)
		}
	}
	return srvRecords, nil
}

// Get - Retrieves DNS records for a bucket.
func (c *RedisDNS) Get(bucket string) ([]SrvRecord, error) {
	var srvRecords []SrvRecord
	for _, domainName := range c.domainNames {
		key := msg.Path(fmt.Sprintf("%s.%s", bucket, domainName), c.prefixPath)
		records, err := c.list(key, false)
		if err != nil {
			return nil, err
		}
		// Make sure we have record.Key is empty
		// this can only happen when record.Key
		// has bucket entry with exact prefix
		// match any record.Key which do not
		// match the prefixes we skip them.
		for _, record := range records {
			if record.Key != "" {
				continue
			}
			srvRecords = append(srvRecords, record)
		}
	}
	if len(srvRecords) == 0 {
		return nil, ErrNoEntriesFound
	}
	return srvRecords, nil
}

// redisMsgUnPath converts a redis key to domainname.
func redisMsgUnPath(s string) string {
	ks := strings.Split(strings.Trim(s, redisKeySeparator), redisKeySeparator)
	for i, j := 0, len(ks)-1; i < j; i, j = i+1, j-1 {
		ks[i], ks[j] = ks[j], ks[i]
	}
	return strings.Join(ks, ".")
}

// Retrieves list of entries under the key passed.
func (c *RedisDNS) list(key string, domain bool) ([]SrvRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultContextTimeout)
	defer cancel()
	iter := c.redisClient.Scan(ctx, 0, key+"*", 0).Iterator()

	var srvRecords []SrvRecord
	for iter.Next(ctx) {
		var srvRecord SrvRecord
		val, err := c.redisClient.Get(ctx, iter.Val()).Result()
		if err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(val), &srvRecord); err != nil {
			return nil, err
		}
		srvRecord.Key = strings.TrimPrefix(iter.Val(), key)
		srvRecord.Key = strings.TrimSuffix(srvRecord.Key, srvRecord.Host)

		// Skip non-bucket entry like for a key
		// /skydns/net/miniocloud/10.0.0.1 that may exist as
		// dns entry for the server (rather than the bucket
		// itself).
		if srvRecord.Key == "" {
			continue
		}

		srvRecord.Key = redisMsgUnPath(srvRecord.Key)
		srvRecords = append(srvRecords, srvRecord)
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	if len(srvRecords) == 0 && domain {
		return nil, ErrDomainMissing
	}

	sort.Slice(srvRecords, func(i int, j int) bool {
		return srvRecords[i].Key < srvRecords[j].Key
	})
	return srvRecords, nil
}

// Put - Adds DNS entries into redis endpoint in RedisDNS redis message format.
func (c *RedisDNS) Put(bucket string) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultContextTimeout)
	defer cancel()
	c.Delete(bucket) // delete any existing entries.

	t := time.Now().UTC()
	for ip := range c.domainIPs {
		bucketMsg, err := newCoreDNSMsg(ip, c.domainPort, defaultTTL, t)
		if err != nil {
			return err
		}
		for _, domainName := range c.domainNames {
			key := msg.Path(fmt.Sprintf("%s.%s", bucket, domainName), c.prefixPath)
			key = key + redisKeySeparator + ip
			err = c.redisClient.Set(ctx, key, string(bucketMsg), 0).Err()
			cancel()
			if err != nil {
				c.redisClient.Del(ctx, key)
				cancel()
				return err
			}
		}
	}
	return nil
}

// Delete - Removes DNS entries added in Put().
func (c *RedisDNS) Delete(bucket string) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultContextTimeout)
	defer cancel()
	for _, domainName := range c.domainNames {
		key := msg.Path(fmt.Sprintf("%s.%s", bucket, domainName), c.prefixPath)
		iter := c.redisClient.Scan(ctx, 0, key+"*", 0).Iterator()
		for iter.Next(ctx) {
			err := c.redisClient.Del(ctx, iter.Val()).Err()
			if err != nil {
				return err
			}
		}
		if err := iter.Err(); err != nil {
			return err
		}
	}
	return nil
}

// DeleteRecord - Removes a specific DNS entry
func (c *RedisDNS) DeleteRecord(record SrvRecord) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultContextTimeout)
	defer cancel()
	for _, domainName := range c.domainNames {
		key := msg.Path(fmt.Sprintf("%s.%s", record.Key, domainName), c.prefixPath)
		err := c.redisClient.Del(ctx, key+redisKeySeparator+record.Host).Err()
		if err != nil {
			return err
		}
	}
	return nil
}

// String stringer name for this implementation of dns.Store
func (c *RedisDNS) String() string {
	return "redisDNS"
}

// RedisDNS - represents dns config for RedisDNS server.
type RedisDNS struct {
	domainNames []string
	domainIPs   set.StringSet
	domainPort  string
	prefixPath  string
	redisClient *redis.Client
}

// RedisOption - functional options pattern style
type RedisOption func(*RedisDNS)

// RDomainNames set a list of domain names used by this RedisDNS
// client setting, note this will fail if set to empty when
// constructor initializes.
func RDomainNames(domainNames []string) RedisOption {
	return func(args *RedisDNS) {
		args.domainNames = domainNames
	}
}

// RDomainIPs set a list of custom domain IPs, note this will
// fail if set to empty when constructor initializes.
func RDomainIPs(domainIPs set.StringSet) RedisOption {
	return func(args *RedisDNS) {
		args.domainIPs = domainIPs
	}
}

// RDomainPort - is a string version of server port
func RDomainPort(domainPort string) RedisOption {
	return func(args *RedisDNS) {
		args.domainPort = domainPort
	}
}

// RDNSPath - custom prefix on etcd to populate DNS
// service records, optional and can be empty.
// if empty then c.prefixPath is used i.e "/skydns"
func RDNSPath(prefix string) RedisOption {
	return func(args *RedisDNS) {
		args.prefixPath = prefix
	}
}

// NewRedisDNS - initialize a new RedisDNS set/unset values.
func NewRedisDNS(client *redis.Client, setters ...RedisOption) (Store, error) {
	args := &RedisDNS{
		redisClient: client,
	}

	for _, setter := range setters {
		setter(args)
	}

	if len(args.domainNames) == 0 || args.domainIPs.IsEmpty() {
		return nil, errors.New("invalid argument")
	}

	// strip ports off of domainIPs
	domainIPsWithoutPorts := args.domainIPs.ApplyFunc(func(ip string) string {
		host, _, err := net.SplitHostPort(ip)
		if err != nil {
			if strings.Contains(err.Error(), "missing port in address") {
				host = ip
			}
		}
		return host
	})
	args.domainIPs = domainIPsWithoutPorts

	return args, nil
}

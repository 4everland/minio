package cmd

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"math/rand"
	"time"

	"github.com/minio/minio/internal/arn"
	"github.com/minio/minio/internal/config"
	xldap "github.com/minio/minio/internal/config/identity/ldap"
	"github.com/minio/minio/internal/config/identity/openid"
	idplugin "github.com/minio/minio/internal/config/identity/plugin"
	"github.com/minio/minio/internal/config/policy/opa"
	polplugin "github.com/minio/minio/internal/config/policy/plugin"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/logger"
)

// Init - initializes config system by reading entries from config/iam
func (sys *IAMSys) InitByPg(ctx context.Context, objAPI ObjectLayer, dbPool *pgxpool.Pool, iamRefreshInterval time.Duration) {
	globalServerConfigMu.RLock()
	s := globalServerConfig
	globalServerConfigMu.RUnlock()

	var err error
	globalOpenIDConfig, err = openid.LookupConfig(s,
		NewGatewayHTTPTransport(), xhttp.DrainBody, globalSite.Region)
	if err != nil {
		logger.LogIf(ctx, fmt.Errorf("Unable to initialize OpenID: %w", err))
	}

	// Initialize if LDAP is enabled
	globalLDAPConfig, err = xldap.Lookup(s, globalRootCAs)
	if err != nil {
		logger.LogIf(ctx, fmt.Errorf("Unable to parse LDAP configuration: %w", err))
	}

	authNPluginCfg, err := idplugin.LookupConfig(s[config.IdentityPluginSubSys][config.Default],
		NewGatewayHTTPTransport(), xhttp.DrainBody, globalSite.Region)
	if err != nil {
		logger.LogIf(ctx, fmt.Errorf("Unable to initialize AuthNPlugin: %w", err))
	}

	setGlobalAuthNPlugin(idplugin.New(authNPluginCfg))

	authZPluginCfg, err := polplugin.LookupConfig(s[config.PolicyPluginSubSys][config.Default],
		NewGatewayHTTPTransport(), xhttp.DrainBody)
	if err != nil {
		logger.LogIf(ctx, fmt.Errorf("Unable to initialize AuthZPlugin: %w", err))
	}

	if authZPluginCfg.URL == nil {
		opaCfg, err := opa.LookupConfig(s[config.PolicyOPASubSys][config.Default],
			NewGatewayHTTPTransport(), xhttp.DrainBody)
		if err != nil {
			logger.LogIf(ctx, fmt.Errorf("Unable to initialize AuthZPlugin from legacy OPA config: %w", err))
		} else {
			authZPluginCfg.URL = opaCfg.URL
			authZPluginCfg.AuthToken = opaCfg.AuthToken
			authZPluginCfg.Transport = opaCfg.Transport
			authZPluginCfg.CloseRespFn = opaCfg.CloseRespFn
		}
	}

	setGlobalAuthZPlugin(polplugin.New(authZPluginCfg))

	sys.Lock()
	defer sys.Unlock()

	sys.ldapConfig = globalLDAPConfig.Clone()
	sys.openIDConfig = globalOpenIDConfig.Clone()
	sys.iamRefreshInterval = iamRefreshInterval

	// Initialize IAM store
	sys.initStoreByPg(objAPI, dbPool)

	retryCtx, cancel := context.WithCancel(ctx)

	// Indicate to our routine to exit cleanly upon return.
	defer cancel()

	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Load IAM data from storage.
	for {
		if err := sys.Load(retryCtx); err != nil {
			if configRetriableErrors(err) {
				logger.Info("Waiting for all MinIO IAM sub-system to be initialized.. possible cause (%v)", err)
				time.Sleep(time.Duration(r.Float64() * float64(5*time.Second)))
				continue
			}
			if err != nil {
				logger.LogIf(ctx, fmt.Errorf("Unable to initialize IAM sub-system, some users may not be available %w", err))
			}
		}
		break
	}

	refreshInterval := sys.iamRefreshInterval

	// Set up polling for expired accounts and credentials purging.
	switch {
	case sys.openIDConfig.ProviderEnabled():
		go func() {
			timer := time.NewTimer(refreshInterval)
			defer timer.Stop()
			for {
				select {
				case <-timer.C:
					sys.purgeExpiredCredentialsForExternalSSO(ctx)

					timer.Reset(refreshInterval)
				case <-ctx.Done():
					return
				}
			}
		}()
	case sys.ldapConfig.Enabled():
		go func() {
			timer := time.NewTimer(refreshInterval)
			defer timer.Stop()

			for {
				select {
				case <-timer.C:
					sys.purgeExpiredCredentialsForLDAP(ctx)
					sys.updateGroupMembershipsForLDAP(ctx)

					timer.Reset(refreshInterval)
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Start watching changes to storage.
	go sys.watch(ctx)

	// Load RoleARNs
	sys.rolesMap = make(map[arn.ARN]string)

	// From OpenID
	if riMap := globalOpenIDConfig.GetRoleInfo(); riMap != nil {
		sys.validateAndAddRolePolicyMappings(ctx, riMap)
	}

	// From AuthN plugin if enabled.
	if authn := newGlobalAuthNPluginFn(); authn != nil {
		riMap := authn.GetRoleInfo()
		sys.validateAndAddRolePolicyMappings(ctx, riMap)
	}

	sys.printIAMRoles()
}

// initStoreByPg initializes IAM stores
func (sys *IAMSys) initStoreByPg(objAPI ObjectLayer, pgPool *pgxpool.Pool) {
	if sys.ldapConfig.Enabled() {
		sys.SetUsersSysType(LDAPUsersSysType)
	}

	if pgPool == nil {
		if globalIsGateway {
			if globalGatewayName == NASBackendGateway {
				sys.store = &IAMStoreSys{newIAMObjectStore(objAPI, sys.usersSysType)}
			} else {
				sys.store = &IAMStoreSys{newIAMDummyStore(sys.usersSysType)}
				logger.Info("WARNING: %s gateway is running in-memory IAM store, for persistence please configure redis",
					globalGatewayName)
			}
		} else {
			sys.store = &IAMStoreSys{newIAMObjectStore(objAPI, sys.usersSysType)}
		}
	} else {
		sys.store = &IAMStoreSys{newIAMPgStore(pgPool, sys.usersSysType)}
	}
}

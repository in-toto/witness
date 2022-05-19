package main

import (
	"github.com/InVisionApp/go-health/v2"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/common/fflag"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

type Config struct {
	Agent        *agentConfig                `hcl:"agent"`
	Plugins      *catalog.HCLPluginConfigMap `hcl:"plugins"`
	Telemetry    telemetry.FileConfig        `hcl:"telemetry"`
	HealthChecks health.Config               `hcl:"health_checks"`
	UnusedKeys   []string                    `hcl:",unusedKeys"`
}

type agentConfig struct {
	DataDir                       string    `hcl:"data_dir"`
	AdminSocketPath               string    `hcl:"admin_socket_path"`
	InsecureBootstrap             bool      `hcl:"insecure_bootstrap"`
	JoinToken                     string    `hcl:"join_token"`
	LogFile                       string    `hcl:"log_file"`
	LogFormat                     string    `hcl:"log_format"`
	LogLevel                      string    `hcl:"log_level"`
	SDS                           sdsConfig `hcl:"sds"`
	ServerAddress                 string    `hcl:"server_address"`
	ServerPort                    int       `hcl:"server_port"`
	SocketPath                    string    `hcl:"socket_path"`
	TrustBundlePath               string    `hcl:"trust_bundle_path"`
	TrustBundleURL                string    `hcl:"trust_bundle_url"`
	TrustDomain                   string    `hcl:"trust_domain"`
	AllowUnauthenticatedVerifiers bool      `hcl:"allow_unauthenticated_verifiers"`
	AllowedForeignJWTClaims       []string  `hcl:"allowed_foreign_jwt_claims"`

	AuthorizedDelegates []string `hcl:"authorized_delegates"`

	ConfigPath string
	ExpandEnv  bool

	// Undocumented configurables
	ProfilingEnabled bool               `hcl:"profiling_enabled"`
	ProfilingPort    int                `hcl:"profiling_port"`
	ProfilingFreq    int                `hcl:"profiling_freq"`
	ProfilingNames   []string           `hcl:"profiling_names"`
	Experimental     experimentalConfig `hcl:"experimental"`

	UnusedKeys []string `hcl:",unusedKeys"`
}

type sdsConfig struct {
	DefaultSVIDName             string `hcl:"default_svid_name"`
	DefaultBundleName           string `hcl:"default_bundle_name"`
	DefaultAllBundlesName       string `hcl:"default_all_bundles_name"`
	DisableSPIFFECertValidation bool   `hcl:"disable_spiffe_cert_validation"`
}

type experimentalConfig struct {
	SyncInterval       string `hcl:"sync_interval"`
	NamedPipeName      string `hcl:"named_pipe_name"`
	AdminNamedPipeName string `hcl:"admin_named_pipe_name"`
	Flags fflag.RawConfig `hcl:"feature_flags"`
	UnusedKeys []string `hcl:",unusedKeys"`
}

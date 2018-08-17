package ovtd

import (
	"flag"
	yaml "gopkg.in/yaml.v2"
	"os"
)

type NodeConfigYAML struct {
	Name    string   `yaml:"name"`
	Publish []string `yaml:"publish"`
	Active  bool     `yaml:"active"`
}

type NetworkClusterYAML struct {
	Token             string                     `yaml:"token"`
	TokenExpireBefore uint64                     `yaml:"token_expire_before"`
	TokenExpireAfter  uint64                     `yaml:"token_expire_after"`
	Term              uint64                     `yaml:"term"`
	HeartbeatPeriod   uint32                     `yaml:"heartbeat_period"`
	HeartbeatTimeout  uint32                     `yaml:"heartbeat_timeout"`
	Index             uint64                     `yaml:"index"`
	Nodes             map[string]*NodeConfigYAML `yaml:"nodes"`
}

type DynamicConfigYAML struct {
	Active  string                         `yaml:"active"`
	Machine string                         `yaml:"machine_id"`
	Network map[string]*NetworkClusterYAML `yaml:"network,omitempty"`
}

type DynamicConfig struct {
	file   *os.File
	Config DynamicConfigYAML
}

type Options struct {
	ClusterConfig    string
	PIDFile          string
	Control          string
	HeartbeatTimeout uint32
	HeartbeatPeriod  uint32
}

func OpenDynamicConfig(path string) (*DynamicConfig, error) {
	var err error
	creating := false
	cfg := new(DynamicConfig)

	info, err := os.Stat(path)
	if err != nil {
		creating = true
	}

	cfg.file, err = os.OpenFile(path, os.O_RDWR|os.O_CREATE, os.ModeExclusive)
	if err != nil {
		return nil, err
	}

	// init
	if creating {
		if err = cfg.Save(); err != nil {
			return nil, err
		}
		return cfg, nil
	}

	// load
	cfg.Load()

	return cfg, nil
}

func (cfg *DynamicConfig) Close() error {
	return cfg.file.Close()
}

func (cfg *DynamicConfig) Save() error {
	cfg.file.Seek(0, os.SEEK_SET)
	cfg.file.Truncate(0)

	str, err := yaml.Marshal(cfg.Config)
	if err != nil {
		return err
	}

	_, err = cfg.file.Write([]byte(str))
	if err != nil {
		return err
	}

	return nil
}

func (cfg *DynamicConfig) Load() error {
	var err error
	var info os.FileInfo

	info, err = cfg.file.Stat()

	buf := make([]byte, info.Size(), info.Size())

	cfg.file.Seek(0, os.SEEK_SET)
	if size, err := cfg.file.Read(buf); err != nil {
		return nil
	}

	return yaml.Unmarshal(buf, cfg.Config)
}

func (cfg *DynamicConfig) GetPart(begin uint64, end uint64) {
}

func parse_args() *Options {
	dyn_cfg := flag.String(
		"cluster-config",
		"/etc/ovt_net.yaml",
		"Dynamic configure maintained by overturn daemon.",
	)

	pid := flag.String(
		"pidfile",
		"/var/run/ovtd.pid",
		"PID file of daemon process.",
	)

	ctl := flag.String(
		"control",
		"unix:/var/run/ovtd.sock",
		"Control socket.",
	)

	hb_timeout := flag.Uint(
		"default-heartbeat-timeout",
		1000,
		"Default heartbeat timeout in network cluster.",
	)

	hb_period := flag.Uint(
		"default-heartbeat-period",
		200,
		"Default heartbeat period in network cluster.",
	)

	help := flag.Bool(
		"help",
		false,
		"Print the usage.",
	)

	flag.Parse()

	if *help {
		flag.Usage()
		return nil
	}

	return &Options{
		ClusterConfig:    *dyn_cfg,
		PIDFile:          *pid,
		Control:          *ctl,
		HeartbeatTimeout: uint32(*hb_timeout),
		HeartbeatPeriod:  uint32(*hb_period),
	}
}

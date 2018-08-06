package ovtd

import (
    "flag"
    yaml "gopkg.in/yaml.v2"
    log "github.com/sirupsen/logrus"
    "os"
)

type NodeConfig struct {
    ID          string      `yaml:"id"`
    Publish     string      `yaml:"publish"`
    Active      bool        `yaml:"active"`
}

type NetworkCluster struct {
    Token               string                      `yaml:"token"`
    TokenExpireBefore   uint64                      `yaml:"token_expire_before"`
    TokenExpireAfter    uint64                      `yaml:"token_expire_after"`
    Term                uint64                      `yaml:"term"`
    HeartbeatPeriod     uint32                      `yaml:"heartbeat_period"`
    HeartbeatTimeout    uint32                      `yaml:"heartbeat_timeout"`
    Index               uint64                      `yaml:"index"`
    Nodes               map[string]*NodeConfig      `yaml:"nodes"`
}

type DymanicConfigStruct struct {
    Active      string                          `yaml:"active"`
    Network     map[string]*NetworkCluster      `yaml:"network,omitempty"`
}

type DynamicConfig struct {
    file        *os.File
    Config      DymanicConfigStruct
}

type Options struct {
    ClusterConfig       string
    PIDFile             string
    Control             string
    HeartbeatTimeout    uint
    HeartbeatPeriod     uint
}


func OpenDynamicConfig(path string) *DynamicConfig, error {
    var err error
    creating := false
    cfg := new(DynamicConfig)

    info, err := os.Stat(path)
    if err != nil {
        creating = true        
    }

    cfg.file, err = os.OpenFile(path, os.O_RDWR | os.O_CREAT, os.ModeExclusive)
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
    cfg.Truncate(0)

    str, err = yaml.Marshal(cfg.Config)
    if err != nil {
        return err
    }

    _, err = file.Write([]byte(str))
    if err != nil {
        return err
    }

    return nil
}


func (cfg *DynamicConfig) Load() error {
    var err error, info os.FileInfo

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
            "cluster-config"
            , "/etc/ovt_net.yaml"
            , "Dynamic configure maintained by overturn daemon."
        )

    pid := flags.String(
            "pidfile"
            , "/var/run/ovtd.pid"
            , "PID file of daemon process."
        )

    ctl := flags.String(
            "control"
            , "unix:/var/run/ovtd.sock"
            , "Control socket."
        )

    hb_timeout := flags.Uint(
            "default-heartbeat-timeout"
            , 1000
            , "Default heartbeat timeout in network cluster."
        )

    hb_period := flags.Uint(
            "default-heartbeat-period"
            , 200
            , "Default heartbeat period in network cluster."
        )

    help := flag.Bool(
            "help"
            , false
            , "Print the usage."
        )

    flag.Parse()

    if *help {
        flag.Usage()
        return nil
    }

    return &Options{
        ClusterConfig:      *dyn_cfg,
        PIDFile:            *pid,
        Control:            *ctl,
        HeartbeatTimeout:   *hb_timeout,
        HeartbeatPeriod:    *hb_period,
    }
}


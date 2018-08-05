package ovtd

import (
    "flag"
    yaml "gopkg.in/yaml.v2"
    log "github.com/sirupsen/logrus"
    "os"
)


type Network struct {
    Token       string     `yaml:"token"`
    EndPoints   []string   `yaml:"endpoints"`
}

type DymanicConfigStruct struct {
    Term        uint64              `yaml:"term"`
    Index       uint64              `yaml:"index"`
    Active      string              `yaml:"active"`
    Network     map[string]*Network `yaml:"network,omitempty"`
}

type DynamicConfig struct {
    file        *os.File
    Config      DymanicConfigStruct
}

type StaticConfig struct {
    MaxVoteTimeout      uint16      `yaml:"max_vote_timeout,omitempty"`
    Conrtol             string      `yaml:"control,omitempty"`
    PidFile             string      `yaml:"pid_file,omitempty"`
    DynamicConfig       string      `yaml:"dynamic_config,omitempty"`
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
        cfg.Config.Term = 0
        cfg.Config.Index = 0
        cfg.Config.Active = ""

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
    
    cfg := flag.String(
            "config"
            , "/etc/overturn.yaml"
            , "Static configure."
        )

    dyn_cfg := flag.String(
            "dynamic_config"
                , "/etc/ovr_net.yaml"
            , "Dynamic configure which is maintained by overturn daemon."
        )

    help := flag.Bool(
            "help"
            , false
            , "Print the usage"
        )

    flag.Parse()

    if *help {
        flag.Usage()
        return nil
    }

    return &Options{
        Config:         *cfg
        DynamicConfig:  *dyn_cfg
    }
}


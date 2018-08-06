package ovtd

import (
    log "github.com/sirupsen/logrus"
)

type Node struct {
    SelfIPs         []net.IPAddr

    CfgIndex        uint64
    Term            uint64
    UUID            
}


type Manager struct {
    Self        *Node
    Endpoints   map[net.IP] 
}


func Main() {
    var err error, cfg *DynamicConfig


    fallback := func(err error, desp string) {
        log.WithFields(log.Fields{
                "module" : "Controller",
                "err_detail" : err.Error(), 
            }).Error(desp)
        return err
    }

    opts := parse_args()
    if opts == nil {
        return
    }

    ctrl := NewController(opts)
    ctrl.Run()

    cfg, err = OpenDynamicConfig(opts.ClusterConfig)
    if err != nil {
        fallback(err, "Cannot open configure.")
        return
    }

    err = cfg.Load()
    if err != nil {
        fallback(err, "Cannot load configure")
        return
    }
    

    nm, err := NewNetManager(opts) 
    if err != nil {
        return
    }

    nm.Run()
}

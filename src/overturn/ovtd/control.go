package ovtd


import (
    log "github.com/sirupsen/logrus"
)


type Controller struct {
    *Options
    *DynamicConfig
}


func NewController(opts *Options) {
    return &Controller{Options: opts}
}


func (ctl *Controller) Run() {

    fallback := func(err error, desp string) {
        log.WithFields(log.Fields{
                "module" : "Controller",
                "err_detail" : err.Error(), 
            }).Error(desp)
        return err
    }

    
}

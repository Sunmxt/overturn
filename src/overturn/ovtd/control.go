package ovtd

import (
	"errors"
	log "github.com/Sirupsen/logrus"
	"github.com/google/uuid"
)

const (
	ERR_CANNOT_GEN_MACHINE_ID = "Cannot generate machine ID."
	ERR_NO_ACTIVE_NETWORK     = "No active network."
	ERR_CONF_PERSIST          = "Cannot persist configure."
)

type Controller struct {
	*Options
	*DynamicConfig
	Machine   uuid.UUID
	RPCServer *UserRPCServer
}

func NewController(opts *Options) *Controller {
	return &Controller{Options: opts, DynamicConfig: nil}
}

func NewID() (string, error) {
	new_id, err := uuid.NewUUID()
	if err != nil {
		return "", err
	}
	return new_id.String(), nil
}

func (ctl *Controller) PersistDynamicClusterConfig() error {

	if err := ctl.DynamicConfig.Save(); err != nil {
		log.WithFields(log.Fields{
			"module":     "Controller",
			"err_detail": err.Error(),
		}).Error(ERR_CONF_PERSIST)
		return errors.New(ERR_CONF_PERSIST)
	}

	return nil
}

func (ctl *Controller) DispatchMessage() {
}

func (ctl *Controller) GetMachineID() uuid.UUID {
	return ctl.Machine
}

func (ctl *Controller) Run() error {
	var err error
	var cfg *DynamicConfig
	updated := false
	opts := ctl.Options

	fallback := func(err error, desp string) error {
		log.WithFields(log.Fields{
			"module":     "Controller",
			"err_detail": err.Error(),
		}).Error(desp)
		return err
	}

	cfg, err = OpenDynamicConfig(opts.ClusterConfig)
	if err != nil {
		fallback(err, "Cannot open configure.")
		return err
	}

	err = cfg.Load()
	if err != nil {
		fallback(err, "Cannot load configure")
		return err
	}

	if cfg.Config.Active == "" {
		log.WithFields(log.Fields{
			"module": "Controller",
		}).Error(ERR_NO_ACTIVE_NETWORK)
		return errors.New(ERR_NO_ACTIVE_NETWORK)
	}

	// Parse ID
	if cfg.Config.Machine == "" {
		cfg.Config.Machine, err = NewID()
		if err != nil {
			log.WithFields(log.Fields{
				"module":     "Controller",
				"err_detail": err.Error(),
			}).Error(ERR_CANNOT_GEN_MACHINE_ID)
			return errors.New(ERR_CANNOT_GEN_MACHINE_ID)
		}

		log.WithFields(log.Fields{
			"module": "Controller",
		}).Warningf("New machine ID: %v", cfg.Config.Machine)
		updated = true
	}
	ctl.Machine, err = uuid.Parse(cfg.Config.Machine)
	if err != nil {
		log.WithFields(log.Fields{
			"module":     "Controller",
			"event":      "initialize",
			"err_detail": err.Error(),
		}).Errorf("Invalid machine ID: %v.", cfg.Config.Machine)
		return errors.New("Invalid machine ID.")
	}

	// start network cluster
	var exists bool
	var active_config *NetworkClusterYAML
	active_config, exists = cfg.Config.Network[cfg.Config.Active]
	if active_config == nil || !exists { // create with default configure.

		log.WithFields(log.Fields{
			"module": "Controller",
		}).Warningf("Create non-existing active network %v.", cfg.Config.Active)

		active_config = &NetworkClusterYAML{
			Token:             "",
			TokenExpireBefore: 0,
			TokenExpireAfter:  0,
			Term:              0,
			HeartbeatPeriod:   opts.HeartbeatPeriod,
			HeartbeatTimeout:  opts.HeartbeatTimeout,
			Index:             0,
			Nodes:             make(map[string]*NodeConfigYAML),
		}

		cfg.Config.Network[cfg.Config.Active] = active_config
	}

	ctl.DynamicConfig = cfg
	// update configure
	if updated {
		if err = ctl.PersistDynamicClusterConfig(); err != nil {
			return err
		}
	}

	if ctl.RPCServer, err = NewUserRPCServer(ctl.Options.Control); err != nil {
		return err
	}

	var cluster_manager *ClusterManager
	cluster_manager, err = NewClusterManager(ctl, active_config)
	cluster_manager.Start()

	// RPC here
	return ctl.RPCServer.Serve()

}

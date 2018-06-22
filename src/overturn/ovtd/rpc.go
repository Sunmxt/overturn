package ovtd

import (
	"bytes"
	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"net"
	"net/rpc"
	"os"
	ctlrpc "overturn/ovtd/rpc"
	"sync/atomic"
)

type UserRPCServer struct {
	Listener net.Listener
	Server   *rpc.Server

	running uint32
}

func NewUserRPCServer(path string) (*UserRPCServer, error) {
	var err error
	var domain, address string
	var listener net.Listener

	fallback := func(err error) (*UserRPCServer, error) {
		log.WithFields(log.Fields{
			"module": "Controller",
			"event":  "rpc",
		}).Error(err.Error())
		return nil, err
	}

	if domain, address, err = ctlrpc.ParseRPCNetPath(path); err != nil {
		return fallback(err)
	}

	if domain == "unix" {
		_, err = os.Stat(address)
		if err == nil {
			os.Remove(address)
		}
	}
	if listener, err = net.Listen(domain, address); err != nil {
		return fallback(err)
	}

	rpc_server := &UserRPCServer{
		Listener: listener,
		Server:   rpc.NewServer(),
		running:  1,
	}
	if err = rpc_server.Server.RegisterName("DaemonControl", rpc_server); err != nil {
		return fallback(err)
	}

	return rpc_server, nil
}

func (rpc *UserRPCServer) Close() error {
	for {
		running := rpc.running
		if running == 0 {
			return errors.New("RPCServer not running.")
		}
		if atomic.CompareAndSwapUint32(&rpc.running, running, 0) {
			return nil
		}
	}

	return rpc.Listener.Close()
}

func (rpc *UserRPCServer) Serve() error {
	for rpc.running > 0 {
		conn, err := rpc.Listener.Accept()
		if err != nil {
			log.WithFields(log.Fields{
				"module": "RPCControl",
				"event":  "Connect",
			}).Error(err.Error())
			continue
		}

		rpc.Server.ServeConn(conn)
	}
	return nil
}

// RPC Exported methods
func (rpc *UserRPCServer) Version(args ctlrpc.VersionArgs, result *ctlrpc.VersionResult) error {
	var err error = nil

	if !bytes.Equal(args.Magic[:], ctlrpc.RPC_MAGIC[:]) {
		err = fmt.Errorf("RPC: Version (Invalid Magic: %x)", args.Magic[:])
		log.WithFields(log.Fields{
			"module": "RPCControl",
			"event":  "Call",
		}).Error(err.Error())

		return err
	}

	copy(result.Magic[:], args.Magic[:])
	args.Minor = ctlrpc.RPC_VERSION_MINOR
	args.Major = ctlrpc.RPC_VERSION_MAJOR

	log.WithFields(log.Fields{
		"module": "RPCControl",
		"event":  "Call",
	}).Infof("RPC: Version (RequestVersion: %v.%v) [Return: %v, %v]", args.Minor, args.Major, args.Minor, args.Major)

	return nil
}

func (rpc *UserRPCServer) StopDaemon(args ctlrpc.StopDaemonArgs, result *ctlrpc.StopDaemonResult) error {
	err := errors.New("RPC StopDaemon not available.")

	log.WithFields(log.Fields{
		"module": "RPCControl",
		"event":  "Call",
	}).Infof(err.Error())

	return err
}
